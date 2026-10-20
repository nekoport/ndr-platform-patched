"""Suricata rule management engine (Phase 6 - rule manager).

Reads and mutates the shared rules volume that the ndr-suricata container
also uses (compose mounts ./sensor/suricata/rules at /var/lib/suricata/rules
in both containers):

  suricata.rules   generated rule set actually loaded by the engine
  disable.conf     SIDs excluded on every (re)generation (suricata-update)
  enable.conf      SIDs forced back in (rare; read but not written here)
  custom.rules     operator-authored local rules (v0.11 custom editor)

Design notes:
- "Disabled" means "listed in disable.conf" - the same mechanism an
  operator would use by hand with suricata-update, so CLI and UI state
  can never diverge.
- Enabling/disabling ALWAYS regenerates suricata.rules via suricata-update
  (this does not require the sensor to be running) and then attempts a
  live reload over the Suricata unix command socket. If the socket is not
  reachable the change is reported as pending and simply applies at the
  next sensor start, because suricata reads suricata.rules at boot.
- All subprocess/socket work is serialized by a module lock so two API
  workers cannot regenerate rules concurrently.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import threading
from datetime import datetime, timezone

from app.config import config

# One apply operation at a time (toggle + update share the rules volume).
apply_lock = threading.Lock()

RULE_LINE = re.compile(
    r"^(?P<action>alert|drop|pass|reject)\s+(?P<protocol>\S+)\s+"
    r"(?P<src>\S+)\s+(?P<sport>\S+)\s*(?P<dir>->|<>)\s*"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<opts>.*)\)\s*$")
OPT_SID = re.compile(r"(?:^|;)\s*sid\s*:\s*(\d+)", re.S)
OPT_GID = re.compile(r"(?:^|;)\s*gid\s*:\s*(\d+)", re.S)
OPT_REV = re.compile(r"(?:^|;)\s*rev\s*:\s*(\d+)", re.S)
OPT_MSG = re.compile(r"(?:^|;)\s*msg\s*:\s*\"([^\"]*)\"", re.S)
OPT_CLASS = re.compile(r"(?:^|;)\s*classtype\s*:\s*([^;]+)", re.S)
OPT_PRIO = re.compile(r"(?:^|;)\s*priority\s*:\s*(\d+)", re.S)

SID_TOKEN = re.compile(r"^(?:(\d+):)?(\d+)$")  # plain sid or gid:sid


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ paths
def rules_path() -> str:
    return os.path.join(config.rules_dir, "suricata.rules")


def disable_path() -> str:
    return os.path.join(config.rules_dir, "disable.conf")


# ------------------------------------------------------------------ parse
def parse_rules_file(path: str | None = None) -> dict:
    """Parse the generated suricata.rules into structured entries.

    Malformed/comment lines never abort parsing; they are counted so the
    UI can be honest about anything the engine would ignore.
    """
    path = path or rules_path()
    out = {"items": [], "skipped": 0, "exists": os.path.isfile(path)}
    if not out["exists"]:
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = RULE_LINE.match(line)
            if not m:
                out["skipped"] += 1
                continue
            opts = m.group("opts")
            sid_m = OPT_SID.search(opts)
            if not sid_m:
                out["skipped"] += 1
                continue
            msg_m = OPT_MSG.search(opts)
            class_m = OPT_CLASS.search(opts)
            prio_m = OPT_PRIO.search(opts)
            gid_m = OPT_GID.search(opts)
            rev_m = OPT_REV.search(opts)
            out["items"].append({
                "sid": int(sid_m.group(1)),
                "gid": int(gid_m.group(1)) if gid_m else 1,
                "rev": int(rev_m.group(1)) if rev_m else None,
                "action": m.group("action"),
                "protocol": m.group("protocol"),
                "src": m.group("src"), "sport": m.group("sport"),
                "dst": m.group("dst"), "dport": m.group("dport"),
                "msg": msg_m.group(1) if msg_m else None,
                "classtype": (class_m.group(1).strip()
                              if class_m else None),
                "priority": int(prio_m.group(1)) if prio_m else None,
            })
    return out


def read_disable_sids(path: str | None = None) -> set[int]:
    """SIDs disabled via disable.conf (plain `sid` or `gid:sid` tokens).

    Regex entries (`re:...`) are operator-owned; we never touch them.
    """
    path = path or disable_path()
    sids: set[int] = set()
    if not os.path.isfile(path):
        return sids
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = SID_TOKEN.match(line)
            if m:
                sids.add(int(m.group(2)))
    return sids


def add_disable_sid(sid: int, comment: str | None = None,
                    path: str | None = None) -> None:
    path = path or disable_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existing = ""
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            existing = fh.read()
    for line in existing.splitlines():
        m = SID_TOKEN.match(line.strip())
        if m and int(m.group(2)) == sid:
            return  # already disabled
    header = ""
    if not existing:
        header = ("# Managed by NDR platform - SIDs here are removed from "
                  "suricata.rules on every regeneration.\n")
    note = f"# {comment}\n" if comment else ""
    with open(path, "a", encoding="utf-8") as fh:
        if header:
            fh.write(header)
        if note:
            fh.write(note)
        fh.write(f"{sid}\n")


def remove_disable_sid(sid: int, path: str | None = None) -> int:
    """Remove all matching sid tokens; returns lines removed.

    Lines that are comments or regex entries are preserved verbatim so
    operator-managed state never gets silently rewritten.
    """
    path = path or disable_path()
    if not os.path.isfile(path):
        return 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    kept, removed = [], 0
    for line in lines:
        m = SID_TOKEN.match(line.strip())
        if m and int(m.group(2)) == sid:
            removed += 1
            continue
        kept.append(line)
    if removed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(kept)
    return removed


def file_mtime(path: str | None = None) -> str | None:
    path = path or rules_path()
    try:
        return datetime.fromtimestamp(os.stat(path).st_mtime,
                                      tz=timezone.utc).isoformat()
    except OSError:
        return None


# ------------------------------------------------------- update / reload
def run_update(timeout: int | None = None) -> dict:
    """Regenerate suricata.rules via suricata-update (sensor not required).

    Returns {ok, output, error}; output tail is safe to show in the UI
    (the tool prints no credentials, but we cap it anyway).
    """
    cmd = ["suricata-update",
           "--suricata-conf", config.suricata_conf,
           "--data-dir", config.rules_data_dir,
           "--no-reload"]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, text=True,
            timeout=timeout or config.rules_update_timeout)
        if proc.returncode != 0 and "no-reload" in (proc.stderr or ""):
            # older suricata-update without --no-reload
            proc = subprocess.run(  # noqa: S603
                cmd[: -1], capture_output=True, text=True,
                timeout=timeout or config.rules_update_timeout)
        output = "\n".join(
            (proc.stdout or "").splitlines()[-30:] +
            (proc.stderr or "").splitlines()[-10:])[-4000:]
        return {"ok": proc.returncode == 0,
                "output": output,
                "error": None if proc.returncode == 0
                         else f"suricata-update exited {proc.returncode}"}
    except FileNotFoundError:
        return {"ok": False, "output": "",
                "error": "suricata-update binary not found in API image"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "",
                "error": "suricata-update timed out "
                         f"after {timeout or config.rules_update_timeout}s"}


def reload_via_socket(timeout: int = 15) -> dict:
    """Best-effort live reload over the Suricata unix command socket.

    Any failure is reported, never raised - a failed reload only means
    the change applies at next sensor start.
    """
    path = config.suricata_unix_socket
    if not os.path.exists(path):
        return {"ok": False, "detail": f"socket not present ({path}) - "
                "change applies at next sensor start"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            banner = s.recv(4096)  # {"version": "0.1"}
            json.loads(banner.decode("utf-8", "replace") or "{}")
            s.sendall(json.dumps(
                {"command": "reload-rules", "arguments": {}}).encode())
            reply = json.loads(s.recv(4096).decode("utf-8", "replace") or "{}")
        if reply.get("return") == "OK" or reply.get("message"):
            return {"ok": reply.get("return", "OK") == "OK",
                    "detail": reply.get("message", "reload requested")}
        return {"ok": False, "detail": f"unexpected reply: {reply}"}
    except Exception as exc:  # noqa: BLE001 - degrade, never raise
        return {"ok": False, "detail": f"reload not applied ({exc}) - "
                "change applies at next sensor start"}


def sensor_online() -> bool:
    try:
        return os.path.exists(config.suricata_unix_socket)
    except Exception:  # noqa: BLE001
        return False


# ----------------------------------------------------- custom rules (v0.11)
# Operator-authored local rules live in custom.rules (loaded via the
# default.rule_reference + local include) and are appended into the
# suricata.rules custom section so the running engine picks them up.
# SIDs use the reserved local range 1,000,000-1,999,999 so they can never
# collide with subscribed rule sources (ET uses 2,000,000+).

CUSTOM_SID_BASE = 1_000_000
CUSTOM_SID_MAX = 1_999_999
CUSTOM_BEGIN = "# --- ndr-custom-rules begin (managed by NDR UI) ---"
CUSTOM_END = "# --- ndr-custom-rules end ---"
CUSTOM_MARKERS = (CUSTOM_BEGIN, CUSTOM_END)

KNOWN_PROTOCOLS = ("tcp", "udp", "icmp", "ip", "http", "tls", "dns", "ftp",
                   "ssh", "smb", "modbus", "dnp3", "enip", "nfs", "ikev2",
                   "krb5", "dhcp", "rfb", "mqtt", "http2", "quic")


def custom_path() -> str:
    return os.path.join(config.rules_dir, "custom.rules")


def parse_rule_text(text: str) -> dict:
    """Validate ONE rule line; returns the parsed dict or raises ValueError.

    Enforces the custom-SID policy on top of the generic grammar:
    msg, sid and rev are mandatory (rev >= 2 after the first edit), and the
    SID must sit inside the local range so UI-created rules can never
    shadow a subscribed ET rule.
    """
    line = (text or "").strip()
    if not line:
        raise ValueError("rule text is empty")
    if len(line) > 4096:
        raise ValueError("rule text exceeds 4096 characters")
    m = RULE_LINE.match(line)
    if not m:
        raise ValueError(
            "invalid rule syntax - expected "
            "'<action> <protocol> <src> <sport> -> <dst> <dport> (...)'")
    opts = m.group("opts")
    sid_m = OPT_SID.search(opts)
    msg_m = OPT_MSG.search(opts)
    if not sid_m:
        raise ValueError("rule has no sid: option (mandatory)")
    if msg_m is None or not msg_m.group(1).strip():
        raise ValueError("rule has no msg: option (mandatory)")
    sid = int(sid_m.group(1))
    if not (CUSTOM_SID_BASE <= sid <= CUSTOM_SID_MAX):
        raise ValueError(
            f"custom rule sid must be inside the reserved local range "
            f"{CUSTOM_SID_BASE}-{CUSTOM_SID_MAX} (got {sid})")
    proto = m.group("protocol").lower()
    if proto not in KNOWN_PROTOCOLS and not proto.startswith("$"):
        raise ValueError(
            f"unknown protocol {m.group('protocol')!r} - use one of "
            f"{', '.join(KNOWN_PROTOCOLS)} or a protocol variable ($HOME_NET "
            "style)")
    rev_m = OPT_REV.search(opts)
    prio_m = OPT_PRIO.search(opts)
    class_m = OPT_CLASS.search(opts)
    return {
        "sid": sid,
        "gid": 1,
        "rev": int(rev_m.group(1)) if rev_m else None,
        "action": m.group("action"),
        "protocol": proto,
        "src": m.group("src"), "sport": m.group("sport"),
        "dst": m.group("dst"), "dport": m.group("dport"),
        "msg": msg_m.group(1),
        "classtype": class_m.group(1).strip() if class_m else None,
        "priority": int(prio_m.group(1)) if prio_m else None,
        "rule_text": line,
    }


def next_custom_sid(used: set[int]) -> int:
    """First free SID in the local range (deterministic, low->high)."""
    for sid in range(CUSTOM_SID_BASE, CUSTOM_SID_MAX + 1):
        if sid not in used:
            return sid
    raise ValueError("local SID range 1,000,000-1,999,999 is exhausted")


def write_custom_file(rule_texts: list[str]) -> str:
    """Persist enabled custom rules to custom.rules; returns the path."""
    path = custom_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    header = ("# Managed by the NDR custom rule editor - do not edit by "
              "hand; changes are overwritten on every save.\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header)
        for text in rule_texts:
            fh.write(text.rstrip() + "\n")
    return path


def sync_custom_section(rule_texts: list[str], path: str | None = None) -> int:
    """Replace the marker-delimited custom section inside suricata.rules.

    suricata-update regenerates the file on every update, so the section
    is re-synced after each mutation instead of being appended blindly
    (which would duplicate rules). Returns the number of rules in the
    section. A missing file is created so a first-ever deploy works.
    """
    path = path or rules_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        # drop any previous custom section
        out, inside = [], False
        for line in lines:
            if line.strip() == CUSTOM_BEGIN:
                inside = True
                continue
            if line.strip() == CUSTOM_END:
                inside = False
                continue
            if not inside:
                out.append(line)
        body = "".join(out)
    else:
        body = ""
    section = [f"{CUSTOM_BEGIN}\n"]
    for text in rule_texts:
        section.append(text.rstrip() + "\n")
    section.append(f"{CUSTOM_END}\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body if body.endswith("\n") or not body
                 else body + "\n")
        fh.write("\n".join(section))
    return len(rule_texts)
