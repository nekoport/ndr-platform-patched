"""API configuration from environment."""

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Config:
    database_url: str = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg://ndr:ndr@localhost:5432/ndr")
    opensearch_url: str = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
    # v0.16.1 (P2-3): secret JWT lemah (mis. 9 byte) membuat HMAC mudah
    # di-brute-force. Bila JWT_SECRET tidak diset / lebih pendek 32 char,
    # config MENOLAK default lemah dan menurunkan secret acak ephemeral
    # (48 hex) + WARNING keras - sesi hangus saat API restart sampai
    # operator menetapkan JWT_SECRET permanen (lihat .env.example).
    jwt_secret: str = os.environ.get("JWT_SECRET", "")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = _int("ACCESS_TOKEN_MINUTES", 30)
    admin_username: str = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password: str = os.environ.get("ADMIN_PASSWORD", "admin")
    login_max_failed: int = _int("LOGIN_MAX_FAILED", 5)
    login_lockout_minutes: int = _int("LOGIN_LOCKOUT_MINUTES", 15)
    sensor_id: str = os.environ.get("SENSOR_ID", "sensor-01")
    retention_days: int = _int("RETENTION_DAYS", 60)
    session_cookie: str = "ndr_session"

    # search guardrails (doc section 4.5)
    search_max_size: int = _int("SEARCH_MAX_SIZE", 500)
    search_default_size: int = _int("SEARCH_DEFAULT_SIZE", 50)
    search_timeout_seconds: int = _int("SEARCH_TIMEOUT_SECONDS", 5)
    # v0.13.0: X-Forwarded-For is ONLY honoured when the API sits behind
    # the TLS gateway (set TRUST_PROXY=1). Default 0: the socket peer is
    # used, so a spoofed XFF cannot bypass the login rate limiter or
    # poison audit records.
    trust_proxy: bool = os.environ.get("TRUST_PROXY", "0") == "1"
    search_rate_limit_per_min: int = _int("SEARCH_RATE_LIMIT", 30)
    search_max_range_days: int = _int("SEARCH_MAX_RANGE_DAYS", 60)

    # allowed index aliases for user queries - never raw indices
    allowed_read_aliases: tuple = (
        "ndr-events-read", "ndr-alerts-read", "ndr-health-read",
        "ndr-zeek-conn-read", "ndr-zeek-dns-read", "ndr-zeek-http-read",
        "ndr-zeek-tls-read", "ndr-suricata-read", "ndr-ioc-matches-read",
    )

    # threat intelligence (doc 9)
    ti_ioc_page_size: int = _int("TI_IOC_PAGE_SIZE", 100)
    ti_ioc_max_page: int = _int("TI_IOC_MAX_PAGE", 500)
    ti_jobs_history_limit: int = _int("TI_JOBS_HISTORY_LIMIT", 50)

    # suricata rule manager (shared rules volume with ndr-suricata)
    rules_data_dir: str = os.environ.get("RULES_DATA_DIR",
                                         "/var/lib/suricata")
    rules_dir: str = os.environ.get("RULES_DIR",
                                    "/var/lib/suricata/rules")
    suricata_conf: str = os.environ.get("SURICATA_CONF",
                                        "/etc/suricata/suricata.yaml")
    suricata_unix_socket: str = os.environ.get(
        "SURICATA_UNIX_SOCKET", "/var/run/suricata/suricata-command.socket")
    rules_update_timeout: int = _int("RULES_UPDATE_TIMEOUT", 300)
    # v0.12.7: Zeek policy inventory for the Rule Manager (local.zeek is
    # mounted read-only into the API container by docker-compose)
    zeek_local_conf: str = os.environ.get(
        "ZEEK_LOCAL_CONF", "/opt/ndr/zeek/local.zeek")

    # pcap & evidence workflow (doc section 15)
    pcap_dir: str = os.environ.get("PCAP_DIR", "/var/lib/ndr/pcap")
    pcap_export_dir: str = os.environ.get("PCAP_EXPORT_DIR",
                                          "/var/lib/ndr/pcap-exports")
    pcap_export_ttl_minutes: int = _int("PCAP_EXPORT_TTL_MINUTES", 60)
    pcap_export_max_files: int = _int("PCAP_EXPORT_MAX_FILES", 5)
    pcap_export_max_bytes: int = _int("PCAP_EXPORT_MAX_BYTES", 2_000_000_000)
    pcap_export_max_sessions: int = _int("PCAP_EXPORT_MAX_SESSIONS", 50)
    # analyst-controlled pre/post window around an alert/incident when
    # resolving sessions (doc 5.6: selective PCAP needs a capture buffer)
    pcap_session_buffer_minutes: int = _int("PCAP_SESSION_BUFFER_MINUTES", 5)
    # conservative estimate of how long one rolling pcap file spans; used
    # to turn file mtimes into a capture coverage window
    pcap_file_span_minutes: int = _int("PCAP_FILE_SPAN_MINUTES", 15)
    arkime_viewer_url: str = os.environ.get("ARKIME_VIEWER_URL",
                                            "http://127.0.0.1:8005")
    evidence_session_limit: int = _int("EVIDENCE_SESSION_LIMIT", 200)

    # -------------------------------------------------- v0.16.0
    # export alert (req 6): batas baris per permintaan (guard memori)
    export_max_rows: int = _int("EXPORT_MAX_ROWS", 50000)
    # watchlist judi online (req 18): daftar keyword utk DISPLAY di UI
    # (matcher aslinya di pipeline; sinkronkan env di kedua layanan)
    gambling_keywords: list = [k.strip().lower() for k in
                               os.environ.get("GAMBLING_KEYWORDS", "").split(",")
                               if k.strip()]

    # SSO Arkime (req 13) - kini BAKED, bukan lagi patch VM.
    # arkime_public_base: base path publik yang dilihat browser untuk
    # asset/deep-link viewer melalui proxy API (default sama dengan
    # mount proxy di main.py). arkime_proxy_secret: shared secret antara
    # API dan viewer (header x-ndr-secret) - WAJIB sama dengan env
    # ARKIME_PROXY_SECRET di layanan arkime.
    arkime_public_base: str = os.environ.get(
        "ARKIME_PUBLIC_BASE", "/backend/api/arkime")
    arkime_proxy_secret: str = os.environ.get(
        "ARKIME_PROXY_SECRET", "") or os.environ.get(
        "ARKIME_VIEWER_SECRET", "")

    # rule stats (req 14/15): interval refresh background (menit).
    # 0 = matikan refresher (endpoint stats masih bisa agregasi on-the-fly).
    rule_stats_refresh_minutes: int = _int("RULE_STATS_REFRESH_MIN", 15)

    # TLS hardening (v0.12). Set TLS_ENABLED=1 when the API is served
    # over HTTPS - either directly (uvicorn --ssl-certfile/--ssl-keyfile)
    # or behind the TLS gateway (docker-compose profile "tls", nginx
    # termination). Controls the session cookie Secure flag and adds
    # HSTS to every response. Session cookies over plain HTTP stay
    # Secure=False so demo/http deployments keep working.
    tls_enabled: bool = os.environ.get("TLS_ENABLED", "0") == "1"


def _harden_jwt_secret() -> None:
    """v0.16.1 (P2-3): tolak secret JWT lemah.

    Secret pendek (contoh live: 9 byte) membuat HMAC-SHA256 mudah
    di-brute-force. Tanpa JWT_SECRET / di bawah 32 char, kita menurunkan
    secret acak 48-hex EPHEMERAL:
      * keuntungan  : tidak ada lagi kunci lemah yang bisa dipakai musuh;
      * konsekuensi : semua sesi hangus setiap API restart;
      * permanen    : set JWT_SECRET (>= 32 char acak) di .env - contoh
        generator: `openssl rand -hex 32`.
    """
    import secrets as _secrets

    secret = (Config.jwt_secret or "").strip()
    if len(secret) >= 32:
        return
    Config.jwt_secret = _secrets.token_hex(24)
    import logging
    logging.getLogger("uvicorn.error").warning(
        "JWT_SECRET tidak diset atau terlalu pendek (%s char) - memakai "
        "secret acak EPHEMERAL; semua sesi hangus saat API restart. "
        "Tetapkan JWT_SECRET permanen (>= 32 char, mis. `openssl rand "
        "-hex 32`) di .env.", len(secret))


_harden_jwt_secret()
config = Config()
