"""Pipeline configuration from environment variables (12-factor style)."""

import os
from dataclasses import dataclass, field


def _env_list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    # identity
    sensor_id: str = os.environ.get("SENSOR_ID", "sensor-01")

    # inputs (mounted read-only by compose)
    input_root: str = os.environ.get("PIPELINE_INPUT_ROOT", "/input")
    sources: list[str] = field(
        default_factory=lambda: _env_list("PIPELINE_SOURCES", "suricata,zeek"))
    zeek_logs: list[str] = field(
        default_factory=lambda: _env_list("PIPELINE_ZEEK_LOGS",
                                          "conn,dns,http,tls,files"))
    suricata_types: list[str] = field(
        default_factory=lambda: _env_list("PIPELINE_SURICATA_TYPES",
                                          "alert,dns,http,tls,fileinfo"))
    suricata_eve_path: str = os.environ.get("PIPELINE_EVE_PATH",
                                            "/input/suricata/eve.json")
    zeek_current_dir: str = os.environ.get("PIPELINE_ZEEK_CURRENT",
                                           "/input/zeek/current")
    zeek_archive_dir: str = os.environ.get("PIPELINE_ZEEK_ARCHIVE",
                                           "/input/zeek")

    # output
    opensearch_url: str = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")
    bulk_max_items: int = _env_int("PIPELINE_BULK_MAX_ITEMS", 500)
    bulk_flush_seconds: float = _env_float("PIPELINE_BULK_FLUSH_SECONDS", 5.0)
    bulk_max_retries: int = _env_int("PIPELINE_BULK_MAX_RETRIES", 8)
    queue_capacity: int = _env_int("PIPELINE_QUEUE_CAPACITY", 20000)

    # v0.16.2 (BUG-0161-04): backpressure adaptif + retry deadletter.
    # Riwayat lapangan (verifikasi 0.16.1): restart dengan backlog eve.json
    # 297 MB diputar sekaligus -> OpenSearch saturasi (CPU ~939%) ->
    # 4.807 dokumen deadletter `sink_timeout` dan TIDAK PERNAH di-retry.
    # cooldown: setelah ConnectionTimeout, sink tidur eksponensial sebelum
    # bulk berikutnya (melindungi OS yang sedang kepanasan) dan memperkecil
    # batch; berhasil -> cooldown menyusut & batch pulih.
    sink_cooldown_max_seconds: float = _env_float(
        "PIPELINE_SINK_COOLDOWN_MAX_SECONDS", 60.0)
    sink_batch_min_items: int = _env_int("PIPELINE_SINK_BATCH_MIN_ITEMS", 50)
    # replay: deadletter `sink_timeout`/`sink_failure` dimainkan ulang ke
    # sink queue secara berkala (doc _id deterministik -> idempoten).
    # 0 pada PIPELINE_DLQ_REPLAY mematikan (kill switch).
    dlq_replay_enabled: bool = _env_int("PIPELINE_DLQ_REPLAY", 1) == 1
    dlq_replay_interval_seconds: int = _env_int(
        "PIPELINE_DLQ_REPLAY_INTERVAL_SECONDS", 300)
    dlq_replay_max_age_hours: int = _env_int(
        "PIPELINE_DLQ_REPLAY_MAX_AGE_HOURS", 24)
    dlq_replay_max_per_cycle: int = _env_int(
        "PIPELINE_DLQ_REPLAY_MAX_PER_CYCLE", 2000)
    dlq_replay_max_attempts: int = _env_int(
        "PIPELINE_DLQ_REPLAY_MAX_ATTEMPTS", 3)
    # pacing: saat backlog tailer > ambang (catch-up pasca-restart), prosesor
    # tidur singkat per N event agar indexing tidak menenggelamkan OpenSearch.
    # 0 pada PIPELINE_CATCHUP_PACE_THRESHOLD mematikan pacing.
    catchup_pace_threshold_seconds: float = _env_float(
        "PIPELINE_CATCHUP_PACE_THRESHOLD_SECONDS", 300.0)
    catchup_pace_batch: int = _env_int("PIPELINE_CATCHUP_PACE_BATCH", 250)
    catchup_pace_sleep_ms: int = _env_int("PIPELINE_CATCHUP_PACE_SLEEP_MS", 100)

    # state
    state_dir: str = os.environ.get("PIPELINE_STATE_DIR", "/data/state")
    raw_retention_hours: int = _env_int("PIPELINE_RAW_RETENTION_HOURS", 72)

    # detection thresholds (Phase 2 baseline heuristics; tune after PoC)
    detect_portscan_unique_ports: int = _env_int("DETECT_PORTSCAN_UNIQUE_PORTS", 100)
    detect_portscan_unique_hosts: int = _env_int("DETECT_PORTSCAN_UNIQUE_HOSTS", 50)
    detect_portscan_window_min: int = _env_int("DETECT_PORTSCAN_WINDOW_MIN", 10)
    detect_nxdomain_min_count: int = _env_int("DETECT_NXDOMAIN_MIN_COUNT", 20)
    detect_nxdomain_ratio: float = _env_float("DETECT_NXDOMAIN_RATIO", 0.5)
    detect_nxdomain_window_min: int = _env_int("DETECT_NXDOMAIN_WINDOW_MIN", 10)
    detect_beacon_min_connections: int = _env_int("DETECT_BEACON_MIN_CONNECTIONS", 20)
    detect_beacon_interval_min_sec: int = _env_int("DETECT_BEACON_INTERVAL_MIN_SEC", 10)
    detect_beacon_interval_max_sec: int = _env_int("DETECT_BEACON_INTERVAL_MAX_SEC", 3600)
    detect_beacon_jitter_max: float = _env_float("DETECT_BEACON_JITTER_MAX", 0.2)
    # v0.13.0: dedicated beaconing window (previously borrowed the portscan
    # window + a hard 60-minute floor nobody asked for)
    detect_beacon_window_min: int = _env_int("DETECT_BEACON_WINDOW_MIN", 10)
    detect_alert_window_min: int = _env_int("DETECT_ALERT_WINDOW_MIN", 10)
    detect_max_tracked_keys: int = _env_int("DETECT_MAX_TRACKED_KEYS", 100_000)

    # network zones for enrichment: "cidr:zone_name,cidr:zone_name"
    zones: list[tuple[str, str]] = field(default_factory=list)

    # metrics
    metrics_port: int = _env_int("METRICS_PORT", 9100)
    health_interval_seconds: float = _env_float("PIPELINE_HEALTH_INTERVAL", 30.0)

    # validation limits
    max_field_len: int = _env_int("PIPELINE_MAX_FIELD_LEN", 2048)
    max_clock_skew_seconds: int = _env_int("PIPELINE_MAX_CLOCK_SKEW", 300)
    max_event_age_days: int = _env_int("PIPELINE_MAX_EVENT_AGE_DAYS", 7)

    # threat intelligence (doc section 9 - Phase 3)
    ti_enabled: bool = _env_bool("TI_ENABLED", True)
    ti_database_url: str = os.environ.get("DATABASE_URL", "")
    ti_job_poll_seconds: int = _env_int("TI_JOB_POLL_SECONDS", 5)
    ti_reload_seconds: int = _env_int("TI_RELOAD_SECONDS", 60)
    ti_http_timeout: int = _env_int("TI_HTTP_TIMEOUT", 30)
    ti_max_feed_bytes: int = _env_int("TI_MAX_FEED_BYTES", 26_214_400)
    ti_verify_tls: bool = _env_bool("TI_VERIFY_TLS", True)
    ti_auto_schedule: bool = _env_bool("TI_AUTO_SCHEDULE", True)
    ti_max_iocs_loaded: int = _env_int("TI_MAX_IOCS_LOADED", 200_000)
    detect_ioc_match: bool = _env_bool("DETECT_IOC_MATCH", True)
    detect_ioc_window_min: int = _env_int("DETECT_IOC_WINDOW_MIN", 10)

    # Phase 4 behavior rules (attack-phase coverage, doc section 10)
    detect_window_min: int = _env_int("DETECT_WINDOW_MIN", 10)
    detect_file_min_bytes: int = _env_int("DETECT_FILE_MIN_BYTES", 5_000_000)
    detect_dga_min_unique: int = _env_int("DETECT_DGA_MIN_UNIQUE", 10)
    detect_dga_entropy_min: float = _env_float("DETECT_DGA_ENTROPY_MIN", 3.5)
    # v0.12.9: extra DGA allowlist suffixes (comma-separated) on top of the
    # built-in popular/CDN list - site-specific SaaS and monitoring agents.
    detect_dga_allowlist: list[str] = field(default_factory=lambda: _env_list(
        "DETECT_DGA_ALLOWLIST", ""))
    detect_tunnel_min_count: int = _env_int("DETECT_TUNNEL_MIN_COUNT", 10)
    detect_tunnel_min_label_len: int = _env_int("DETECT_TUNNEL_MIN_LABEL_LEN", 40)
    # v0.13.0: a typo/stray space in DETECT_LATERAL_PORTS used to crash
    # pipeline STARTUP - parse fail-soft, skip unparsable entries
    detect_lateral_ports: set[int] = field(default_factory=lambda: {
        int(p) for p in _env_list("DETECT_LATERAL_PORTS",
                                  "22,135,139,445,3389,5985,5986")
        if p.strip().lstrip("-").isdigit()})
    detect_lateral_min_conns: int = _env_int("DETECT_LATERAL_MIN_CONNS", 20)
    detect_lateral_cross_zone_min: int = _env_int(
        "DETECT_LATERAL_CROSS_ZONE_MIN", 5)
    detect_exfil_min_bytes: int = _env_int("DETECT_EXFIL_MIN_BYTES", 100_000_000)

    # ---------------------------------------------------------------- v0.16.0
    # auth brute force: gagal auth HTTP (401/403) berulang per (src, dst)
    detect_bruteforce_enabled: bool = _env_bool("DETECT_BRUTEFORCE", True)
    detect_bruteforce_min_failures: int = _env_int(
        "DETECT_BRUTEFORCE_MIN_FAILURES", 20)
    detect_bruteforce_window_min: int = _env_int(
        "DETECT_BRUTEFORCE_WINDOW_MIN", 10)

    # watchlist judi online (requirement 18): keyword matcher pada host/dns.
    # CAMPAIGN tag dipasang di enrichment; detector gambling_access canary
    # (matikan dengan DETECT_GAMBLING=0 tanpa redeploy).
    gambling_keywords: list[str] = field(default_factory=lambda: [
        k.strip().lower() for k in _env_list(
            "GAMBLING_KEYWORDS",
            "judi,slot,togel,sbobet,casino,poker,baccarat,parlay,"
            "sbobet88,judol") if k.strip()])
    gambling_domains_file: str | None = (
        os.environ.get("GAMBLING_DOMAINS_FILE") or None)
    detect_gambling: bool = _env_bool("DETECT_GAMBLING", True)
    detect_gambling_window_min: int = _env_int(
        "DETECT_GAMBLING_WINDOW_MIN", 10)
    detect_gambling_min_hits: int = _env_int("DETECT_GAMBLING_MIN_HITS", 3)

    # attack reconstruction engine (Phase 4, doc section 10)
    recon_enabled: bool = _env_bool("RECON_ENABLED", True)
    recon_max_gap_seconds: int = _env_int("RECON_MAX_GAP_SECONDS", 7200)
    recon_lookback_hours: int = _env_int("RECON_LOOKBACK_HOURS", 24)
    recon_max_active_stories: int = _env_int("RECON_MAX_ACTIVE_STORIES", 500)
    recon_max_evidence: int = _env_int("RECON_MAX_EVIDENCE", 400)
    recon_persist_seconds: float = _env_float("RECON_PERSIST_SECONDS", 10.0)
    recon_queue_capacity: int = _env_int("RECON_QUEUE_CAPACITY", 8000)

    # geoip enrichment (Phase 5, optional - off when both paths unset)
    geoip_mmdb_path: str | None = os.environ.get("GEOIP_MMDB_PATH") or None
    geoip_json_path: str | None = os.environ.get("GEOIP_JSON_PATH") or None

    def __post_init__(self) -> None:
        raw = os.environ.get("PIPELINE_ZONES", "")
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                cidr, zone = entry.split(":", 1)
                self.zones.append((cidr.strip(), zone.strip()))
            except ValueError:
                continue
        if self.ti_enabled and not self.ti_database_url:
            # doc 9: TI needs the shared metadata store; without a DB url
            # the collector cannot run - degrade gracefully, ingest continues.
            self.ti_enabled = False
        if self.recon_enabled and not self.ti_database_url:
            # doc 10: the reconstruction engine persists stories in the
            # same metadata store; without a DB url it cannot run.
            self.recon_enabled = False


def load_config() -> Config:
    return Config()
