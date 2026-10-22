"""NDR API - FastAPI backend (Phase 0-6)."""

# v0.16.1: bugfix lapangan (laporan deploy vendor 0.16.0, 2026-10-22) -
# P0 openpyxl/Zeek symlink/detail-alert alias/Event Search; P1 stats rich,
# Rule Manager status, rasio DNS eksak, JA3/issuer TLS; P2 versi, JWT,
# komponen health, exact total, route 405.

# v0.16.0: filter DSL (R5), export xlsx/csv (R6), DNS Explorer (R7),
# rule stats (R14/15), live SSE metrics (R19), SSO bake (R13),
# gambling view (R18) + alert enrichment (attack_status/CVE/DGA/geo).
#
# v0.16.2 (hasil verifikasi 0.16.1): BUG-0161-01 nesting agregasi engines,
# BUG-0161-02 Reports pakai data stats nyata, BUG-0161-03 upgrade.sh build
# sensor, BUG-0161-04 retry deadletter + pacing catch-up, BUG-0161-05
# guard shard parsial + agregasi .keyword legacy, BUG-0161-06 JWT persisten,
# BUG-0161-07 konsistensi branding.
__version__ = "0.16.2"
