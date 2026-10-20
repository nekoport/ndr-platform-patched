# NDR System Design & Implementation Plan — v1.1 (Disesuaikan dengan Implementasi)

**Dokumen:** NDR System Design & Implementation Plan
**Versi:** 1.1 — penyesuaian terhadap implementasi nyata
**Tanggal:** 12 Oktober 2026
**Baseline:** versi 1.0 (hasil diskusi desain "Diskusi Desain NDR Zeek
Suricata") + seluruh keputusan turunannya
**Dirujuk ke:** ndr-platform **v0.7.0** (Phase 0–5b, 150 automated test)
**Status:** desain diselaraskan dengan sistem yang sudah dibangun

Perubahan utama dari v1.0 → v1.1:

1. Setiap keputusan desain diberi **status implementasi**: ✅ sesuai desain,
   ⚠ sesuai dengan deviasi terkendali (alasan dicatat), 🔜 belum dibangun.
2. Keputusan stack, standar implementasi, struktur repository, dan aturan AI
   coding agent dari diskusi desain dimasukkan — **dengan catatan deviasi**
   terhadap proposal awal (Next.js vs Vite, thread vs Celery, dll.).
3. Cyber Kill Chain 7 tahap Lockheed Martin masuk sebagai kerangka dual-
   framework bersama MITRE ATT&CK (sudah terbangun, Phase 5b).
4. Acceptance test diperluas menjadi suite AT-01..AT-52 di
   `docs/OPERATIONS.md`; DoD checklist diberi status nyata.
5. Roadmap tersisa difokuskan: integrasi TI lanjutan, notifikasi/webhook,
   ekspor PCAP selektif, merge/split campaign oleh analis, hardening TLS.

---

## Bagian A — Status kesesuaian per keputusan desain

### A.1 Stack teknologi

| Area | Proposal diskusi desain | Implementasi v0.7.0 | Status |
|------|------------------------|---------------------|--------|
| Backend REST API | Python 3.12 + FastAPI + Pydantic 2 | Python + FastAPI + Pydantic v2 (`api/`) | ✅ |
| ORM / migrasi | SQLAlchemy 2 + Alembic | SQLAlchemy 2 (API); SQL init + migrasi idempoten runtime (pipeline) | ⚠ deviasi — skema dimiliki pipeline (`store.py`), kolom baru lewat guarded `ALTER TABLE`; Alembic dievaluasi bila skema tumbuh |
| Frontend | TypeScript + React + Vite + Tailwind + shadcn/ui + TanStack Query | Next.js 16 + TypeScript + Tailwind + shadcn/ui (`ui/`) | ⚠ deviasi — satu framework untuk konsol penuh (routing, SSR shell, client views); pola fetch per-view setara TanStack Query |
| Graf serangan | Cytoscape.js | SVG force-directed kustom + ECharts (relationship graph, attack graph) | ⚠ deviasi — deterministik, tanpa dependensi baru, sudah memenuhi klik/pivot/blast radius |
| Peta geografis | Leaflet | SVG world map + garis busur + GeoIP opsional (file JSON) | ⚠ deviasi — GeoIP diperlakukan sebagai perkiraan, IP tanpa lokasi tidak dipaksakan |
| Data operasional | PostgreSQL | PostgreSQL (incidents, users, audit, TI, konfigurasi) | ✅ |
| Pencarian event | OpenSearch + `opensearch-py` | OpenSearch + guard DSL (`api/app/os_client.py`) | ✅ |
| Background jobs | Celery + Redis | Pipeline Python threading: bounded queue, backpressure, drop-oldest, deadletter | ⚠ deviasi terkendali — satu-node MVP tidak butuh broker; pemisahan proses tetap bersih sehingga migrasi ke Celery saat scale-out tidak mengubah kontrak |
| Sensor | Zeek + Suricata + Arkime | Zeek + Suricata + Arkime (profile sensor, host network) | ✅ |
| Deployment | Docker Compose | Docker Compose 9 service + profile sensor | ✅ |
| CI | GitHub Actions | `.github/workflows/ci.yml` (pytest pipeline+api, build UI) | ✅ |
| Logging & metrics | Structured JSON logs + Prometheus-compatible | Log terstruktur + `/metrics` counter/gauge per tahap pipeline | ✅ (scraper/TSDB eksternal belum dibundel — 🔜 ops) |

### A.2 Standar implementasi

| Area | Proposal | Implementasi | Status |
|------|----------|--------------|--------|
| Python environment | `uv` | `requirements.txt` + pin versi, build Docker deterministik | ⚠ deviasi kosmetik; `uv` dapat diadopsi tanpa dampak arsitektur |
| Package manager FE | `pnpm` | `npm` (lockfile dikomit) | ⚠ deviasi kosmetik |
| API contract | REST + OpenAPI | FastAPI menghasilkan OpenAPI otomatis (`/openapi.json`) | ✅ |
| Authentication | OIDC/OAuth2 bila ada IdP | JWT httpOnly cookie + `token_version` + bcrypt + RBAC 5 peran lokal | ⚠ deviasi — belum ada IdP di lingkungan target; antarmuka auth terpusat (`security.py`) sehingga OIDC bisa ditambah tanpa menyentuh endpoint |
| Testing backend | pytest | pytest — 98 test pipeline + 52 test API | ✅ |
| Lint/format Python | Ruff + mypy | linter standar; type hints menyeluruh (penuh mypy 🔜) | ⚠ |
| Testing FE | Vitest + RTL + Playwright | `tsc --noEmit` + build + smoke browser headless | ⚠ — test suite FE formal 🔜 |
| Keamanan operasional | — | RBAC ditegakkan backend, audit log, rate limit, DSL guard, deadletter | ✅ |

### A.3 Struktur repository

Proposal monorepo (`apps/api`, `apps/worker`, `apps/web`, `services/*`,
`packages/*`) disederhanakan sesuai realitas modular monolith:

```text
ndr-platform/
├── api/        # FastAPI + RBAC + guard + routers  (= apps/api)
├── pipeline/   # ingest, normalisasi, dedup, enrich, intel,
│               # detection, rekonstruksi, sink        (= services/* + worker)
├── ui/         # Next.js konsol SOC                   (= apps/web)
├── sensor/     # profil Zeek/Suricata/Arkime          (= integrations/*)
├── opensearch/ # mapping + ISM + init
├── postgres/   # skema init
├── docs/       # ARCHITECTURE, OPERATIONS, DEPLOYMENT, SIZING + plan v1.1
├── scripts/    # poc, healthcheck, backup, rule-update
├── .github/workflows/ci.yml
└── AGENTS.md   # aturan AI coding agent (baru di v1.1)
```

Status: ⚠ deviasi terstruktur — pemisahan modul tetap tegas di dalam
`pipeline/app/` (sources/normalize/detection/intel/correlation/sink), sesuai
prinsip "modular monolith terlebih dahulu" yang disepakati. Folder `tests/`
menempel per layanan (lebih dekat pytest idiomatic).

### A.4 Aturan AI coding agent

Seluruh 10 aturan dari diskusi desain kini terdokumentasi resmi di
**`AGENTS.md`** (file baru v1.1), sudah disesuaikan dengan stack aktual
(mis. aturan migrasi skema menunjuk pola guarded-ALTER yang benar-benar
dipakai). Status: ✅ baru ditambahkan.

### A.5 Menu navigasi

| Usulan diskusi desain | Implementasi v0.7.0 | Status |
|-----------------------|---------------------|--------|
| Overview | Group **Monitor**: Dashboard (kesehatan, EPS, kapasitas, alert feed) | ✅ |
| Detection (alerts, incidents, campaigns, reconstruction) | Group **Detect**: Incidents (rekonstruksi + attack graph + Kill Chain), Alert Center, Threat Intel, Threat Map (relationship graph + geographic) | ✅ |
| Investigation (DSL, threat map, graph, sessions, PCAP) | Group **Investigate**: Event Search (DSL ter-guard), Topology, Assets | ⚠ — sessions/PCAP belum jadi halaman (pivot bukti menampilkan metadata sesi; ekspor PCAP 🔜) |
| Threat Intelligence | Item Threat Intel (group Detect) + halaman admin feed/allowlist | ✅ |
| Reports | Item Reports (group Govern) | ✅ |
| Administration (users, sensors, NTP, audit, storage, backup, update) | Group **Govern**: Sensors, Users, Audit Log (+ operasional via compose/scripts) | ⚠ — NTP UI, diagnostic bundle, version history 🔜 |

### A.6 Prioritas pengembangan

| Prioritas (diskusi desain) | Status v0.7.0 |
|----------------------------|----------------|
| **P0 — wajib MVP**: user/role, sensor/network mgmt, TI update, system health, system+app audit, Alert Center, retensi, backup, report dasar, Advanced DSL | ✅ terpenuhi (**rule management versi penuh selesai di v0.8.0** — Rule Manager UI; ⚠ NTP UI masuk daftar 🔜; PCAP evidence = arsip hash, ekspor selektif 🔜) |
| **P1 — inti nilai NDR**: Attack Reconstruction, Kill Chain, ATT&CK, campaign correlation, relationship graph, Threat Map, DGA, outcome assessment, report investigasi | ✅ terpenuhi seluruhnya (Phase 4 + 5 + 5b) |
| **P2 — lanjutan**: integrasi tambahan, otomasi respons, multi-sensor, sandbox, analitik lanjutan | 🔜 roadmap Phase 6+ |

## Bagian B — Status modul (daftar A–G diskusi desain)

**A. Dashboard & System Health — ✅**: status sensor/interface, EPS, packet
drop, ingestion latency (pipeline metrics), status service, CPU/RAM/disk via
health; alarm teks saat sensor idle/disk penuh pada Overview.

**B. Alert Center & Incident Management — ✅/⚠**: daftar alert + filter DSL +
severity + status (`new/acknowledged/in_progress/closed/false_positive`) +
assignee ✅; agregasi tanpa kehilangan event asli (evidence refs) ✅;
incident: status `open/confirmed/benign/closed` + catatan + riwayat +
outcome ✅ (⚠ pemetaan ke New/Investigating/Escalated/Resolved/Closed
diperlukan bila diinginkan — perubahan kosmetik); tag 🔜.

**C. Attack Reconstruction & Campaign — ✅/⚠**: timeline Kill Chain 7 tahap
dengan 4 status + ATT&CK ✅; korelasi lintas-IP/host/domain/IOC ✅;
relationship graph + threat map ✅; DGA + C2 ✅; confidence + alasan +
pemisahan fakta/dugaan ✅; **merge/split campaign oleh analis dengan audit
trail 🔜** (merge otomatis yang aman sudah ada).

**D. Advanced Search & Evidence Management — ✅/⚠**: DSL dengan validasi +
guard + contoh ✅; pencarian Zeek/Suricata/IOC ✅; hubungan alert → sesi
(community_id, metadata) ✅; bukti mentah arsip gzip + sha256 + deadletter ✅;
status bukti (kedaluwarsa/tidak ditemukan) ✅ (**v0.9.0**: available/
partially_available/expired/not_captured per sesi); hash integritas ✅;
**ekspor PCAP selektif per alert/incident ✅ (v0.9.0, file-level + manifest
SHA-256 + TTL + chain of custody; granularitas dinyatakan jujur)**; catatan
akses ekspor (audit) ✅.

**E. Data Lifecycle & Storage — ✅/⚠**: retensi metadata via ISM ✅
(**60 hari aktif — desain menyebut 90 hari; kenaikan ke 90 hanya penyesuaian
policy + kapasitas, dicek di SIZING**); PCAP retensi mengikuti Arkime/arkip
⚠; indikator kapasitas ✅; backup script + prosedur ✅; pengujian restore
berkala 🔜.

**F. Notification & Integration — 🔜**: notifikasi incident kritis, webhook,
retry, manajemen kanal — **belum dibangun** (roadmap Phase 6, prioritas
tertinggi di antara modul yang hilang).

**G. System Configuration & Maintenance — ⚠**: konfigurasi sensor & sumber
✅ (Sensors + compose + ENV); retensi/threshold ✅; **NTP config UI 🔜**
(precheck sensor sudah memvalidasi sinkronisasi waktu); diagnostic bundle
🔜; version/rollback via compose + git 🔜.

## Bagian C — Tahapan implementasi: status nyata

| Tahap (desain) | Isi | Status v0.7.0 |
|----------------|-----|----------------|
| 0 Discovery & desain | spesifikasi, data model, aturan korelasi | ✅ dokumen v1.0 + plan v1.1 |
| 1 Sensor foundation | Zeek/Suricata/Arkime + SPAN + health | ✅ |
| 2 Normalisasi & Alert Center | schema, provenance, dedup, agregasi, counter | ✅ |
| 3 Threat Intelligence | feed, IOC store, expiry, provenance, allowlist | ✅ |
| 4 Correlation & Attack Reconstruction | entity/timeline/stage/ATT&CK/outcome | ✅ (+ Kill Chain 7 tahap di 5b) |
| 5 Campaign correlation | lintas-IP, confidence relasi, merge | ✅ merge otomatis; ⚠ merge/split analis 🔜 |
| 6 Threat Map & investigation UI | peta, graph, navigasi node→bukti | ✅ (PCAP link-out 🔜) |
| 7 Reporting & hardening | laporan, RBAC, audit, retensi, backup, uji performa | ⚠ reporting ✅; TLS hardening + uji beban formal 🔜 |
| 8 Integrasi sandbox | evidence tambahan dari analisis malware | 🔜 desain sudah menyebutnya komponen terpisah |

## Bagian D — Definition of Done "sensor pertama": checklist status

- [x] Trafik SPAN/TAP tertangkap, kesehatan capture dipantau — health + sensors + metrics
- [x] Zeek, Suricata, Arkime menyediakan data tertelusur — event terindeks + referensi bukti
- [x] TI dengan provenance, freshness, expiry — `ti_matches` + halaman Threat Intel
- [x] Event duplikat tidak dihitung ganda — dedup uuid5 (AT-02)
- [x] Event berulang jadi alert agregat ber-counter — grouping window (AT-03)
- [x] Raw event tersedia — arsip gzip + sha256
- [x] Attack timeline otomatis dengan referensi bukti — evidence per item
- [x] Multi-IP campaign menjelaskan alasan hubungan — edge `correlated_with` + reason
- [x] Kasus tak terkait tidak digabung otomatis — disiplin korelasi (AT-06/AT-08)
- [x] Threat Map & Attack Relationship Graph terhubung — satu data korelasi
- [⚠] Analis menelusuri node → alert, sesi, PCAP — alert + metadata sesi ✅; **ekspor/link PCAP 🔜**
- [x] Outcome assessment membedakan percobaan/belum pasti/berbasis bukti — 4 label + proven/suspected/unknown
- [x] DGA memberi skor + alasan yang bisa diperiksa
- [x] Incident workspace + catatan analis — detail + notes + history + audit
- [⚠] Laporan dibuat, direvisi, difinalisasi, diaudit — generate/unduh + audit ✅; **versioning & workflow finalisasi 🔜**
- [⚠] Retensi, kapasitas, packet loss, latency, performa diuji — mekanisme ✅; **uji beban formal (PoC 7 hari) 🔜**
- [⚠] Seluruh acceptance test lulus — AT-01..AT-52 terdefinisi & mayoritas terverifikasi di pengembangan; **run formal di VM produksi 🔜**

## Bagian E — Gap tersisa & roadmap (Phase 6+)

> **Update v0.8.0**: gap **rule management UI penuh sudah ditutup** — view
> **Detect → Rule Manager** (update Emerging Threats via `suricata-update` +
> live reload unix socket; enable/disable per-SID via `disable.conf` pada
> volume rules bersama; cache metadata Postgres; hit count 7 hari; RBAC
> `rule_admin`; audit `rules.*`). Acceptance: AT-53..AT-58 (OPERATIONS §13).
> CLI `make rule-update` tetap ada untuk otomasi/cron.

Urutan prioritas disusun ulang terhadap nilai operasional:

1. **Notification & webhook (modul F)** — notifikasi incident kritis, kanal
   dapat dikonfigurasi, status kirim/retry, audit. Prasyarat operasional SOC.
2. ~~**Ekspor PCAP selektif**~~ — **✅ selesai v0.9.0**: panel *PCAP &
   sessions* di detail alert/incident (dok §15.1 langkah 1–9): resolusi sesi
   + status bukti §15.2, ekspor selektif ber-manifest SHA-256 dengan batas
   ukuran/file + TTL + register chain of custody + RBAC `evidence_export`
   (auditor ditolak), granularitas file-level dinyatakan eksplisit;
   acceptance AT-59..AT-65 di OPERATIONS §14.
3. **Campaign merge/split oleh analis** — aksi ter-audit pada incident;
   melengkapi merge otomatis; acceptance AT-13.
4. **Integrasi TI lanjutan** — STIX/TAXII, MISP feed, AlienVault OTX di atas
   kerangka feed yang ada (URLhaus, ThreatFox, Feodo sudah ✅).
5. **Report workflow** — versioning draft/final, template, persetujuan.
6. **Hardening** — TLS antar service + reverse proxy, mypy/Ruff penuh, test
   suite frontend (Vitest/RTL), uji beban formal PoC.
7. **Ops lanjutan** — NTP config UI, diagnostic bundle, prediksi kapasitas
   storage, pengujian restore berkala.
8. **Skala berikutnya** — multi-sensor, HA, Celery/Redis bila throughput
   thread tidak lagi cukup, sandbox terpisah (tahap 8).

## Bagian F — Keputusan yang masih terbuka (dari desain, dipertahankan)

- Retensi metadata final (60 vs 90 hari) → kunci setelah ukuran PoC.
- Target angka performa (packet loss maksimum, latency ingest) → disepakati
  setelah uji beban di hardware produksi.
- Adopsi uv/pnpm/OIDC → deviasi kosmetik yang disengaja; dibuka kembali bila
  kebutuhan muncul, tanpa dampak arsitektur.
- Template laporan & alur persetujuan → saat report workflow dibangun.

## Bagian G — Pemetaan acceptance test

Acceptance test diskusi desain (AT-01..AT-15 pada dokumen v1.0) telah
diperluas dan dioperasionalkan menjadi **AT-01..AT-52 di
`docs/OPERATIONS.md`**:

| Rentang | Cakupan |
|---------|---------|
| AT-01..AT-14 | fondasi sensor, dedup, agregasi, TI, retensi, health |
| AT-15..AT-29 | detection rules, DSL, audit, RBAC, report dasar |
| AT-30..AT-39 | attack reconstruction, merge, late evidence, outcome, RBAC triage |
| AT-40..AT-47 | threat map & relationship graph (multi-IP campaign, blast radius, GeoIP) |
| AT-48..AT-52 | Cyber Kill Chain dual framework (klasifikasi, 4 status, non-sekuensial, stage history, laporan) |

Dua acceptance dari desain yang **belum punya AT formal**: ekspor PCAP
selektif (menyusul fitur #2 roadmap) dan merge/split campaign oleh analis
(menyusul fitur #3).

---

**Prinsip yang tetap (tidak berubah dari desain awal):** produk ini bukan
sekadar pengumpul alert — ia merekonstruksi rangkaian serangan secara
otomatis dan membuktikan mengapa event-event dianggap berkaitan; setiap
kesimpulan membedakan *observed* dari *inferred*; tidak ada overclaim
otomatis; dan Cyber Kill Chain + MITRE ATT&CK adalah dua kerangka yang saling
melengkapi di atas bukti yang sama.
