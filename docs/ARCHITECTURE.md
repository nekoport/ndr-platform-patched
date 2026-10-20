# Arsitektur Implementasi — NDR Fondasi (Phase 0–2)

Dokumen ini menjelaskan **bagaimana desain dijadikan kode**: alur data, model
indeks, keputusan komponen, dan model keamanan. Referensi butir dokumen
desain dicantumkan per bagian.

---

## 1. Diagram komponen

```
                         ┌────────────────────────────────────────────┐
 SPAN/TAP ──────────────►│ host network (profile: sensor)             │
                         │  ┌────────┐ ┌───────────┐ ┌──────────┐     │
                         │  │  Zeek  │ │ Suricata  │ │  Arkime  │     │
                         │  │ JSON   │ │ EVE JSON  │ │ capture  │     │
                         │  └───┬────┘ └────┬──────┘ └────┬─────┘     │
                         └──────┼───────────┼─────────────┼───────────┘
                                │           │             └──► PCAP volume (600 GB)
                        /var/lib/ndr/zeek/logs   /suricata/logs
                                │           │
                         ┌──────▼───────────▼──────┐
                         │ ndr-pipeline (Python)   │
                         │ tail→parse→normalize→   │
                         │ validate→dedup→enrich→  │
                         │ detect→bulk             │      /metrics :9100
                         └───────┬────────────────┘
                                 │ bulk (backpressure)
                 ┌───────────────▼───────────────┐
                 │ OpenSearch  (heap 6g, 1 node) │  ISM: delete 60d
                 │ ndr-zeek-* ndr-suricata-*     │
                 │ ndr-alerts-* ndr-health-*     │
                 └───────────────┬───────────────┘
                                 │ guarded search (alias-only, DSL guard)
      ┌────────────┐   ┌─────────▼─────────┐   ┌──────────────┐
      │ PostgreSQL │◄──┤ ndr-api (FastAPI) │◄──┤ ndr-ui       │
      │ users/audit│   │ JWT+RBAC+audit    │   │ (Next.js,    │
      │ sensors    │   └───────────────────┘   │  /backend proxy)│
      └────────────┘                           └──────────────┘
```

## 2. Alur event & keterkaitan dokumen desain

| Tahap (dok §7.1) | Implementasi |
|---|---|
| 1–2 Capture/telemetry | Zeek af_packet (JSON), Suricata EVE (types: alert/dns/http/tls/fileinfo/stats), Arkime PCAP + indeks miliknya |
| 3 Parse | `pipeline/app/normalize/__init__.py` — parser EVE + Zeek per log; baris gagal → deadletter |
| 4 Normalize | `CommonEvent` (ECS-like) — field sesuai dok §6.2, raw line tetap disimpan (arsip gzip + `raw_event_ref` sha256) |
| 5 Validate | `app/validate.py` — timestamp (skew/umur), IP/port, panjang field; gagal → deadletter **bukan dibuang diam-diam** |
| 6 Deduplicate | `app/dedup.py` LRU 200k + `event_id` deterministik (uuid5) → replay aman (_id sama ter-overwrite) |
| 7 Enrich | `app/enrich.py` zone CIDR; GeoIP/TI = hook fase berikut |
| 8 Persist/search | `app/sink/opensearch.py` bulk 500 item / 5 s, retry backoff, deadletter item error |
| 9 Detect | Suricata signature (alert event) + 4 heuristik di bawah |
| 10 Aggregate | `app/detection/rules.py` window per group key (bukan sekadar signature sama — dok §8.1) |
| 11–12 Correlate/Assess | fondasi: alert docs menyimpan rationale/reasons/evidence/confidence terpisah; Kill Chain & ATT&CK = Phase 5 |
| 13–16 Notify/Investigate/Report/Retain | notifikasi = Phase 7; investigate = UI; retain = ISM |

**Deteksi heuristik yang tersedia (Phase 2)** — semua explainable, confidence
label `heuristic-uncalibrated`, tidak ada klaim otomatis (dok §8.6):

1. `suricata_alert_group` — grup (signature_id × source_ip), window 10 menit.
2. `portscan_suspected` — ≥100 port unik ATAU ≥50 host unik per source / 10 menit.
3. `dns_nxdomain_burst` — ≥20 query dan rasio NXDOMAIN ≥0,5 / 10 menit (sinyal DGA lemah, dok §8.7).
4. `beaconing_possible` — ≥20 koneksi, interval rata-rata 10–3600 s, jitter ≤0,2.

## 3. Model indeks OpenSearch

| Pola | Isi | Retensi |
|---|---|---|
| `ndr-zeek-conn-YYYY.MM.DD` | koneksi | 60d |
| `ndr-zeek-dns-…` / `-http-…` / `-tls-…` | metadata protokol | 60d |
| `ndr-suricata-YYYY.MM.DD` | EVE terpilih (termasuk alert) | 60d |
| `ndr-alerts-YYYY.MM.DD` | alert hasil agregasi pipeline | 60d |
| `ndr-health-YYYY.MM.DD` | heartbeat/counter pipeline (1 doc/menit) | 14d |
| `arkime_sessions3-*` | milik Arkime — **tidak** dikelola skema NDR | 60d (ISM Arkime/PCAP policy) |

Keputusan penting:

- **Tidak ada duplikasi raw→normalized**: normalisasi hanya di field yang sama
  satu indeks per sumber; `ndr-events-read` adalah alias lintas indeks untuk
  common search (menghindari ganda storage — dok §4.4 catatan).
- `dynamic: false` + mapping eksplisit (ip/keyword/date/long/wildcard) —
  mencegah mapping explosion (dok §4.4).
- 1 primary shard per indeks harian, **0 replica** (single node; dok §4.4).
- Refresh 10 s (event) / 5 s (alert/health) — target ingestion latency P95 <10 s.
- ISM policy `ndr-retention` (delete by age) ditempel lewat index template.
- Indeks `-000000-bootstrap` dibuat sekali agar alias valid sebelum data pertama.

## 4. Pipeline: threading & backpressure

```
Tailer threads ──► raw_queue (20k) ──► Processor ──► detect_queue ──► Detection ──► sink_queue ──► BulkSink
                                       (parse/validate/       (pass-through
                                        dedup/enrich/          + flush rules
                                        raw archive)           setiap 30 s)
```

- Semua queue **bounded**; ketika penuh, produsen **blocking** → backpressure
  menjalar sampai ring buffer NIC (perilaku ditentukan & terukur — dok §7.3).
- OpenSearch mati → sink retry backoff eksponensial (maks 8×) → deadletter;
  metrik `sink_retries`/`sink_failures` terlihat di `/metrics` dan health doc.
- Checkpoint offset/inode per file disimpan (`state/checkpoints.json`) — restart
  tidak membaca ulang; rotasi Zeek (inode berubah) terdeteksi otomatis.
- Raw archive: `state/raw/YYYYMMDDHH-<engine>.jsonl.gz`, retensi 72 h
  (konfigurasi), memenuhi prinsip *preserve raw evidence* tanpa menggandakan
  storage di OpenSearch.

## 5. API: guard & keamanan

- **DSL guard** (`api/app/os_client.py`, dok §4.5): hanya read-alias
  whitelist; clause whitelist (`bool/term/terms/range/match/match_phrase/
  exists/prefix`); tolak `script/regexp/fuzzy/wildcard/query_string/nested`;
  prefix leading-wildcard ditolak; sort field whitelist; **rentang waktu
  wajib** (default 24 jam, maks = retensi); size ≤500; `track_total_hits`
  10k; timeout 5 s; rate limit 30 query/menit/user; semua search **diaudit**.
- **RBAC backend-enforced** per endpoint (dok §12.2): `view/search` semua
  role; `alert_update` tanpa auditor; `sensor_admin`; `user_admin` &
  `audit_read` sesuai matriks. Auditor read-only.
- **Session**: JWT httpOnly cookie SameSite=Lax (UI mem-proxy `/backend` ke
  API sehingga same-origin); `token_version` untuk force-logout; lockout
  5 gagal / 15 menit; bcrypt cost 10; password bootstrap wajib ganti.
- **Audit** (dok §13.3): setiap login/search/mutasi → `audit_records`
  (actor, role, action, target, result, source_ip, request_id, before/after).
  Tidak ada secret di log.
- Rate limit login per-IP (10/5 menit).

## 6. UI Console (Next.js)

- Single-route app (`/`) dengan view state (11 view): Dashboard, Alert Center,
  **Threat Intel**, Threat Map, Event Search, Topology, Assets, Reports,
  Sensors, Users, Audit.
- **Demo mode** (`NEXT_PUBLIC_DEMO_MODE=true`): data fixture untuk preview dan
  pengembangan UI tanpa backend; label eksplisit "demo data". Produksi: false.
- Live mode: fetch same-origin `/backend/*` → rewrite → `ndr-api:8080`.
- Menampilkan disclaimer evidence-first di tempat relevan (rationale,
  confidence, footer, banner Threat Intel).

## 6b. Threat Intelligence (Phase 3, dok §9)

```
ti_feeds (PostgreSQL) ──poll──► IntelService thread (ndr-pipeline)
   ▲                               │ 1. claim job 'queued' (atomic)
   │ 'Update Now' → ti_update_jobs ┘ 2. fetch adapter (urlhaus/threatfox/
   │                                   feodo/file; HTTPS verify, 25MB cap)
 ndr-api (POST /api/ti/feeds/...)    3. normalize+validate IOC (tolak IP privat)
   ▲                                 4. upsert ioc_records (provenance dipertahankan)
   │                                 5. expire_stale() → status 'expired' (tanpa delete)
 UI Threat Intel                     6. reload matcher snapshot (atomic swap)
```

- **Matcher**: snapshot in-memory (set IP, domain exact+suffix-walk, URL exact,
  hash per algoritma) + allowlist; reload atomik tiap 60 s atau segera setelah
  job selesai. Match maksimal 3 IOC per event.
- **Output**: event membawa `matched_ioc` (mapping `matched_ioc` di template
  event), satu dok per (event,ioc) ke `ndr-ioc-matches-*` (ISM 90 hari, alias
  `ndr-ioc-matches-read` di-whitelist guard), dan alert `ioc_match` (grup per
  source+IOC; severity = confidence feed; rationale selalu ber-disclaimer).
- **API `/api/ti/*`**: feeds CRUD + update-now (permission `ti_admin`:
  administrator/security_engineer), jobs history, ioc search, matches
  (API-constructed guarded query), allowlist CRUD; kredensial config di-mask
  (`*****`) di semua response; patch dengan nilai mask tidak menimpa rahasia.
- **Kegagalan feed**: job gagal → error + traceback disimpan di job, IOC tidak
  disentuh (dok §9.3).

## 6c. Rule Manager Suricata (Phase 6)

```
UI Detect → Rule Manager ──► ndr-api  /api/rules/*
                                 │ 1. tulis/hapus SID di disable.conf
                                 │    (volume bersama ./sensor/suricata/rules)
                                 │ 2. suricata-update --suricata-conf …
                                 │    → regenerasi suricata.rules
                                 │ 3. unix socket reload-rules (best-effort)
                                 ▼
ndr-suricata ◄── mount volume yang sama ◄── suricata-command.socket
```

- **Satu sumber kebenaran**: "disabled" = baris SID di `disable.conf` —
  mekanisme resmi `suricata-update`; state UI, CLI (`make rule-update`), dan
  sensor mustahil berbeda. Baris operator non-standar (`re:...`) dipertahankan.
- **Meta cache** `suricata_rule_meta` (Postgres): rule yang dihapus
  `suricata-update` dari `suricata.rules` tetap terlihat di UI (msg/classtype
  terakhir + siapa mematikan/kapan) — file hasil saja tidak bisa menjelaskan
  rule yang tidak dimuat.
- **Live reload best-effort**: socket dibagi via named volume `suricata-run`;
  bila sensor mati → banner "reload pending", perubahan berlaku saat sensor
  start berikutnya (Suricata membaca rules saat boot). Tidak pernah raise ke
  request path.
- **RBAC**: lihat = `view` (semua role); update/toggle = `rule_admin`
  (administrator/security_engineer); semua mutasi ter-audit
  (`rules.update`/`rules.enable`/`rules.disable`).
- **Izin volume**: service one-shot `init-rules` chown direktori rules ke uid
  10002 (user `ndr-api`) sekali saat stack naik.

## 6d. PCAP & Evidence Workflow (Phase 6, dok §15)

```
detail Alert/Incident (UI) ──► ndr-api /api/evidence/*
   │ 1. resolusi sesi: entitas alert ± buffer (default 5m)
   │    → ndr-events-read (query API-constructed, bukan DSL user)
   │ 2. status bukti per sesi (dok §15.2): coverage window
   │    dari mtime file rolling di $NDR_DATA_ROOT/pcap (ro)
   │ 3. ekspor: validasi reason + limit (max file/byte)
   │    → copy file pcap + manifest.json (SHA-256 per file)
   │    → zip + hash bundle → $NDR_DATA_ROOT/pcap-exports
   ▼
pcap_exports (Postgres) + audit log ── TTL sweep (hapus otomatis)
```

- **Sumber status jujur**: `available` / `partially_available` / `expired` /
  `not_captured` diturunkan dari cakupan file capture yang benar-benar ada —
  sistem tidak pernah mengarang ketersediaan bukti (dok §15.2, AT-11).
- **Granularitas file-level** untuk PoC: bundle berisi file rolling PCAP
  yang menaungi jendela sesi + manifest; dinyatakan eksplisit di manifest,
  UI, dan dokumen (tidak overclaim chain of custody). Inspeksi presisi
  per paket tetap lewat deep-link Arkime viewer (port 8005).
- **Chain of custody** (dok §15.3): tabel `pcap_exports` + audit
  `evidence.pcap.export/.download/.expire` mencatat actor, role, reason
  (wajib), alert/incident, sesi terpilih, jendela waktu, file+SHA-256,
  ukuran, dan TTL.
- **Anti full-PCAP**: batas maks file/byte per ekspor ditolak di sisi
  server sebelum menyentuh storage; TTL menghapus bundle sementara
  (default 60 menit).
- **RBAC**: lihat sesi/register/storage = `view`; ekspor/unduh =
  `evidence_export` (administrator/security_engineer/soc_analyst/
  soc_lead — auditor eksplisit tidak bisa, AT-18/AT-28).
- **Volume**: `${NDR_DATA_ROOT}/pcap` di-mount **read-only** ke ndr-api;
  `${NDR_DATA_ROOT}/pcap-exports` (rw) di-chown uid 10002 oleh service
  one-shot `init-rules`. Gauge Sensors kini memakai data live endpoint
  storage (bukan angka placeholder).

## 7. Apa yang sengaja BELUM ada (mengikuti dokumen)

- Kafka/K8s/ClickHouse/graph DB — belum dibutuhkan (dok §3.2).
- GeoIP enrichment, campaign/graph clustering, report engine bermusim,
  notifikasi, STIX/TAXII & MISP adapter ber-kredensial — Phase 4–7.
- Automatic blocking/response — bukan fungsi inti MVP (dok §2.2).
- TLS antar-service — fase hardening (Phase 7), sebelumnya wajib network
  isolation (compose internal + bind 127.0.0.1 + firewall).

## 8. Attack Reconstruction Engine (Phase 4, dok §10)

### 8.1 Posisi dalam pipeline

```
detection rules ──fan-out alert doc──┐
intel match (event ber-IOC) ─────────┤
dns / tls / http / fileinfo ──ctx────┤
                                     ▼
                    ReconstructionService (thread)
   ┌───────────────────────────────────────────────────┐
   │ Signal   = alert / ioc_event  (bisa MEMBUAT story)│
   │ Context  = dns answer / sni / file (hanya menempel)│
   │ Tracker  = domain↔IP (DNS answer), dstIP↔host(SNI) │
   │ StoryIndex = entitas → story aktif (gap-aware)     │
   └───────────────────────────────────────────────────┘
                                     │ snapshot per RECON_PERSIST_SECONDS
                                     ▼
        PostgreSQL: incidents, incident_nodes / _edges / _evidence /
                    _notes / _history
```

Kontrak keandalan: engine **tidak pernah memblokir ingest**. Queue input
dibatasi; context yang penuh dibuang (best-effort); hook `emit` rule deteksi
exception-safe. Detection tetap benar meski engine mati.

### 8.2 Lima lapis korelasi (dok §10.3)

| Lapis | Implementasi |
|-------|--------------|
| Entity | `entities.py`: normalisasi IP/domain/hash; irisan entitas menautkan sinyal ke story |
| Temporal | `StoryIndex.candidates`: sinyal diterima hanya dalam `[first−gap, last+gap]`; story idle > 2×gap ditutup |
| Behavior | Taxonomy fase (`detection/taxonomy.py`) + 5 rule perilaku baru (delivery/C2/lateral/impact) |
| TI | Event ber-`matched_ioc` jadi sinyal; confidence feed menentukan bobot & marker `c2_ioc_high`/`payload_ioc_high` |
| Evidence | `trackers.py` menyimpan jawaban DNS & SNI; alert pada IP X otomatis menautkan domain yang X resolve (relasi `inferred`) |

### 8.3 Model data story

- **Node**: `ip|domain|hash|ioc` + role (`attacker`, `compromised_host`,
  `c2_infra`, `payload`, `exfil_target`); node diberi fase terdalam yang
  menyentuhnya.
- **Edge**: relasi hati-hati per fase — `probed` (recon), `targeted` (initial
  access), `delivered_to`, `contacted` (C2), `lateral_to`, `transferred_to`;
  relasi dari konteks ditandai `inferred` (tidak pernah diklaim observed).
- **Evidence**: daftar terurut waktu (maks `RECON_MAX_EVIDENCE`, default 400),
  dedup pada `(ref_index, ref_id)` — replay-safe.
- **Confidence**: `100·(1−e^(−w/120))`, saturasi maks 97, selalu diberi label
  `heuristic-uncalibrated`.
- **Outcome**: marker fase → `indeterminate | attempted | suspected_success |
  strong_success`; output selalu memuat daftar **proven / suspected / unknown**
  + disclaimer buta jaringan (dok §10.2).

### 8.4 Merge & dedup

Sinyal dengan entitas yang mengarah ke ≥2 story menyebabkan **merge** (story
besar menyerap kecil; entitas diindeks ulang). Sinyal duplikat (alert id sama)
diabaikan dua lapis: global `signals_seen` dan `_evidence_refs` per story.

### 8.5 Restart & bukti terlambat

Saat start, `load_active(lookback)` memuat story `open|confirmed` yang diperbarui
dalam `RECON_LOOKBACK_HOURS` — bobot confidence di-invert dari kurva saturasi
agar kontinuitas terjaga. Bukti yang datang terlambat menempel selama story
masih dalam jendela lookback; sesudahnya story ditutup otomatis (dok §10: fase
terlewat & bukti telat harus tetap tertangani).

### 8.6 API & izin

| Endpoint | Izin | Catatan |
|----------|------|---------|
| `GET /api/incidents` | view | filter status/severity/q + paging |
| `GET /api/incidents/summary` | view | KPI untuk badge sidebar |
| `GET /api/incidents/{id}` | view | nodes+edges+evidence+notes+history |
| `PATCH /api/incidents/{id}/status` | incident_update | + catatan opsional; audit + history |
| `POST /api/incidents/{id}/notes` | incident_update | catatan analis |
| `GET /api/incidents/{id}/report` | view | Markdown; aksi di-audit |

`incident_update` = administrator, security_engineer, soc_analyst, soc_lead
(auditor read-only), konsisten dengan prinsip RBAC dok §12.

## 8b. Cyber Kill Chain & Dual Framework Mapping (Phase 5b, dok §11)

Lockheed Martin Cyber Kill Chain (7 tahap) dimasukkan sebagai **kerangka
analisis kedua yang melengkapi MITRE ATT&CK — bukan menggantikannya**:

| Aspek | Cyber Kill Chain | MITRE ATT&CK |
|-------|------------------|--------------|
| Fokus | Urutan tahapan serangan | Taktik & teknik yang dipakai |
| Kegunaan | Memahami perkembangan serangan | Mengidentifikasi perilaku/teknik spesifik |
| Tampilan NDR | Attack timeline & stage progression | Mapping teknik (mis. `T1046 Network Service Discovery`) |
| Korelasi | Menghubungkan bukti lintas tahap | Memberi konteks teknis pada tiap bukti |

### 8b.1 Kill Chain Stage Classifier (`pipeline/app/detection/killchain.py`)

Setiap alert dan event ber-IOC diklasifikasikan ke **satu dari 7 tahap LM**
berdasarkan rule, perilaku, dan konteks TI. Model internal 6 fase (§8) tetap
menjadi model kerja mesin rekonstruksi; proyeksi ke tahap LM bersifat
deterministik: `recon→reconnaissance`, `initial_access→exploitation`,
`delivery→delivery`, `c2→command_and_control`, `lateral|impact→
actions_on_objectives` (lateral movement adalah bagian dari Actions on
Objectives sesuai definisi LM). Hasil klasifikasi ditulis ke alert doc:

```json
"kill_chain": {"stage": "exploitation", "stage_label": "Exploitation",
               "basis": "suricata category 'web-application-attack'",
               "reason": "... classified as Exploitation by rule/behavior mapping"},
"mitre": [{"tactic": "Initial Access", "technique_id": "T1190",
           "technique": "Exploit Public-Facing Application"}]
```

`attack_phase` (6 fase) tetap dipertahankan untuk kompatibilitas. Tabel
ATT&CK per rule/kategori hidup di modul yang sama (`ATTCK_FOR_RULE`,
`ATTCK_FOR_CATEGORY`, `ATTCK_FOR_STAGE`) sehingga **dual framework selalu
total**: setiap tahap punya pemetaan ATT&CK.

### 8b.2 Stage Progression Engine + Evidence-Based Stage Assessment

`AttackStory.stage_progression()` menilai ketujuh tahap dari bukti, dengan
**empat status berbasis bukti** — bukan rantai yang dipaksakan:

| Status | Arti |
|--------|------|
| `observed` | Ada sinyal langsung (alert / ioc_event) yang dipetakan ke tahap |
| `suspected` | Hanya bukti konteks (DNS/TLS/HTTP/fileinfo) yang konsisten |
| `not_observed` | Telemetri jaringan mencakup tahap ini, tapi tidak ada bukti di story ini |
| `insufficient_telemetry` | Tahap **tidak bisa dinilai dari trafik jaringan saja** — `weaponization` terjadi di infrastruktur penyerang; `installation` butuh telemetri endpoint |

Setiap tahap membawa `reason` (alasan berbahasa Inggris yang bisa diperiksa),
`confidence` (heuristik tidak terkalibrasi — sinyal langsung > konteks, bonus
severity), dan daftar teknik ATT&CK yang mendukung. **Cyber Kill Chain tidak
diperlakukan sebagai urutan wajib**: serangan nyata bisa melewati tahap
(tahap terlewat tetap `not_observed`, bukan diisi kosong), berjalan paralel
(beberapa tahap `observed` sekaligus tanpa syarat tahap sebelumnya), atau
tidak menyediakan bukti cukup (`insufficient_telemetry`).

### 8b.3 Stage history — perubahan penilaian dari waktu ke waktu

Saat status sebuah tahap berubah, transisi dicatat ke `stage_history`:
`{ts, stage, from, to, evidence_ref}`. Baseline awal = penilaian tanpa bukti
(`not_observed`/`insufficient_telemetry`), sehingga entri pertama yang bermakna
misalnya `reconnaissance: not_observed → observed`. History di-persist di kolom
`incidents.outcome` (JSON) dan direstore saat restart bersama evidence.

### 8b.4 Dampak ke API, laporan, dan UI

- `GET /api/incidents/{id}` menambah `stage_progression` (7 tahap),
  `stage_history`, `deepest_stage`; node membawa `kill_chain_stage`; item
  evidence membawa `stage` + `attck`. Untuk incident lama (pra-doc 11) API
  menghitung ulang dari evidence lewat `api/app/killchain.py` — logika
  identik dengan pipeline, sehingga tampilan tetap konsisten.
- Laporan Markdown menambah bagian **Kill Chain Stage Assessment** (tabel
  status/confidence/ATT&CK/reason) + **Assessment changes over time**.
- UI: kartu *Cyber Kill Chain assessment* di detail incident (strip 7 tahap —
  garis putus-putus = buta telemetri; detail per tahap dengan reason + chip
  ATT&CK), *Stage assessment history* di panel graf, kolom *Kill chain* pada
  tabel evidence, chip tahap terdalam pada daftar incident, dan badge
  *kill chain* + blok klasifikasi pada detail alert. Tabel `incident_evidence`
  dapat kolom `stage` + `attck` (migrasi idempoten di pipeline & API; skema
  Postgres init diperbarui).

## 9. Threat Map & Relationship Graph (Phase 5)

### 9.1 Satu data korelasi, dua visualisasi

Kedua tampilan Threat Map membaca sumber yang sama — hasil rekonstruksi Phase 4
(tabel `incidents*`) — sehingga tidak ada dualitas data antara peta geografis
dan graf relasi:

```
PostgreSQL incidents/nodes/edges          OpenSearch events (guarded agg)
        │                                          │
        ▼                                          ▼
 api/app/graph.py ── MergedGraph ── cross_correlate()
        │                        (shared infra + principal links)
        ├─► GET /api/graph/relationships  → Attack Relationship Graph (UI)
        ├─► GET /api/graph/geo            → Geographic Threat Map (UI)
        └─► GET /api/graph/entity/{key}   → pivot + blast radius (ter-audit)
```

### 9.2 Aturan korelasi lintas kampanye

`MergedGraph.cross_correlate()` menambahkan edge `correlated_with` HANYA ketika
dua entitas dari kampanye berbeda berbagi bukti yang bisa diperiksa:

- entitas bersama ber-role `c2_infra | payload | delivery_infra | exfil_target`
  atau bertanda `ti_match`, dan muncul di ≥2 kampanye;
- **member link**: pasangan entitas yang terhubung langsung ke infrastruktur
  bersama (observed, atau `resolved_to`/`queried` dari konteks DNS);
- **principal link**: kepala kampanye (role `attacker`, atau `compromised_host`
  dengan bukti terbanyak) dipasangkan antar kampanye — sehingga kampanye
  multi-IP tetap terlihat walau penyerang dua hop dari infrastruktur bersama;
- setiap edge membawa `reasons[]` yang menyebut entitas bersama secara eksplisit.
  Kedekatan waktu TIDAK PERNAH menjadi alasan relasi.

### 9.3 Blast radius

`blast_radius()` melakukan BFS ≤2 hop dari entitas terpilih pada graf gabungan,
lalu memisahkan jalur **direct** (semua edge observed) dan **indirect**
(mengandung edge inferred), dan meringkas host internal yang terdampak. UI
selalu menyatakan bahwa dampak adalah estimasi korelasi, bukan konfirmasi
kompromi.

### 9.4 GeoIP opsional

- `pipeline/app/geoip.py`: nonaktif secara default; dua backend — MaxMind MMDB
  via paket opsional `maxminddb` (`GEOIP_MMDB_PATH`) atau sidecar JSON
  CIDR→geo longest-prefix (`GEOIP_JSON_PATH`, lihat `.env.example`).
- Space internal/reserved (RFC1918, loopback, dll.) tidak pernah di-geolocate.
- Field hasil: `source.geo` / `destination.geo` (`country`, `country_iso_code`,
  `asn_org`, `location.lat/lon`) — sudah dipetakan di template events.
- API `/api/graph/geo` mengagregasi pasangan eksternal↔internal (composite agg,
  hanya API-constructed), mengklasifikasikan arah dari zona + RFC1918, dan
  menempatkan IP tanpa geo ke `unmapped[]` — UI menampilkannya sebagai daftar,
  tidak dipaksakan ke peta dunia. OpenSearch mati → payload kosong yang jujur.
