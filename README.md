# NDR Platform — Fondasi Phase 0–6

Implementasi baseline dari **NDR System Design & Implementation Plan v1.0** untuk
satu VM Ubuntu 24.04 (8 core / 24 GB RAM / 3 TB storage), dengan cakupan:

| Fase | Isi | Status |
|------|-----|--------|
| Phase 0 | Discovery & desain (dokumen asli) | ✅ acuan |
| Phase 1 | Sensor foundation: Zeek, Suricata, Arkime + SPAN/TAP | ✅ dibangun |
| Phase 2 | Ingestion, normalisasi, pencarian, Alert Center, health monitoring | ✅ dibangun |
| UI v0.3–0.4 | Konsol visual SOC: Dashboard live, Threat Map, Topology, Threat Intel, Assets, Reports | ✅ dibangun |
| Phase 3 | Threat Intelligence: feed ingestion, IOC match, allowlist audit | ✅ dibangun |
| Phase 4 | Automatic Attack Reconstruction: correlation engine, attack story, attack graph, outcome assessment, laporan insiden | ✅ dibangun |
| Phase 5 | Interactive Threat Map: Attack Relationship Graph (pusat investigasi kampanye) + Geographic Threat Map, keduanya dari data korelasi yang sama — pivot bukti, blast radius, overlay TI, GeoIP opsional | ✅ dibangun |
| **Phase 5b** | **Cyber Kill Chain & Dual Framework Mapping**: klasifikasi 7 tahap Lockheed Martin di setiap alert/event (melengkapi MITRE ATT&CK), stage progression engine, penilaian tahap berbasis bukti (observed/suspected/not_observed/insufficient_telemetry), stage history, tampilan di incident/alert/laporan | ✅ dibangun |
| **Phase 6** | **Rule Manager Suricata**: UI terpusat untuk update Emerging Threats rules (suricata-update + live reload via unix socket) dan enable/disable per-SID (disable.conf pada volume rules bersama), cache metadata rule di Postgres, hit count 7 hari, audit penuh | ✅ dibangun |
| **Phase 6** | **PCAP & Evidence Workflow (dok §15)**: panel PCAP & sessions di detail alert/incident — resolusi sesi + status bukti (available/partially/expired/not_captured), ekspor selektif ber-manifest SHA-256 dengan batas ukuran + TTL + register chain of custody, RBAC `evidence_export`, deep-link Arkime viewer, gauge storage live | ✅ dibangun |
| **v0.16.0** | **Fase 1 tender 19 requirement** (R5 filter DSL AST anti-injeksi, R6 export XLSX/CSV, R7 DNS & TLS Explorer, R12 GeoIP tag alert, R13 SSO Arkime bake, R14/15 rule stats 24h/7d, R18 watchlist judi online, R19 live metrics SSE) | ✅ dibangun |
| **v0.16.1** | **Perbaikan bug lapangan vendor 0.16.0** (laporan deploy 2026-10-22): **P0** openpyxl wajib + lazy-import export, symlink Zeek `logs/current -> spool/zeek` + self-heal, detail alert alias multi-index kini ids-query (tak lagi 502), Event Search free-text dibangun server (event_type/IP fast-path, tanpa term teks ke field ip); **P1** `/api/stats/overview` kaya data agregasi nyata (hosts/zone_traffic/protocols/top-*/MTTR), Rule Manager `GET /api/rules/status` + UI tahan gagal, rasio DNS denominator eksak (bug 9133%), JA3 dihitung pipeline dari client-hello Zeek + TLS insights multi-alias; **P2** `/api/version`, guard JWT secret lemah, komponen pipeline di health doc, exact total opsional, `GET /api/alerts/search` 405 eksplisit | ✅ dibangun |
| **v0.16.2** | **Perbaikan bug hasil verifikasi 0.16.1** (BUG-0161-01..07): **P1** sub-agregasi `engines` kini DI-NEST di `by_ts` (KPI "Events (24h)" & "Events processed" hidup lagi) + KPI UI memakai `count` eksak; Reports selalu-0 diperbaiki (memakai `alerts_7d`/`events_7d`/`mttr_hours_avg`/`closed_7d` dari stats + chart severity harian nyata dari `alert_daily_7d`); **P2** `upgrade.sh` membangun profil sensor (image zeek/suricata/arkime ikut baru), deadletter `sink_timeout/sink_failure` direplay berkala (idempoten by _id, kill switch env), sink breaker anti-saturasi (cooldown eksponensial + batch adaptif) + pacing catch-up saat backlog > ambang, guard `_shards.failed` (tidak ada lagi hasil parsial bisu) + agregasi engine memakai varian `.keyword` untuk index lama ber-mapping text; **P3** fallback JWT secret kini PERSISTEN (file lintas-worker/restart, tidak ada lagi 401 acak), `upgrade.sh` merotasi JWT_SECRET lemah otomatis, branding legacy "Ever SEEN" dinormalkan ke "NDR Console" | ✅ dibangun |
| **v0.10.0** | **UX & Administrasi SOC**: klik node/edge Threat Map (perbaikan klik setelah pan), Geographic Map baru + fullscreen bigscreen, jump-to-Threat-Map dari tiap alert, verdict hasil serangan (`outcome`) + kolom Protocol + timestamp, filter rentang waktu (today/24h/7d/14d/30d/custom) di Alert/Incident/Threat Intel, eskalasi alert → incident manual, pemisahan menu Detection vs Configuration (Rule Manager, Intel Feeds, Assets, Users, Roles), registri aset manual + enrichment nama aset di alert, CRUD User + halaman Roles (matriks RBAC), paginasi semua tabel | ✅ dibangun |
| **v0.11.0** | **Rule Editor + TI Standar + System Settings**: custom rule editor Suricata (validasi live, SID lokal 1.000.000-1.999.999, sync ke engine), TI feed sync STIX 1/2 + TAXII 2.1 + MISP (parser + IOC ingest + UI Add feed), halaman Settings (ganti nama sistem, logo & favicon, NTP + status check, network + interfaces, Network Diagnosis ping/traceroute/DNS/port), RBAC `rule_admin` & `system_admin` | ✅ dibangun |
| **v0.12.0** | **Campaign & Hardening**: campaign merge/split insiden (bookkeeping analis, rollup otomatis, audit penuh), report versioning (snapshot Markdown immutable per insiden), TLS hardening (gateway nginx profil `tls`, header keamanan, cookie Secure), load test suite + hasil terukur, PCAP telemetry Arkime (deep-link per sesi + status jujur) | ✅ dibangun |
| **v0.12.1** | **IOC match detail enrichment**: lifecycle IOC (first/last seen + expires) di sheet match, tombol "Open in Event Search" (deep-link `event_id`), kartu "Related alerts" per host (korelasi beaconing + IOC match) | ✅ dibangun |
| **v0.12.2** | **Pra-deploy hardening**: `.env.example` lengkap (memperbaiki installer yang gagal tanpa file ini), dialog ganti password UI (forced `must_change_password` + manual, sinkron revokasi sesi backend) | ✅ dibangun |
| **v0.12.3** | **Perbaikan hasil deployment VM nyata** (laporan pengguna 10.0.106.232): image Suricata `suricata/suricata:8.0` tidak ada → `jasonish/suricata:8.0` (+ethtool); URL deb Arkime 404 → pola `arkime_<ver>-1.ubuntu2404_amd64.deb`; `pipeline/requirements.txt` kurang `SQLAlchemy`+`psycopg` (pipeline crash-loop); mismatch tipe kolom Postgres `UUID` vs ORM `String(36)` (users, pcap_exports + drift incidents/campaigns/incident_nodes/edges/evidence ISO-string) → schema disamakan TEXT + **test regresi konsistensi schema↔ORM**; `install.sh` build base & sensor dipisah (kegagalan sensor tidak lagi menggugurkan base); panduan `CAPTURE_IFACE` + daftar kandidat interface SPAN di installer | ✅ dibangun |
| **v0.12.4** | **Perbaikan deployment 0.12.3 (laporan pengguna)**: [BLOCKER] `sensor/zeek/Dockerfile` men-COPY `scripts/` yang tidak ada → build ketiga image sensor gagal (`"/scripts": not found`) → baris dihapus (custom script opsional kini terdokumentasi di komentar); [DOC] perintah reset Postgres di DEPLOYMENT.md rusak (`sudo rm -rf .../postgres/*` — glob di-expand shell user biasa yang tak bisa baca dir 750, rm gagal diam-diam) → diganti `sudo env NDR_DATA_ROOT=... bash -c 'rm -rf ... && mkdir -p ... && chown 999:999 ...'` tanpa glob; [MINOR] migrasi runtime `ALTER TABLE ADD COLUMN` exception-driven di `api/app/main.py` + `pipeline/app/correlation/store.py` membanjiri log Postgres `column already exists` tiap boot → kini **inspector-guarded** (cek kolom via `sqlalchemy.inspect` dulu; dialect-agnostic SQLite/Postgres) | ✅ dibangun |
| **v0.12.5** | **Port semua fix tervalidasi-VM (LAPORAN-DEV-GABUNGAN) ke repo resmi** — sensor: `local.zeek` kompatibel Zeek 9 (`base/protocols/weird` + 3 redef yang dihapus upstream dibuang, `ZEEK_IMAGE` bisa di-pin), `iproute2+ethtool` di image Zeek, `SpoolDir` via `zeekctl.cfg` + symlink `current` RELATIF (pipeline tidak buta lagi), token `460-660` invalid di `suricata.yaml` dihapus (Suricata 8.0.7 exit), layout Arkime 5.6 (`db/db.pl`, viewer via bundled node, CWD per proses, `snapLen=65535` utk frame GRO ~17KB) — API: `guarded_search` tak lagi mengirim clause kosong (Alerts 400), bootstrap `aliases` pindah ke dalam `template` (bootstrap mati di template pertama → nol indeks), dok alert kini punya `@timestamp` (sort gagal), migrasi CHECK `ti_feeds.adapter` +stix/taxii/misp (500 saat buat feed standar), Rule Manager cache parse+sync by mtime (47,3s → 1,4s tervalidasi), `GET /api/sensors`+`/api/health` status efektif dari freshness 5 menit, graf relasi bulk-fetch+indeks (17,6s → 0,6s, payload identik) — pipeline: sweep pakai wall-clock (sebelumnya TIDAK PERNAH jalan → 0 alert), `inferred` bool (persist story rollback), `_jload` JSONB-aman di recon+TI (thread mati diam-diam), TI job `json.dumps(default=str)`+recovery job orphan, starter feed abuse.ch di-seed (dead code), heartbeat tabel `sensors` — UI: `searchAlerts` flatten hits (baris `-`/severity `unknown`, escalate rusak) | ✅ dibangun |
| **v0.12.7** | **7 perbaikan UI/UX (laporan pengguna) + arsip 0.12.6 yang ternyata belum memuatnya**: (1) **Sidebar** — ScrollArea Radix diganti nav native `overflow-y-auto` + `min-h-0` (wajib di flex column) + scrollbar tipis; menu bisa discroll penuh di layar pendek; (2) **Alert Center** — paginasi **server-side sungguhan** (Next → API `from/size` → OpenSearch; window 500/baris, `from` jalan melewati baris 500; filter verdict pindah server-side), badge "**N matches (server-side)**", Paginator 10–100/baris; chart header pindah ke **endpoint agregasi baru `POST /api/alerts/stats`** (query guard sama dengan /search, `size:0`, hanya bucket) → severity/status/verdict **akurat untuk result set segala ukuran** (scatter & MITRE tetap dari sampel 500 terbaru); (3) **Threat map** — geo flows dibatasi **top-volume pairs (default 120** via `max_pairs`), hanya **top-40 arc** yang dianimasikan (sisanya statis), endpoint pulse dibatasi 120, graph relasi di-prune ke **140 entitas** paling berbukti (TI-match → lintas-kampanye → evidence; `meta.full_counts` menjaga transparansi); (4) **Attack graph** — enrichment DNS/TLS/HTTP/tracker diperketat: node context dibudget `MAX_CTX_NODES=36`, domain tracker per-IP 6→3, jawaban DNS jadi node maks 2 (sisanya tetap di evidence), edge dibatasi `MAX_EDGES=120`, UI merender maks 60 node terpilih + label relasi hanya di node terpilih → graf kini menyerangan, bukan "semua trafik"; (5) **Rule Manager** — paginasi server-side penuh (limit/offset + Paginator 10–100/baris; dulu fetch tetap 200 sehingga 53k rule ET tak terlihat semua); (6) **Bedakan sumber rule** — tab **All / Suricata (ET) / Lokal (custom) / Zeek (scripts)** + kolom & badge Source per baris + `by_source` di summary; Zeek berupa inventaris skrip `local.zeek` **read-only** via endpoint baru **`GET /api/rules/zeek`** (mount read-only); (7) **Menu hijau → biru glossy** — palet emerald diremap ke sky-blue di level theme (`@theme` CSS vars, 288 call site tak tersentuh satu-satu) + class `.ndr-gloss` (gradien berlapis + inner highlight + outer glow) untuk item menu aktif, tab aktif & logo; warna status semantik (merah/amber) dipertahankan | ✅ dibangun |
| **v0.15.0** | **Anti-wedge sink + ensure-index + checkpoint guard + tooling ops (action list LAPORAN-DEV-ACTION-0.15.0)** — **[A1]** `install.sh` tak lagi chown `999:999` hardcoded: uid/gid postgres di-deteksi dari image yang benar-benar dipakai (`docker run --entrypoint sh $PG_IMAGE id -u postgres`; alpine=70, debian=999) — fresh install `postgres:16-alpine` tak lagi rusak; **[A2]** sink anti-wedge: client `timeout=120, max_retries=0, retry_on_timeout=False, maxsize/pool_maxsize=50` (urllib3 TIDAK me-resend bulk yang masih diproses server — akar wedge Lucene DWPT 10.15/10.18/10.19); `ConnectionTimeout/TimeoutError` → dead-letter `sink_timeout` TANPA retry; 429/5xx/network → backoff ≤ `PIPELINE_BULK_MAX_RETRIES` → `sink_failure`; **[A3]** sizing bulk didokumentasikan (`.env.example` + `docs/SIZING-8c-24GB-3TB.md §7` + benchmark `scripts/poc/sink_benchmark.sh` 10/20/200; 200 = live-proven 302 EPS) + `PIPELINE_BULK_MAX_ITEMS=200` sbg default .env.example; **[A4]** image OpenSearch dipin eksplisit di `.env.example` — catatan: **2.20 tidak pernah dirilis**, jalur 2.x berakhir di **2.19.6** (in-place dari 2.19.2); 3.x evaluasi terpisah; **[B1]** sink kini **ensure-index** idempoten (`PUT /<index>` bila belum ada) sebelum bulk pertama per target — template + alias harian selalu berlaku meski `auto_create_index` gagal (kasus ndr-alerts 10.17); gagal di-log eksplisit & dicoba ulang batch berikutnya; **[B2]** tool resmi `scripts/deadletter-replay.py` (filter reason/prefix, dry-run default + `--execute`, bulk batch 200, idempoten `_id` asli); **[B3]** checkpoints.json v2: `version` + checksum sha256 (file korup diabaikan utuh), validasi shape `[st_ino, st_dev]`, **deteksi [dev, ino] terbalik** → warning + offset DIPERTAHANKAN (dulu near-miss re-read 18 GB), reset hanya dengan menghapus file (eksplisit); **[B4]** entrypoint Arkime set ulang `headerAuthEnabled=true` utk admin (idempoten, cari indeks `arkime_users*`) — SSO proxy tidak lagi 403 pasca-recreate; **[BUG GAP]** `.env.example` kini mendefinisikan `OPENSEARCH_IMAGE`/`POSTGRES_IMAGE` (compose menuntut keduanya, dulu kosong) | ✅ dibangun |
| **v0.14.0** | **Alert Whitelist (2-layer, two-man rule) + in-page/auto refresh + honest dashboard failure state** — **[WHITELIST]** tabel `alert_allowlist` + API lengkap (`GET/POST /api/allowlist`, approve/reject/extend/delete, summary, audit, guard anti-universe 0.0.0.0/0 & CIDR terlalu lebar, duplikat → 409); **dua lapis**: L0 = alert tidak pernah diindeks (counter `hit_count` saja, story/attack-graph TETAP jalan), L1 = alert terindeks bertanda `suppressed/suppressed_by` + dikeluarkan dari antrian triase default (toggle "Show suppressed"); **tata kelola dua mata**: analyst mengajukan (pending), admin/security_engineer approve (admin self-approve aktif langsung & ter-audit); alasan wajib + TTL opsional (24h/30d/90d, expired auto-nonaktif dan bisa diperpanjang 1-klik); **retroaktif** opsional menandai alert serupa 7 hari terakhir via `update_by_query` (max 2000, best-effort, jujur laporkan jumlah); matcher IP exact/CIDR + domain suffix case-insensitive + pin signature; UI: tombol "Whitelist similar…" di detail alert (prefilled), panel kelola di Settings, kartu transparansi di Dashboard; **[REFRESH]** tombol refresh manual + auto-refresh selectable (off/10s/30s/1m/5m, persist per-halaman) di Incidents, Alert Center, DGA Activity, Threat Intel, Whitelist; **[DASHBOARD KOSONG]** bila API tak terjangkau dashboard kini JUJUR menampilkan banner "Dashboard data unavailable" + tombol Retry (dulu kartu kosong diam) — dan timeline dashboard memakai agregasi nyata `GET /api/events/timeline`; **[REKONSTRUKSI v0.13.0 — sandbox merestore snapshot lama, semua diulang & ditambah test]**: blocker raw_archive per-engine, users by-username UI, PATCH alerts timeout 90 s, toggle rule ASYNC JOB (`GET /api/rules/jobs/{id}`; `wait=1` legasi), DELETE TI feed, ids-query/batch export + `_PCAP_SUFFIXES`, TRUST_PROXY (XFF tak lagi dipercaya default), UserUpdate.role & SensorUpdate.status validator, killchain jujur, events timeline, normalize dns_qtype + severity aman + files.log + file_size coerce, PARSER_VERSION 0.7.0 (dedup key milik parser), metrics snapshot read-only + rotate eksklusif + `detection_dropped`, DETECT_BEACON_WINDOW_MIN tanpa floor, DETECT_LATERAL_PORTS fail-soft, FileTransfer menerima `files`, exfil hanya byte TERKIRIM (download besar bukan lagi kandidat exfil), correlation LRU deterministik + context gap-check + sweep ingest-timeline + pembersihan set kosong, deploy glue (install.sh 711 + chown snapshot, sensor-down aman, upgrade.sh backfill, gen-certs idempotent, UI Dockerfile `npm ci`, bootstrap alias BACKFILL, suricata chown uid API, .env.example lengkap) — semuanya kini terlindungi test permanen | ✅ dibangun |
| **v0.12.9** | **5 laporan pengguna: jump fokus, intel feeds, DGA audit, detail IOC, PCAP** — (1) **Jump Threat Map dari Alert Center kini FOCUSED** (endpoint baru `GET /api/alerts/{id}/relationship`, basis jujur `incident`/`alert`/`none`): tombol Waypoints membuka **relasi serangan milik alert itu saja** — subgraf insiden bila alert tercatat sbg bukti, atau graf minimal dari entitas alert sendiri (semua edge observed + mengutip alert id, tidak ada relasi ditebak) — peta global/geo TIDAK lagi dimuat (payload kecil, ringan); tombol "Show full threat map" membuka peta lengkap secara eksplisit; (2) **Threat Intel - detail IOC dirinci**: panel "Activity on your network (7d)" (endpoint baru `GET /api/ti/iocs/activity`: jumlah match, host unik, first/last match, top host, recent matches per-event + related `ioc_match` alerts via signature tercatat `ioc:<value>` — tanpa tebakan), provenance feed terstruktur (feed, confidence, umur, referensi) menggantikan dump JSON; banner "Why so few IOC matches?" menjelaskan coverage + tombol one-click **Enable + update** untuk 3 starter feed abuse.ch; (3) **DGA audited vs referensi internet** (Wong 2023 arXiv:2304.07943; Notos/Kopis USENIX 2010-11; Woodbridge 2016 arXiv:1611.00791; Tranco NDSS 2019; praktik Splunk/Elastic): **allowlist domain populer/CDN built-in** (+ `DETECT_DGA_ALLOWLIST`) dikecualikan dari hitungan unique & rata-rata entropy (dilaporkan transparan di reasons), sample queries kini membawa **entropy per domain** `domain (3.58)`; panel "How this detection works" (mekanisme, tuning, keterbatasan dictionary-DGA, referensi) di menu DGA; (4) **Dokumentasi OPERATIONS.md**: §16.5 jump fokus, §17 tiga lapis penyimpanan potongan PCAP + cara verifikasi (Arkime rolling freeSpaceG, raw gzip 72h + sha256, export selektif manifest-hash), §18 sumber intel feed yang disarankan + cara menambah feed | ✅ dibangun |
| **v0.12.8** | **Fokus DGA + kecepatan + keterbacaan korelasi (laporan pengguna)**: (1) **Menu DGA sendiri** — "DGA Activity" di grup Detect: lensa pre-filter atas dua deteksi keluarga DGA yang sudah ada (`dga_suspected` + `dns_nxdomain_burst`, tanpa detector baru), endpoint agregasi baru **`GET /api/alerts/dga/summary`** (guard sama dengan /stats, `size:0`, bucket source + timeline per jam/hari + filter `terms alert_type`), KPI + timeline + tabel alert ber-paginasi + panel "Top querying hosts" & "Sampled flagged domains" (domain yang dicatat detector di bukti alert), filter window 24h/7d/14d; (2) **Rule Manager instan** — akar masalah sisa 500: cache merged-items baru berjalan **tanpa query SuricataRuleMeta ~53rb baris** per request (signature file + signature tabel custom-rule), build cache diserialisasi `threading.Lock` (request summary+list paralel tak lagi menjalankan meta-sync 53rb baris dua kali → kontensi lock Postgres hilang), `_sync_meta` bulk (dict lookup, bukan `db.get` per baris), UI stale-while-revalidate (data terakhir langsung tampil saat menu dibuka ulang, refresh senyap di belakang; kegagalan refresh tak lagi mengosongkan layar) + debounce search 250ms; (3) **Threat Map terstruktur** — redesign mengikuti pola peta ancaman industri (Kaspersky Cyberthreat Live Map, Fortinet Outbreak Map, Zscaler ThreatLabz): **satu arc per negara asal** (ketebalan = koneksi teragregasi, warna = sinyal terkuat, maks 20 negara, animasi hanya top-10), panel peringkat **Origin countries** (klik = filter), panel **External endpoints** (peringkat TI/alert/volume), matriks flow **ber-paginasi** (dulu terpotong 40 baris), detail endpoint tetap satu-klik; (4) **Incident mudah dibaca & terbukti** — **Relations ledger**: tabel audit semua relasi (from → relation → to, jumlah evidence, window, confidence, observed vs inferred), baris evidence **bisa dibuka** menampilkan detail payload persis yang direkam engine (query konteks, ref event, fakta host/file); (5) **Alert Center terbukti** — section baru **"Correlation & incident linkage"**: insiden yang benar-benar merekam alert ini sebagai bukti (endpoint baru **`GET /api/alerts/{id}/related-incident`**, tanpa tebakan similarity) + tombol **"Verify in Event Search"** (pasangan source/destination alert ±15 menit) + field provenance (rule, group key, alert id); detail sheet diekstrak ke komponen bersama (Alert Center & menu DGA memakai alur yang sama) | ✅ dibangun |
| **v0.12.6** | **Perbaikan Alert Center - detail (laporan pengguna)**: panel "PCAP & sessions (doc 15)" gagal `Failed to load sessions: Error: Alert not found` padahal alert tampak di daftar — resolusi alert sebelumnya hanya GET-by-id terhadap alias `ndr-alerts-read` yang membentang banyak indeks harian (fan-out get tidak menemukan dokumen) dan **semua** error backend ditelan jadi 404 → kini **`get_alert_doc`** dua lapis (get `_id` → fallback term-search field `alert_id`, DSL dibangun API) dipakai 4 endpoint (sessions/detail/update/escalate; PATCH menulis ke `_id` hasil resolusi); kegagalan backend kini **502** jujur, hanya "alert tak ada" yang 404; section "Evidence (N sample events)" yang **bertumpuk** dengan tabel sessions (event yang sama tampil dua kali) di-merge ke satu panel **"PCAP & evidence (doc 15)"** — blok *Trigger evidence* tetap tampil walau lookup sesi gagal; tabel sessions kini scroll horizontal di dalam panel (kolom Evidence status tak lagi terpotong) | ✅ dibangun |
| Phase 6+ | Notification & webhook, sandbox detonation, response automation, PCAP packet-precise slice | 🔜 berikutnya |

## Cyber Kill Chain & Dual Framework Mapping (Phase 5b, dok §11)

Cyber Kill Chain (7 tahap Lockheed Martin) dimasukkan sejak awal desain sebagai
**kerangka pelengkap MITRE ATT&CK — bukan pengganti**. Kill Chain menjawab
"serangan sudah berkembang sampai mana" (attack timeline & stage progression);
ATT&CK menjawab "teknik apa yang dipakai" (mis. `T1046 Network Service
Discovery`). Keduanya tampil bersama di setiap bukti.

- **Kill Chain Stage Classifier** — setiap alert dan event ber-IOC dipetakan ke
  tujuh tahap berdasarkan rule, perilaku, dan konteks TI. Alert doc membawa
  `kill_chain` (tahap + alasan yang bisa diperiksa) **dan** `mitre` (teknik
  ATT&CK) sekaligus.
- **Stage Progression Engine** — perkembangan serangan disusun dari waktu dan
  hubungan antar-entitas, termasuk **cabang, tahap yang hilang, dan aktivitas
  paralel**. Kill Chain **bukan urutan wajib**: tahap bisa dilewati, paralel,
  atau tidak punya bukti cukup.
- **Evidence-Based Stage Assessment** — tiap tahap diberi status `observed`,
  `suspected`, `not_observed`, atau `insufficient_telemetry` beserta alasan dan
  confidence. `weaponization` dan `installation` secara prinsip tidak dapat
  dinilai dari trafik jaringan saja — sistem menyatakannya jujur sebagai
  *insufficient telemetry*, bukan menebak.
- **Stage history** — perubahan penilaian dari waktu ke waktu dicatat
  (`not_observed → observed`, dsb.) lengkap dengan referensi bukti pemicunya.
- **Tampilan**: strip 7 tahap + detail per tahap di detail incident, chip tahap
  di daftar incident, kolom kill chain di tabel evidence, badge klasifikasi di
  detail alert, dan bagian khusus di laporan Markdown insiden.

Contoh alur investigasi (IP A dan IP B **tidak otomatis** dianggap satu pelaku —
hubungan antar keduanya harus didukung korelasi + confidence + bukti):
`Reconnaissance` (IP A memindai beberapa server) → `Exploitation` (IP B mengirim
pola exploit ke server yang sama) → `Command & Control` (server melakukan
koneksi berkala ke domain bereputasi buruk) → `Actions on Objectives` (NDR
memeriksa koneksi internal lanjutan / transfer data yang mendukung dugaan
kompromi).

## Automatic Attack Reconstruction (Phase 4, dok §10)

Fitur pembeda utama: NDR ini **merekonstruksi rangkaian serangan secara otomatis**
dari fase awal sampai fase akhir — analis tidak perlu menelusuri alert terpisah
secara manual.

**Lima lapis korelasi** (berjalan sebagai thread `attack-reconstruction` di pipeline):

1. **Entity correlation** — alert & event direduksi menjadi entitas ternormalisasi
   (IP, domain dari DNS/SNI/HTTP, file hash); story di-grow dari irisan entitas.
2. **Temporal correlation** — sinyal dalam jendela `RECON_MAX_GAP_SECONDS`
   (default 2 jam) digabung; story tetap bisa diperbarui bukti terlambat selama
   `RECON_LOOKBACK_HOURS` (24 jam), termasuk setelah restart engine.
3. **Behavior correlation** — 9 rule bertag fase: portscan & NXDOMAIN burst
   (recon), alert Suricata berkategori eksploitasi (initial access),
   `file_transfer_suspected` (delivery), beaconing + `dga_suspected` +
   `dns_tunneling_suspected` (C2), `internal_lateral_suspected` (lateral),
   `large_outbound_transfer` (impact).
4. **Threat Intelligence correlation** — event ter-match IOC menjadi sinyal;
   match confidence tinggi menaikkan penilaian outcome (dengan disclaimer).
5. **Evidence correlation** — jawaban DNS dan SNI/HTTP host dicatat sebagai
   konteks lintas-log: alert beaconing pada IP X otomatis menautkan domain
   yang X resolve/dikunjungi beberapa menit sebelumnya.

**Hasil untuk analis** (view **Incidents**):

- **Attack timeline** — urutan kejadian per waktu dengan fase, sumber
  (Zeek/Suricata/pipeline/TI), referensi bukti, dan JSON detail yang bisa dibuka.
- **Attack graph** — graf SVG berlapis per fase: penyerang → target → infra C2
  → host lateral → tujuan eksfil; relasi *observed* (garis penuh) vs *inferred*
  (garis putus) eksplisit; klik node untuk detail.
- **Evidence per fase** — kartu fase berstatus OBSERVED (bukti langsung),
  SUSPECTED (hanya konteks), atau none.
- **Attack outcome** — dipisah tegas: `attempted` (baru percobaan),
  `suspected_success` (rantai lanjut), `strong_success` (TI high-confidence di
  rantai), `indeterminate` — plus daftar **proven / suspected / unknown** yang
  menyatakan jujur buta jaringan: eksekusi proses & sensitivitas data tidak
  bisa dibuktikan dari trafik saja.
- **Laporan insiden** — Markdown yang bisa diunduh (tab Report) dengan
  ringkasan eksekutif, penilaian outcome, tabel timeline, bukti per fase,
  graf entitas-relasi, dan catatan analis — setiap klaim membawa referensi
  `index:doc_id`.
- **Triage ter-audit** — status open/confirmed/benign/closed + catatan, semua
  masuk incident history dan audit log; auditor hanya bisa membaca.

Insiden didedup & di-merge otomatis: sinyal yang mengarah ke story yang sama
(jenis entitas sama + dalam jendela waktu) tidak membuat alert duplikat, dan
story yang saling tumpang-tindih digabung menjadi satu insiden.

## Interactive Threat Map (Phase 5) — Attack Relationship Graph sebagai pusat investigasi

Dua visualisasi yang **memakai data korelasi yang sama** (dok §10 → API graph),
saling terhubung satu klik:

### A. Attack Relationship Graph (tab utama)
- **Node** = IP eksternal, host internal, domain, hash/IOC — teragregasi lintas
  kampanye; ukuran node ∝ jumlah bukti, warna ∝ peran (attacker, c2_infra,
  compromised_host, exfil_target, payload), cincin ungu berdenyut = IOC match.
- **Edge beralasan** — garis penuh = relasi teramati, putus = inferred dari
  konteks entitas/temporal, amber putus = **korelasi lintas kampanye**.
  Setiap edge bisa diklik dan selalu menjawab *mengapa terhubung*: alasan
  korelasi yang bisa diperiksa (mis. "shared domain infrastructure:
  update-checkserve.net (TI-matched)"), jumlah bukti, confidence, dan kampanye
  sumber. **Dekat waktu saja TIDAK PERNAH membuat relasi.**
- **Multi-IP campaign** — dua entitas dari kampanye berbeda terhubung otomatis
  hanya jika berbagi infrastruktur yang bisa dibuktikan (C2/delivery/exfil sama,
  atau entitas TI-matched sama) — termasuk tautan *principal* antar kampanye
  sehingga kampanye multi-IP tetap muncul meski penyerangnya dua hop dari
  infrastruktur bersama.
- **Kampanye** — chip per insiden (dengan confidence); pilih satu kampanye untuk
  mengisolasi rantainya di graf dan menampilkan **attack sequence**
  (urutan bukti per waktu dengan fase & referensi).
- **Evidence pivot** — klik node → panel: kampanye, relasi + alasan, alert
  terkait (dengan `index:alert_id`), metadata sesi terbaru, dan **blast radius**:
  host internal terdampak *direct* (jalur observed) vs *indirect* (jalur
  mengandung inferred) — dengan disclaimer bahwa dampak adalah estimasi
  korelasi, bukan konfirmasi kompromi.
- **Overlay TI** — toggle yang menandai entitas IOC-match beserta sumber & waktu
  pembaruan intel; match selalu diberi disclaimer *contextual evidence*.

### B. Geographic Threat Map (tab pendukung)
- Garis lengkung eksternal ↔ jaringan terpantau: **ketebalan ∝ frekuensi**
  koneksi, **warna ∝ sinyal ancaman** (merah = TI-matched, amber = mengandung
  alert, oranye = inbound, biru = outbound), ukuran titik ∝ volume.
- **Klik garis/titik/matriks** → detail IP: negara & ASN (perkiraan), frekuensi,
  hit IOC, alert, **insiden terkait**, dan tombol **"Open in attack relationship
  graph"** — membuka node `ip:<address>` yang sama di tab graf.
- **Tidak ada pemaksaan peta**: IP internal dan alamat tanpa data GeoIP masuk
  panel **"Not on the map"** lengkap dengan alasan dan frekuensinya — GeoIP
  dinyatakan eksplisit sebagai *perkiraan lokasi jaringan, bukan bukti lokasi
  fisik penyerang*.
- **GeoIP opsional** (default mati): aktifkan via `GEOIP_MMDB_PATH`
  (GeoLite2 + paket `maxminddb`) atau `GEOIP_JSON_PATH` (sidecar CIDR→geo,
  longest-prefix match — lihat `.env.example`). Tanpa sumber data, field geo
  tidak ditulis dan peta tetap berfungsi dari sisi korelasi.

### API graph (read-only, izin `view`)

| Endpoint | Isi |
|----------|-----|
| `GET /api/graph/relationships` | graf entitas gabungan lintas kampanye + edge korelasi beralasan |
| `GET /api/graph/geo` | agregasi flow eksternal↔internal dari index events (guarded) + unmapped |
| `GET /api/evidence/pcap/storage` | statistik direktori capture + jendela cakupan (sumber gauge Sensors) |
| `GET /api/evidence/alerts/{id}/sessions` | resolusi sesi alert + status bukti per sesi (dok §15.2) |
| `GET /api/evidence/incidents/{id}/sessions` | resolusi sesi incident + status bukti per sesi |
| `POST /api/evidence/pcap/export` | ekspor selektif: reason + sesi → bundle zip + manifest SHA-256 (RBAC `evidence_export`) |
| `GET /api/evidence/pcap/exports` | register chain of custody + limit kebijakan |
| `GET /api/evidence/pcap/exports/{id}/download` | unduh bundle (410 bila TTL lewat) |
| `GET /api/graph/entity/{key}` | pivot entitas: relasi, kampanye, blast radius, alert, metadata sesi (ter-audit) |

## Rule Manager Suricata (Phase 6)

Tempat terpusat untuk mengelola rule Suricata — pertanyaan "di mana update rule,
di mana disable/enable rule?" kini punya jawaban UI, bukan hanya CLI:

- **Update rules** — tombol "Update rules" di view **Detect → Rule Manager**
  menjalankan `suricata-update` di dalam container API (config sensor yang sama,
  volume rules yang sama), lalu mencoba live reload lewat unix command socket
  Suricata. Jika sensor mati, perubahan tetap aman dan berlaku saat sensor
  berikutnya start. CLI lama tetap ada: `make rule-update`.
- **Enable/disable per-SID** — switch di tabel rule menulis/menghapus SID di
  `disable.conf` pada volume rules bersama (`./sensor/suricata/rules`),
  kemudian meregenerasi `suricata.rules`. Ini persis mekanisme yang didokumentasikan
  `suricata-update`, jadi state UI, CLI, dan sensor tidak mungkin berbeda.
  Rule yang dinonaktifkan tetap tampil (metadata di-cache di Postgres) lengkap
  dengan siapa yang mematikan dan kapan.
- **Konteks operasional** — hit count alert 7 hari per rule (agregasi
  `signature_id`), filter kategori/status/pencarian, chip aksi (alert/drop),
  banner "reload pending" yang jujur ketika socket tidak tersedia.
- **Keamanan** — update & toggle terbatas pada role `administrator` dan
  `security_engineer` (capability `rule_admin`), setiap perubahan tercatat di
  audit log (aksi `rules.update` / `rules.enable` / `rules.disable`).

## PCAP & Evidence Workflow (Phase 6, dok §15)

Mekanisme PCAP selektif yang dijelaskan di dokumen desain kini berjalan
end-to-end. Panel **PCAP & sessions** ada di detail setiap alert dan
incident:

- **Resolusi sesi + status bukti** — sesi (metadata Zeek/Suricata) di sekitar
  entitas alert ± buffer capture ditampilkan lebih dulu (dok §15.1 langkah
  1–3); setiap sesi membawa status `available` / `partially available` /
  `expired (retention)` / `not captured` yang diturunkan dari cakupan file
  rolling `/var/lib/ndr/pcap` — sehingga "tidak ditemukan", "sensor tidak
  merekam", dan "sudah terhapus retention" selalu bisa dibedakan (dok §15.2).
- **Ekspor selektif ber-manifest** — analis memilih sesi, mengisi **reason**
  (wajib), dan backend menegakkan batas kebijakan (maks 5 file / ~2 GB per
  ekspor), mem-bundle zip berisi PCAP + `manifest.json` (SHA-256 per file +
  hash bundle), mencatat register **chain of custody** (`pcap_exports` +
  audit), dan menghapus bundle otomatis setelah TTL (default 60 menit).
  Bila bukti tidak tersedia, ekspor tercatat `failed` dengan alasan jelas —
  sistem tidak pernah mengarang bukti.
- **Granularitas jujur** — PoC ini file-level (file rolling yang menaungi
  jendela sesi), dinyatakan eksplisit di manifest dan UI; inspeksi paket
  presisi lewat tombol **Open in Arkime viewer** (port 8005).
- **RBAC** — ekspor/unduh butuh capability `evidence_export`
  (administrator/security_engineer/soc_analyst/soc_lead); **auditor hanya
  bisa melihat** (AT-18/AT-28). Lihat OPERATIONS §14 untuk alur, endpoint,
  konfigurasi, dan AT-59..AT-65.

## Konsol UI (v0.6)

Konsol Next.js berisi 13 view visual penuh (bukan sekadar tabel):

- **Dashboard** — KPI dengan sparkline, EPS live chart (tick 2 detik), tren alert
  7 hari bertumpuk per severity, donut severity, radar deteksi per rule,
  top talkers, heatmap densitas 7×24, stream event live, gauge health, zona throughput.
- **Threat Map (v0.6)** — dua tab terhubung: **Attack Relationship Graph**
  (force-directed deterministik: kampanye, edge beralasan, pivot bukti, blast
  radius, overlay TI, attack sequence) dan **Geographic Map** (arc beranimasi
  dengan ketebalan frekuensi, matriks komunikasi, agregasi negara, panel
  "Not on the map", navigasi silang ke graf).
- **Topology** — diagram jaringan SVG (internet → sensor → switch → 5 zona),
  aliran paket beranimasi, klik host untuk drilldown (sparkline, alert, flows).
- **Incidents (baru, Phase 4)** — daftar attack story dengan KPI (open/confirmed/benign),
  filter status/severity/pencarian, badge outcome, chip fase berwarna per kill-chain,
  ring confidence; detail insiden: banner outcome proven/suspected/unknown,
  attack graph SVG interaktif, phase progression cards, timeline bukti yang bisa
  dibuka per item, tabel evidence dengan referensi indeks, generator laporan
  Markdown (copy/download), aksi triage dengan catatan wajib ter-audit.
- **Alert Center** — funnel triage, scatter timeline (bubble = risk), severity donut,
  strip MITRE ATT&CK, tabel dengan risk bar, sheet detail: skor risiko, mapping
  ATT&CK, rationale + bukti, catatan analis, aksi status.
- **Threat Intel** — siklus hidup feed (Update Now / jadwal / status
  queued→running→success/partial/failed), kartu feed dengan jumlah IOC & TTL,
  IOC store explorer (filter tipe/status/keyword, klik untuk detail + provenance),
  stream IOC match (klik untuk konteks event + JSON), tren match 24 jam,
  distribusi tipe & famili malware, dan **allowlist workflow ter-audit**
  (dok §9.2 langkah 10). Disclaimer permanen: *IOC match = contextual evidence,
  bukan bukti otomatis kompromi*.
- **Event Search** — simple + advanced DSL (dengan guard yang sama seperti API),
  facet sidebar (top values per field), histogram distribusi hasil, drawer JSON mentah.
- **Assets** — inventaris 27 host dengan skor risiko heuristik, filter zona/status,
  sparkline trafik per host, drilldown komunikasi eksternal.
- **Reports** — ringkasan mingguan: KPI, narasi eksekutif, MTTR, performa rule
  (confidence vs estimasi false-positive), aset berisiko, expose eksternal; cetak ke PDF.
- **Sensors / Users / Audit** — kartu sensor dengan sparkline & target kualitas capture,
  manajemen pengguna RBAC, log audit dengan filter & agregasi aksi.

Mode demo (`NEXT_PUBLIC_DEMO_MODE=true`) menampilkan dataset sintetis deterministik
27 host, 18 endpoint eksternal, timeline 7 hari — untuk evaluasi UI tanpa backend.
Mode live memakai endpoint API yang sama seperti sebelumnya (`/backend`).

## Arsitektur singkat

```
SPAN/TAP ──► [Zeek] [Suricata] [Arkime]        (profile: sensor, host network)
                │        │         │
                ▼        ▼         └─► PCAP storage (selektif)
         ndr-pipeline (Python: parse → normalize → validate → dedup →
                       enrich + TI match → detection → bulk)
                │                    ▲
                ▼                    │ reload IOC snapshot
         OpenSearch ←────────  intel collector (thread dalam pipeline:
         (metadata 60d,                 poll job ti_update_jobs, fetch feed,
          ioc-matches 90d, ISM)         upsert ioc_records, expire stale)
                │                    ▲
 ndr-api (FastAPI: RBAC, DSL guard,  │ queue job 'Update Now'
          audit, TI feeds CRUD) ─────┘
                │
 ndr-ui (Next.js console, 12 view)
                │
         PostgreSQL (users, audit, sensors, ti_feeds, ti_update_jobs,
                     ioc_records, ioc_allowlist, incidents,
                     incident_nodes/edges/evidence/notes/history)
```

Thread baru dalam pipeline (Phase 4): `attack-reconstruction` menerima fan-out
alert dari semua rule deteksi + event ter-match IOC + konteks DNS/SNI/fileinfo,
membangun attack story (lima lapis korelasi: entitas, temporal, perilaku, TI,
bukti), lalu menyimpan snapshot insiden ke PostgreSQL. API menyediakan
list/detail/triage/report; UI menampilkan rekonstruksi lengkap di view Incidents.

Prinsip desain diambil langsung dari dokumen: *evidence first*, *observed vs
inferred*, *no automatic overclaim*, raw evidence dipertahankan (arsip gzip +
hash), dedup ≠ agregasi, IOC match dikontekstualkan (bukan verdict).

## Threat Intelligence (Phase 3, dok §9)

- **Feed starter tanpa kredensial berbayar**: Feodo Tracker (IP C2), URLhaus
  (payload URL), ThreatFox (multi-tipe), plus adapter `file` untuk feed internal
  /fixture PoC offline. Semua fetch HTTPS terverifikasi (bisa dimatikan via env
  untuk lab), payload di-cap 25 MB, IOC dinormalisasi & divalidasi — IP privat /
  loopback ditolak agar tidak self-match.
- **Siklus hidup (dok §9.2)**: fetch → validasi skema → normalisasi → dedup
  dengan **provenance per feed dipertahankan** → simpan first/last seen,
  published, expiry, confidence → match dengan event (source/dest IP, dns.query,
  tls.sni, http.host/url, file hash) → tandai **expired** (tidak pernah dihapus);
  feed gagal **tidak mengubah IOC sama sekali**.
- **Enrichment & deteksi**: event ter-match membawa `matched_ioc` (maks 3)
  di indeks event, dicatat juga ke `ndr-ioc-matches-*` (retensi 90 hari, alias
  `ndr-ioc-matches-read` di-whitelist DSL guard), dan memicu alert `ioc_match`
  (grup per sumber+IOC per jendela; severity mengikuti confidence feed;
  rationale selalu menyatakan ini bukan bukti kompromi).
- **Update Now (dok §9.3)**: tombol UI → job `queued` di `ti_update_jobs` →
  collector pipeline klaim atomik → status success / partial_success / failed
  dengan hitungan new/changed/unchanged/expired + detail error; kredensial feed
  di-mask di semua response API dan tidak pernah di-log.
- **Allowlist ter-audit**: entri FP terverifikasi (tipe + nilai + alasan wajib)
  menyupresi match setelah reload matcher; setiap perubahan masuk audit log.

## Mulai cepat di VM

```bash
# 1. salin repo ke VM, lalu:
cd ndr-platform
cp .env.example .env
nano .env                       # wajib: CAPTURE_IFACE; opsional: NDR_DATA_ROOT

# 2. jalankan installer (butuh root, Docker sudah terpasang)
sudo ./install.sh               # base stack
sudo ./install.sh --sensor      # base + Zeek/Suricata/Arkime (SPAN siap)
```

Login pertama: `admin` + password yang dicetak installer (wajib diganti).

## Verifikasi SPAN sebelum menyalakan sensor

```bash
sudo ./scripts/sensor-precheck.sh ens160
```

## Operasional harian

```bash
make status          # ringkasan kesehatan
make logs S=ndr-pipeline
make backup
./scripts/poc/measure_eps.sh        # EPS & ukuran indeks (PoC Hari 2–3)
./scripts/poc/dsl_latency.sh admin 'password' 30   # P50/P95/P99 query
```

## Struktur repo

```
ndr-platform/
├── docker-compose.yml      semua service (profile: sensor opsional)
├── install.sh              installer satu-perintah
├── Makefile                shortcut operasional
├── sensor/                 Zeek, Suricata, Arkime (Dockerfile + config)
├── pipeline/               Python event pipeline + unit tests
├── api/                    FastAPI backend + unit tests
├── ui/                     Next.js console (standalone build)
├── opensearch/             bootstrap: template indeks + ISM retensi (60d event, 90d ioc-match)
├── postgres/init/          skema logis (users, audit, sensors, TI tables, settings)
├── scripts/                precheck, healthcheck, backup, upgrade, PoC
└── docs/                   DEPLOYMENT, OPERATIONS, SIZING, ARCHITECTURE
```

## Dokumentasi

- **[DESIGN-PLAN-v1.1](docs/DESIGN-PLAN-v1.1.md)** — dokumen desain disesuaikan dengan implementasi: status tiap keputusan (sesuai/deviasi/belum), gap tersisa, roadmap Phase 6+.
- **[DEPLOYMENT](docs/DEPLOYMENT.md)** — langkah lengkap dari VM kosong sampai operasional.
- **[OPERATIONS](docs/OPERATIONS.md)** — rutinitas harian, troubleshooting, backup/restore, pemetaan acceptance test AT-01..AT-52.
- **[SIZING-8c-24GB-3TB](docs/SIZING-8c-24GB-3TB.md)** — revisi alokasi dari baseline 16c/64GB + formula kapasitas.
- **[ARCHITECTURE](docs/ARCHITECTURE.md)** — alur data, model indeks, model keamanan.
- **[AGENTS.md](AGENTS.md)** — aturan wajib untuk AI coding agent yang bekerja di repo ini.

## Batasan implementasi ini (jujur & terukur)

- Retensi metadata **60 hari** (bukan 90) — konsekuensi storage 3 TB; naikkan
  setelah GB/day aktual terukur (lihat SIZING).
- PCAP selektif milik Arkime; bukti pre-alert **belum dijamin** — wajib uji di PoC Hari 6.
- Detection heuristik Phase 2–4 (alert grouping, portscan, NXDOMAIN burst,
  beaconing, DGA, DNS tunneling, lateral, outbound besar, file transfer,
  **ioc_match**) sengaja **explainable dan low-noise**, bukan ML;
  threshold di `.env`, tuning setelah benchmark.
- Rekonstruksi serangan memakai **network telemetry saja**: eksekusi payload,
  isi data, dan persistensi di host **tidak teramati** — daftar *unknown*
  selalu tampil di outcome insiden. Integrasi log endpoint menyusul untuk
  memperkuat validasi fase lanjutan.
- IOC match = contextual evidence. Feed starter dipilih yang legal & tanpa
  registrasi (abuse.ch CC BY 4.0); produksi bisa menambah MISP/OTX via adapter
  baru + kredensial (tersimpan aman, di-mask UI).
- UI admin user/sensor masih berbasis API; UI penuh menyusul Phase 7.
- OpenSearch security plugin dinonaktifkan **hanya di dalam jaringan internal
  compose**; akses dari luar hanya via SSH tunnel. Hardening TLS menyusul.

## Uji

```bash
cd pipeline && python -m pytest tests/     # 98 test (incl. 15 kill-chain + 22 reconstruction + 5 GeoIP)
cd api && python -m pytest tests/          # 78 test (incl. 16 evidence/PCAP + 10 rule-manager + 4 kill-chain API + 6 incidents + 7 threat-map graph)
cd ui && npm run build                     # build standalone
```
