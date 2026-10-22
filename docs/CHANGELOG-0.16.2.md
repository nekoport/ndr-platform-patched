# CHANGELOG — NDR Platform 0.16.2

**Tanggal:** 22 Oktober 2026
**Dasar:** `LAPORAN-VERIFIKASI-0.16.1.md` (17 temuan 0.16.0: 14 PASS / 2 PARTIAL / 1 BELUM, plus 7 temuan baru BUG-0161-01..07)
**Cakupan:** perbaikan seluruh temuan baru hasil verifikasi 0.16.1. Tidak ada perubahan skema index; tidak ada detector baru; seluruh perubahan mempunyai kill switch / perilaku fail-soft.

---

## Ringkasan

| ID | Prioritas | Ringkasan | Status |
|---|---|---|---|
| BUG-0161-01 | P1 | Agregasi `engines` tidak di-nest → KPI "Events (24h)" & "Events processed" = 0 | ✅ diperbaiki (API + UI) |
| BUG-0161-02 | P1 | Reports selalu 0 (alerts/MTTR tidak pernah dipetakan) | ✅ diperbaiki (API + UI) |
| BUG-0161-03 | P2 | `upgrade.sh` tidak membangun profil sensor | ✅ diperbaiki |
| BUG-0161-04 | P2 | Deadletter `sink_timeout` tanpa retry + backlog restart saturasi OpenSearch | ✅ diperbaiki (replay + breaker + pacing) |
| BUG-0161-05 | P2 | `guarded_aggregate` hasil parsial bisu; `source_engine` text di index lama | ✅ diperbaiki |
| BUG-0161-06 | P3 | JWT_SECRET default < 32 byte → 401 acak antar-worker | ✅ diperbaiki (persisten + rotasi otomatis) |
| BUG-0161-07 | P3 | Branding "Ever SEEN" vs "NDR Console" | ✅ diperbaiki |

---

## 1. BUG-0161-01 (P1) — Timeline `engines` kini nested di `by_ts`

**Sebelum:** `api/app/routers/events.py` menaruh sub-agregasi `engines` SEJAJAR dengan `by_ts` di level atas, tetapi membaca `b.get("engines")` per bucket `by_ts` → selalu kosong → KPI Dashboard "Events (24h)" = 0 dan Reports "Events processed" = 0 meski total 10 juta+ event terbaca (`total` benar, per-engine kosong).

**Sesudah:**
- Pencarian utama menghitung `by_ts` (count per interval) pada level alias — **eksak** untuk semua index, tanpa agregasi yang bisa gagal.
- Split engine dihitung dengan sub-agregasi `engines` yang **benar-benar nested** di dalam `by_ts["aggs"]`, dijalankan **per kelompok index** (lihat §5) lalu digabung per bucket.
- Respons baru: `warnings: [...]` — index yang tidak bisa ikut split engine dilaporkan transparan (tidak pernah silent partial).
- UI: `TimelinePoint.count` (total eksak per bucket) ikut dipetakan; KPI "Events (24h)" dan sparkline memakai `count` dengan fallback `zeek+suricata`; timeline kini diambil 48 jam sehingga delta "vs prev 24h" benar-benar berfungsi.

## 2. BUG-0161-02 (P1) — Reports memakai angka nyata dari stats

**Sebelum:** `reports.tsx` menjumlah `timeline.alerts_*` (hardcode 0 di `api.ts`, tidak pernah dikirim API) dan `timeline.zeek+suricata` (24 jam + engines kosong) → SEMUA kartu Reports 0 meski `/api/stats/overview` membalas `alerts_7d 8.297`, `events_7d 36.5jt`.

**Sesudah:**
- Backend: `alert_daily_7d` kini memuat **split severity per hari** (sub-agg `terms severity`: `critical/high/medium/low`).
- UI: KPI Reports memakai `stats.alerts_7d`, `stats.events_7d`, `stats.mttr_hours_avg` (rata-rata tertimbang backend), `stats.closed_7d` — semuanya dengan fallback ke perhitungan lama bila field tak tersedia.
- Chart "Detection volume - 7 days" kini menggambar `rich.alert_daily` (alert harian 7d + severity nyata), bukan lagi timeline event 24 jam; formatter sumbu mendukung bucket harian.
- Mode demo ikut konsisten (`demoAlertDaily`).

## 3. BUG-0161-03 (P2) — `upgrade.sh` membangun profil sensor

- `docker compose build` diganti `docker compose --profile sensor build` (fallback build dasar bila profil tidak tersedia) — image zeek/suricata/arkime kini ikut diperbarui sebelum `--force-recreate`, menutup celah "container baru, image lama" (P2-5 verifikasi).
- Komentar checkpoint di script dikoreksi: file log BERBEDA inode dibaca dari **awal** (offset 0), bukan dari EOF seperti klaim lama; file SAMA yang tumbuh selama downtime dimainkan ulang dari checkpoint (desain no-loss) — banjir indexing kini diredam §4.

## 4. BUG-0161-04 (P2) — Retry deadletter + backpressure backlog

Tiga lapis, semuanya dengan kill switch:

1. **Sink breaker anti-saturasi** (`pipeline/app/sink/opensearch.py`): setelah `ConnectionTimeout`, sink tidur eksponensial (2 s → maks `PIPELINE_SINK_COOLDOWN_MAX_SECONDS`, default 60) dan memperkecil batch efektif (×½, batas bawah `PIPELINE_SINK_BATCH_MIN_ITEMS`); bulk sukses → cooldown meluruh ½ dan batch pulih ×1.5. Batch dipecah jadi chunk — **tidak ada item yang hilang** saat breaker trip (sisa masuk deadletter replayable). Gauge baru: `sink_cooldown_s`, `sink_batch_size`.
2. **DeadLetterReplayer** (`pipeline/app/sink/replay.py`, thread baru): secara berkala (`PIPELINE_DLQ_REPLAY_INTERVAL_SECONDS`, default 300 s) memutar ulang record `sink_timeout`/`sink_failure` ke sink queue. Aman karena: hanya reason replayable; record kini menyimpan `index` tujuan; `_id` deterministik → overwrite idempoten (nol duplikat); backoff umur (≥ 1 interval); batas `MAX_PER_CYCLE`/`MAX_ATTEMPTS`; state retry persisten (`state/deadletter_replay_state.json`); kill switch `PIPELINE_DLQ_REPLAY=0`. Record lama pra-0.16.2 tanpa field `index` dihitung `dlq_skipped` (tidak bisa direplay aman). Gauge: `dlq_replayed`, `dlq_skipped`.
3. **Catch-up pacing** (`pipeline/app/main.py`): saat backlog tailer melewati `PIPELINE_CATCHUP_PACE_THRESHOLD_SECONDS` (default 300 s — kasus backlog 297 MB pasca-restart), processor tidur `PIPELINE_CATCHUP_PACE_SLEEP_MS` (default 100) tiap `PIPELINE_CATCHUP_PACE_BATCH` (default 250) event → OpenSearch tidak dibanjiri sekaligus. Gauge `catchup_pacing`; log eksplisit saat aktif/selesai.

## 5. BUG-0161-05 (P2) — Tidak ada lagi hasil parsial bisu

- `guarded_aggregate()` kini memeriksa `_shards.failed`:
  - default (**strict**): hasil parsial DITOLAK dengan `DSLValidationError` (HTTP 400 bermakna, bukan angka kurang-hitung yang terlihat normal);
  - `allow_partial=True`: hasil diterima tetapi di-log WARNING + diberi kunci `_ndr_partial_shards`.
- Helper baru `keyword_aggregation_groups(alias, field)` memakai `field_caps` untuk mengelompokkan index konkret: yang memetakan field sebagai `keyword` diagregasi langsung; index lama dinamis ber-mapping `text` diagregasi lewat sub-field `source_engine.keyword`; index tanpa varian agregasi-able dilaporkan sebagai `excluded`. Seluruh index konkret diverifikasi anggota alias whitelist (`resolve_alias_indices`) — tidak ada index di luar whitelist yang bisa diselundupkan (param `concrete` di `guarded_aggregate`).
- Endpoint timeline memakai mekanisme ini sehingga 6 index lama 2026.10.14 (mapping text) tidak lagi menggagalkan shard; split engine tetap lengkap, count utama tetap eksak.

## 6. BUG-0161-06 (P3) — JWT secret persisten + rotasi otomatis

- API (`_harden_jwt_secret`): bila `JWT_SECRET` tidak diset/terlalu pendek, secret kini **digenerate sekali dan ditulis ke file** `JWT_SECRET_FILE` (default `/var/lib/ndr-api/jwt-secret.key`, mode 0600, volume baru `api-state`) sehingga **semua worker memakai secret yang sama** dan sesi bertahan lintas restart — akar dari 401 "Invalid session" acak di 0.16.1. Fallback ephemeral hanya bila disk tidak writable (di-log ERROR).
- `upgrade.sh`: `.env` dengan `JWT_SECRET` lemah/placeholder dirotasi otomatis (`openssl rand -hex 32`) dengan backup `.env.bak-jwt-*`.
- Compose: volume bernama baru `api-state` di-mount ke `/var/lib/ndr-api` pada `ndr-api`.

## 7. BUG-0161-07 (P3) — Konsistensi branding

- Nama legacy tersimpan di DB (`system_settings.system.name = "Ever SEEN"`) dinormalkan sekali di startup API ke **"NDR Console"** (idempoten; nama kustom yang diset operator setelahnya dihormati penuh). Halaman login, sidebar, dan judul tab kini konsisten.

---

## Test & verifikasi

- **Pipeline: 204 test PASS** (termasuk 7 test baru `test_v0162_replay.py`: record index, replay replayer + backoff + attempt cap + kill switch, breaker cooldown tanpa data loss, pemulihan).
- **API: 267 test PASS** (termasuk 11 test baru `test_v0162_fixes.py`: guard shard parsial, keanggotaan index konkret, grup agregasi keyword legacy, split severity `alert_daily_7d`, JWT persisten, normalisasi branding, kontrak timeline baru).
- **UI: `tsc --noEmit` lulus tanpa error.**

## Kompatibilitas

- Tanpa migrasi skema DB/index; alias, template, dan API contract lama tetap berlaku.
- `GET /api/events/timeline` menambah field opsional (`warnings`, `count` per point) — backward compatible.
- Volume baru `api-state` dibuat otomatis oleh `docker compose up`.
- Setelah upgrade, 4.807 record `sink_timeout` 0.16.1 yang lama (tanpa field `index`) tidak bisa direplay otomatis — disimpan sebagai bukti di deadletter sesuai retensi 72 jam; event mentah tetap tersedia di raw archive.
