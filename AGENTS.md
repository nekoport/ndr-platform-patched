# AGENTS.md — Aturan untuk AI Coding Agent (NDR Platform)

Aturan ini ditetapkan dalam diskusi desain (ChatGPT, sesi "Diskusi Desain NDR
Zeek Suricata") dan **disesuaikan dengan stack yang benar-benar dipakai** di
ndr-platform v0.7.0. Setiap AI coding agent yang bekerja di repository ini
wajib mematuhi aturan berikut.

## Stack aktual (yang boleh dipakai)

| Area | Teknologi |
|------|-----------|
| Backend REST API | Python 3.12 + FastAPI (`api/`) |
| Detection & correlation engine | Python threading, bounded queue + backpressure (`pipeline/`) |
| Frontend SOC | Next.js 16 + TypeScript + Tailwind CSS + shadcn/ui + ECharts (`ui/`) |
| Data operasional | PostgreSQL (skema `postgres/init/001_schema.sql`) |
| Pencarian event | OpenSearch (`opensearch/`) |
| Network security engines | Zeek + Suricata + Arkime (`sensor/`, profile sensor) |
| Deployment | Docker Compose (`docker-compose.yml`) |
| Testing | pytest (pipeline + api), build/tsc untuk UI |

**Catatan deviasi yang sudah disepakati terhadap desain awal:** pipeline
memakai thread (bukan Celery + Redis) untuk MVP satu-node; frontend memakai
Next.js (bukan Vite + React); graf relasi memakai SVG/ECharts (bukan
Cytoscape.js); peta memakai SVG + GeoIP opsional (bukan Leaflet). Jangan
menambahkan framework/bahasa baru tanpa alasan teknis terdokumentasi.

## 1. Aturan wajib

1. **Jangan membuat microservice baru atau menambah bahasa pemrograman baru**
   tanpa alasan teknis yang terdokumentasi (ADR di `docs/`).
2. **Jangan mengakses database secara langsung dari frontend.** Frontend hanya
   boleh memanggil API backend (`ui/lib/ndr/api.ts`).
3. **Setiap perubahan skema PostgreSQL** harus mengikuti pola yang ada:
   `postgres/init/001_schema.sql` diperbarui untuk deploy baru, plus migrasi
   idempoten terjaga (inspector-guarded `ALTER TABLE ... ADD COLUMN` — cek
   kolom via `sqlalchemy.inspect` dulu, jangan exception-driven, agar log
   Postgres tidak dibanjiri `column already exists` tiap boot) di
   `pipeline/app/correlation/store.py` dan `api/app/main.py`.
4. **Setiap endpoint wajib memiliki**: validasi input (Pydantic), otorisasi
   (`require_permission`), penanganan error, dan pengujian (`api/tests/`).
5. **Setiap correlation/detection rule harus menyimpan alasan, bukti,
   confidence, dan versi/kategori rule** — tidak ada penilaian tanpa
   provenance. Lihat pola `rules.py` (rationale/reasons/evidence) dan
   `killchain.py` (reason + confidence per klasifikasi).
6. **Jangan menyatakan serangan berhasil hanya berdasarkan signature IDS atau
   IOC match.** Gunakan outcome labels (`attempted`, `suspected_success`,
   `strong_success`, `indeterminate`) dan status tahap
   (observed/suspected/not_observed/insufficient_telemetry) sesuai bukti.
7. **Jangan menjalankan query OpenSearch tanpa batas**: wajib ada time range,
   batas size, whitelist index/alias, tanpa script/regexp — semua lewat DSL
   guard (`api/app/os_client.py`, diuji di `test_dsl_guard.py`).
8. **Jangan menyimpan PCAP besar di PostgreSQL atau OpenSearch.** Bukti mentah
   masuk arsip gzip + sha256 (`pipeline/app/sink/raw_archive.py`); ekspor
   PCAP selektif tetap tugas Arkime.
9. **Jangan mengubah konfigurasi produksi atau menjalankan destructive
   operation** (hapus indeks, truncate tabel, restart sensor produksi) tanpa
   persetujuan eksplisit pengguna.
10. **Setiap fitur harus memiliki acceptance criteria dan regression tests.**
    Acceptance test operasional dicatat di `docs/OPERATIONS.md`
    (AT-01..AT-52); regresi otomatis wajib lulus sebelum commit:
    `cd pipeline && python -m pytest tests/ && cd ../api && python -m pytest tests/`
    dan `cd ui && npx tsc --noEmit`.
11. **Hati-hati kelas bug SQLite-vs-Postgres** (validasi live 0.12.5):
    kolom JSONB dapat kembali sebagai dict/list dari psycopg — jangan
    `json.loads()` langsung, pakai helper `_jload` (recon & TI); kolom
    BOOLEAN menolak INTEGER 1/0 di raw SQL — tulis `bool(...)`; `WHERE
    boolean=1` error di Postgres — pakai `WHERE boolean`; stringifikasi
    payload non-JSON (`json.dumps(..., default=str)`) untuk payload
    dinamis.
12. **Satu jam, satu satuan**: jangan campur `time.monotonic()` dengan
    `time.time()` dalam perbandingan yang sama (sweep deteksi tidak
    pernah jalan gara-gara ini). Rule: event/epoch cutoff = `time.time()`;
    monotonic hanya untuk durasi internal proses.
13. **Pin image upstream untuk reproducibility**: `:lts` bisa berpindah
    versi besar (Zeek 7/8→9 merusak deploy sekali). Gunakan ARG build
    (`ZEEK_IMAGE`, `ARKIME_DEB`, `SURICATA_IMAGE`) + dokumentasikan
    override di `.env.example`; sebelum bump versi upstream, cek
    kompatibilitas entrypoint/config.

## 2. Konvensi tambahan

- **Bahasa**: kode & komentar Inggris; dokumentasi `docs/` dan README Bahasa
  Indonesia; teks UI Inggris.
- **Kompatibilitas mundur**: jangan menghapus/mengubah nama field publik API
  yang sudah dipakai UI tanpa alasan dan pembaruan UI yang menyertai.
- **No-overclaim**: setiap tampilan yang memuat penilaian otomatis wajib
  membawa disclaimer (buta jaringan, confidence tidak terkalibrasi, GeoIP =
  perkiraan).
- **Kegagalan terisolasi**: komponen downstream (rekonstruksi, sink, GeoIP)
  tidak boleh memblokir ingest; ikuti pola bounded-queue + drop-oldest yang
  sudah ada.
