# Load Testing (v0.12)

Dokumen ini mendokumentasikan metodologi, alat, dan hasil pengujian
beban API NDR Platform. Alat pengujian dikirim sebagai bagian dari
repo sehingga tim dapat mengulang pengukuran yang sama pada VM
produksi kapan saja.

## 1. Perangkat

| Komponen | Lokasi | Fungsi |
|---|---|---|
| `scripts/loadtest/target_app.py` | target uji | Aplikasi API asli (`app.main:app`) + SQLite seeded (60 insiden, 5 campaign, admin) + OpenSearch sintetis in-memory (120 event) |
| `scripts/loadtest/load_api.py` | generator | Async HTTP generator (httpx): login sekali, lalu N VU mengirim trafik campuran konsol SOC |
| `scripts/loadtest/run.sh` | orkestrator | Nyalakan target, tunggu health, jalankan beban, simpan `result.json`, matikan target |

Trafik campuran (bobot): incidents list 20%, events search 20%,
incidents summary 15%, alerts search 15%, campaigns list 10%,
campaign detail 10%, graph relationships 5%, stats overview 5%.
Setiap VU memberi jeda berpikir 10-60 ms agar pola menyerupai analisis
yang menelusuri halaman konsol.

## 2. Lingkungan pengukuran

Pengukuran dilakukan pada sandbox CI (2 vCPU / 3 GB RAM), BUKAN pada
VM produksi 8 core / 24 GB. Catatan jujur:

- OpenSearch diganti fake in-memory -> angka merepresentasikan lapisan
  API (guard, handler, serialisasi, ORM) saja; latensi kueri nyata di
  OpenSearch harus diukur terpisah di VM produksi (lihat bagian 5).
- Rate limit search produksi (30 permintaan/menit/pengguna, doc 4.5)
  diangkat pada target via `SEARCH_RATE_LIMIT=1000000` agar generator
  dapat menguji jalur pencarian itu sendiri. Jangan mengubah ini di
  produksi.
- SQLite menggantikan PostgreSQL -> jalur DB sedikit lebih murah dari
  produksi; untuk angka produksi, jalankan ulang dengan target asli.

## 3. Hasil (sandbox 2 vCPU)

### 10 VUs x 20 detik (profil konsol ringan)

| Metrik | Nilai |
|---|---|
| Throughput | **131.4 req/s** |
| Error | **0%** (0 / 2.638) |
| Latensi p50 / p95 / p99 | **28.8 / 102.9 / 283.8 ms** |
| p95 terburuk per skenario | graph_relationships 361.7 ms |

### 25 VUs x 30 detik (beban tinggi)

| Metrik | Nilai |
|---|---|
| Throughput | **116.3 req/s** |
| Error | **0%** (0 / ~3.5k) |
| Latensi p50 / p95 / p99 | **149.8 / 359.1 / 663.8 ms** |
| p50 terburuk per skenario | graph_relationships ~570 ms (normal: agregasi graf dari seluruh insiden) |

Interpretasi:

- Titik jenuh lapisan API di sandbox berada di sekitar 115-130 req/s
  dengan latensi p95 < 400 ms - jauh di atas kebutuhan satu konsol SOC
  (puluhan analisis paralel menghasilkan puluhan req/s, bukan ratusan).
- Skenario paling mahal adalah `graph_relationships` (membangun graf
  hubungan dari data insiden) dan `events_search` (guard + serialisasi
  50 hit). Keduanya tetap < 900 ms p99 pada 25 VU.
- Tidak ada error 5xx; tidak ada kebocoran koneksi selama uji.

## 4. Cara mengulang di VM produksi

```bash
cd /opt/ndr-platform
./scripts/loadtest/run.sh 25 60 8010        # 25 VU x 60s
# hasil: scripts/loadtest/result.json + last_run.txt
```

Untuk mengukur TUMPUKAN penuh (API + OpenSearch + PostgreSQL asli):

```bash
# 1. API produksi jalan di API_PORT (default 8080, localhost only)
# 2. jalankan generator langsung ke API asli:
python scripts/loadtest/load_api.py \
  --base-url http://127.0.0.1:8080 \
  --vus 25 --duration 60 \
  --username admin --password '<password-admin-asli>'
```

Catatan: pada stack asli JANGAN mengangkat rate limit; jika generator
terkena 429, kecilkan bobot search atau turunkan VU - itu justru
membuktikan guard bekerja di bawah beban.

## 5. Kriteria sehat (rujukan tim)

| Indikator | Ambang | Tindakan bila terlampaui |
|---|---|---|
| Error rate | < 1% | periksa log API + health OpenSearch |
| p95 all-scenario | < 500 ms (25 VU) | selidiki skenario terlambat; cek CPU VM |
| Throughput 25 VU | > 100 req/s | scale: VM produksi 8 core diramal 3-5x sandbox |
| 429 pada search | sesuai guard | perilaku benar (doc 4.5), bukan bug |

Hasil JSON mentah tiap sesi disimpan `scripts/loadtest/result.json`
(terakhir) dan dapat diarsipkan per rilis untuk perbandingan tren.
