# Revisi Sizing untuk VM 8 core / 24 GB RAM / 3 TB

Baseline dokumen desain: **16 core / 64 GB RAM / 4 TB metadata + 1 TB PCAP +
200 GB PostgreSQL**. VM yang tersedia lebih kecil, sehingga seluruh alokasi
dihitung ulang dan beberapa target disesuaikan secara eksplisit.

---

## 1. Ringkasan keputusan

| Parameter | Baseline dokumen | VM ini | Alasan |
|---|---|---|---|
| CPU | 16 core | 8 core | alokasi capture dipangkas, benchmark tetap wajib |
| RAM | 64 GB | 24 GB | heap OpenSearch 16→6 GB; sensor engine dikurangi |
| Metadata storage | 4 TB usable | **2,1 TB** | layout 3 TB total |
| PCAP | 1 TB usable | **600 GB** | selektif, rolling by free-space |
| PostgreSQL | 200 GB | 100 GB | bukan raw event |
| Backup | — | 100 GB | dump PG + snapshot OS |
| Retensi metadata | 90 hari | **60 hari** | konsekuensi storage; naikkan setelah terukur |
| Sandbox | di luar fase 1 | idem | tidak berubah |

## 2. Alokasi RAM (24 GB)

| Komponen | Limit container | Catatan |
|---|---|---|
| OpenSearch | 8 GB (heap **6g** + JVM overhead) | heap ≤ 50% RAM total aturan aman |
| Suricata | 4 GB | workers auto (≈2–3 thread pada 8 core) |
| Zeek | 3 GB | af_packet ring 256 MB masuk hitungan |
| Arkime | 2 GB | capture + viewer |
| ndr-pipeline | 1,5 GB | queue 20k event + matcher TI (~0–100 MB sesuai jumlah IOC; 100k IOC ≈ 40–60 MB) |
| ndr-api | 750 MB | 2 worker uvicorn |
| ndr-ui | 500 MB | Next.js standalone |
| PostgreSQL | 1 GB | shared_buffers 256 MB |
| **Subtotal** | **≈20,75 GB** | |
| OS + page cache + headroom | ≈3,25 GB | cache page penting utk OpenSearch |

Aturan main: **jangan** menaikkan heap melebihi 6g pada VM ini; page cache
yang tersisa justru dibutuhkan performa pencarian.

Catatan Phase 3 (Threat Intel): collector berjalan sebagai thread di dalam
ndr-pipeline — tidak ada container baru. IOC store di PostgreSQL; snapshot
matcher in-memory proporsional terhadap jumlah IOC aktif (≈0,5 KB/IOC) sehingga
100–200k IOC masih muat di limit 1,5 GB yang sama. Indeks `ndr-ioc-matches-*`
dihitung di dalam retensi metadata 60/90 hari di atas (asumsi match < 1% dari
total event).

## 3. Alokasi CPU (8 core, estimasi)

| Komponen | Core | Catatan |
|---|---|---|
| Suricata | 2–3 | workers; ring buffer per thread |
| Zeek | 1–2 | 1 worker af_packet |
| OpenSearch | 2 | indexing + search |
| Arkime | 1 | capture |
| pipeline | 1 | parsing/dedup |
| api+ui+postgres+OS | ~1 | rata |
| **Total** | ~8 | benchmark per-core wajib (PoC Hari 7) |

## 4. Storage & formula kapasitas

Formula dokumen (§5.5):

```
Estimasi retensi  = GB_per_hari_aktual × RETENTION_DAYS
Kapasitas usable  = estimasi_retensi / 0.70     (30% headroom operasi)
```

Kapasitas metadata tersedia = 2,1 TB → plafon ingest berkelanjutan:

```
2.100 GB × 0,70 ÷ 60 hari ≈ 24,5 GB/hari
```

Estimasi ilustratif dari dokumen (§5.4, Arkime-like metadata):

| Trafik rata-rata | GB/hari | 60 hari (raw) | usable ÷0,70 | Muat di 2,1 TB? |
|---|---|---|---|---|
| 50 Mbps | ~15 | 900 GB | 1,29 TB | ✅ nyaman |
| 75 Mbps | ~22,5 | 1,35 TB | 1,93 TB | ✅ hampir batas |
| 100 Mbps | ~30 | 1,8 TB | 2,57 TB | ❌ perlu 45 hari atau pengurangan field |

**Implikasi praktis**:

- Jika pengukuran Hari 2–3 menunjukkan ≤ 15 GB/hari → retensi bisa naik ke 90 hari
  (butuh 1,93 TB ≤ 2,1 TB, masih dalam batas, ketat).
- Jika 20–25 GB/hari → tetap 60 hari, siapkan rencana pruning field/leveldown.
- Jika > 25 GB/hari → turunkan retensi ke 45 hari atau kurangi tipe event yang
  diindeks (mis. `fileinfo`, `dns` response only).

Angka lain tetap seperti dokumen: PCAP 50–100 Mbps ≈ 540 GB–1,08 TB/hari jika
full capture — karena itu PCAP **selektif**; 1% dari 100 Mbps ≈ 10,8 GB/hari →
600 GB cukup ~55 hari; 5% ≈ 54 GB/hari → ~11 hari. Arkime menghapus PCAP
otomatis saat free space < `ARKIME_FREESPACE_G` (40 GB default).

## 5. Risiko & mitigasi spesifik VM kecil

| Risiko | Mitigasi |
|---|---|
| CPU capture saturasi saat puncak 1 Gbps | pantau `kernel_drops` Suricata + `rx_dropped` NIC; jika muncul: kurangi 1 thread Zeek, atau naikkan prioritas Suricata, atau akui batas ~peak 300–500 Mbps |
| Heap GC pressure OpenSearch | heap 6g + refresh 10s + 1 shard/hari; pantau `indices.merges`; jangan naikkan heap |
| Disk penuh lebih cepat dari perkiraan | watermark 85/90/95 + healthcheck harian + alert kapasitas (AT-21) |
| Backlog pipeline saat beban tinggi | queue 20k + backpressure; jika sering: kurangi tipe event di `PIPELINE_SURICATA_TYPES` |
| Semua service satu host | snapshot + backup tetap wajib; HA eksplisit di luar cakupan (dok §18.3) |

## 6. Checklist benchmark sebelum keputusan final (PoC 7 hari)

- [ ] EPS per engine stabil 24 jam (`scripts/poc/measure_eps.sh`)
- [ ] GB/day aktual per 24 jam (`scripts/poc/index_growth.sh`, cron harian)
- [ ] Packet loss 0% normal (counter NIC + `kernel_drops`)
- [ ] P95 query < 3 s saat ingestion (`scripts/poc/dsl_latency.sh`)
- [ ] Ingestion latency P95 < 10 s (`backlog_seconds` < 10)
- [ ] CPU per core tidak ada yang pinned > 90% berkelanjutan
- [ ] Heap OpenSearch < 75% steady-state
- [ ] Proyeksi 60 hari ≤ 2,1 TB × 0,70

Hasil pengukuran → putuskan retensi final dan apakah baseline hardware
perlu naik (dok §22 butir 19).

## 7. SINK BULK SIZING (v0.15.0, action report A3)

Ukuran batch bulk pipeline (`PIPELINE_BULK_MAX_ITEMS`) sangat memengaruhi
jumlah segmen kecil Lucene + overhead HTTP. Data yang sudah terukur live
(VM referensi 10.0.106.232, single-node, 1 shard/indeks):

| Konfigurasi | Hasil terukur | Kesimpulan |
|---|---|---|
| batch kecil (~20 item/flush) | jam sibuk: bulk > 30 dtk → timeout → retry amplifier → **wedge Lucene DWPT** (insiden 10.15/10.18/10.19, sink lama) | JANGAN dipakai di produksi |
| `PIPELINE_BULK_MAX_ITEMS=200` | **302 EPS stabil, antrean ≤ 30, 0 timeout** (sink anti-wedge v0.15.0) | **default yang direkomendasikan** |
| default kode 500 | aman di hardware sehat; di atas 250 EPS per shard, pantau `sink_pending` | untuk kapasitas lebih besar |

- Timeout **tidak pernah** di-retry sejak 0.15.0 (anti-wedge A2); 429/5xx/network
  di-retry ≤ `PIPELINE_BULK_MAX_RETRIES` lalu dead-letter.
- Benchmark sendiri 3 konfigurasi (10/20/200) dengan:
  `sudo CONFIGS=10,20,200 DURATION=300 bash scripts/poc/sink_benchmark.sh`
  (mengganti sementara `PIPELINE_BULK_MAX_ITEMS` di .env, merekam eps/pending/
  retries/deadletter, lalu mengembalikan nilai awal). Kriteria lulus: eps ≥ 150
  tanpa deadletter `sink_timeout` berturut-turut > 30 dtk.
