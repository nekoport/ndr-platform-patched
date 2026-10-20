# Panduan Operasional — NDR Fondasi (Phase 0–2)

Dokumen ini adalah runbook harian: apa yang diperiksa, arti tiap sinyal,
cara menangani insiden operasional, dan cara membuktikan acceptance test
fase ini.

---

## 1. Rutinitas harian (15 menit)

1. **`./scripts/healthcheck.sh`** — satu perintah untuk: container, cluster
   OpenSearch, pipeline (EPS, backlog, queue), disk, error log 5 menit
   terakhir.
2. Buka **Overview** di console: status `healthy`, EPS stabil, disk < 80%.
3. Buka **Alert Center**: triage alert `new` (set minimal `acknowledged`).
4. Cek **Audit Log** untuk login gagal/aktivitas tak dikenal.
5. Jika sensor aktif: `docker exec ndr-zeek zeekctl status`,
   counter `rx_dropped` pada capture interface.

## 2. Arti sinyal kesehatan

| Sinyal | Ambang | Arti | Tindakan |
|---|---|---|---|
| Cluster status | `yellow` | replica tak bisa ditempatkan (normal single-node utk beberapa indeks) | aman bila stabil |
| Cluster status | `red` | shard primary bermasalah | `curl _cat/shards?v` cari UNASSIGNED; cek disk |
| `backlog_seconds` | > 300 | pipeline tertinggal dari realtime | cek CPU/disk I/O, EPS; lihat §4 |
| `queue_depth` | mendekati kapasitas | OpenSearch lambat diterima | cek heap/GC OS; cek indexing latency |
| `parse_errors` | naik terus | format event tak dikenal | inspeksi deadletter; update normalizer |
| Disk | ≥ 80% | peringatan | evaluasi retensi; jalankan backup; cek indeks terbesar |
| Disk | ≥ 90% | kritis; OS akan block write di 95% (flood_stage) | turunkan retensi ISM sementara, hapus indeks lama |
| NTP | unsynced | timestamp event tidak bisa dipercaya | `timedatectl set-ntp true`; periksa firewall NTP |

## 3. Retensi & ISM

- Policy `ndr-retention`: delete indeks `ndr-*` berumur > `RETENTION_DAYS`
  (default 60). Health docs: 14 hari (`ndr-health-retention`).
- Lihat daftar & umur indeks: `curl -s 'http://127.0.0.1:9200/_cat/indices/ndr-*?v'`
- ISM Explain satu indeks:
  `curl -s 'http://127.0.0.1:9200/_plugins/_ism/explain/ndr-zeek-conn-2026.10.12'`
- Mengubah retensi: ubah `RETENTION_DAYS` di `.env` → update policy manual:

  ```bash
  # contoh 60 -> 45 hari
  curl -X PUT http://127.0.0.1:9200/_plugins/_ism/policies/ndr-retention \
    -H 'Content-Type: application/json' -d @- <<'JSON'
  {"policy":{"description":"NDR retention 45d","default_state":"hot",
   "states":[{"name":"hot","actions":[],"transitions":[{"state_name":"delete",
   "conditions":{"min_index_age":"45d"}}]},
   {"name":"delete","actions":[{"delete":{}}],"transitions":[]}],"ism_template":[]}}
  JSON
  ```

## 4. Pipeline: diagnosis cepat

```bash
# metrik live tanpa auth (localhost saja)
curl -s http://127.0.0.1:9100/metrics | python3 -m json.tool

# log pipeline
docker logs -f --tail 200 ndr-pipeline

# dead-letter (event yang ditolak, dengan alasan)
docker exec ndr-pipeline sh -c 'ls -la /data/state/deadletter/ | tail'
docker exec ndr-pipeline sh -c 'zcat /data/state/deadletter/deadletter-*.jsonl.gz | tail -5'

# checkpoint posisi baca file
docker exec ndr-pipeline cat /data/state/checkpoints.json | head -c 400; echo
```

Pipeline **tidak pernah membuang event diam-diam**: malformed → deadletter,
backpressure → queue penuh → tailer menahan baca (ring buffer NIC menyerap).
Jika backlog terus tumbuh: biasanya OpenSearch lambat (heap/GC) atau disk I/O.

## 5. Sensor: diagnosis cepat

```bash
# zeek
docker exec ndr-zeek zeekctl status
docker exec ndr-zeek ls -la /usr/local/zeek/logs/current

# suricata
docker logs --tail 50 ndr-suricata
docker exec ndr-suricata suricatasc -c status
docker exec ndr-suricata suricatasc -c "dump-counters" | head

# arkime
docker logs --tail 50 ndr-arkime
curl -s "http://127.0.0.1:9200/_cat/indices/arkime_sessions3-*?v" | tail -3
```

Packet drop pada Suricata muncul di EVE `stats` (field `kernel_drops`) —
dikirim tiap 60 detik. Naikkan `ring-size`/threads bila perlu (RAM ada
batasnya; lihat SIZING).

### 5.1 Drop level NIC (rx_dropped) — batas wajar & tuning

Cek level interface host:

```bash
ip -s link show "$CAPTURE_IFACE"     # lihat rx_dropped vs rx_packets
```

Panduan toleransi untuk SPAN:

| rasio rx_dropped/rx_packets | Arti | Tindakan |
|---|---|---|
| < 0,5 % | normal (burst awal, ring belum tumbuh) | tidak perlu apa-apa, pantau saja |
| 0,5 – 1 % | mulai tinggi | tuning di bawah; pantau 24 jam |
| > 1 % | paket analitik hilang | wajib tuning + cek CPU/SPAN util |

Tuning bila melewati batas:

```bash
# offload harus OFF di port SPAN (entrypoint sensor sudah mencoba;
# verifikasi di host agar tidak tergantung container)
sudo ethtool -K "$CAPTURE_IFACE" gro off lro off tso off gso off 2>/dev/null

# perbesar ring buffer (jika driver mendukung; virtio biasanya tidak)
sudo ethtool -G "$CAPTURE_IFACE" rx 4096 2>/dev/null || echo "driver tak mendukung - aman diabaikan"

# backlog kernel
sudo sysctl -w net.core.netdev_max_backlog=5000
echo 'net.core.netdev_max_backlog=5000' | sudo tee /etc/sysctl.d/90-ndr-capture.conf
```

Catatan `promisc`: precheck menampilkan `promiscuous OFF` bila dijalankan
**sebelum** sensor naik — itu wajar. Entry-point `ndr-suricata` dan
`ndr-arkime` men-set `ip link set <iface> promisc on` saat start. Untuk
menjamin mode permanen (meski sensor mati), jalankan:

```bash
sudo ip link set "$CAPTURE_IFACE" promisc on
# persisten:
printf 'ACTION=="add", SUBSYSTEM=="net", KERNEL=="%s", RUN+="/usr/sbin/ip link set %%k promisc on"\n' "$CAPTURE_IFACE" | \
  sudo tee /etc/udev/rules.d/90-ndr-promisc.rules
```

## 6. Backup & restore

**Backup** (`./scripts/backup.sh`): dump PostgreSQL + tar konfigurasi +
snapshot OpenSearch ke `$NDR_DATA_ROOT/backup/<stamp>/`. Retensi lokal 14
titik. Jadwalkan harian:

```bash
sudo crontab -e
0 2 * * * /opt/ndr/scripts/backup.sh >> /var/log/ndr-backup.log 2>&1
```

**Restore PostgreSQL**:

```bash
gunzip -c backup/<stamp>/postgres-ndr.sql.gz | \
  docker exec -i ndr-postgres psql -U ndr -d ndr
```

**Restore OpenSearch snapshot**: daftar snapshot
`curl http://127.0.0.1:9200/_snapshot/ndr-backups/_all?pretty`, lalu restore
indeks tertentu (`indices: "ndr-alerts-*"`), bukan seluruh cluster.

**Uji restore** wajib dilakukan sekali setelah install (AT-22) dan sebelum
dinyatakan siap operasional.

## 7. Threat Intelligence (Phase 3)

### Rutinitas TI (harian/mingguan)

- Cek kartu **Threat Intel → Threat feeds**: semua feed enabled harus
  `success`/`partial_success`. Feed `failed` > 24 jam: buka job terakhir
  (tab *Update jobs*) — baca kolom Detail (HTTP status / DNS error), cek
  konektivitas VM ke feed, lalu tekan **Update now**.
- `partial_success` berarti ada baris yang dilewati (nilai tidak valid / IP
  privat). Normal untuk feed publik besar; periksa angka `warnings`.
- Pantau **Expiring 3d**: jika muncul terus, feed terkait terlalu jarang
  update — turunkan `schedule_min` atau perpanjang TTL feed (PATCH via API).
- Tinjau **Matches** tab setiap pagi: setiap match adalah *konteks*, bukan
  verdict. Konfirmasi dengan user/aset sebelum eskalasi.

### Allowlist (FP workflow, dok §9.2 langkah 10)

1. Klik match/IOC yang terverifikasi FP → catat tipe + nilai + alasan
   (wajib, contoh: "Business partner SMTP relay - FP confirmed, tiket T-42").
2. Tab *Allowlist* → **Add allowlist entry** → isi → simpan.
3. Matcher me-reload otomatis ≤ 60 s (atau langsung setelah job TI berikutnya);
   match baru untuk nilai tersebut berhenti muncul.
4. Menghapus entri: ikon X. Semua perubahan tercatat di Audit Log
   (`ti.allowlist.add` / `ti.allowlist.remove`).

### Menambah feed baru

```bash
curl -sS -X POST https://<host>/backend/api/ti/feeds \
  -H 'Content-Type: application/json' --cookie 'ndr_session=<...>' -d '{
    "name": "my-misp", "adapter": "urlhaus",        # pilih adapter yang cocok
    "url": "https://misp.example.org/feed.csv",
    "enabled": true, "schedule_min": 120, "ttl_days": 14,
    "config": {"api_key": "SECRET"}                  # di-mask di semua response
  }'
```

- Kredensial tidak pernah tampil kembali di UI/log; PATCH dengan nilai
  `*****` tidak akan menimpa rahasia tersimpan.
- Adaptor tersedia: `urlhaus` (CSV #komentar), `threatfox` (JSON API POST),
  `feodo` (JSON array IP), `file` (JSONL lokal untuk fixture/PoC offline —
  contoh format di `pipeline/tests/samples/ti_fixture.jsonl`).
- Feed mati TIDAK menghapus IOC: IOC hanya berubah status `expired` setelah
  `expires_at` lewat (ditandai, tetap bisa ditelusuri).

### Troubleshooting TI

| Gejala | Sebab umum | Aksi |
|---|---|---|
| `TI disabled` di log pipeline | `DATABASE_URL` tidak terpasang / postgres down | cek compose env + `make status` |
| Job stuck `queued` | pipeline mati | nyalakan pipeline; job diproses ulang otomatis |
| Match tidak muncul padahal IOC ada | matcher belum reload | tunggu ≤60 s atau trigger Update feed |
| Feed gagal DNS/timeout | egress VM diblok | buka firewall / proxy; feed tidak merusak data lama |

## 8. Acceptance test tambahan Phase 3

| ID | Skenario | Langkah | Hasil yang diharapkan |
|---|---|---|---|
| AT-27 | Update Now | klik Update now pada feed enabled | job queued→running→success; hitungan new/changed tampil |
| AT-28 | Feed gagal | matikan egress, Update now | status failed + error jelas; IOC lama tetap aktif (dok §9.3) |
| AT-29 | IOC match | replay trafik ke IP di feed fixture | event memuat matched_ioc; alert ioc_match dengan rationale disclaimer |
| AT-30 | Allowlist audit | tambah + hapus entri FP | 2 audit record baru; match ter-supresi setelah reload |
| AT-31 | Masking kredensial | GET /api/ti/feeds | `config.api_key` = `*****`, bukan nilai asli |
| AT-32 | RBAC TI | login analyst, POST feed | 403 dari backend |

## 8b. Attack Reconstruction (Phase 4) — operasional

### Variabel tuning (.env)

| Variabel | Default | Arti |
|----------|---------|------|
| `RECON_ENABLED` | true | matikan untuk menghentikan engine tanpa mengubah deteksi |
| `RECON_MAX_GAP_SECONDS` | 7200 | jeda maksimum antar sinyal untuk tetap dianggap satu insiden |
| `RECON_LOOKBACK_HOURS` | 24 | berapa lama story tetap bisa menerima bukti terlambat |
| `RECON_MAX_ACTIVE_STORIES` | 500 | batas story aktif di memori (tertua di-close duluan) |
| `DETECT_EXFIL_MIN_BYTES` | 100000000 | ambang transfer keluar (rule impact) |
| `DETECT_LATERAL_*` | 445 dst. | port/koneksi untuk rule lateral movement |

### Rutinitas

- **Cek kesehatan**: `curl -s localhost:9100/metrics | grep recon_` —
  `recon_open_stories`, `recon_signals`, `recon_merges`, `recon_errors`.
  `recon_errors` naik terus = periksa koneksi PostgreSQL dari pipeline.
- **Triage insiden**: buka view *Incidents* → pilih story → baca banner
  outcome (proven/suspected/unknown) → Confirm/Benign/Close **dengan catatan**
  → status + catatan masuk incident history & audit log.
- **Laporan**: tab *Report* → Generate → Copy/Download `.md` untuk tiket/CMDB.
- **False positive berulang**: catat di notes, lalu turunkan noise lewat
  threshold rule penyumbang (lihat `top_rules` pada alert penyusun story) —
  jangan matikan rule jika belum ada data PoC 7 hari.

### Troubleshooting

| Gejala | Kemungkinan | Langkah |
|--------|-------------|---------|
| View Incidents kosong padahal alert ramai | RECON_ENABLED=false atau DB down | cek env + `docker logs ndr-pipeline | grep recon` |
| Semua alert jadi satu insiden raksasa | gap terlalu besar / entitas umum | turunkan `RECON_MAX_GAP_SECONDS` |
| Story hilang setelah restart | lookback terlalu pendek | naikkan `RECON_LOOKBACK_HOURS` |
| Outcome terlalu berani | marker TI high banyak | ingat: label tetap + disclaimer; validasi endpoint sebelum containment |

## 8c. Threat Map & Relationship Graph (Phase 5) — operasional

### Variabel (.env)

| Variabel | Default | Arti |
|----------|---------|------|
| `GEOIP_MMDB_PATH` | (kosong) | path GeoLite2 `.mmdb` di dalam container pipeline; butuh paket `maxminddb` |
| `GEOIP_JSON_PATH` | (kosong) | sidecar JSON CIDR→geo (longest-prefix); format contoh di `.env.example` |

Keduanya opsional. Tanpa sumber geo, field `*.geo` tidak ditulis ke events dan
tab Geographic memakai panel "Not on the map" — korelasi & relationship graph
tidak terpengaruh.

### Rutinitas

- **Investigasi kampanye**: view *Threat Map* → tab *Attack Relationships* →
  pilih chip kampanye → graf terisolasi + attack sequence; klik node untuk
  pivot (alert, metadata sesi, blast radius), klik edge untuk alasan korelasi.
- **Navigasi silang**: klik IP di tab *Geographic* → tombol "Open in attack
  relationship graph" membuka node `ip:<address>` yang sama, dan sebaliknya.
- **Aktivasi GeoIP**: letakkan `GeoLite2-Country.mmdb` di volume pipeline
  (mis. `${NDR_DATA_ROOT}/geoip/`), set `GEOIP_MMDB_PATH`, `docker compose up
  -d pipeline`, lalu verifikasi field geo masuk: `curl
  'localhost:9200/ndr-zeek-*/_search?q=source.geo.country:*&size=1'`.
  Alternatif tanpa lisensi: buat `geoip.json` dari CSV MaxMind (lihat
  `.env.example`) dan set `GEOIP_JSON_PATH`.
- **Memahami graf kosong**: tab Attack Relationships hanya menampilkan
  kampanye berstatus `open|confirmed`; insiden benign/closed tidak digambar
  (pivot entitas tetap bisa mencari lintas status).

### Troubleshooting

| Gejala | Kemungkinan | Langkah |
|--------|-------------|---------|
| Tab Geographic kosong + catatan "events index unavailable" | OpenSearch down / index belum ada | cek `docker ps`, tunggu ingest pertama, cek alias `ndr-events-read` |
| Semua flow masuk "Not on the map" | GeoIP belum dikonfigurasi | set `GEOIP_MMDB_PATH`/`GEOIP_JSON_PATH`, restart pipeline |
| Graf tidak menampilkan dua kampanye terkait | status kampanye bukan open/confirmed, atau tidak berbagi infrastruktur | cek filter; korelasi lintas kampanye butuh bukti bersama yang bisa diperiksa |
| Pivot 404 untuk IP yang jelas ada | IP belum masuk kampanye mana pun | pivot hanya mencakup entitas di incident store; tunggu recon atau periksa rule penyumbang |

## 9. Acceptance test yang berlaku di Phase 0–2

| ID | Skenario | Cara uji | Target |
|---|---|---|---|
| AT-01 | Capture dari SPAN/TAP | `sensor-precheck.sh` + `zeekctl status`, EVE tumbuh | data mengalir, counters terbaca |
| AT-02 | Replay event sama 2× | tulis baris EVE sama 2× ke eve.json | hitungan tak bertambah (`duplicates`) |
| AT-03 | Ratusan alert sejenis | replay file alert banyak | teragrup di Alert Center, drill-down jalan |
| AT-06 | 2 IP beda, signature sama | 2 alert dari src berbeda | TIDAK digabung jadi satu grup/campaign |
| AT-09 | IOC expired | (Phase 3) | — |
| AT-10 | Domain DGA-like | replay DNS NXDOMAIN burst | score+alasan tampil, tanpa klaim "confirmed" |
| AT-11 | PCAP tidak tersedia | buka alert sebelum sensor aktif | status bukti jelas, metadata tetap ada |
| AT-12 | Event terlambat | replay log lama | diindeks ke tanggal event time, ingest_time terpisah |
| AT-15 | Load test capture | replay pcap di Hari 7 | drops/EPS/latensi terukur |
| AT-16 | Rule update invalid | `make rule-update` saat tanpa jaringan | rules lama tetap jalan, status gagal terlihat |
| AT-18 | RBAC | login `auditor`, coba PATCH alert | 403 dari backend |
| AT-20 | NTP out of sync | matikan NTP | precheck/healthcheck memperingatkan |
| AT-21 | Disk hampir penuh | `fallocate` file besar di volume data | healthcheck merah sebelum penuh |
| AT-22 | Backup/restore | §6 | data pulih & terverifikasi |
| AT-23 | DSL berbahaya | `{"script":{...}}` di UI/API | ditolak, sistem aman |
| AT-26 | Update rule/TI manual | `make rule-update` | status & waktu tercatat |

Sisanya (AT-04/05/07/08/13/14/25, dst.) menyentuh fitur Phase 4–6.

## 10. Ujaran harian singkat (cheatsheet)

```bash
make status                 # semua container
make logs S=ndr-api         # log satu service
curl -s localhost:9100/metrics | jq .eps_total
curl -s 'localhost:9200/_cat/indices/ndr-*?v&s=store.size:desc' | head
./scripts/healthcheck.sh
```

## 11. Acceptance test tambahan Phase 4 (attack reconstruction)

Jalankan setelah `sudo ./install.sh` dengan replay PCAP uji atau trafik sintetis
(weapons: nmap + curl exploit-pattern + dig DGA-like + smb/rdp internal + iperf
besar keluar). Semua kasus memakai akun admin, kecuali AT-38 (RBAC).

| ID | Skenario | Langkah | Kriteria lulus |
|----|----------|---------|----------------|
| AT-33 | Rantai 6 fase terekonstruksi | replay scan→exploit→C2→lateral→transfer dari satu sumber ke satu target dalam 2 jam | 1 insiden (bukan N alert lepas) memuat fase recon..impact berstatus OBSERVED pada tab graph/timeline |
| AT-34 | Korelasi jawaban DNS | biarkan host resolve domain X, lalu picu beaconing ke IP X | story menampilkan node domain X + edge `contacted`/`resolved_to` bertanda inferred |
| AT-35 | Pisah vs merge | dua penyerang berbeda menyerang host berbeda; lalu satu penyerang sama menyentuh story keduanya | awalnya 2 insiden; setelah sinyal penghubung, merge menjadi 1 (metrics `recon_merges` naik) |
| AT-36 | Bukti terlambat | matikan pipeline, hasilkan alert, nyalakan lagi dalam lookback, picu sinyal lanjutan | story lama dimuat ulang dan bertambah bukti (updated_at berubah) |
| AT-37 | Outcome dipisah jujur | buka insiden dengan rantai penuh + TI match high | label `strong_success` HANYA jika ada TI high; panel Proven/Suspected/Unknown terisi; disclaimer tampil; tidak ada klaim "compromised" tanpa TI |
| AT-38 | RBAC triage + audit | login auditor (read-only) | PATCH status → 403; triage oleh analyst menulis 1 baris incident_history + 1 audit record `incident.status_change` |
| AT-39 | Laporan insiden | klik Report → Generate → Download | file Markdown memuat Executive Summary, Outcome Assessment, Timeline, Evidence per fase, referensi `index:doc_id` |

## 12. Acceptance test tambahan Phase 5 (threat map & relationship graph)

| ID | Skenario | Langkah | Kriteria lulus |
|----|----------|---------|----------------|
| AT-40 | Multi-IP campaign | dua host berbeda mengontak infrastruktur C2 yang sama (sudah TI-match) | graf menampilkan edge `correlated_with` antar entitas dengan alasan "shared ... infrastructure: <C2>" dan kedua incident_id |
| AT-41 | Alasan korelasi selalu ada | klik beberapa edge di graf (observed, inferred, correlated) | setiap edge punya minimal satu alasan; tidak ada edge yang hanya berdalih kedekatan waktu |
| AT-42 | Pivot bukti | klik node IP eksternal | panel menampilkan alert terkait + metadata sesi + tombol kampanye; aksi tercatat `graph.entity_pivot` di audit |
| AT-43 | Blast radius | klik node web-prod-02 pada skenario AT-33 | panel blast radius memisahkan DIRECT (jalur observed) dan INDIRECT (ada inferred), menyebut host internal terdampak + disclaimer estimasi |
| AT-44 | Geo frequency & warna | buka tab Geographic saat ada trafik TI-match | ketebalan garis proporsional frekuensi; flow TI-match merah, mengandung alert amber; klik arc membuka detail IP/IOC/frekuensi/insiden |
| AT-45 | Tanpa GeoIP tetap jujur | jalankan tanpa GEOIP_* | tidak ada titik dipaksakan ke peta; panel "Not on the map" menyebut alasan; catatan GeoIP = perkiraan tampil |
| AT-46 | Navigasi silang | klik IP di geo → "Open in attack relationship graph" | tab berpindah ke graf dengan node `ip:<address>` terpilih (pivot termuat) |
| AT-47 | GeoIP opsional berfungsi | set GEOIP_JSON_PATH berisi RFC5737 ranges, restart, generate trafik | events membawa `source.geo.*`; peta memplot titik; entri tanpa data tetap ke "Not on the map" |

## 12b. Acceptance test tambahan Phase 5b (Cyber Kill Chain & dual framework)

| ID | Skenario | Langkah | Kriteria lulus |
|----|----------|---------|----------------|
| AT-48 | Klasifikasi dual-framework di alert | buka Alert Center, pilih alert portscan / SQLi / beaconing | detail alert menampilkan badge *kill chain* (tahap + reason) DAN blok *MITRE ATT&CK mapping* (mis. portscan → Reconnaissance + T1046/T1595.002) sekaligus |
| AT-49 | Strip 7 tahap dengan 4 status | buka detail incident dari skenario AT-33 | kartu *Cyber Kill Chain assessment* menampilkan 7 tahap; tahap dengan alert = OBSERVED, konteks saja = SUSPECTED, tanpa bukti = NOT OBSERVED, `weaponization`/`installation` = INSUFFICIENT TELEMETRY (garis putus-putus); setiap tahap punya reason + confidence |
| AT-50 | Bukan urutan wajib | buka incident story-scanner (recon saja) | tahap `exploitation`, `command_and_control`, dst. tetap NOT OBSERVED (tidak diisi), chain tidak dipaksakan; tidak ada tahap yang "dicentang" tanpa bukti |
| AT-51 | Stage history terekam | hasilkan alert baru pada story aktif (mis. beaconing menyusul portscan) | panel *Stage assessment history* menambah entri transisi (mis. `command_and_control: not_observed → observed`) dengan waktu + referensi alert; setelah restart pipeline history tidak hilang |
| AT-52 | Kill chain di laporan insiden | buka incident → Report → Generate | Markdown memuat bagian *Kill Chain Stage Assessment* (tabel Stage/Status/Confidence/ATT&CK/Reason) + *Assessment changes over time*; timeline membawa kolom kill-chain stage |

## 13. Rule Manager Suricata (Phase 6) — operasional

Tempat mengelola rule IDS kini ada dua lapis: **UI (Detect → Rule Manager)**
untuk pekerjaan harian analis/insinyur, dan **CLI lama** untuk otomasi.

### Di mana melakukan apa

| Tugas | Cara UI | Cara CLI |
|-------|---------|----------|
| Update rule Emerging Threats | Rule Manager → tombol **Update rules** (log `suricata-update` tampil di panel) | `make rule-update` |
| Disable satu rule | cari SID → matikan switch di kolom **On** | tambahkan SID ke `sensor/suricata/rules/disable.conf`, lalu `make rule-update` |
| Enable kembali | nyalakan switch-nya | hapus baris SID dari `disable.conf`, lalu `make rule-update` |
| Cek status rule | kartu ringkas (loaded/enabled/disabled/sensor) | `docker exec ndr-suricata suricatasc -c ruleset-stats` |

Keduanya menulis ke **file state yang sama** (`disable.conf` pada volume
`./sensor/suricata/rules`), jadi tidak ada kemungkinan UI dan CLI berbeda.

### Cara kerja (penting dipahami operator)

1. Toggle **disable** menambah baris SID ke `disable.conf`, lalu API menjalankan
   `suricata-update` untuk meregenerasi `suricata.rules` (SID hilang dari rule
   set aktif), lalu mencoba **live reload** via unix socket
   (`/var/run/suricata/suricata-command.socket`, dibagi antara container
   `ndr-api` dan `ndr-suricata`).
2. Jika sensor mati / socket tidak ada, UI menampilkan banner **reload pending**
   — perubahan sudah tersimpan dan otomatis berlaku saat sensor berikutnya start
   (Suricata membaca `suricata.rules` saat boot).
3. Rule yang di-disable **tetap terlihat** di tabel (metadata ter-cache di
   tabel `suricata_rule_meta` di Postgres) lengkap dengan `changed_by` dan
   `changed_at`; hit count "Alerts 7d" membantu menilai rule mana yang bising
   sebelum dimatikan.
4. Baris non-standar di `disable.conf` (mis. entri regex `re:...` buatan
   operator) **dipertahankan** oleh API — hanya baris SID yang dikelola yang
   ditambah/dihapus.

### Hak akses & audit

- `view` semua role boleh melihat; **update/toggle** hanya
  `administrator` + `security_engineer` (capability `rule_admin`).
- Semua perubahan masuk audit log: `rules.update`, `rules.enable`,
  `rules.disable` (aktor, IP, hasil, detail).

### Acceptance test tambahan Phase 6

| ID | Skenario | Langkah | Kriteria lulus |
|----|----------|---------|----------------|
| AT-53 | Update rule dari UI | Rule Manager → **Update rules** (dengan jaringan) | log `suricata-update` tampil, jumlah rule ter-update, timestamp "last regenerated" berubah |
| AT-54 | Disable rule dari UI | matikan switch SID yang bising | rule berpindah ke status disabled, `disable.conf` bertambah 1 baris SID, audit log mencatat `rules.disable` dgn aktor |
| AT-55 | Disable bertahan lintas update | jalankan `make rule-update` setelah AT-54 | SID tetap disabled (suricata-update menghormati `disable.conf`), UI masih menampilkannya sebagai disabled |
| AT-56 | Reload pending saat sensor mati | matikan profil sensor, disable rule | banner "reload pending" tampil; nyalakan sensor → rule set aktif sesuai status terbaru |
| AT-57 | RBAC rule manager | login `soc_analyst`, coba toggle/update | switch nonaktif di UI; panggilan API langsung → 403; auditor masih bisa melihat |
| AT-58 | Rule update gagal | putus internet, **Update rules** | status gagal jelas, rules lama tetap jalan (konsisten AT-16), error tampil di panel log |

## 14. PCAP & Evidence Workflow (Phase 6, dok §15) — operasional

Mekanisme PCAP selektif dari dokumen desain kini terimplementasi sebagai
bagian dari detail **Alert** dan **Incident** (panel *PCAP & sessions*).

### Alur analis (dok §15.1 langkah 1–9)

1. Buka detail alert/incident → panel **PCAP & sessions** otomatis
   menampilkan sesi (metadata event Zeek/Suricata) untuk entitas alert
   dalam jendela waktu alert ± buffer capture (default 5 menit, dapat
   diubah via `PCAP_SESSION_BUFFER_MINUTES`).
2. Setiap sesi membawa **status bukti** (dok §15.2):
   `available` / `partially available` / `expired (retention)` /
   `not captured` — diturunkan dari cakupan file capture rolling
   (`/var/lib/ndr/pcap`), sehingga "tidak ditemukan", "sensor tidak
   merekam", dan "sudah terhapus retention" selalu bisa dibedakan.
3. Analis mencentang sesi yang dibutuhkan (default: yang `available`),
   mengisi **reason** (wajib — masuk manifest & audit), lalu klik
   **Export N sessions**.
4. API memvalidasi ulang seluruh sesi secara server-side, memetakan
   jendela waktu ke file PCAP yang menaunginya, menegakkan batas
   kebijakan (default: maks 5 file / ~2 GB per ekspor), mem-bundle
   `zip` berisi PCAP + `manifest.json` (SHA-256 per file + hash bundle),
   mencatatnya ke register **chain of custody**, dan menerapkan **TTL**
   (default 60 menit) — file otomatis dihapus setelah TTL lewat.
5. Jika tidak ada file capture yang menaungi jendela sesi, ekspor
   tercatat berstatus `failed` dengan alasan yang jelas (sensor belum
   berjalan / sudah di-prune) — sistem tidak pernah mengarang bukti.
6. Tombol **Open in Arkime viewer** membuka Arkime (port 8005, login
   tersendiri) untuk inspeksi paket presisi per sesi.

### Batas granularitas (jujur, dok §15.3)

Ekspor PoC ini **file-level**: yang diunduh adalah file-file rolling PCAP
yang menaungi jendela sesi terpilih, bukan potongan paket presisi per
sesi. Manifest, UI, dan catatan ekspor menyatakan ini eksplisit. Untuk
potongan presisi, gunakan Arkime viewer. Jangan klaim chain of custody
penuh sebelum kontrol operasional menuntutnya.

### RBAC & audit (AT-18/AT-19/AT-28)

| Aksi | Permission | Peran |
|------|-----------|-------|
| Lihat sesi & register ekspor, storage PCAP | `view` | semua peran |
| Ekspor & unduh bundle | `evidence_export` | administrator, security_engineer, soc_analyst, soc_lead (**auditor tidak bisa** — read-only) |

Setiap ekspor/unduh/kedaluwarsa tercatat di tabel `pcap_exports` (actor,
peran, reason, alert/incident, sesi, jendela, file+hash, TTL) **dan** di
audit log (`evidence.pcap.export` / `.download` / `.expire`).

### Endpoint API

| Endpoint | Fungsi |
|----------|--------|
| `GET /api/evidence/pcap/storage` | statistik direktori capture + jendela cakupan (dipakai juga gauge Sensors) |
| `GET /api/evidence/alerts/{id}/sessions` | resolusi sesi + status bukti per alert |
| `GET /api/evidence/incidents/{id}/sessions` | resolusi sesi + status bukti per incident |
| `POST /api/evidence/pcap/export` | buat bundle ekspor (reason + daftar sesi) |
| `GET /api/evidence/pcap/exports` | register ekspor + limit kebijakan |
| `GET /api/evidence/pcap/exports/{id}/download` | unduh bundle zip (410 bila kedaluwarsa) |

### Konfigurasi (.env)

`PCAP_EXPORT_TTL_MINUTES` (60), `PCAP_EXPORT_MAX_FILES` (5),
`PCAP_EXPORT_MAX_BYTES` (2000000000), `PCAP_SESSION_BUFFER_MINUTES` (5),
`PCAP_FILE_SPAN_MINUTES` (15), `ARKIME_VIEWER_URL` (`http://127.0.0.1:8005`
— set ke `http://<ip-vm>:8005` agar tombol deep-link bisa dibuka analis).

### Acceptance test tambahan Phase 6 (PCAP & evidence)

| ID | Skenario | Langkah | Kriteria lulus |
|----|----------|---------|----------------|
| AT-59 | PCAP tersedia | buka detail alert dengan sesi baru | sesi berstatus **Available**, bisa dicentang & diekspor |
| AT-60 | PCAP ter-prune | buka alert > cakupan capture | status **Expired (retention)** jelas, metadata tetap tampil (konsisten AT-11) |
| AT-61 | Export sukses | pilih sesi + reason → Export | bundle zip berisi manifest + hash; register bertambah; audit tercatat |
| AT-62 | Tanpa reason | klik Export dengan reason kosong | tombol disabled — ekspor tak mungkin tanpa alasan |
| AT-63 | TTL | set `PCAP_EXPORT_TTL_MINUTES=1`, tunggu | file bundle terhapus otomatis; unduh mengembalikan 410; register berstatus expired |
| AT-64 | RBAC ekspor | login auditor → coba ekspor/unduh | 403 dari backend; lihat sesi tetap boleh |
| AT-65 | Sensor tidak capture | kosongkan direktori pcap | semua sesi **Not captured**; ekspor tercatat `failed` dengan alasan |

## 15. v0.10.0 — UX & Administrasi SOC (operasional)

### 15.1 Hasil serangan (verdict `outcome`) pada alert

Setiap alert sekarang membawa field `outcome` — hasil serangan versi konsol,
ditentukan pipeline saat deteksi (bukan kata di judul rule):

| Nilai | Arti | Ditetapkan saat |
|-------|------|-----------------|
| `suspected_success` | Signature reaksi server (keluarga ATTACK_RESPONSE / classtype attack-response) — target berreaksi konsisten dengan aksi yang berhasil | classtype/signature attack-response |
| `attempted` | Signature kelas eksploit/attack teramati; signature hanya membuktikan percobaan, bukan keberhasilan | classtype attempted/exploit/web-application/attack/trojan/malware |
| `indeterminate` | Aktivitas recon/scan/policy dan semua rule perilaku — aktivitas bisa jadi benign, tidak ada klaim hasil | recon/scan/policy/activity, portscan, nxdomain, beaconing, ioc_match |
| `strong_success` | Hanya untuk correlation engine (rantai penuh ber-TI dengan penanda sukses) — tidak pernah diset pada satu alert | — |

Urutan penilaian classtype: attack-response → trojan/malware/C2 → recon/scan
(determinasi `indeterminate`, termasuk `attempted-recon`) → attempted/exploit →
policy/lainnya. UI: kolom **Verdict** di Alert Center + filter dropdown; judul
alert tetap teks rule verbatim (kata "Attempt" adalah bagian nama signature
Suricata, bukan verdict kami).

### 15.2 Eskalasi manual alert → incident

- **Otomatis (tetap)**: correlation engine menyusun incident dari alert, IOC
  match, dan konteks lintas-log via entitas/perilaku bersama; tiap relasi
  beralasan + confidence; kedekatan waktu saja tidak pernah membuat relasi.
- **Manual (baru)**: tombol petir pada tiap baris alert (dan di detail sheet)
  menaikkan alert menjadi incident baru `inc-esc-<alert_id>` — status open,
  entitas & evidence persis dari alert, **tanpa relasi rekayasa**; engine
  boleh menggabungkannya nanti bila bukti terkait muncul. Idempoten (409 bila
  sudah dieskalasi). RBAC `incident_update`; audit `alert.escalate`.
- Parameter otomatis yang dipakai engine: IP/domain/hash bersama antar
  deteksi, TI match pada rantai, rule perilaku (DGA → beaconing pada host
  sama), pasangan source/destination identik lintas signature.

### 15.3 Filter rentang waktu & paginasi

- Preset **Today / 24h / 7d / 14d / 30d / All / Custom** (datetime-local) pada
  Alert Center, Incidents, dan Threat Intel. Alert & incident memfilter di
  sisi data (`last_seen` dalam rentang; demo dataset tersebar 35 hari agar
  tiap preset terukur berbeda).
- Paginasi (ukuran halaman 10/25/50/100) pada: Alert Center, Incidents,
  Assets, Users, Audit Log, Event Search, registri aset.

### 15.4 Navigasi & peta

- Menu di-regroup: **Monitor / Detect / Investigate / Govern / Configuration**.
  Rule Manager, Intel Feeds, Assets, Users, Roles pindah ke **Configuration**;
  hasil deteksi Threat Intel tetap di **Detect**.
- Threat Intel (hasil: matches + IOC store) dipisah dari **Intel Feeds**
  (manajemen: feed, update jobs, allowlist).
- Threat Map: node/edge bisa diklik untuk detail (pivot + blast radius).
  Perbaikan akar: `setPointerCapture` pada pan/zoom mengalihkan event `click`
  ke root SVG sehingga klik node mati — kini drag memakai listener window
  dan klik bubble normal (guard `didDrag()` tetap mencegah salah pilih
  setelah pan).
- Geographic Map baru: graticule, glow arc TI-matched, label negara, chip KPI,
  dan tombol **Fullscreen** (mode bigscreen CSS, Esc untuk keluar — aman di
  iframe preview tanpa Fullscreen API).
- Tiap baris alert punya tombol **Open in Threat Map** (fokus IP sumber di
  graph, atau di peta geografis bila entitas belum ada di graph).

### 15.5 Aset, User, Role

- **Registri aset manual** (tabel `assets`): Add/Edit/Delete di Assets;
  enrichment nama aset pada kolom Source/Destination Alert Center (API
  meng-annotate `source_asset_name`/`destination_asset_name`; demo mencocokkan
  live termasuk aset yang baru didaftarkan). Sumber data dijelaskan di halaman:
  *discovered hosts* (dari telemetri) vs *registered* (manual).
- **User CRUD**: tambah (dengan initial password + `must_change_password`),
  edit (role/full name/aktif/reset password — token version dinaikkan sehingga
  sesi lama ter-revoke), hapus (guard: tidak bisa hapus diri sendiri; guard
  last-admin juga pada disable/demote). Endpoint: `POST/PATCH/DELETE
  /api/users*` (RBAC `user_admin`).
- **Halaman Roles**: matriks RBAC yang dipakai backend
  (`GET /api/roles` dari `security.PERMISSIONS`) — read-only by design:
  perubahan matriks = perubahan kode (review + audit), assignment role per
  user dilakukan di halaman Users.

## 16. v0.12.5 — Catatan operasional & kebijakan tampilan

### 16.1 Judul insiden "unknown source (...)" — by design, bukan bug

Sebagian besar insiden hasil rekonstruksi otomatis berjudul
`unknown source (C2|activity|...)`. Mekanismenya (`story.py::_retitre`):
judul memakai node ber-role `attacker`, dan role tersebut HANYA diberikan
pada bukti fase recon/initial_access yang terkorelasi ke story yang sama.
Pada trafik SPAN yang didominasi ET INFO/alert C2 tanpa bukti recon yang
terkorelasi, tidak ada node attacker → fallback "unknown source". Ini
konsisten dengan prinsip no-overclaim (tak bisa menyebut aktor tanpa bukti).

Panduan analis:
- Buka insiden dari Alert Center → cek tab Timeline/Graph untuk melihat
  rantai bukti yang ADA; atribusi IP eksternal bisa dilakukan manual via
  notes/campaign.
- Judul berubah otomatis begitu bukti recon/initial_access masuk ke story
  yang sama (pipeline assign role `attacker`).
- Perbaikan kebijakan judul (fallback "unattributed <ip>" dsb.) adalah
  keputusan produk + update test — belum diubah di v0.12.5.

### 16.2 Log yang aman diabaikan (benign)

- OpenSearch `ISM JobSweeper ... Indexing failed for job ndr-retention`
  (INFO, periodik): job ISM mencatat metadata ke indeks sistem saat
  beban tinggi; cek retensi via `GET /_plugins/_ism/explain/<indeks>`,
  bukan dari log ini.
- Zeek `sendmail not found`: notice tidak di-relay email (by design,
  `Notice::mail_dest = ""`).
- Arkime: warning `hostname`/`authMode`/GeoIP/memlock saat startup —
  aman untuk single-node.

### 16.3 GeoIP opsional (peta geografis)

Tanpa `GEOIP_*` (path MMDB) semua IP eksternal masuk panel
"Not on the map" — sesuai desain (no-overclaim: tanpa data geo, IP tidak
dipetakan). Untuk mengaktifkan: sediakan file MaxMind GeoLite2-City.mmdb
di VM, set `GEOIP_CITY_DB` + `GEOIP_ASN_DB` di `.env` pipeline, lalu
restart pipeline (lihat `pipeline/app/geoip.py`).

### 16.4 Ukuran graf relasi besar

`GET /api/graph/relationships` sudah dioptimasi (bulk-fetch + indeks,
~30x lebih cepat tervalidasi live), tetapi pada jaringan sangat ramah
payload bisa mencapai beberapa MB. Untuk bigscreen jangka panjang,
pertimbangkan filter `severity_min`/`q`/`limit` di endpoint, atau
render canvas — backlog, bukan bug.

### 16.5 v0.12.9 — Jump "Threat Map" dari Alert Center kini FOCUSED

Tombol ikon Waypoints pada baris alert (dan "View its attack relationship"
di detail sheet) TIDAK lagi membuka peta global/geografis. Ia membuka
**relasi terfokus milik alert itu saja** di tab Threat Map:

- `basis: incident` — alert tercatat sebagai bukti insiden hasil
  rekonstruksi → yang digambar subgraf rantai insiden tsb (shape sama
  dengan graf relasi global, dipangkas 60 node / 200 edge).
- `basis: alert` — belum terkorelasi → graf minimal yang jujur dari
  entitas milik alert sendiri (source, destination, IOC) dengan alert
  sebagai satu-satunya sumber kutipan; tidak ada relasi yang ditebak.
- `basis: none` — alert tanpa source/destination → sengaja kosong.

Tombol "Show full threat map" di banner membuka peta global lengkap
(graf gabungan + geo) secara eksplisit. Endpoint: 
`GET /api/alerts/{alert_id}/relationship`.

## 17. Penyimpanan potongan PCAP & raw evidence — apa yang berjalan & cara verifikasi

Tiga lapis penyimpanan bukti, semua AKTIF (terverifikasi live di VM
2026-10-14: "Arkime sessions + PCAP rolling OK, viewer hidup"):

1. **PCAP rolling (Arkime)** — file PCAP sungguhan ditulis sensor Arkime
   ke `${NDR_DATA_ROOT}/pcap` (`pcapDir=/opt/arkime/raw` di kontainer),
   snapLen 65535 (GRO/GSO SPAN), ditulis per-koneksi. Rotasi berbasis
   DISK: `ARKIME_FREESPACE_G` (default 40 GB) — Arkime menghapus PCAP
   tertua saat ruang bebas di bawah ambang itu. Ini sumber "potongan
   pcap" yang diakses viewer Arkime dan sesi evidence.
2. **Raw event archive (pipeline)** — setiap baris mentah EVE/Zeek yang
   lolos validasi disalin ke `<PIPELINE_STATE_DIR>/raw/YYYYMMDDHH-<engine>.jsonl.gz`
   (gzip per jam per engine), retensi default 72 jam
   (`PIPELINE_RAW_RETENTION_HOURS`), dan setiap dokumen event menyimpan
   referensi sha256 (`raw_event_ref`) ke baris aslinya — integritas
   bukti bisa dibuktikan ulang.
3. **Export selektif (API)** — `POST /api/evidence/pcap/export`
   memilih file rolling yang menutup sesi alert/insiden, mengemas zip
   dengan manifest SHA-256 per file + bundle, TTL ekspor default 60 menit
   (`PCAP_EXPORT_TTL_MINUTES`), semua tercatat di register ekspor.

Verifikasi cepat di VM:

```bash
# 1) PCAP Arkime tumbuh & rolling jalan
du -sh /opt/ndr/pcap && ls -lh /opt/ndr/pcap | tail -5
# 2) status + coverage dari API (login admin dulu):
#    GET /api/evidence/pcap/storage  -> kapasitas, file, coverage window
# 3) raw archive pipeline tumbuh (72 jam terakhir)
docker exec ndr-pipeline sh -c 'ls /data/state/raw | tail -5'
# 4) uji end-to-end: buka Alert Center -> detail alert -> PCAP & evidence
#    -> link "Open in Arkime" harus membuka viewer pada 5-tuple +/-2 menit
```

Catatan batas desain (dok §15): ekspor granularitas FILE-LEVEL (bukan
potongan paket presisi; presisi paket pakai viewer Arkime), dan dokumen
event menyimpan sha256 baris — bukan nama file arsip — sehingga
rekonstruksi baris mentah dari arsip memerlukan pencarian per file jam
(backlog kecil, bukan bug).

## 18. Sumber intel feed yang disarankan (dan cara menambahkannya)

Feed bawaan (starter, DISABLED sampai diaktifkan — lihat banner
"Enable + update" di menu Threat Intel): `feodo-c2`, `urlhaus-recent`,
`threatfox-2d` (semua abuse.ch, gratis dan publik). Adapter yang
didukung API/UI: `urlhaus`, `threatfox`, `feodo`, `file`, `stix`,
`taxii`, `misp`.

Sumber publik yang bisa langsung dipakai:

| Sumber | Adapter | URL / cara |
|---|---|---|
| abuse.ch Feodo Tracker (C2 IP blocklist) | `feodo` | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` |
| abuse.ch URLhaus (malware URL) | `urlhaus` | `https://urlhaus.abuse.ch/downloads/csv_recent/` |
| abuse.ch ThreatFox (IOC C2/payload) | `threatfox` | `https://threatfox.abuse.ch/api/v1/` (config `{"days": 2}`) |
| CISA AIS (STIX/TAXII, perlu akun) | `taxii` | discovery TAXII 2.1 + Basic auth di config |
| AlienVault OTX (perlu API key) | `taxii`/`stix` | export STIX pulses via edge TAXII OTX |
| MISP komunitas (CIRCL dsb) | `misp` | URL feed manifest + auth key di config |
| OpenPhish (free feed terbatas) | `file`/`stix` | unduh berkala, sajikan via `file`/HTTP statis |
| Feed internal/CSIRT nasional (CSV/JSON/JSONL) | `file` | taruh file di path yang bisa dibaca pipeline |

Cara menambahkan: **Configuration → Intel Feeds → Add feed** (nama,
adapter, URL, jadwal menit — 0 = manual, TTL hari, config JSON untuk
kredensial) → aktifkan switch → **Update now**. Matcher memuat ulang
snapshot IOC tiap 60 detik (`TI_RELOAD_SECONDS`); IOC match muncul di
menu Threat Intel + alert `ioc_match` hanya ketika trafik benar-benar
menyentuh IOC aktif (source/destination IP, dns.query, tls.sni,
http.host/url, file hash). Kredensial feed dimask di semua jalur baca
dan tidak pernah di-log (dok 9.3). Jaringan pipeline harus boleh egress
HTTPS ke host feed; verifikasi gagal sync di tab Update jobs.

Praktik keandalan: jangan tumpuk banyak feed duplikat (dedup IOC per
(tipe, nilai) otomatis dengan provenance feed dipertahankan); pantau
`feeds_degraded`; gunakan allowlist (menu Threat Intel) untuk FP yang
sudah diverifikasi, bukan mematikan feed.
