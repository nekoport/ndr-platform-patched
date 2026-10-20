# Panduan Deployment — VM Ubuntu 24.04 (8 core / 24 GB / 3 TB)

Dokumen ini memandu deployment dari VM kosong sampai NDR fondasi beroperasi.
Estimasi waktu: 30–60 menit (tergantung kecepatan unduhan image).

> Catatan: seluruh dokumentasi platform ada di folder **`/docs/`** (bukan
> `/doc/`) — ARCHITECTURE, DEPLOYMENT, OPERATIONS, SIZING, TLS-HARDENING,
> SECURITY-AUDIT, LOAD-TESTING, DESIGN-PLAN.

---

## 1. Persiapan VM & storage

VM minimum: 8 vCPU, 24 GB RAM, 3 TB disk, Ubuntu 24.04 LTS.

### 1.1 Layout storage yang disarankan

Jika Anda bisa mengatur partisi/LVM sebelum install, bagi 3 TB menjadi:

| Mount point | Ukuran | Isi |
|---|---|---|
| `/` | 100 GB | OS, Docker, image, log container |
| `/var/lib/ndr/opensearch` | 2,1 TB | metadata Zeek/Suricata (retensi 60 hari) |
| `/var/lib/ndr/pcap` | 600 GB | PCAP selektif Arkime (rolling by free-space) |
| `/var/lib/ndr/postgres` | 100 GB | data operasional/audit |
| `/var/lib/ndr/backup` | 100 GB | dump PG + snapshot OpenSearch |

Jika hanya ada satu partisi besar, installer tetap bekerja — semua data
ditempatkan di bawah `NDR_DATA_ROOT` (default `/var/lib/ndr`). Pantau free
space lewat `make status`; watermark OpenSearch 85/90/95% sudah diset.

Rekomendasi filesystem: **XFS** atau **ext4**. Hindari NFS untuk data OpenSearch.

### 1.2 Sinkronisasi waktu (wajib)

Akurasi timeline bergantung pada NTP. Jalankan dan pastikan:

```bash
sudo timedatectl set-ntp true
timedatectl status | grep -E "synchronized|NTP"
```

---

## 2. Pasang Docker (jika belum ada)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

---

## 3. Salin repo & isi konfigurasi

```bash
sudo mkdir -p /opt/ndr && sudo chown $USER /opt/ndr
# salin folder ndr-platform ke /opt/ndr (scp/rsync/git sesuai kebiasaan Anda)
cd /opt/ndr

cp .env.example .env
nano .env
```

Nilai yang **wajib** diperiksa:

| Variabel | Arti | Contoh |
|---|---|---|
| `CAPTURE_IFACE` | interface penerima SPAN/TAP (**tanpa IPv4** — cek `ip -o addr show scope global`; yang tak muncul = kandidat SPAN) | `enp6s19` |
| `SENSOR_ID` | nama logis sensor | `sensor-01` |
| `NDR_DATA_ROOT` | root data | `/var/lib/ndr` |
| `UI_PORT` | port web console | `3000` |

Secret (`POSTGRES_PASSWORD`, `JWT_SECRET`, `ADMIN_PASSWORD`,
`ARKIME_PASSWORD_SECRET`) boleh dibiarkan `CHANGE_ME` — **installer akan
meng-generate otomatis** jika masih kosong/placeholder... sebenarnya installer
meng-generate saat `.env` dibuat olehnya; jika Anda membuat `.env` manual,
generate sendiri:

```bash
openssl rand -base64 24   # POSTGRES_PASSWORD
openssl rand -hex 32      # JWT_SECRET
openssl rand -base64 18   # ADMIN_PASSWORD
openssl rand -hex 16      # ARKIME_PASSWORD_SECRET
```

`RETENTION_DAYS=60` adalah baseline storage 3 TB. Naikkan hanya setelah
pengukuran GB/day (lihat SIZING).

---

## 4. Verifikasi SPAN/TAP (sebelum sensor aktif)

```bash
sudo apt-get install -y tcpdump ethtool
./scripts/sensor-precheck.sh ens160
```

Script mengecek: interface ada & up, driver/link speed, promiscuous, offload
(GRO/LRO/TSO sebaiknya off), **sampling trafik 5 detik** (harus terlihat
paket), counter rx_dropped, NTP, dan `vm.max_map_count`.

Jika tidak ada paket terlihat: periksa konfigurasi SPAN di switch (arah RX/TX,
VLAN yang dimonitor) — ini penyebab tersering "sensor diam".

---

## 5. Jalankan installer

```bash
sudo ./install.sh              # base stack saja
# atau, jika SPAN sudah terverifikasi:
sudo ./install.sh --sensor     # base + zeek + suricata + arkime
```

Installer akan: precheck sistem → generate `.env` (bila belum ada) → buat
struktur direktori data → build image → start service → tunggu OpenSearch
sehat → cetak URL + password admin.

---

## 6. Verifikasi pasca-install

```bash
# status seluruh service
./scripts/healthcheck.sh

# 1) OpenSearch hijau/kuning
curl -s http://127.0.0.1:9200/_cluster/health | head -c 200; echo

# 2) template & ISM terpasang
curl -s "http://127.0.0.1:9200/_index_template/ndr-alerts" | head -c 200; echo
curl -s "http://127.0.0.1:9200/_plugins/_ism/policies/ndr-retention" | head -c 200; echo

# 3) API hidup
curl -s http://127.0.0.1:8080/api/meta; echo

# 4) UI merender (dari LAN)
# buka http://<IP-VM>:3000 → login admin
```

Jika Zeek/Suricata/Arkime berjalan, dalam 1–2 menit muncul data:

```bash
curl -s "http://127.0.0.1:9200/ndr-events-read/_count" ; echo
```

---

## 7. Keamanan akses (penting)

- Semua port data (9200, 5432, 8080, 9100) **hanya bind ke 127.0.0.1**.
  Satu-satunya port publik adalah UI (3000) dan Arkime viewer (8005, bila sensor aktif).
- Akses SSH ke VM dibatasi; tunnel untuk akses data:

  ```bash
  ssh -L 9200:127.0.0.1:9200 -L 8080:127.0.0.1:8080 user@vm-ndr
  ```

- Firewall contoh (ufw):

  ```bash
  sudo ufw allow 22/tcp          # SSH (batasi source IP kantor)
  sudo ufw allow 3000/tcp        # NDR console
  sudo ufw allow 8005/tcp        # Arkime viewer (opsional)
  sudo ufw enable
  ```

- OpenSearch security plugin dimatikan untuk menyederhanakan fase fondasi;
  **jangan pernah mengekspos 9200 ke luar host**. Aktifkan TLS/plugin pada
  fase hardening (Phase 7).

- Ganti password admin pada login pertama (wajib oleh sistem:
  `must_change_password`).

---

## 8. Autostart & lifecycle

`restart: unless-stopped` sudah diset di semua service. Pastikan Docker start
saat boot:

```bash
sudo systemctl enable docker
```

Perintah harian ada di `Makefile` (`make up/down/status/logs/backup`).

---

## 9. Upgrade & rollback

```bash
./scripts/upgrade.sh            # build + restart + health probe
```

Rollback: simpan image lama sebelum upgrade, atau checkout versi repo
sebelumnya lalu `docker compose up -d --build`. Backup sebelum upgrade:

```bash
./scripts/backup.sh
```

---

## 10. Troubleshooting instalasi

| Gejala | Sebab umum | Perbaikan |
|---|---|---|
| OpenSearch `exit code 78` | `vm.max_map_count` < 262144 | `sudo sysctl -w vm.max_map_count=262144` (installer sudah menangani) |
| OpenSearch tak sehat, log `disk usage exceeded flood-stage` | disk penuh | kosongkan ruang / turunkan retensi / perbesar disk |
| Zeek log kosong | SPAN tidak terlihat | jalankan `sensor-precheck.sh`; periksa switch |
| Suricata mati langsung | interface salah / rules kosong | cek `CAPTURE_IFACE`; `docker logs ndr-suricata`; jalankan `make rule-update` |
| Arkime init gagal | OpenSearch belum sehat | `docker restart ndr-arkime` setelah OS sehat |
| Upgrade dari 0.12.2: API crash `column "id" is of type uuid` | volume Postgres lama masih memakai schema UUID | hapus volume Postgres lalu init ulang: `docker compose stop ndr-api ndr-pipeline && sudo env NDR_DATA_ROOT="${NDR_DATA_ROOT:-/var/lib/ndr}" bash -c 'rm -rf "$NDR_DATA_ROOT/postgres" && mkdir -p "$NDR_DATA_ROOT/postgres" && chown 999:999 "$NDR_DATA_ROOT/postgres"' && docker compose up -d` (login ulang admin bootstrap; indeks OpenSearch & PCAP tidak terdampak). CATATAN: jangan pakai pola `sudo rm -rf .../postgres/*` — glob `*` di-expand shell user biasa yang tidak bisa membaca dir mode 750, sehingga rm gagal diam-diam; rm+mkdir+chown harus berjalan di dalam shell root (`sudo bash -c`/`sudo env`) |
| Build sensor gagal `"/scripts": not found` (rilis 0.12.3) | `sensor/zeek/Dockerfile` men-COPY direktori `scripts/` yang tidak ada → satu perintah build membuat ketiga image sensor gagal | tarik arsip ≥ 0.12.4 (baris COPY dihapus) lalu `sudo ./install.sh --sensor` |
| Build gagal `suricata/suricata:8.0 pull access denied` | image lama salah nama (rilis < 0.12.3) | tarik arsip ≥ 0.12.3 (default `jasonish/suricata:8.0`) atau set `SURICATA_IMAGE=jasonish/suricata:8.0` di `.env` |
| Upgrade ke 0.12.5: Alert Center kosong / 400 `empty clause found` | rilis < 0.12.5: query kosong dikirim ke `bool.filter`, template tanpa `aliases` (bootstrap mati di template pertama), dok alert tanpa `@timestamp` | tarik arsip ≥ 0.12.5, lalu `docker compose up -d --build` dan **rerun bootstrap**: `docker compose run --rm init-opensearch` (pasang template+alias yang benar). Untuk indeks alert lama, tambahkan mapping: `curl -X PUT "$OS_URL/ndr-alerts-*/_mapping" -H 'Content-Type: application/json' -d '{"properties":{"@timestamp":{"type":"date"}}}'` — dok lama tanpa `@timestamp` tidak akan muncul di filter rentang waktu (by design) |
| Upgrade ke 0.12.5: sensor wajib rebuild | `local.zeek`/entrypoint Zeek & Arkime berubah (Zeek 9 kompatibel, SpoolDir di volume, layout Arkime 5.6, snapLen 65535) | `sudo ./install.sh --sensor` (build ulang image sensor; `.env` dipertahankan) |
| Detail alert: `Failed to load sessions: Error: Alert not found` padahal alert tampak di daftar (rilis ≤ 0.12.5) | resolusi alert hanya GET-by-id pada alias `ndr-alerts-read` multi-indeks; error backend lain juga ditelan jadi 404 | tarik arsip ≥ 0.12.6 (resolusi dua lapis `get_alert_doc` + error 502 jujur); tidak perlu reset data |
| Build gagal `arkime_*.deb 404` | pola nama aset lama salah (rilis < 0.12.3) | gunakan arsip ≥ 0.12.3 (pola `arkime_<ver>-1.ubuntu2404_amd64.deb`); bila revisi berubah, set `ARKIME_DEB` di build |
| UI 502 saat login | API belum siap / `BACKEND_INTERNAL_URL` salah | `docker logs ndr-api`; tunggu; cek env |
| Pipeline `parse_errors` naik | versi EVE/Zeek berbeda | lihat `deadletter-*.jsonl.gz` di volume state; sesuaikan normalizer |
