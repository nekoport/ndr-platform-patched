# UPGRADING — 0.15.0 / 0.16.0 → 0.16.1

Rilis 0.16.1 = **bugfix lapangan** atas 0.16.0 (tanpa perubahan skema data
OpenSearch, tanpa detector baru, tanpa migrasi DB). Upgrade dipandu
`scripts/upgrade.sh`.

## 1. Langkah upgrade (VM 10.0.106.232)

```bash
# 0) backup
sudo tar -C /opt -czf /var/lib/ndr/backup/opt-ndr-code-pre-0161-$(date +%FT%T).tgz ndr
sudo cp /opt/ndr/.env /var/lib/ndr/backup/env-pre-0161-$(date +%FT%T).txt

# 1) tarik paket 0.16.1 ke /opt/ndr (pertahankan .env + sensor/suricata/rules)
sudo mkdir -p /tmp/ndr-0161 && sudo tar -xzf ndr-platform-0.16.1.tar.gz -C /tmp/ndr-0161 \
  && sudo rsync -a --delete --exclude '.env' --exclude 'sensor/suricata/rules' \
       /tmp/ndr-0161/ /opt/ndr/

# 2) (opsional tapi disarankan) pastikan JWT_SECRET kuat di .env
grep '^JWT_SECRET=' /opt/ndr/.env || echo "JWT_SECRET=$(openssl rand -hex 32)" | sudo tee -a /opt/ndr/.env

# 3) build + recreate (script sudah --force-recreate semua layer)
cd /opt/ndr && sudo bash scripts/upgrade.sh
```

## 2. Apa yang berubah saat runtime

* **Zeek**: entrypoint kini membuat symlink `logs/current -> spool/zeek`
  + self-heal tiap 60 s. *Tidak perlu* lagi workaround manual
  `ln -sfn spool/zeek ...` setiap recreate (workaround W2 di laporan
  bug kini jadi perilaku bawaan).
* **API**: `requirements.txt` memuat `openpyxl` — rebuild image API
  wajib (`docker compose build ndr-api`, sudah dilakukan upgrade.sh).
* **Checkpoint pipeline**: TIDAK perlu ditulis ulang manual. Saat
  container zeek di-recreate, inode log baru dikenali → file baru dibaca
  dari EOF (checkpoint v2 0.15.0 validasi `[dev,ino]`).
* **Workaround W4** (`--force-recreate suricata`) kini dibawa
  `scripts/upgrade.sh`.

## 3. Verifikasi 10 menit (setelah upgrade)

1. `curl -s localhost:8080/api/version | jq` → `"version": "0.16.1"`.
2. `readlink -f /var/lib/ndr/zeek/logs/current` → berakhir di
   `spool/zeek` (bukan `spool/zeek/current`), dan dokumen baru masuk:
   `curl -s "localhost:9200/ndr-zeek-dns-*/_count"`.
3. UI → Alert Center terbuka tanpa error boundary; klik satu alert →
   detail terbuka (bukan 502).
4. UI → Event Search → preset "All DNS events" → hits > 0.
5. UI → DNS & TLS → rasio NOERROR ≤ 100% dan penyebutnya "dengan
   response"; JA3 teratas & Issuer terisi (data baru bertahap).
6. UI → Dashboard: Events/Throughput/Hosts/Zone throughput terisi
   (agregasi 24 jam pertama bisa lambat beberapa detik saat pertama).
7. UI → Rule Manager: kartu Rules/Sensor memakai `/api/rules/status`
   (bila file tak terlihat, kartu menampilkan PATH persis untuk
   diagnosa mount).
8. Sensors: panel "Component pipeline" menampilkan metrik komponen dari
   health doc baru (muncul dalam 1 interval health, ~60 s).

## 4. Rollback

```bash
sudo rsync -a --delete --exclude '.env' --exclude 'sensor/suricata/rules' \
  /var/lib/ndr/backup/opt-ndr-code-pre-0161-<TS>.tgz  # gunakan tar -x ke /tmp dulu
cd /opt/ndr && docker compose build && sudo bash scripts/upgrade.sh
```

Kode 0.16.1 tidak mengubah skema/data → rollback aman ke 0.16.0/0.15.0.
Dokumen JA3/issuer baru tetap valid di index lama (field sudah ada di
template sejak 0.12.9).

## 5. Catatan

* **MTTA** sengaja tidak dihitung (tidak ada timestamp ack terpisah);
  Reports menampilkan MTTR dari insiden closed. Jangan tafsir 0 sebagai
  "tak pernah ditangani".
* **JA3 pipeline** dihitung dari field client-hello Zeek (GREASE
  dibuang). Hash konsisten internal; bisa berbeda kecil vs tool pyshark.
* **Komponen sensor** di panel Sensors = metrik pipeline, bukan CPU
  proses Zeek/Suricata (lintas container tidak dapat diamati) — pakai
  `docker stats` untuk CPU host.
* Konsol nama ("Ever SEEN" dsb.) diatur di Settings → System; login dan
  layout kini konsisten memakai "NDR Console" sebagai default.
