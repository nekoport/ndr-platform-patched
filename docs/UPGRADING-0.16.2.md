# UPGRADING — 0.16.1 → 0.16.2

**Target:** VM NDR 10.0.106.232 (`/opt/ndr`, Docker Compose)
**Estimasi downtime:** < 2 menit (recreate aplikasi + sensor), backlog ditangani tanpa banjir (pacing aktif otomatis).

---

## 0. Prasyarat

```bash
cd /opt/ndr
# backup rutin (sesuai kebiasaan 0.16.1)
tar -czf /var/lib/ndr/backup/opt-ndr-code-pre-0162-$(date +%Y%m%dT%H%M%S).tgz \
    --exclude=.env --exclude=sensor/suricata/rules .
cp .env /var/lib/ndr/backup/env-pre-0162-$(date +%Y%m%dT%H%M%S).txt
```

## 1. Langkah upgrade

```bash
cd /opt/ndr
# 1) ekstrak paket baru (jangan menimpa .env dan ruleset)
rsync -a --delete \
      --exclude=.env --exclude=sensor/suricata/rules \
      /tmp/ndr-0162/ /opt/ndr/

# 2) build SEMUA image (0.16.2 sudah termasuk profil sensor di upgrade.sh,
#    tapi pre-build eksplisit tetap menjadi kebiasaan aman)
docker compose --profile sensor build

# 3) jalankan upgrade (kini otomatis: build sensor + rotasi JWT lemah)
bash scripts/upgrade.sh
```

`upgrade.sh` 0.16.2 otomatis:
- membangun image **termasuk profil sensor** (BUG-0161-03) — tidak perlu lagi pre-build manual untuk kebenaran upgrade;
- merotasi `JWT_SECRET` lemah/placeholder di `.env` (BUG-0161-06) dengan backup `.env.bak-jwt-*` bila Anda belum merotasi manual seperti saat verifikasi.

## 2. Perubahan infrastruktur yang perlu diketahui

| Perubahan | Dampak | Tindakan operator |
|---|---|---|
| Volume baru `api-state` (mount `/var/lib/ndr-api`) | Dibuat otomatis saat `up`; menyimpan fallback secret JWT | Tidak ada; jangan hapus volume ini (sesi hangus bila dihapus tanpa `JWT_SECRET` di `.env`) |
| `JWT_SECRET` dirotasi otomatis oleh upgrade.sh (bila lemah) | Semua sesi user hangus sekali (login ulang) | Informasikan pengguna |
| Env pipeline baru (semua punya default yang sudah baik) | Replay deadletter + pacing aktif otomatis | Opsional menyetel ulang: lihat `.env.example` blok `v0.16.2 (BUG-0161-04)` |

Kill switch yang tersedia (tambahkan di `.env` lalu recreate pipeline):
```bash
PIPELINE_DLQ_REPLAY=0                          # matikan replay deadletter
PIPELINE_CATCHUP_PACE_THRESHOLD_SECONDS=0      # matikan pacing catch-up
PIPELINE_SINK_COOLDOWN_MAX_SECONDS=0           # matikan sink breaker (tidak disarankan)
```

## 3. Verifikasi pasca-upgrade (± 10 menit)

1. **Versi & kesehatan**
   ```bash
   curl -s http://127.0.0.1:${API_PORT:-8080}/api/version | jq .version   # "0.16.2"
   docker compose ps                 # 8/8 Up
   ```
2. **KPI Dashboard** — login UI → Dashboard: kartu **Events (24h)** kini > 0 (angka eksak = `total` timeline), delta "vs prev 24h" terisi.
3. **Reports** — semua kartu terisi: Alerts (7d), Events processed, Avg MTTR/Mms, Closed/FP; chart "Detection volume - 7 days" menampilkan stacked severity harian.
4. **Timeline engines** — `curl -s "http://127.0.0.1:${API_PORT:-8080}/api/events/timeline?hours=4" -H "Cookie: <sesi>" | jq '.points[0].engines'` → berisi `zeek`/`suricata`. Bila muncul `warnings`, index lama tidak ikut split engine (count tetap eksak).
5. **Replay deadletter** — log pipeline (`docker logs ndr-pipeline 2>&1 | grep replay`) menampilkan `[replay] deadletter replayer aktif`. Record baru `sink_timeout` (bila ada) akan muncul `dlq_replayed` di metrics; cek `curl -s localhost:${METRICS_PORT:-9100}/metrics | grep -E "dlq_|sink_cooldown"`.
6. **Branding** — judul tab & sidebar **NDR Console** (bukan "Ever SEEN") setelah login pertama.
7. **Sesi stabil** — login 4× berturut-turut tanpa 401 "Invalid session" (JWT kini konsisten lintas worker/restart).

## 4. Rollback

```bash
docker compose down
rsync -a --delete --exclude=.env --exclude=sensor/suricata/rules \
      /var/lib/ndr/backup/opt-ndr-code-pre-0162-*.tgz /tmp/rollback/  # ekstrak dulu
rsync -a --delete --exclude=.env --exclude=sensor/suricata/rules /tmp/rollback/ /opt/ndr/
docker compose --profile sensor up -d --build
```
Checkpoint pipeline dan deadletter berada di volume `ndr-pipeline-state` — tidak tersentuh rollback kode.

## 5. Catatan operasional

- **4.807 deadletter `sink_timeout` lama (0.16.1)** tidak dapat direplay otomatis (record lama belum menyimpan `index` tujuan). Mereka tetap tersimpan di `state/deadletter/` sesuai retensi 72 jam sebagai bukti; event mentahnya tersedia di raw archive. Untuk index ulang massal, gunakan replay manual dari raw archive (opsional, tidak wajib).
- Index lama 2026.10.14 (mapping `text`) akan menghilang sendiri oleh retensi 60 hari. Sampai saat itu, split engine pada jendela yang menyentuh tanggal tersebut tetap lengkap (varian `.keyword`), dan `warnings` timeline menandai index yang benar-benar tak teragregasi.
- OpenSearch `yellow` (8 replica unassigned) tetap normal untuk single-node; template `number_of_replicas: 0` sudah berlaku untuk index baru sejak 0.16.0.
