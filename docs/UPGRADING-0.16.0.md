# UPGRADE 0.15.0 -> 0.16.0

Upgrade in-place tanpa reset data. Estimasi downtime: 2-5 menit
(restart API/UI/pipeline; Arkime hanya bila SSO diaktifkan).

## 0. Prasyarat

```bash
# di VM, dari direktori deployment lama
cp .env .env.backup-0.15.0
docker compose ps   # catat layanan yang hidup
```

## 1. Ambil versi baru

```bash
tar xzf ndr-platform-0.16.0.tar.gz -C /opt/ndr-new
cd /opt/ndr-new/ndr-platform
cp /path/to/.env.backup-0.15.0 .env
```

## 2. Tambah env baru di .env (opsional per fitur)

```bash
# SSO Arkime (req 13) - aktifkan bila ingin SSO:
echo "ARKIME_PROXY_SECRET=$(openssl rand -hex 24)" >> .env
# (default ARKIME_PUBLIC_BASE=/backend/api/arkime sudah cocok dgn UI)

# rule stats (req 14/15): default 15 menit; 0 = matikan
echo "RULE_STATS_REFRESH_MIN=15" >> .env
# export alert (req 6)
echo "EXPORT_MAX_ROWS=50000" >> .env
```

Tanpa env apapun pun, upgrade tetap jalan: SSO off (proxy 503 jujur),
detector baru default-on (matikan dengan `DETECT_BRUTEFORCE=0`
/ `DETECT_GAMBLING=0`), GeoIP tetap off sampai `GEOIP_MMDB_PATH` diisi.

## 3. Build + restart

```bash
docker compose build api ui pipeline
docker compose up -d
# profile sensor (bila Arkime dipakai dan SSO diaktifkan):
docker compose --profile sensor up -d arkime
```

- Postgres: tabel `rule_stats` dibuat otomatis (create_all idempoten
  pada boot API; fresh install lewat postgres/init/001_schema.sql).
- OpenSearch: bootstrap meng-update template (idempoten). Index BARU
  langsung punya mapping lengkap; index LAMA mendapat mapping baru
  hanya untuk index berikutnya (rollover) - perilaku normal ISM.

## 4. Verifikasi 10 menit

```bash
# 1. versi
curl -s http://127.0.0.1:${API_PORT}/api/meta | grep 0.16.0
# 2. health
curl -s http://127.0.0.1:${API_PORT}/api/health | jq .status
# 3. router baru terpasang (401/403 = terpasang; 404 = gagal build)
for p in dns/summary tls/summary gambling/summary rules/stats; do
  curl -s -o /dev/null -w "%{http_code} /api/$p\n" \
    http://127.0.0.1:${API_PORT}/api/$p
done
# 4. SSE hidup (harus stream data: {...} lalu Ctrl-C)
curl -N http://127.0.0.1:${API_PORT}/api/metrics/live --max-time 5
# 5. rule stats terisi setelah <= 15 menit (atau paksa):
#    UI Rule Manager -> badge "rule stats: aktif (rule_stats)"
# 6. SSO (bila diaktifkan): login UI -> Alert Center -> alert detail ->
#    "Buka sesi asli di Arkime Viewer" -> viewer terbuka TANPA login.
#    Gagal 403? cek ARKIME_PROXY_SECRET sama di kedua layanan +
#    `docker compose logs arkime | grep SSO`
```

## 5. Rollback

```bash
cd /path/0.15.0 && docker compose up -d --build
# tabel rule_stats tidak mengganggu versi lama (tidak di-pakai);
# env tambahan diabaikan versi lama.
```

## Catatan khusus

1. **Template OpenSearch diperbarui oleh bootstrap** (idempoten,
   pola `aliases` di dalam `template` yang terbukti sejak 0.12.5).
   Jangan edit template manual di OS.
2. **webBasePath Arkime WAJIB trailing slash** - sudah dijamin
   entrypoint 0.16.0 (`${WEB_BASE%/}/`). Jangan kembalikan ke
   konfigurasi manual lama tanpa slash (asset 404 -> halaman putih).
3. **Kontrak `/api/alerts/stats`**: buckets kini list `{key,count}`;
   UI 0.16.0 memakai bentuk baru. Integrasi eksternal yang memakai
   bentuk dict pindah ke `aggregations.*` (tetap disediakan).
4. **GeoIP**: isi `GEOIP_MMDB_PATH` (GeoLite2-City / DBIP city-lite
   + file ASN) lalu restart pipeline. Tanpa DB, alert tetap sehat
   (geo kosong, tanpa fabricated data).
5. **Kill switch detector baru**: `DETECT_BRUTEFORCE=0`,
   `DETECT_GAMBLING=0` tanpa redeploy (restart pipeline saja).
