# CHANGELOG - v0.16.0

Rilis Fase 1 blueprint 19 requirement tender. Fokus: fitur investigasi
dan pelaporan (filter, export, DNS, geo, stats, live), bake SSO ke
produk, dan penguatan skema alert. Tidak mengubah algoritma deteksi
lama; dua detector baru (auth brute force, gambling watchlist) mengikuti
protokol flag env + kill switch yang diwajibkan CATATAN-REVIEW.

## Requirement yang tercapai di rilis ini

| R | Requirement | Implementasi |
|---|-------------|--------------|
| R1 | Deteksi multi-engine | `detection_engine` (signature/behaviour/intel) pada SEMUA alert + detector `auth_bruteforce_suspected` (flag `DETECT_BRUTEFORCE`) |
| R3 | Status anomali | `attack_status` kosakata tender: attack_successful / attempt / failure / indeterminate; bukti HTTP status menang atas verdict kategori; compromise TIDAK pernah diklaim di level alert |
| R5 | Filtering custom | Filter DSL AST JSON (`and/or/not`, `is/is_one/include/exclude`, range, CIDR) - whitelist field/op per konteks, nesting max 6, injeksi mustahil; dipakai di alerts search/stats/export + DNS |
| R6 | Export alert | `POST /api/alerts/export` xlsx/csv: search_after pagination, cap `EXPORT_MAX_ROWS` (default 50k), audit per permintaan; tombol UI di Alert Center |
| R7 | Informasi DNS | `ndr-zeek-dns` + API `/api/dns/summary|search`: rasio resolved (NOERROR+answers) vs gagal, top domain/klien, tabel transaksi request+response lengkap |
| R8 | Deteksi DGA | `dga_score` 0-100 (normalisasi mean entropy) pada alert dga_suspected |
| R9 | Trafik terenkripsi | `/api/tls/summary`: versi TLS, JA3, SNI, issuer (metadata-only, tanpa dekripsi) |
| R10 | Penjelasan + TTP + CVE | `explanation` (Bahasa Indonesia, index:false), parser CVE dari signature/reason, `mitre` terindeks (fix mapping), kill_chain per alert |
| R12 | GeoIP+ASN+Org | Alert diberi `geo_src`/`geo_dst` (country/iso/asn_org) terpusat via `_AlertGeoTagger` dari GeoEnricher yang sama; event `source.geo`/`destination.geo` (GeoLite2/DBIP atau JSON sidecar); tanpa DB = jujur kosong |
| R13 | SSO Arkime | BAKED: router `arkime_proxy` (proxy passthrough + relay cookie + retry 403), `config.ini.template` webBasePath+header-auth dirender entrypoint, compose env `ARKIME_PROXY_SECRET`/`ARKIME_PUBLIC_BASE` di API & Arkime, `.env.example` + dokumentasi rotasi. Secret kosong = SSO off (503 jujur), tanpa patch manual |
| R14+15 | Kelola rule + statistik hit | Tabel Postgres `rule_stats` + refresher 15 menit (`RULE_STATS_REFRESH_MIN`), agregasi terms 24h/7d + sev_max + last_hit + sample alert; `GET /api/rules/stats`; kolom Hits 24h/7d + Last hit + badge noisy di Rule Manager |
| R18 | Judi Online | `GamblingWatchlist` (keyword + domain file) -> tag campaign `judi-online` di event; detector `gambling_access` (flag `DETECT_GAMBLING`); view `/api/gambling/*` + menu UI |
| R19 | Graph trafik realtime | `GET /api/metrics/live` SSE 2 detik (eps, eps per engine, antrean, alerts/events 5 menit) + widget Live Traffic di Dashboard + cap 20 koneksi |

## Bugfix penting

- **bootstrap ALERT_FIELDS**: `mitre`, `kill_chain`, `attack_phase`
  sejak lama ditulis builder tetapi tidak dideklarasikan pada mapping
  (`dynamic:false`) sehingga TIDAK terindeks; agregasi
  `by_mitre`/`by_kill_chain` di `/api/alerts/stats` gagal di OS live.
  Kini didaftarkan (+ `geo_src`/`geo_dst`).
- **Kontrak `/api/alerts/stats` (bug A6)**: buckets kini LIST
  `{key,count}` urut count desc (yang dijanjikan kontrak UI); bentuk
  dict 0.13.0 tetap tersedia di `aggregations.*` - dua generasi aman.
- **Export column guard**: kolom tanpa titik (mis. `raw_event`) dulu
  lolos ke backend; sekarang whitelist PENUH (exact atau dot-prefix).
- **`_cell` rollup**: `mitre.techniques`/`top_rules.signature` selalu
  kosong karena traversal dot menabrak list; ditangani sebelum walk.
- **Router baru tanpa `request`**: `dns_summary`, `tls_summary`,
  `gambling_summary`, `gambling_events` memanggil `audit(request)`
  tanpa parameter (NameError 500 saat dipanggil) - diperbaiki.
- Arkime `build_expression`: IP/port TANPA kutip (quirk viewer 5.6.2 -
  `'ip == "x"'` -> "not a valid ip"); deep-link ke PUBLIC BASE via
  proxy SSO, bukan URL viewer internal.

## Skema & infra

- Template `ndr-zeek-dns`/`ndr-zeek-tls` (replicas=0 semua).
- ALERT_FIELDS + attack_status/detection_engine/cve/dga_score/campaign/
  explanation(index:false)/mitre/kill_chain/attack_phase/geo_*.
- Postgres `rule_stats` (001_schema.sql + create_all idempoten).
- `.env.example`: EXPORT_MAX_ROWS, RULE_STATS_REFRESH_MIN,
  ARKIME_PROXY_SECRET, ARKIME_PUBLIC_BASE, DETECT_BRUTEFORCE*,
  GAMBLING_*, DETECT_GAMBLING*, GEOIP_*.
- Versi: api/pipeline `0.16.0`.

## API baru ringkas

```
POST /api/alerts/export        xlsx/csv (req 6)
GET  /api/dns/summary          rasio resolve + top (req 7)
POST /api/dns/search           transaksi DNS (req 7)
GET  /api/tls/summary          metadata TLS (req 9)
GET  /api/gambling/summary     ringkasan judi-online (req 18)
GET  /api/gambling/events      event ter-tag (req 18)
GET  /api/metrics/live         SSE realtime (req 19)
GET  /api/rules/stats          statistik hit (req 14/15; ?refresh=1)
ANY  /api/arkime/{rest}        SSO proxy viewer (req 13)
```

## Kualitas

- API: 238 test passed (32 baru `test_v0160_features.py`).
- Pipeline: 189 test passed (25 baru `test_v0160_detection.py`).
- UI: `tsc --noEmit` bersih + `next build` sukses.
- Detector baru mengikuti protokol: flag env default-on, kill switch
  env, canary (severity medium, tanpa klaim compromise), tanpa `text`
  analyzed (diet indeks dipertahankan).
