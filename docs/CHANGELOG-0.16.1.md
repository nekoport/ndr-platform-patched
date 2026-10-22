# CHANGELOG v0.16.1 — Perbaikan Bug Lapangan Vendor 0.16.0

Tanggal: 22 Oktober 2026
Basis: laporan deploy "apa adanya" paket vendor `ndr-platform-0.16.0.tar.gz`
(sha256 `bf06e3e8...`) di VM 10.0.106.232 — dokumen:
`LAPORAN-BUG-VENDOR-0.16.0.md`.

## Prinsip perbaikan

* **Tanpa overclaim**: setiap angka yang tampil berasal dari agregasi nyata;
  bagian yang tidak bisa dihitung di-*degrade* secara jujur (kosong + catatan),
  tidak pernah difabrikasi.
* **Degradasi tidak boleh mematikan fitur lain**: satu endpoint yang gagal
  tidak lagi mengosongkan seluruh halaman.
* **Semua fix terlindungi test** (regresi permanen).

## P0 (blocker)

| # | Bug lapangan | Akar masalah | Perbaikan 0.16.1 |
|---|---|---|---|
| P0-1 | API crash total (`ModuleNotFoundError: openpyxl`) | `alerts.py` mengimpor openpyxl top-level; dependency tidak ada di `api/requirements.txt` | `openpyxl>=3.1` ditambahkan ke requirements **dan** import XLSX dibuat lazy — bila dependency tetap hilang, hanya export XLSX yang menjawab 503, API tetap hidup |
| P0-2 | Pipeline buta terhadap seluruh log Zeek | `entrypoint.sh` membuat symlink `logs/current -> spool/zeek/current` padahal zeekctl menulis ke `spool/zeek/` langsung | symlink diperbaiki ke `spool/zeek` + **self-heal** tiap 60 s di loop supervisi (membuat ulang bila zeekctl deploy/cron menggantinya) |
| P0-3 | Alert Center blank (`Cannot read properties of null (reading 'field')`) | elemen `null` di array filter AST mencapai `.map` pembaca `leaf.field` | `sanitizeFilterAst()` (normalisasi null-safe) dipasang di 3 titik: inisialisasi rows dialog, `filterSummary`, dan saat AST masuk state (`setDslFilter`) |
| P0-4 | Detail alert 502 pada alias multi-index (9 index) | guard lama memeriksa `exc.error` = `'illegal_argument_exception'` sehingga pesan alias *has more than one index* tidak pernah kena | **Jalur utama kini ids-query (search, fan-out aman)**, bukan `GET _id`; guard RequestError kini memeriksa seluruh `exc.args` |
| P0-5 | Event Search selalu 0 hasil (term teks `"dns"` ke field `ip`) | UI membangun DSL simple di client dengan `term source.ip` untuk teks apa pun | mode simple kini mengirim `query_text`; **API membangun query-nya sendiri**: fast-path event_type (`dns`→`term event_type`), fast-path IP/CIDR (`term` field ip), sisanya wildcard case-insensitive pada whitelist field teks — tidak pernah menyentuh field ip dengan teks; preset "All DNS events" = `term event_type:dns` eksplisit |

## P1 (major)

| # | Bug | Perbaikan |
|---|---|---|
| P1-1 | KPI "Events (24h)" 0 padahal timeline 10,2 jt | `events_24h` tetap eksak (count API) dan UI kini memakainya bersama timeline nyata |
| P1-2 | Dashboard/Topology/Assets/Reports semua nol | `GET /api/stats/overview` kini mengisi field rich dari agregasi NYATA: `hosts` (top talker internal + bytes in/out + status heuristik dari alert), `zone_traffic` (Mbps per zone dari NetworkZone Postgres), `protocols`, `top_ports`, `top_dns`, `top_http_hosts`, `top_tls_sni`, `alert_daily_7d`, `alerts_7d`, `events_7d`, `mttr` (dari insiden closed 7d), `traffic_24h`, `hosts_monitored/at_risk/watch`. MTTA di-*null*-kan dengan jujur (tidak ada timestamp ack terpisah). UI `getRichOverview` memetakan semuanya |
| P1-3 | Rule Manager "suricata.rules not found" + "Sensor: offline" | Endpoint baru **`GET /api/rules/status`** (ringan, tanpa parsing 45 MB) menampilkan path/socket PERSIS dari perspektif container API; UI memakai status ini untuk kartu KPI, fetch status **terpisah** dari summary/list sehingga satu kegagalan tidak mengosongkan halaman; label kini jujur ("memuat…", path eksplisit) bukan klaim "not found" |
| P1-4 | Rasio DNS 9133% mustahil | penyebut = dokumen dengan `dns.rcode` (agg filter `exists`, eksak — tidak terpengaruh cap `track_total_hits`), pembilang = bucket NOERROR dari agg yang sama; `no_response` dilaporkan terpisah; total dokumen tetap tersedia (eksak via agg `match_all`) untuk konteks |
| P1-5 | JA3 & issuer TLS kosong | (a) TLS Insights kini **fan-out 2 alias** (`ndr-zeek-tls-read` + `ndr-suricata-read`) sehingga JA3/issuer Suricata EVE (`tls.ja3.hash`, `tls.issuerdn` yang sudah dinormalisasi) ikut teragregasi; (b) **JA3 Zeek dihitung di pipeline** dari bahan client-hello yang Zeek 5+ log (`client_cipher_suites/extensions/curves/point_formats`, md5 sesuai spec JA3, GREASE dibuang) — deterministik, teruji, tanpa plugin; hash konsisten internal untuk agregasi & threat-hunting (perbedaan kecil vs implementasi pyshark dicatat jujur) |

## P2 (minor / reliabilitas)

| # | Bug | Perbaikan |
|---|---|---|
| P2-1 | Metrik komponen sensor kosong | health doc pipeline kini membawa `components` (tailer/ingest-zeek/ingest-suricata/normalize/detection/sink/correlation — metrik nyata: eps, queue, backlog, pending, stories); `/api/health` meneruskannya; panel Sensors "Component pipeline" merender detail + menyembunyikan baris cpu/mem bila tidak ada data resource (CPU proses sensor lintas container tidak dapat diamati — disarankan `docker stats` di host) |
| P2-2 | Branding tidak konsisten ("Ever SEEN" vs "NDR Console") | login kini konsisten "NDR Console — Network Detection & Response" (subjudul basi "Phase 0-2" dihapus); nama konsol setelah login tetap dari Settings → System (satu sumber kebenaran; ubah di sana bila ingin nama lain) |
| P2-3 | Secret JWT lemah (9 byte) | `config.py` menolak secret < 32 char: menurunkan secret acak ephemeral + WARNING keras (sesi hangus saat restart) — tetapkan `JWT_SECRET` permanen di `.env` (`openssl rand -hex 32`; `install.sh` sudah melakukannya otomatis) |
| P2-4 | Total hit ter-cap 10.000 tampil apa adanya | `SearchRequest.exact_total` (opsional) → `track_total_hits: true`; UI menampilkan penanda `>=` + tombol "Hitung total persis"; DNS/TLS memakai agg `match_all` untuk total eksak |
| P2-5 | `docker compose up -d` tidak mengganti container suricata | `scripts/upgrade.sh` kini `--force-recreate` untuk layer aplikasi + sensor; aman terhadap checkpoint pipeline v2 (validasi [dev,ino]) |
| P2-6 | `GET /api/alerts/search` jatuh ke `/{alert_id}` (502) | route eksplisit `GET /api/alerts/search` → **405** dengan petunjuk method |
| P2-7 | `GET /api/version` 404 | endpoint baru `/api/version` (tanpa auth, ringan) + `scripts/upgrade.sh` mem-probe endpoint ini |

## Test

* Pipeline: `197 passed` (termasuk 7 test baru `test_v0161_fixes.py`: vektor JA3,
  GREASE, normalizer tls Zeek, komponen health, queue penuh).
* API: `255 passed` (termasuk 16 test baru `test_v0161_fixes.py` + 2 test
  kontrak v0.16.0 diperbarui ke kontrak benar: rasio DNS ≤100% dan total TLS eksak).
* UI: `tsc --noEmit` 0 error; `next build` sukses.
