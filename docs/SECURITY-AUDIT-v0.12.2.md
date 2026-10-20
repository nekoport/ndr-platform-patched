# Audit Keamanan & Integrasi pra-Deploy (v0.12.2)

Tanggal: 2026-10-13 · Ruang lingkup: jalur browser → UI → API, autentikasi,
RBAC, rate-limit, TLS, paparan port Docker, secret, dan kesesuaian seluruh
panggilan API UI vs endpoint backend. Hasil: **249 test lulus** (API 140 +
pipeline 109) + verifikasi browser alur ganti password.

## 1. Hasil audit keamanan frontend ↔ backend

### 1.1 Yang sudah kokoh (tanpa perubahan)

| Lapisan | Implementasi | Status |
|---|---|---|
| Sesi | JWT httpOnly cookie (`ndr_session`), SameSite=lax, path=/, exp 30 menit, `Secure` mengikuti `TLS_ENABLED` | ✅ |
| Revokasi | `token_version` di JWT vs DB — ganti password menarik semua sesi | ✅ |
| Password | bcrypt rounds=10, wajib ganti password bootstrap (`must_change_password`) | ✅ |
| Lockout | 5 gagal → kunci 15 menit + rate-limit login per-IP 10/5 menit | ✅ |
| RBAC | `require_permission()` backend-enforced per endpoint (UI hanya menyembunyikan tombol, backend yang memutuskan) | ✅ |
| CSRF | Same-origin proxy (tanpa CORS), SameSite=lax, body wajib JSON → form lintas-situs gagal 422 | ✅ |
| CORS | `allow_origins=[]` — tidak ada origin lintas-situs sama sekali | ✅ |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`; HSTS hanya saat TLS aktif | ✅ |
| Gateway TLS | TLS 1.2/1.3, cipher kuat, HSTS, sesi ticket off, proxy `/backend/` strip-prefix konsisten dengan rewrite UI | ✅ |
| Search guard | DSL whitelist alias + klausa, anti script/regexp/wildcard, sort whitelist, time-range wajib, rate 30/menit per user | ✅ |
| Audit | Semua mutasi tercatat ke tabel audit (login gagal pun tercatat) | ✅ |
| Paparan port | API/OpenSearch/Postgres/pipeline-metrics terikat `127.0.0.1` saja; yang terekspos jaringan hanya UI (dan gateway TLS bila profil `tls` aktif) | ✅ |
| Secret installer | `install.sh` generate acak: POSTGRES (24B), JWT (32B hex), ADMIN (18B), Arkime (16B hex); `.env` chmod 600 | ✅ |

### 1.2 Temuan & perbaikan (v0.12.2)

1. **[BLOCKER] `.env.example` tidak ada di repo/arsip** — `install.sh`
   (`cp .env.example .env`) dan `backup.sh` akan gagal di VM.
   **Perbaikan**: file dibuat lengkap (semua variabel compose wajib + tuning
   threshold deteksi + komentar Indonesia). Diverifikasi: semua `${VAR}`
   compose terisi setelah alur generate installer disimulasikan.
2. **[GAP] UI tidak punya alur ganti password** — backend menyediakan
   `POST /api/auth/change-password` + menandai `must_change_password`, tapi
   tidak ada satu pun panggilan dari UI; password bootstrap tidak pernah
   dirotasi lewat UI. **Perbaikan**: dialog ganti password (komponen baru),
   mode **forced** saat `must_change_password` (tidak bisa ditutup, ESC/
   klik-luar diblokir) dan **manual** via ikon kunci di sidebar; setelah
   sukses semua sesi dicabut → kembali ke halaman login (sinkron dengan
   perilaku backend). Demo mode mensimulasikan alur first-login.
3. **[TEST] conftest tidak kebal env warisan** — `setdefault` membuat
   `ADMIN_PASSWORD` dari shell luar mengubah bootstrap admin sehingga test
   gagal non-deterministik. **Perbaikan**: conftest memaksa kontrak test
   (JWT_SECRET/ADMIN_*/TLS_ENABLED) + script rilis menjalankan pytest di
   env bersih.
4. **[TEST] test diagnosis DNS flaky** — `getaddrinfo("localhost")` nyata
   bisa gagal transien di sandbox penuh beban; test kini memakai resolver
   deterministik (yang diuji logika endpoint, bukan resolver OS).

### 1.3 Trade-off yang disengaja (dokumentasikan ke tim)

- `DISABLE_SECURITY_PLUGIN=true` pada OpenSearch: diterima karena 9200 hanya
  terikat `127.0.0.1` + jaringan docker internal. **Jangan pernah** publish
  9200/5432/8080 ke LAN.
- Tanpa profil `tls`, UI dilayani HTTP — cookie sesi tidak berflag Secure.
  Untuk pemakaian lab internal via SSH tunnel ini ok; untuk akses LAN lebih
  lebar, aktifkan profil TLS (`TLS_ENABLED=1`).

## 2. Hasil verifikasi integrasi UI ↔ API

- **Semua** panggilan `fetch` di `ui/lib/ndr/api.ts` (statis + dinamis)
  dipetakan ke endpoint backend yang benar: auth (4), health/stats (2),
  events/alerts search, incidents (detail/status/notes/reports), campaigns,
  assets CRUD, users/roles, sensors, audit, settings (system/branding/ntp/
  network/diagnosis), TI (overview/feeds/jobs/iocs/matches/allowlist),
  rules (summary/list/update/validate/toggle/custom CRUD), evidence
  (storage/sessions/export/download/arkime-status), graph (relationships/
  geo). Tidak ada endpoint yatim di kedua arah.
- Jalur sama-origin: browser → `/backend/*` (rewrite Next.js → `ndr-api:8080`
  di jaringan compose) → cookie httpOnly mengalir tanpa CORS. NTP status
  menggunakan POST sesuai backend. Download PCAP memakai URL proxy yang sama.
- Session bootstrap: `me()` 401 → UnauthorizedError → layar login; sesi
  demo (`?demo=1` / `NEXT_PUBLIC_DEMO_MODE`) terpisah dari jalur live.
- `NEXT_PUBLIC_DEMO_MODE` dibake saat build (`ARG` default `false`) — image
  produksi otomatis mode live.
- Rate-limit vs polling UI: dashboard 45 dtk, view data 60 dtk (bukan
  endpoint search) — jauh di bawah batas 30/menit untuk search.
- Regresi: **API 140 + pipeline 109 = 249 lulus** (termasuk dari dalam
  arsip rilis). Browser: alur ganti password forced + manual diverifikasi
  tanpa error konsol (uiverify/63, 64).

## 3. Checklist deploy ke VM (trafik SPAN asli)

1. Salin arsip ke VM, ekstrak, lalu `sudo ./install.sh --sensor`
   (installer kini berjalan: `.env.example` tersedia).
2. Periksa `.env`: `CAPTURE_IFACE` (interface SPAN), `NDR_DATA_ROOT`,
   `UI_PORT`; secret otomatis ter-generate. Catat password admin yang
   dicetak installer.
3. Verifikasi SPAN dulu tanpa sensor: `sudo ./scripts/sensor-precheck.sh
   <iface>` — harus terlihat paket (sampling 5 detik); periksa offload dan
   `rx_dropped`.
4. Pasca-install: `./scripts/healthcheck.sh`; login UI → **dialog ganti
   password muncul otomatis** → buat password baru → login ulang.
5. Keamanan akses: terima sertifikat self-signed `deploy/tls/ca.crt` di
   browser ATAU ganti `server.crt/key` dengan sertifikat CA internal;
   `TLS_ENABLED=1 docker compose --profile tls up -d gateway`.
6. Batasi akses: hanya port UI/gateway yang boleh terbuka; 9200/5432/8080
   tetap localhost. Untuk akses jarak jauh tanpa TLS, gunakan SSH tunnel:
   `ssh -L 3000:127.0.0.1:3000 user@vm`.
7. Amati pipeline: `make logs S=ndr-pipeline`; EPS dan last-event akan
   bergerak begitu Zeek/Suricata menulis log dari trafik SPAN; alert
   behavioral (port scan, beaconing, DGA, dll.) muncul di Alert Center.
