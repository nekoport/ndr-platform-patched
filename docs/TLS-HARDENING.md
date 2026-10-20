# TLS Hardening (v0.12)

Dokumen ini menjelaskan pengamanan transport NDR Platform: HTTPS
termination lewat gateway nginx (profil compose `tls`), hardening
header pada API, dan perilaku cookie sesi yang mengikuti status TLS.
Semua langkah dapat dijalankan pada VM tunggal yang sama tanpa
mengubah perilaku deployment HTTP demo.

## 1. Ringkasan kontrol

| Kontrol | Lokasi | Perilaku |
|---|---|---|
| Security headers | `api/app/main.py` middleware `security_headers` | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` pada SEMUA respons API |
| HSTS | middleware API + `deploy/tls/nginx-tls.conf` | Hanya aktif ketika benar-benar melayani HTTPS (`TLS_ENABLED=1`); tidak pernah diiklankan di atas HTTP biasa |
| Cookie `Secure` | `api/app/security.py::set_session_cookie` | `Secure` otomatis ketika `TLS_ENABLED=1`; tetap `HttpOnly; SameSite=Lax` di semua mode |
| TLS 1.2/1.3 + cipher modern | `deploy/tls/nginx-tls.conf` | Hanya ECDHE + AES-GCM/CHACHA20, session tickets off, HTTP/2 |
| Sertifikat | `scripts/gen-certs.sh` | CA lokal + sertifikat server SAN (`ndr.local`, `localhost`, `127.0.0.1`), DH params 2048 |

## 2. Membuat sertifikat (lab / self-signed)

```bash
cd /opt/ndr-platform          # lokasi repo di VM
./scripts/gen-certs.sh ndr.local
```

Hasil di `deploy/tls/`:

- `ca.crt` / `ca.key` - CA lokal (JANGAN menaruh `ca.key` di server produksi)
- `server.crt` / `server.key` (chmod 600) - pasangan server, sudah ditandatangani CA lokal
- `dhparam.pem` - parameter Diffie-Hellman

Import `ca.crt` ke browser/workstation analis (ATAU terima warning
self-signed). Untuk produksi, ganti `server.crt`/`server.key` dengan
pasangan dari PKI internal - nama file dipertahankan sehingga compose
tidak perlu diubah.

## 3. Mengaktifkan gateway TLS

```bash
TLS_ENABLED=1 docker compose --profile tls up -d gateway
```

- `gateway` (nginx:1.27-alpine) meneruskan:
  - `https://host/` -> `ndr-ui:3000` (UI Next.js)
  - `https://host/backend/*` -> `ndr-api:8080/*` (prefix di-strip,
    identik dengan rewrite Next.js di mode tanpa gateway)
  - `http://host/*` -> redirect 301 ke HTTPS (placeholder ACME tetap terbuka)
- Variabel port: `TLS_HTTP_PORT` (default 80), `TLS_HTTPS_PORT` (default 443).
- API mendapat `TLS_ENABLED=1` dari environment sehingga cookie sesi
  diterbitkan dengan flag `Secure` dan respons API menyertakan HSTS.

Verifikasi cepat:

```bash
curl -sSI https://127.0.0.1/api/meta -k | grep -iE "strict-transport|x-frame|x-content"
curl -sS  https://127.0.0.1/api/meta -k
openssl s_client -connect 127.0.0.1:443 -brief </dev/null 2>&1 | head -3
```

## 4. TLS tanpa gateway (uvicorn langsung)

Jika memilih TLS langsung pada API tanpa nginx:

```bash
TLS_ENABLED=1 uvicorn app.main:app --host 0.0.0.0 --port 8443 \
  --ssl-certfile deploy/tls/server.crt --ssl-keyfile deploy/tls/server.key
```

Perilaku cookie/HSTS identik karena keduanya hanya membaca
`TLS_ENABLED`.

## 5. Catatan keamanan

- Cookie sesi: `HttpOnly` + `SameSite=Lax` selalu; `Secure` mengikuti
  `TLS_ENABLED`. Masa aktif cookie = masa aktif token akses
  (`ACCESS_TOKEN_MINUTES`, default 30 menit).
- HSTS `max-age=31536000; includeSubDomains` hanya pada respons HTTPS.
  Jangan set `TLS_ENABLED=1` saat masih melayani HTTP murni - browser
  yang menghormati HSTS akan menolak akses HTTP berikutnya.
- `X-Frame-Options: DENY` menutup framing UI/API (clickjacking);
  full-screen Threat Map memakai CSS `fixed inset-0`, bukan iframe,
  sehingga tidak terdampak.
- Gateway menambahkan header yang sama untuk UI; API menambahkannya
  untuk jalur `/backend` langsung - tidak ada jalur tanpa header.
- `client_max_body_size 5m` di gateway cukup untuk unggah logo/favicon
  (batas platform 300 KB) dengan headroom.
- Rate limit login dan audit tetap berlaku tidak tergantung transport.
