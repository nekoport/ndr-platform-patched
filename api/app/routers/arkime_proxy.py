"""SSO proxy ke Arkime viewer (v0.16.0 - requirement 13, BAKED).

Riwayat: sejak 0.12.9 fitur ini berupa patch deployment manual di VM
(9 titik patch, lihat CATATAN-REVIEW-0.15.0-dan-SSO.md). Tarball vendor
0.13-0.15 tidak pernah memuatnya. Rilis 0.16.0 membawa router ini di
dalam produk sehingga fresh install langsung punya SSO.

Cara kerja:
  * browser -> UI (same-origin) -> /backend/api/arkime/* -> rewrite ke
    API /api/arkime/* -> proxy ini -> Arkime viewer internal.
  * Sesu NDR divalidasi (cookie sesi) + permission `evidence_export`
    (auditor tanpa izin PCAP tidak dapat viewer - keputusan keamanan
    tercatat sejak 0.12.9).
  * Identitas diteruskan via header: x-ndr-user + x-ndr-secret
    (shared secret, tidak pernah keluar server). Viewer dikonfigurasi
    header-auth (userNameHeader=x-ndr-user + requiredAuthHeader/Val +
    userAutoCreateTmpl) sehingga user NDR = user viewer tanpa login
    kedua (auto-provision saat request pertama).
  * Streaming passthrough; client ditutup via BackgroundTask (bukan
    sebelum stream selesai - jebakan ReadError yang pernah terjadi).
  * Set-Cookie viewer DI-RELAY dengan path di-rewrite ke base publik
    (viewer 5.x butuh cookie + token CSRF-nya untuk API POST-nya).
  * Location (302) di-rewrite agar tetap di bawah base publik.
  * Retry SEKALI pada 403 sesaat setelah restart viewer (race
    auto-provision user).

Gotcha yang sudah dibuktikan di lapangan dan DIJAGA di sini:
  1. webBasePath viewer = base publik DENGAN trailing slash
     (/backend/api/arkime/) - tanpa slash, asset 404 -> blank putih.
  2. Forwarding menambahkan prefix publik ke path internal viewer
     (bukan root /).
  3. Ekspresi IP/port tanpa kutip (lihat arkime.build_expression).
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from app.config import config
from app.models import User
from app.security import require_permission

router = APIRouter(tags=["arkime-sso"])

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host",
    "content-length", "cookie", "authorization",
}
MAX_BODY_BYTES = 10_000_000


def _public_base() -> str:
    """Base path publik viewer di browser, selalu trailing slash."""
    base = (config.arkime_public_base or "/backend/api/arkime").rstrip("/")
    return base + "/"


def _target_url(request: Request, rest: str) -> str:
    """URL internal viewer untuk request ini.

    webBasePath viewer diset SAMA dengan prefix publik, sehingga path
    yang diteruskan HARUS menambahkan prefix publik (bukan root /).
    """
    viewer = config.arkime_viewer_url.rstrip("/")
    prefix = _public_base().rstrip("/")
    query = f"?{request.url.query}" if request.url.query else ""
    return f"{viewer}{prefix}/{rest}{query}"


def _identity_headers(user: User, request: Request) -> dict[str, str]:
    headers = {
        "x-ndr-user": user.username,
        "x-ndr-secret": config.arkime_proxy_secret or "",
        "accept-encoding": "identity",
    }
    roles = getattr(user, "role", None)
    if roles:
        headers["x-ndr-roles"] = str(roles)
    if request.client and request.client.host:
        headers["x-forwarded-for"] = request.client.host
    return headers


def _cookie_rewrite(value: str) -> str:
    """Set-Cookie viewer: path diarahkan ke base publik agar browser
    menyimpan cookie viewer di scope proxy (tidak menyebar ke origin
    lain; header-auth tetap ditagihkan per request)."""
    parts = value.split(";")
    first = parts[0]
    kept: list[str] = []
    for attr in parts[1:]:
        k = attr.strip().lower()
        if k.startswith("path="):
            continue
        kept.append(attr)
    return "; ".join([first, f"Path={_public_base().rstrip('/')}/", *kept])


def _response_headers(upstream: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    base = _public_base()
    for k, v in upstream.headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk in ("set-cookie", "content-length",
                                      "content-encoding"):
            continue
        if lk == "location" and v.startswith("/"):
            v = base.rstrip("/") + v
        out[k] = v
    cookies = upstream.headers.get_list("set-cookie")
    for idx, c in enumerate(cookies):
        name = f"x-ndr-arkime-cookie-{idx}"
        out[name] = _cookie_rewrite(c)
    return out


def _relay_cookies(response: Response, headers: dict[str, str]) -> None:
    """Pindahkan cookie yang di-rewrite menjadi header Set-Cookie sungguhan."""
    for k, v in list(headers.items()):
        if k.startswith("x-ndr-arkime-cookie-"):
            response.headers.append("set-cookie", v)
            headers.pop(k, None)


@router.api_route("/api/arkime/{rest:path}",
                  methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                           "OPTIONS"])
async def arkime_proxy(rest: str, request: Request,
                       user: User = Depends(
                           require_permission("evidence_export"))):
    # Permission model (keputusan tercatat): viewer = akses PCAP penuh.
    # Role tanpa evidence_export tidak boleh melewati proxy (sudah
    # ditolak oleh dependency require_permission di atas); metadata
    # tetap tersedia lewat UI (sessions panel / evidence API).
    if not config.arkime_proxy_secret:
        raise HTTPException(503, "SSO viewer not configured "
                                 "(ARKIME_PROXY_SECRET missing)")

    body: bytes = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, "viewer request body too large")

    url = _target_url(request, rest)
    headers = _identity_headers(user, request)
    for k, v in request.headers.items():
        if k.lower() not in HOP_BY_HOP and k.lower() not in headers \
                and k.lower() != "accept-encoding":
            headers[k] = v

    client = httpx.Client(base_url=config.arkime_viewer_url,
                          timeout=httpx.Timeout(30.0, read=120.0),
                          follow_redirects=False)

    def _close() -> None:
        client.close()

    def _build(upstream: httpx.Response) -> StreamingResponse:
        resp_headers = _response_headers(upstream)
        resp = StreamingResponse(
            upstream.iter_raw(),
            status_code=upstream.status_code,
            headers=resp_headers,
            background=BackgroundTask(_close),
        )
        _relay_cookies(resp, resp_headers)
        return resp

    try:
        upstream = client.build_request(request.method, url,
                                        headers=headers, content=body or None)
        sent = client.send(upstream, stream=True)
        # race auto-create user: viewer baru menjatuhkan 403 sebelum
        # user terprovision -> satu retry setelah jeda singkat.
        if sent.status_code == 403:
            sent.close()
            time.sleep(0.3)
            upstream = client.build_request(request.method, url,
                                            headers=headers,
                                            content=body or None)
            sent = client.send(upstream, stream=True)
        return _build(sent)
    except Exception as exc:  # noqa: BLE001
        client.close()
        raise HTTPException(502, f"Arkime viewer unavailable: "
                                 f"{type(exc).__name__}") from exc
