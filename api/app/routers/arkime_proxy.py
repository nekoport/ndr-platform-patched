"""SSO reverse proxy into the Arkime viewer (doc 15 evidence workflow).

Why this exists: the viewer has its own user store, so jumping from the
NDR console used to mean a second login (or shared passwords). Instead
the viewer trusts ONLY this proxy: it listens on the sensor LAN but
accepts solely requests carrying the NDR username + proxy secret headers
(header-auth, auto-provisioning unknown users). Browsers can never talk
to it directly (401 without the headers).

Flow: browser (NDR session cookie, same origin /backend/* rewrite) ->
FastAPI (validates NDR session + `evidence_export` capability, asserts
NDR username) -> viewer 127.0.0.1:8005 (header-auth). First visit
auto-creates the Arkime account (userAutoCreateTmpl in config.ini).

Security notes:
- gated on `evidence_export` (raw PCAP access), same as selective
  export: auditors keep metadata via the NDR UI, not the viewer.
- the proxy secret never leaves the server (.env 600 -> env -> viewer).
- hop-by-hop headers are stripped; the viewer's Set-Cookie (session/token
  for its own CSRF on POST APIs) is relayed under the same public prefix
  path, so it never reaches other origins; header-auth still applies on
  every request.
- viewer Location redirects are rewritten back under the proxy prefix.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from app.config import config
from app.models import User
from app.security import require_permission

router = APIRouter(prefix="/api/arkime", tags=["arkime-sso"])

USER_HEADER = "x-ndr-user"
SECRET_HEADER = "x-ndr-proxy-key"

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}
_DROP_RESP = {"content-encoding", "content-length", "transfer-encoding",
              "connection"}


def _target_url(request: Request) -> str:
    """`/api/arkime/<sub>` here becomes `<public_base>/<sub>` on the
    viewer: the viewer's webBasePath IS the public prefix (so its
    injected `<base href>` matches what the browser sees) and it
    strips that prefix itself."""
    base = config.arkime_viewer_url.rstrip("/")
    prefix = (config.arkime_public_base or "/api/arkime").rstrip("/")
    sub = request.url.path[len("/api/arkime/"):]
    return f"{base}{prefix}/{sub}"


@router.api_route("/{subpath:path}",
                  methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def arkime_proxy(subpath: str, request: Request,
                       user: User = Depends(
                           require_permission("evidence_export"))):
    secret = config.arkime_proxy_secret
    if not secret:
        raise HTTPException(500, "Arkime SSO proxy not configured "
                                 "(ARKIME_PROXY_SECRET empty)")
    body = await request.body()
    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }
    fwd_headers[USER_HEADER] = user.username
    fwd_headers[SECRET_HEADER] = secret
    # NOTE: the httpx client must stay open until the response stream
    # is fully consumed, so it is closed via BackgroundTask (closing it
    # here would break StreamingResponse mid-send with ReadError).
    client = httpx.AsyncClient(timeout=60.0, follow_redirects=False)
    try:
        upstream = await client.send(
            client.build_request(
                request.method, _target_url(request),
                headers=fwd_headers,
                content=body or None,
                params=dict(request.query_params)),
            stream=True)
        if upstream.status_code == 403 and request.method in ("GET", "HEAD"):
            # First visit races viewer-side auto-provisioning (the
            # account is created mid-request and the role check runs
            # before it lands); one retry lands on the fresh account.
            await upstream.aread()
            await upstream.aclose()
            upstream = await client.send(
                client.build_request(
                    request.method, _target_url(request),
                    headers=fwd_headers,
                    content=body or None,
                    params=dict(request.query_params)),
                stream=True)
    except Exception as exc:  # noqa: BLE001 - viewer down -> honest 502
        await client.aclose()
        raise HTTPException(502, f"Arkime viewer unreachable: "
                                 f"{type(exc).__name__}")
    resp_headers: dict[str, str] = {}
    for k, v in upstream.headers.multi_items():
        if k.lower() in _DROP_RESP:
            continue
        if k.lower() == "location":
            internal = config.arkime_viewer_url.rstrip("/")
            if v.startswith(internal):
                v = v[len(internal):]
        resp_headers.setdefault(k, v)
    return StreamingResponse(
        upstream.aiter_bytes(),
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=upstream.headers.get("content-type"),
        background=BackgroundTask(client.aclose),
    )
