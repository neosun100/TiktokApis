"""HTTP transport with Chrome TLS/HTTP2 fingerprinting via curl_cffi.

curl_cffi is mandatory.  A plain ``requests`` fallback would silently lose the
TLS fingerprint, re-order headers and add default ones — every one of those is
a wire mismatch in a project whose requests are signed over header order.

Environment:
    TIKTOK_PROXY               proxy URL for every request (http/https/socks5h).
    TIKTOK_HTTP_IMPERSONATE    curl_cffi impersonation target (default "chrome").
"""

from __future__ import annotations

import os
import threading

from curl_cffi import requests as _curl
from curl_cffi.requests.exceptions import RequestException as _CurlRequestException

from builder.errors import TransportError

DEFAULT_TIMEOUT = 30

_local = threading.local()


def _session() -> _curl.Session:
    # curl_cffi sessions are not thread-safe; upload speed probes run in a
    # thread pool, so each thread keeps its own connection pool.
    session = getattr(_local, "session", None)
    if session is None:
        session = _curl.Session()
        _local.session = session
    return session


def proxy_url() -> str:
    return (os.environ.get("TIKTOK_PROXY") or "").strip()


def _kwargs(kwargs):
    values = dict(kwargs)
    values.setdefault("impersonate", os.environ.get("TIKTOK_HTTP_IMPERSONATE", "chrome"))
    values.setdefault("default_headers", False)
    values.setdefault("http_version", "v2")
    if values.get("timeout") is None:
        values["timeout"] = DEFAULT_TIMEOUT
    proxy = proxy_url()
    if proxy and "proxies" not in values and "proxy" not in values:
        values["proxy"] = proxy
    return values


def request(method, url, **kwargs):
    try:
        return _session().request(method, url, **_kwargs(kwargs))
    except _CurlRequestException as exc:
        # The curl message embeds the full URL (signed query included).
        raise TransportError(f"网络请求失败: {type(exc).__name__}",
                             method=method, url=url) from None


def get(url, **kwargs):
    return request("GET", url, **kwargs)


def post(url, **kwargs):
    return request("POST", url, **kwargs)


def ensure_ok(response, *, method: str = "") -> None:
    """Raise a redacted :class:`TransportError` for any non-2xx response."""
    status = int(getattr(response, "status_code", 0) or 0)
    if 200 <= status < 300:
        return
    url = str(getattr(response, "url", "") or "")
    raise TransportError("TikTok 返回非 2xx", method=method, url=url, http_status=status)
