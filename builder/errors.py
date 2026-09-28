"""Exception hierarchy shared by every TikTok client layer.

Each error carries machine-readable fields next to its human message, so a
caller can branch on ``code`` without parsing Chinese text.  None of them ever
embeds a request query string: signed URLs contain ``msToken``/``X-Bogus``/
``X-Gnarly`` and device ids, which must not reach logs via ``str(exc)``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


class TiktokError(RuntimeError):
    """Base class for every error raised by this package."""


class BrowserEvidenceError(TiktokError):
    """The request cannot match the browser wire contract."""


class TransportError(TiktokError):
    """The HTTP exchange itself failed (network error or non-2xx status)."""

    def __init__(self, message: str, *, method: str = "", url: str = "",
                 http_status: int | None = None):
        self.method = method.upper()
        self.path = redact_url(url)
        self.http_status = http_status
        suffix = f" [{self.method} {self.path}" + (
            f" -> HTTP {http_status}]" if http_status is not None else "]")
        super().__init__(message + suffix)


class BusinessError(TiktokError):
    """HTTP 200 with a non-success business code in the JSON body.

    TikTok reports risk control, captcha demands, rate limits and parameter
    errors this way.  Treating such a body as a normal result makes a failed
    write indistinguishable from a successful one.
    """

    def __init__(self, *, path: str, code: Any, message: str = "",
                 log_id: str = "", payload: Mapping | None = None):
        self.path = redact_url(path)
        self.code = code
        self.status_message = str(message or "")[:300]
        self.log_id = str(log_id or "")
        # Kept for programmatic inspection only; never formatted into str().
        self.payload = dict(payload or {})
        detail = f"code={code!r}"
        if self.status_message:
            detail += f", message={self.status_message!r}"
        if self.log_id:
            detail += f", log_id={self.log_id}"
        super().__init__(f"TikTok 业务失败 [{self.path}]: {detail}")


class VerificationRequired(BusinessError):
    """The server demands an interactive challenge (captcha / 2FA / SMS).

    The library never solves these; the caller must hand the challenge to a
    human (for example by completing it in the same browser session) and
    re-capture the session state afterwards.
    """


def redact_url(url: str) -> str:
    """Return ``host/path`` only — the query string never leaves this module."""
    parts = urlsplit(str(url or ""))
    if parts.netloc:
        return f"{parts.netloc}{parts.path}"
    return parts.path or ""
