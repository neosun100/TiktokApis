"""Turn a live Chrome session into a ``.tiktok-runtime.json`` profile.

Two halves:

* :func:`collect_snapshot` drives Chrome (CDP) and returns *raw* evidence:
  the exact headers/URL of a real same-origin API request, cookies,
  document.cookie, both web storages and navigator/screen metrics.
* :func:`profile_from_snapshot` is pure: it maps that evidence onto the
  fields :class:`builder.auth.TiktokAuth` consumes and lists what is missing.

Values are copied from the browser, never synthesised.  A field that cannot
be found is reported in ``missing`` instead of being defaulted.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .cdp import Chrome, CDPError

ORIGIN = "https://www.tiktok.com"

# JS run inside the page: navigator/screen facts the query builders declare.
_METRICS_JS = """(() => ({
  screen_width: String(screen.width), screen_height: String(screen.height),
  browser_language: navigator.language, browser_platform: navigator.platform,
  tz_name: Intl.DateTimeFormat().resolvedOptions().timeZone,
  device_pixel_ratio: String(window.devicePixelRatio),
  inner_width: String(window.innerWidth), inner_height: String(window.innerHeight),
  cpu_core_number: String(navigator.hardwareConcurrency || ''),
  user_agent: navigator.userAgent,
}))()"""

_STORAGE_JS = """(() => {
  const dump = (s) => { const o = {}; for (let i = 0; i < s.length; i++) { const k = s.key(i); o[k] = s.getItem(k); } return o; };
  return {local: dump(localStorage), session: dump(sessionStorage), document_cookie: document.cookie};
})()"""

# Query keys of a captured web API request that are session evidence.
_QUERY_FIELDS = {
    "device_id": "device_id", "odinId": "odin_id", "region": "region",
    "priority_region": "priority_region", "WebIdLastTime": "web_id_last_time",
    "clientABVersions": "client_ab_versions",
}

# Storage keys that hold the security-sdk ticket-guard state.  Discovered by
# content, not by a fixed key name, because the key names are not yet
# confirmed on the current bundle; each hit is reported with its source key.
_TICKET_MARKERS = {
    "ticket_guard_private_key": ("-----BEGIN PRIVATE KEY-----", "ec_privateKey"),
    "ticket_guard_ts_sign": ("ts_sign",),
    "ticket_guard_encrypt_ticket": ("encrypt_ticket",),
}

REQUIRED = ("cookie", "document_cookie", "device_id", "odin_id", "user_agent",
            "local_storage", "session_storage", "browser_metrics")


def _search_json(value, key: str):
    """Depth-first lookup of ``key`` in JSON that may be nested as strings."""
    if isinstance(value, str) and value[:1] in "{[":
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if isinstance(value, Mapping):
        if key in value and isinstance(value[key], str):
            return value[key]
        for item in value.values():
            found = _search_json(item, key)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _search_json(item, key)
            if found:
                return found
    return None


def find_ticket_guard_state(storages: Mapping[str, Mapping[str, str]]) -> dict[str, dict]:
    """Locate ticket-guard material in web storage by content."""
    found: dict[str, dict] = {}
    for area, entries in storages.items():
        for key, raw in (entries or {}).items():
            text = str(raw or "")
            for field, markers in _TICKET_MARKERS.items():
                if field in found or not any(marker in text for marker in markers):
                    continue
                if field == "ticket_guard_private_key":
                    if "-----BEGIN PRIVATE KEY-----" in text and text.lstrip().startswith("-----"):
                        value = text
                    else:
                        value = _search_json(text, "ec_privateKey")
                else:
                    value = _search_json(text, markers[0])
                if value:
                    found[field] = {"value": value, "source": f"{area}:{key}"}
    return found


def profile_from_snapshot(snapshot: Mapping) -> dict:
    """Map raw browser evidence onto a runtime profile (pure function).

    Returns ``{"profile": {...}, "missing": [...], "sources": {...}}``.
    """
    request = snapshot.get("api_request") or {}
    headers = {str(k).lower(): v for k, v in (request.get("headers") or {}).items()}
    query = dict(parse_qsl(urlsplit(request.get("url", "")).query, keep_blank_values=True))
    metrics = dict(snapshot.get("metrics") or {})
    storage = snapshot.get("storage") or {}
    profile: dict = {}
    sources: dict = {}

    def put(field, value, source):
        if value not in (None, "", {}):
            profile[field] = value
            sources[field] = source

    put("cookie", headers.get("cookie"), "api_request.headers.cookie")
    put("user_agent", headers.get("user-agent") or metrics.get("user_agent"), "api_request.headers")
    put("sec_ch_ua", headers.get("sec-ch-ua"), "api_request.headers")
    put("sec_ch_ua_platform", headers.get("sec-ch-ua-platform"), "api_request.headers")
    put("accept_language", headers.get("accept-language"), "api_request.headers")
    put("tt_csrf_token", headers.get("tt-csrf-token"), "api_request.headers")
    for key, field in _QUERY_FIELDS.items():
        put(field, query.get(key), f"api_request.query.{key}")
    put("document_cookie", storage.get("document_cookie"), "page.document.cookie")
    put("local_storage", dict(storage.get("local") or {}), "page.localStorage")
    put("session_storage", dict(storage.get("session") or {}), "page.sessionStorage")
    browser_metrics = {k: metrics[k] for k in (
        "screen_width", "screen_height", "browser_language", "browser_platform", "tz_name",
        "device_pixel_ratio", "inner_width", "inner_height", "cpu_core_number") if metrics.get(k)}
    put("browser_metrics", browser_metrics, "page.navigator/screen")
    for field, hit in find_ticket_guard_state({"local": storage.get("local") or {},
                                              "session": storage.get("session") or {}}).items():
        put(field, hit["value"], hit["source"])
    missing = [field for field in REQUIRED if field not in profile]
    return {"profile": profile, "missing": missing, "sources": sources}


def _pick_api_request(chrome: Chrome, origin_host: str) -> dict:
    """The newest same-origin ``/api/`` XHR with its on-wire headers."""
    urls = {}
    for event in chrome.events("Network.requestWillBeSent"):
        params = event["params"]
        urls[params["requestId"]] = params["request"]["url"]
    best = None
    for event in chrome.events("Network.requestWillBeSentExtraInfo"):
        params = event["params"]
        url = urls.get(params["requestId"], "")
        parts = urlsplit(url)
        if parts.netloc == origin_host and parts.path.startswith("/api/") and "device_id=" in url:
            best = {"url": url, "headers": params.get("headers", {})}
    return best or {}


def collect_snapshot(chrome: Chrome, *, origin: str = ORIGIN, settle: float = 6.0) -> dict:
    """Reload the origin and collect raw evidence from the live page."""
    chrome.call("Network.enable")
    chrome.navigate(origin + "/")
    deadline = time.monotonic() + settle
    request = {}
    while time.monotonic() < deadline:
        request = _pick_api_request(chrome, urlsplit(origin).netloc)
        if request:
            break
        time.sleep(0.5)
    return {
        "captured_at": int(time.time()),
        "api_request": request,
        "metrics": chrome.evaluate(_METRICS_JS),
        "storage": chrome.evaluate(_STORAGE_JS),
    }


def logged_in(chrome: Chrome) -> bool:
    cookies = chrome.call("Network.getCookies", {"urls": [ORIGIN]}).get("cookies", [])
    return any(c.get("name") in ("sessionid", "sessionid_ss", "sid_tt") and c.get("value")
               for c in cookies)


def wait_for_login(chrome: Chrome, *, timeout: float = 600.0, poll: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if logged_in(chrome):
            return
        time.sleep(poll)
    raise CDPError(f"{int(timeout)}s 内未检测到登录（sessionid Cookie）")


def write_private_json(path: Path, data: Mapping) -> None:
    """Write JSON readable only by the current user (it holds live cookies)."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    os.chmod(path, 0o600)
