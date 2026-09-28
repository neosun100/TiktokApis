"""Record the wire (method, url, header order, body) of every public API method.

Used to freeze behaviour before refactors: `uv run python -m tests.golden_harness`
rewrites tests/golden/wire.json; tests/test_golden_wire.py compares against it.
The auth is synthetic and deterministic; signatures are stubbed (their own
tests live elsewhere) so only the request *shape* is compared.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from api.tiktok_web import TiktokWebAPI
from builder.action_gate import ActionGate
from builder.auth import TiktokAuth
from utils import http_client

GOLDEN = Path(__file__).parent / "golden" / "wire.json"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")


class _Stop(Exception):
    pass


def make_auth() -> TiktokAuth:
    cookie = ("tt_csrf_token=csrf; s_v_web_id=verify_x; multi_sids=7000000000000000001%3Aabc; "
              "sessionid=sess; msToken=mtok; store-country-code=hk")
    auth = TiktokAuth(cookie, device_id="7000000000000000002", odin_id="7000000000000000003",
                      user_agent=UA, web_id_last_time="1700000000",
                      session_storage={"msToken": "mtok"}, secsdk_csrf_token="secsdk",
                      browser_metrics={"screen_width": "2560", "screen_height": "1440",
                                       "browser_language": "zh-CN", "browser_platform": "Win32",
                                       "tz_name": "Asia/Shanghai", "dynosaur_page": "www.tiktok.com/"})
    auth.sign_request = lambda path, **kw: {"X-Dynosaur": "D", "msToken": "mtok",
                                            "X-Bogus": "B", "X-Gnarly": "G"}
    auth.build_ticket_guard = lambda path, **kw: {"tt-ticket-guard-client-data": "cd"}
    return auth


DUMMY = {
    "sec_uid": "MS4wSEC", "aweme_id": "7100000000000000001", "item_id": "7100000000000000001",
    "comment_id": "7200000000000000001", "reply_id": "7200000000000000002",
    "user_id": "6800000000000000001", "room_id": "7300000000000000001",
    "live_id": "12", "keyword": "cats", "text": "hi", "content": "hi",
    "unique_id": "someone", "collection_id": "7400000000000000001",
    "author_id": "6800000000000000001", "target_uid": "6800000000000000001",
    "anchor_id": "6800000000000000001", "to_uid": "6800000000000000001",
    "name": "fav", "item_ids": ["7100000000000000001"], "room_ids": ["7300000000000000001"],
    "user_ids": ["6800000000000000001"], "effect_ids": ["1"], "ab_param": "x",
    "creation_id": "ROO_abcdefghijklmnopq", "video_id": "v0", "referer": None,
    "root_referer": "https://www.tiktok.com/", "permission_list": "1", "date": "2026-09-28",
    "host_user_id": "6800000000000000001", "sec_anchor_id": "MS4wANCHOR",
    "history_len": "3", "query_referer": "https://www.tiktok.com/",
    "owner_user_id": "6800000000000000001", "collection_name": "fav2",
    "commit_ids": ["7100000000000000001"], "profile_url": "https://www.tiktok.com/@someone",
    "from_collection_id": "7400000000000000001", "target_collection_id": "7400000000000000002",
    "sec_user_id": "MS4wSEC", "upload_timestamp": "1700000000", "time_usage": "10",
    "conversation_id": "0:1:1:2", "conversation_short_id": 7001, "conversation_type": 1,
    "anchor_index": 0, "direction": 1, "limit": 20, "cursor": "0",
    "owner_id": "6800000000000000001", "local_timeregi_stamp": "1700000000",
    "webapp_watch_duration": "10",
}


def _call_args(method):
    sig = inspect.signature(method)
    args, kwargs = [], {}
    for name, param in list(sig.parameters.items())[1:]:
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        if param.default is param.empty:
            if name not in DUMMY:
                return None
            if param.kind == param.KEYWORD_ONLY:
                kwargs[name] = DUMMY[name]
            else:
                args.append(DUMMY[name])
    return args, kwargs


def record() -> dict:
    captured: dict = {}
    current: list = []

    def fake_request(method, url, **kwargs):
        headers = kwargs.get("headers") or {}
        body = kwargs.get("data")
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError:
                body = f"<{len(body)} bytes>"
        current.append({"method": method, "url": url, "headers": list(headers.keys()),
                        "body": body})
        raise _Stop()

    import secrets
    import time
    import uuid

    saved = (http_client.request, http_client.get, http_client.post)
    frozen = (time.time, time.time_ns, uuid.uuid4, secrets.choice, secrets.randbits)
    time.time = lambda: 1_700_000_000.123
    time.time_ns = lambda: 1_700_000_000_123_000_000
    uuid.uuid4 = lambda: uuid.UUID("12345678-1234-4234-8234-123456789abc")
    secrets.choice = lambda seq: seq[0]
    secrets.randbits = lambda k: 1
    http_client.request = fake_request
    http_client.get = lambda url, **k: fake_request("GET", url, **k)
    http_client.post = lambda url, **k: fake_request("POST", url, **k)
    try:
        _record_all(captured, current)
    finally:
        http_client.request, http_client.get, http_client.post = saved
        time.time, time.time_ns, uuid.uuid4, secrets.choice, secrets.randbits = frozen
    return captured


def _record_all(captured: dict, current: list) -> None:
    for name, method in sorted(inspect.getmembers(TiktokWebAPI, inspect.isfunction)):
        if name.startswith("_") or name.startswith(("iter_", "get_all_", "receive_", "upload_",
                                                    "creator_", "publish_", "probe_", "wait_")):
            continue
        call = _call_args(method)
        if call is None:
            captured[name] = {"skipped": "needs non-dummy args"}
            continue
        api = TiktokWebAPI(make_auth(), gate=ActionGate.unlimited())
        current.clear()
        try:
            getattr(api, name)(*call[0], **call[1])
            captured[name] = {"skipped": "returned without HTTP"}
        except _Stop:
            captured[name] = current[0]
        except Exception as exc:  # noqa: BLE001 - recording why a method was not exercised
            captured[name] = {"error": type(exc).__name__}


if __name__ == "__main__":
    GOLDEN.write_text(json.dumps(record(), ensure_ascii=False, indent=1, sort_keys=True) + "\n")
    print(f"wrote {GOLDEN}")
