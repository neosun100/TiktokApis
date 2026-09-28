"""Live protobuf decoding and the WS event loop (fake socket, no network)."""

import gzip
import sys
import types

import pytest

from api.tiktok_web import TiktokWebAPI
from builder.auth import TiktokAuth
from builder.errors import BrowserEvidenceError, TransportError
from signing import live_wire
from signing.protobuf import ProtobufWireError, field_bytes, field_message, field_string, field_varint


def user(uid=1, nick="n"):
    return field_varint(1, uid) + field_string(3, nick) + field_string(38, "disp")


def chat(text, mid):
    body = field_message(2, user()) + field_string(3, text)
    return field_message(1, field_string(1, "WebcastChatMessage") + field_bytes(2, body)
                         + field_varint(3, mid))


def other(method, payload, mid):
    return field_message(1, field_string(1, method) + field_bytes(2, payload) + field_varint(3, mid))


def response(*messages, cursor="c1", need_ack=0, heartbeat=0):
    out = b"".join(messages) + field_string(2, cursor) + field_string(5, "ext")
    if heartbeat:
        out += field_varint(8, heartbeat)
    if need_ack:
        out += field_varint(9, 1)
    return out


def push(payload, *, gz=False, seq=1):
    if gz:
        payload = gzip.compress(payload)
    return field_varint(1, seq) + field_varint(2, 77) + field_string(7, "msg") + field_bytes(8, payload)


# --- decoder ---------------------------------------------------------------

def test_decode_chat():
    out = live_wire.decode_response(response(chat("hello", 5)))
    assert out["events"][0]["type"] == "chat"
    assert out["events"][0]["text"] == "hello"
    assert out["events"][0]["user"]["display_id"] == "disp"


def test_unknown_method_body_is_not_parsed():
    # 0x1b = field 3 / wire type 3 (group): unparseable by fields().
    out = live_wire.decode_response(response(other("WebcastFooMessage", b"\x1b\x00", 1),
                                             chat("still here", 2)))
    assert [e["type"] for e in out["events"]] == ["other", "chat"]


def test_bad_known_message_is_isolated():
    bad = field_message(1, field_string(1, "WebcastChatMessage") + field_bytes(2, b"\x1b")
                        + field_varint(3, 1))
    out = live_wire.decode_response(response(bad, chat("ok", 2)))
    assert [e["type"] for e in out["events"]] == ["decode_error", "chat"]


def test_json_body_is_named_as_such():
    with pytest.raises(ProtobufWireError, match="JSON"):
        live_wire.decode_response(b'{"status_code": 10000}')


def test_push_frame_gzip_by_magic():
    frame = live_wire.decode_push_frame(push(response(chat("gz", 1)), gz=True))
    assert frame["response"]["events"][0]["text"] == "gz"


# --- WS loop ---------------------------------------------------------------

class Timeout(Exception):
    pass


class Closed(Exception):
    pass


@pytest.fixture
def live(monkeypatch):
    state = {"incoming": [], "sent": []}

    class FakeWS:
        def send(self, data, opcode=None):
            state["sent"].append(data)

        def recv(self):
            if not state["incoming"]:
                raise Closed()
            item = state["incoming"].pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        def close(self):
            state["closed"] = True

    fake = types.ModuleType("websocket")
    fake.WebSocketException = Exception
    fake.WebSocketTimeoutException = Timeout
    fake.WebSocketConnectionClosedException = Closed
    fake.ABNF = types.SimpleNamespace(OPCODE_BINARY=2)
    fake.create_connection = lambda *a, **k: FakeWS()
    monkeypatch.setitem(sys.modules, "websocket", fake)

    metrics = {"screen_width": "1512", "screen_height": "982", "browser_language": "en-US",
               "browser_platform": "MacIntel", "tz_name": "Asia/Hong_Kong"}
    auth = TiktokAuth("sessionid=x; multi_sids=7000000000000000001%3Aabc", browser_metrics=metrics)
    monkeypatch.setattr(auth, "require_browser_profile", lambda: auth)
    monkeypatch.setattr(auth.signer, "frontier_sign", lambda **k: "B" * 16)
    api = TiktokWebAPI(auth)
    initial = live_wire.decode_response(response(chat("history", 1)))
    monkeypatch.setattr(api, "receive_live_events", lambda *a, **k: initial)
    state["api"] = api
    return state


def collect(state, **kwargs):
    out = []
    with pytest.raises(TransportError):
        for event in state["api"].iter_live_ws_events("111", "222", **kwargs):
            out.append(event)
    return out


def test_history_is_yielded_then_live(live):
    live["incoming"] = [push(response(chat("live", 2)))]
    assert [e["text"] for e in collect(live)] == ["history", "live"]
    assert live["closed"]


def test_without_history_replayed_history_is_suppressed(live):
    live["incoming"] = [push(response(chat("history", 1), chat("live", 2)))]
    assert [e["text"] for e in collect(live, include_history=False)] == ["live"]


def test_decode_error_frame_does_not_kill_stream(live):
    live["incoming"] = [b"\x1b\x1b", push(response(chat("after", 3)))]
    events = collect(live, types=None)
    assert [e["type"] for e in events] == ["chat", "decode_error", "chat"]


def test_ack_echoes_internal_ext(live):
    live["incoming"] = [push(response(chat("x", 4), need_ack=1))]
    collect(live)
    ack = live_wire.fields(live["sent"][-1])
    assert live_wire.string(ack, 7) == "ack"
    assert live_wire.first(ack, 8) == b"ext"


def test_other_events_hidden_by_default_visible_with_none(live):
    live["incoming"] = [push(response(other("WebcastMemberMessage", b"", 9)))]
    assert [e["type"] for e in collect(live)] == ["chat"]
    live["incoming"] = [push(response(other("WebcastMemberMessage", b"", 9)))]
    assert "other" in [e["type"] for e in collect(live, types=None)]


def test_non_numeric_ids_rejected_before_network(live):
    with pytest.raises(ValueError):
        next(live["api"].iter_live_ws_events("abc", "222"))


def test_fetch_uses_browser_metrics_not_literals(live, monkeypatch):
    captured = {}

    def fake_request(auth, **kwargs):
        captured["query"] = kwargs["params"].to_query()
        raise RuntimeError("stop")

    monkeypatch.setattr(live["api"], "_request_response", fake_request)
    with pytest.raises(RuntimeError):
        live["api"].get_webcast_im_fetch("1", "2")
    assert "tz_name=Asia%2FHong_Kong" in captured["query"]
    assert "Win32" not in captured["query"] and "2560" not in captured["query"]


def test_fetch_without_metrics_fails_closed():
    api = TiktokWebAPI(TiktokAuth("sessionid=x"))
    with pytest.raises(BrowserEvidenceError):
        api.get_webcast_im_fetch("1", "2")
