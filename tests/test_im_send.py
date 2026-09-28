"""send_im_message reply handling over a fake WebSocket (no network, no Node).

Guards: only our sequence id's cmd-100 counts; failure replies raise;
closed sockets raise immediately; sequence id advances.
Does not guard: the Request/Frame bytes against Chrome (needs captures).
"""

import sys
import types
from collections import OrderedDict

import pytest

import static.Tiktok_Request_pb2 as pb
from api.tiktok_web import TiktokWebAPI
from builder.auth import TiktokAuth
from builder.errors import BusinessError, TransportError


class Timeout(Exception):
    pass


class Closed(Exception):
    pass


def _reply(*, seq, cmd=100, status_code=0, check_code=0, server_id=555):
    resp = pb.Response(cmd=cmd, sequence_id=seq, status_code=status_code)
    if cmd == 100:
        resp.body.send_message_body.server_message_id = server_id
        resp.body.send_message_body.check_code = check_code
    return pb.Frame(seqid=seq, payload=resp.SerializeToString()).SerializeToString()


@pytest.fixture
def harness(monkeypatch):
    state = {"incoming": [], "sent": [], "closed": False}

    class FakeWS:
        def send(self, data, opcode=None):
            state["sent"].append(data)

        def settimeout(self, value):
            pass

        def recv(self):
            if not state["incoming"]:
                raise Timeout()
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

    auth = TiktokAuth("sessionid=x; multi_sids=7000000000000000001%3Aabc",
                      browser_metrics={"im_ws_sequence_id": 10})
    monkeypatch.setattr(auth, "require_browser_profile", lambda: auth)
    monkeypatch.setattr(auth, "build_ticket_guard", lambda path: OrderedDict())
    monkeypatch.setattr(auth.signer, "frontier_sign", lambda **k: "A" * 16)
    api = TiktokWebAPI(auth)
    monkeypatch.setattr(TiktokWebAPI, "_im_header_map",
                        classmethod(lambda cls, a, h: OrderedDict([("aid", "1988")])))
    monkeypatch.setattr(TiktokWebAPI, "_im_ws_url", staticmethod(lambda a, w=None: "wss://im/ws"))
    state["api"], state["auth"] = api, auth
    return state


def _send(state, **kwargs):
    return state["api"].send_im_message("0:1:1:2", 7001, "hi there", timeout=1, **kwargs)


def test_success_returns_and_advances_sequence(harness):
    harness["incoming"] = ["hi", _reply(seq=10)]
    out = _send(harness)
    assert out["server_message_id"] == 555
    assert harness["auth"].browser_metrics["im_ws_sequence_id"] == 11
    assert harness["closed"]


def test_foreign_sequence_reply_is_ignored(harness):
    harness["incoming"] = [_reply(seq=99, server_id=1), _reply(seq=10, server_id=2)]
    assert _send(harness)["server_message_id"] == 2


def test_error_status_raises_business_error(harness):
    harness["incoming"] = [_reply(seq=10, status_code=7)]
    with pytest.raises(BusinessError):
        _send(harness)
    assert harness["auth"].browser_metrics["im_ws_sequence_id"] == 10


def test_moderation_check_code_raises(harness):
    harness["incoming"] = [_reply(seq=10, check_code=3)]
    with pytest.raises(BusinessError):
        _send(harness)


def test_closed_socket_raises_immediately(harness):
    harness["incoming"] = [Closed("gone")]
    with pytest.raises(TransportError, match="断开"):
        _send(harness)


def test_timeout_reports_undecodable_frames(harness):
    harness["incoming"] = [b"\xff\xff\xff"]
    with pytest.raises(TransportError, match="1 帧无法解码"):
        _send(harness)


def test_explicit_sequence_is_not_persisted(harness):
    harness["incoming"] = [_reply(seq=50)]
    _send(harness, sequence_id=50)
    assert harness["auth"].browser_metrics["im_ws_sequence_id"] == 10
