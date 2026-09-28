"""iter_im_ws_messages over a fake socket: text, unsupported, errors, close."""

import json
import sys
import types

import pytest

import static.Tiktok_Request_pb2 as pb
from api.tiktok_web import TiktokWebAPI
from builder.auth import TiktokAuth
from builder.errors import TransportError


class Timeout(Exception):
    pass


class Closed(Exception):
    pass


def push(*, mid, mtype=7, content=None, cmd=500):
    resp = pb.Response(cmd=cmd)
    msg = resp.body.has_new_message_notify.message
    msg.conversation_id, msg.server_message_id, msg.message_type = "0:1:1:2", mid, mtype
    msg.content = json.dumps(content if content is not None else {"aweType": 0, "text": f"m{mid}"})
    return pb.Frame(seqid=mid, payload=resp.SerializeToString()).SerializeToString()


@pytest.fixture
def im(monkeypatch):
    state = {"incoming": [], "sent": []}

    class FakeWS:
        def send(self, data, opcode=None):
            state["sent"].append(data)

        def recv(self):
            if not state["incoming"]:
                raise Closed()
            return state["incoming"].pop(0)

        def close(self):
            state["closed"] = True

    fake = types.ModuleType("websocket")
    fake.WebSocketException = Exception
    fake.WebSocketTimeoutException = Timeout
    fake.WebSocketConnectionClosedException = Closed
    fake.create_connection = lambda *a, **k: FakeWS()
    monkeypatch.setitem(sys.modules, "websocket", fake)
    auth = TiktokAuth("sessionid=x")
    monkeypatch.setattr(auth, "require_browser_profile", lambda: auth)
    monkeypatch.setattr(TiktokWebAPI, "_im_ws_url", staticmethod(lambda a, w=None: "wss://im/ws"))
    state["api"] = TiktokWebAPI(auth)
    return state


def drain(state, **kw):
    out = []
    with pytest.raises(TransportError):
        for message in state["api"].iter_im_ws_messages(**kw):
            out.append(message)
    return out


def test_text_dedup_and_heartbeat(im):
    im["incoming"] = ["hi", push(mid=1), push(mid=1), push(mid=2)]
    assert [m["text"] for m in drain(im)] == ["m1", "m2"]
    assert im["sent"] == ["hi"] and im["closed"]


def test_bad_push_does_not_end_stream(im):
    im["incoming"] = [b"\xff\xff", push(mid=3)]
    assert [m.get("text") for m in drain(im)] == ["m3"]
    im["incoming"] = [b"\xff\xff", push(mid=4)]
    assert [m["type"] for m in drain(im, include_unsupported=True)] == ["decode_error", "text"]


def test_non_text_is_reported_when_asked(im):
    im["incoming"] = [push(mid=5, mtype=27, content={"url": "x"}), push(mid=6)]
    assert [m["type"] for m in drain(im)] == ["text"]
    im["incoming"] = [push(mid=5, mtype=27, content={"url": "x"})]
    out = drain(im, include_unsupported=True)
    assert out[0]["type"] == "unsupported" and out[0]["message_type"] == 27


def test_other_commands_ignored(im):
    im["incoming"] = [push(mid=7, cmd=100), push(mid=8)]
    assert [m["server_message_id"] for m in drain(im)] == [8]
