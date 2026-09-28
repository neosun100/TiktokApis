"""IM pull-response decoding (commands 203/204/301).

Guards: text messages are recovered from a schemaless wire tree regardless of
whether the protobuf backend returns string fields as ``str`` or ``bytes``;
unsupported message types are surfaced, never silently dropped.
Does not guard: the real field layout of TikTok's response (needs captures).
"""

import json

import pytest

from api.tiktok_web import TiktokWebAPI
from builder.auth import BrowserEvidenceError
from signing.protobuf import field_message, field_string, field_varint


def _message_body(*, message_type=7, content=None, server_id=99, sender=42):
    content = content if content is not None else {"aweType": 0, "text": "yo 你好"}
    return (
        field_string(1, "0:1:42:43")
        + field_varint(3, server_id)
        + field_varint(5, 7001)
        + field_varint(6, message_type)
        + field_varint(7, sender)
        + field_string(8, json.dumps(content, ensure_ascii=False, separators=(",", ":")))
        + field_varint(10, 1700000000)
    )


def test_flat_text_message_is_recovered():
    out = TiktokWebAPI.decode_im_protobuf(_message_body())
    assert [m["text"] for m in out["messages"]] == ["yo 你好"]
    msg = out["messages"][0]
    assert msg["server_message_id"] == 99
    assert msg["message_type"] == 7
    assert msg["sender"] == 42


def test_nested_text_message_is_recovered():
    # 6 -> 301 -> 1 : the pull response nests message lists inside bodies.
    raw = field_message(6, field_message(301, field_message(1, _message_body())))
    out = TiktokWebAPI.decode_im_protobuf(raw)
    assert [m["text"] for m in out["messages"]] == ["yo 你好"]


def test_duplicate_messages_are_deduplicated():
    body = _message_body()
    raw = field_message(6, field_message(1, body) + field_message(1, body))
    assert len(TiktokWebAPI.decode_im_protobuf(raw)["messages"]) == 1


def test_non_text_message_is_reported_not_dropped():
    raw = _message_body(message_type=27, content={"aweType": 2702, "url": "x"})
    out = TiktokWebAPI.decode_im_protobuf(raw)
    assert out["messages"] == []
    assert out["unsupported"] == [{"server_message_id": 99, "message_type": 27}]


@pytest.mark.parametrize("raw", [b"", "text", None])
def test_rejects_non_bytes(raw):
    with pytest.raises(BrowserEvidenceError):
        TiktokWebAPI.decode_im_protobuf(raw)
