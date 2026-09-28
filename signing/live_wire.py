"""Decode the TikTok live protobuf fields confirmed in Chrome captures."""

from __future__ import annotations

import json
import zlib

from builder.limits import Limits

from .protobuf import ProtobufWireError, field_bytes, field_string, field_varint


def fields(raw: bytes) -> dict[int, list[int | bytes]]:
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise ProtobufWireError("protobuf frame 必须是 bytes")
    data = bytes(raw)
    result: dict[int, list[int | bytes]] = {}
    offset = 0

    def number() -> int:
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ProtobufWireError("protobuf varint 截断")
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7f) << shift
            if byte < 0x80:
                return value
        raise ProtobufWireError("protobuf varint 过长")

    while offset < len(data):
        tag = number()
        field, wire = tag >> 3, tag & 7
        if not field:
            raise ProtobufWireError("protobuf field 0 无效")
        if wire == 0:
            value: int | bytes = number()
        elif wire == 2:
            length = number()
            end = offset + length
            if end > len(data):
                raise ProtobufWireError("protobuf bytes 截断")
            value = data[offset:end]
            offset = end
        elif wire == 1:
            end = offset + 8
            if end > len(data):
                raise ProtobufWireError("protobuf fixed64 截断")
            value = data[offset:end]
            offset = end
        elif wire == 5:
            end = offset + 4
            if end > len(data):
                raise ProtobufWireError("protobuf fixed32 截断")
            value = data[offset:end]
            offset = end
        else:
            raise ProtobufWireError(f"不支持的 protobuf wire type {wire}")
        result.setdefault(field, []).append(value)
    return result


def first(tree: dict, key: int, default=None):
    values = tree.get(key, [])
    return values[0] if values else default


def string(tree: dict, key: int, default: str = "") -> str:
    value = first(tree, key)
    if value is None:
        return default
    if not isinstance(value, bytes):
        raise ProtobufWireError(f"field {key} 不是 string")
    return value.decode("utf-8", errors="replace")


def integer(tree: dict, key: int, default: int = 0) -> int:
    value = first(tree, key)
    if value is None:
        return default
    if not isinstance(value, int):
        raise ProtobufWireError(f"field {key} 不是 varint")
    return value


def nested(tree: dict, key: int) -> dict:
    value = first(tree, key)
    if value is None:
        return {}
    if not isinstance(value, bytes):
        raise ProtobufWireError(f"field {key} 不是 message")
    return fields(value)


def _user(tree: dict) -> dict:
    return {
        "id": integer(tree, 1),
        "nickname": string(tree, 3),
        "display_id": string(tree, 38),
        "sec_uid": string(tree, 46),
    }


_DECODERS = {}


def _decoder(method: str):
    def register(func):
        _DECODERS[method] = func
        return func
    return register


@_decoder("WebcastChatMessage")
def _chat(body: dict) -> dict:
    return {"type": "chat", "user": _user(nested(body, 2)), "text": string(body, 3)}


@_decoder("WebcastLikeMessage")
def _like(body: dict) -> dict:
    return {"type": "like", "count": integer(body, 2), "total": integer(body, 3),
            "user": _user(nested(body, 5))}


@_decoder("WebcastGiftMessage")
def _gift(body: dict) -> dict:
    gift = nested(body, 15)
    return {"type": "gift", "gift_id": integer(body, 2), "combo_count": integer(body, 6),
            "user": _user(nested(body, 7)),
            "gift": {"id": integer(gift, 5), "name": string(gift, 16)}}


def decode_response(raw: bytes) -> dict:
    """Decode one HTTP fetch or uncompressed WS LiveResponse.

    One malformed message yields a ``decode_error`` event instead of losing
    the whole batch; unknown methods are passed through as ``other`` without
    parsing their body (their layout is unconfirmed and may not parse).
    """
    if bytes(raw[:1]) == b"{":
        # Risk control answers the protobuf endpoint with a JSON status body;
        # 0x7b would otherwise surface as a misleading "wire type 3" error.
        try:
            status = json.loads(bytes(raw)).get("status_code")
        except (ValueError, AttributeError):
            status = None
        raise ProtobufWireError(f"直播接口返回 JSON 而非 protobuf（status_code={status!r}）")
    tree = fields(raw)
    events = []
    for item in tree.get(1, []):
        if not isinstance(item, bytes):
            raise ProtobufWireError("LiveResponse.messagesList 不是 message")
        envelope = fields(item)
        method = string(envelope, 1)
        payload = first(envelope, 2, b"")
        if not isinstance(payload, bytes):
            raise ProtobufWireError("直播事件 payload 不是 bytes")
        event = {"method": method, "message_id": integer(envelope, 3)}
        decoder = _DECODERS.get(method)
        if decoder is None:
            event.update(type="other", payload_length=len(payload))
        else:
            try:
                event.update(decoder(fields(payload)))
            except ProtobufWireError as exc:
                event.update(type="decode_error", error=str(exc), payload_length=len(payload))
        events.append(event)
    return {
        "events": events,
        "cursor": string(tree, 2),
        "internal_ext": string(tree, 5),
        "fetch_interval": integer(tree, 3),
        "heartbeat_duration": integer(tree, 8),
        "need_ack": bool(integer(tree, 9)),
        "raw_length": len(raw),
    }


def gunzip_bounded(payload: bytes, limit: int = Limits.MAX_DECOMPRESSED_FRAME_BYTES) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decoder.decompress(payload, limit)
    except zlib.error as exc:
        raise ProtobufWireError(f"PushFrame gzip 无法解压: {exc}") from None
    if decoder.unconsumed_tail:
        raise ProtobufWireError(
            f"PushFrame 解压后超过上限 {limit} 字节（压缩体 {len(payload)} 字节）")
    if not decoder.eof:
        raise ProtobufWireError("PushFrame gzip 数据被截断")
    return out


def decode_push_frame(raw: bytes) -> dict:
    """Decode a live WS PushFrame and its optional gzip LiveResponse."""
    tree = fields(raw)
    payload = first(tree, 8, b"")
    if not isinstance(payload, bytes):
        raise ProtobufWireError("PushFrame.payload 不是 bytes")
    headers = {}
    for item in tree.get(5, []):
        if isinstance(item, bytes):
            pair = fields(item)
            headers[string(pair, 1)] = string(pair, 2)
    if headers.get("compress_type") == "gzip" or payload.startswith(b"\x1f\x8b"):
        payload = gunzip_bounded(payload)
    kind = string(tree, 7)
    return {
        "seq_id": integer(tree, 1), "log_id": integer(tree, 2),
        "payload_type": kind, "headers": headers,
        "response": decode_response(payload) if kind in ("msg", "im_enter_room_resp") else None,
        "payload_length": len(payload),
    }


def encode_frame(kind: str, payload: bytes, *, log_id: int | None = None) -> bytes:
    """Build only the outer fields observed in Chrome's live WS writes."""
    prefix = field_varint(2, log_id) if log_id is not None else b""
    return prefix + field_string(6, "pb") + field_string(7, kind) + field_bytes(8, payload)


def encode_heartbeat(room_id: int) -> bytes:
    return encode_frame("hb", field_varint(1, room_id))


def encode_enter_room(room_id: int, live_id: int, cursor: str) -> bytes:
    payload = b"".join((
        field_varint(1, room_id), field_varint(4, live_id),
        field_string(5, "audience"), field_string(6, cursor),
        field_varint(7, 0), field_string(9, "0"), field_varint(10, 0),
    ))
    return encode_frame("im_enter_room", payload)
