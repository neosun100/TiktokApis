"""Pure-Python TikTok Web signature primitives.

The two encoders in this module are kept separate because Chrome currently
uses different WebMssdk generations for Creator Studio project writes and the
older public Web API family.  They deliberately accept the complete unsigned
wire context (query/body/user-agent) and never pad, truncate, or copy a
captured signature.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Mapping, Sequence


_GNARLY_ALPHABET = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
_BOGUS_ALPHABET = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe="
_SIGMA = (1196819126, 600974999, 3863347763, 1451689750)
_DYNOSAUR_FIELD_COUNT = 25


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    return _u32((value << count) | (value >> (32 - count)))


def _quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = _u32(state[a] + state[b])
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = _u32(state[c] + state[d])
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = _u32(state[a] + state[b])
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = _u32(state[c] + state[d])
    state[b] = _rotl(state[b] ^ state[c], 7)


def _gnarly_block(initial: Sequence[int], rounds: int) -> list[int]:
    """One WebMssdk block, including its non-standard diagonal round."""
    state = list(initial)
    count = 0
    while count < rounds:
        _quarter(state, 0, 4, 8, 12)
        _quarter(state, 1, 5, 9, 13)
        _quarter(state, 2, 6, 10, 14)
        _quarter(state, 3, 7, 11, 15)
        count += 1
        if count >= rounds:
            break
        # This is the diagonal schedule in the browser bundle.  It is not
        # RFC-8439 ChaCha's diagonal schedule.
        _quarter(state, 0, 5, 10, 15)
        _quarter(state, 1, 6, 11, 12)
        _quarter(state, 2, 7, 12, 13)
        _quarter(state, 3, 4, 13, 14)
        count += 1
    return [_u32(a + b) for a, b in zip(state, initial)]


def _gnarly_xor(data: bytes, key_words: Sequence[int], rounds: int) -> bytes:
    if len(key_words) != 12:
        raise ValueError("X-Gnarly needs 12 key words")
    state = [*_SIGMA, *(_u32(x) for x in key_words)]
    out = bytearray(data)
    for offset in range(0, len(out), 64):
        stream = _gnarly_block(state, rounds)
        limit = min(64, len(out) - offset)
        for index in range(limit):
            out[offset + index] ^= (stream[index // 4] >> (8 * (index % 4))) & 0xFF
        state[12] = _u32(state[12] + 1)
    return bytes(out)


def _custom_b64(data: bytes, alphabet: str) -> str:
    result: list[str] = []
    for offset in range(0, len(data), 3):
        first = data[offset]
        second = data[offset + 1] if offset + 1 < len(data) else 0
        third = data[offset + 2] if offset + 2 < len(data) else 0
        result.append(alphabet[first >> 2])
        result.append(alphabet[((first & 3) << 4) | (second >> 4)])
        result.append(alphabet[((second & 15) << 2) | (third >> 6)] if offset + 1 < len(data) else alphabet[64])
        result.append(alphabet[third & 63] if offset + 2 < len(data) else alphabet[64])
    return "".join(result)


def _md5_hex(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.md5(raw).hexdigest()


def _hash_url_state(value: str) -> int:
    """5.3.x FNV-style query/UA binding used by X-Dynosaur."""
    state = 2166136260
    for byte in value.encode("utf-8"):
        mixed = _u32((state ^ byte) * 16777619)
        state = _u32(mixed + _u32(mixed * 32))
    return state


def _encode_env_bytes(value: str, *, variant: str) -> bytes:
    """Encode the compact string fields used by the current Dynosaur TLV."""
    text = str(value)
    if variant == "a":
        xor_base, add_base, pre_xor, rotate, post_add = 103, 1, None, 2, 1
    elif variant == "b":
        xor_base, add_base, pre_xor, rotate, post_add = 102, 0, 165, 1, 0
    else:
        raise ValueError("unknown Dynosaur byte encoder")
    length = len(text)
    size = max(length + 2, 6)
    out = bytearray(size)
    for index, char in enumerate(text):
        value_byte = _u32(ord(char) ^ (xor_base + index))
        value_byte = _u32(value_byte + add_base + (170 & index)) % 256
        if pre_xor is not None:
            value_byte ^= pre_xor
        value_byte = ((value_byte << rotate) | (value_byte >> (8 - rotate))) & 0xFF
        value_byte = ((value_byte ^ 187) + post_add) & 0xFF
        out[index] = value_byte
    for index in range(length, size - 2):
        out[index] = (221 + index) & 0xFF
    out[-2] = 0
    out[-1] = length & 0xFF
    return bytes(out)


def _raw_u32(value: int) -> bytes:
    return _u32(value).to_bytes(4, "big")


def _dynosaur_payload(
    *, ts: int, rand_b: int, query: str, user_agent: str,
    envcode: int, ubcode: int, canvas: int, page: str,
    payload_version: str, sdk_version: str,
    image_ratio: int, text_ratio: int,
    runtime_field8: str = "0",
    runtime_field18: str = "0",
    runtime_field19: str = "0",
) -> bytes:
    mix_value = _u32(
        ((((ts >> 16) & 0xFFFF) ^ ((rand_b >> 16) & 0xFFFF))
         ^ ((ts & 0xFFFF) ^ (rand_b & 0xFFFF)))
        | (int(envcode) << 16)
    )
    fields = [
        _encode_env_bytes("0", variant="a"),
        _encode_env_bytes("1", variant="b"),
        _encode_env_bytes("1", variant="b"),
        _encode_env_bytes("0", variant="a"),
        _encode_env_bytes(str(mix_value), variant="a"),
        _encode_env_bytes(str(int(image_ratio)), variant="a"),
        _encode_env_bytes(str(int(envcode)), variant="a"),
        _encode_env_bytes(str(int(ts)), variant="a"),
        _encode_env_bytes(str(runtime_field8), variant="a"),
        _encode_env_bytes("0", variant="a"),
        _encode_env_bytes(str(payload_version), variant="a"),
        _raw_u32(_hash_url_state("")),
        _encode_env_bytes(str(int(canvas)), variant="a"),
        _encode_env_bytes("0", variant="a"),
        _raw_u32(_hash_url_state(query)),
        _encode_env_bytes(str(int(text_ratio)), variant="a"),
        _raw_u32(_hash_url_state(user_agent)),
        _encode_env_bytes(str(sdk_version), variant="a"),
        _encode_env_bytes(str(runtime_field18), variant="a"),
        _encode_env_bytes(str(runtime_field19), variant="a"),
        _encode_env_bytes(str(int(rand_b)), variant="a"),
        _encode_env_bytes(page, variant="a"),
        _encode_env_bytes(str(int(ubcode)), variant="a"),
        _encode_env_bytes("0", variant="a"),
        _raw_u32(_hash_url_state("")),
    ]
    checksum = 0
    for field in fields:
        checksum ^= field[1]
    fields[0] = _encode_env_bytes(str(checksum), variant="b")
    out = bytearray()
    for index, field in enumerate(fields):
        out.extend((0x20 + index, 0, len(field)))
        out.extend(field)
    if len(fields) != _DYNOSAUR_FIELD_COUNT:
        raise AssertionError("unexpected Dynosaur field count")
    return bytes(out)


def _int_bytes_legacy(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("signature integer is outside uint32")
    # The project-post WebMssdk uses 2 bytes below 255*255 and 4 otherwise.
    width = 2 if value < 255 * 255 else 4
    return value.to_bytes(width, "big")


def _legacy_payload(fields: Mapping[int, int | str]) -> bytes:
    values = dict(fields)
    xor_header = 0
    for key, value in values.items():
        if key != 0 and isinstance(value, int):
            xor_header = _u32(xor_header ^ value)
    values[0] = xor_header
    out = bytearray([len(values)])
    # Object.keys() on these integer-like JS properties is numerically sorted.
    for key in sorted(values):
        value = values[key]
        encoded = _int_bytes_legacy(value) if isinstance(value, int) else str(value).encode("utf-8")
        if len(encoded) > 0xFFFF:
            raise ValueError("signature field is too long")
        out.extend((key & 0xFF, (len(encoded) >> 8) & 0xFF, len(encoded) & 0xFF))
        out.extend(encoded)
    return bytes(out)


_CURRENT_FIELD_ORDER = (10, 15, 3, 5, 7, 8, 16, 9, 0, 4, 11, 13, 6, 14, 12, 2, 1)


def _int_bytes_current(value: int) -> bytes:
    """Current 5.3.x payload integer widths (2 bytes until uint16)."""
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("signature integer is outside uint32")
    width = 2 if value <= 0xFFFF else 4
    return value.to_bytes(width, "big")


def _current_payload(fields: Mapping[int, int | str]) -> bytes:
    """Serialize the 5.3.x payload in the observed browser insertion order."""
    values = dict(fields)
    xor_header = 0
    for key, value in values.items():
        if key != 0 and isinstance(value, int):
            xor_header = _u32(xor_header ^ value)
    values[0] = xor_header
    order = [key for key in _CURRENT_FIELD_ORDER if key in values]
    if len(order) != len(values):
        unknown = sorted(set(values) - set(_CURRENT_FIELD_ORDER))
        raise ValueError(f"unknown current X-Gnarly fields: {unknown}")
    out = bytearray([len(order)])
    for key in order:
        value = values[key]
        encoded = _int_bytes_current(value) if isinstance(value, int) else str(value).encode("utf-8")
        if len(encoded) > 0xFFFF:
            raise ValueError("signature field is too long")
        out.extend((key & 0xFF, (len(encoded) >> 8) & 0xFF, len(encoded) & 0xFF))
        out.extend(encoded)
    return bytes(out)


def _new_key() -> tuple[int, ...]:
    return tuple(secrets.randbits(32) for _ in range(12))


def encode_gnarly_project(
    query_string: str,
    body: str | bytes,
    user_agent: str,
    *,
    ubcode: int = 136,
    canvas: int = 2894886431,
    timestamp: int | None = None,
    timestamp_ms: int | None = None,
    sdk_version: str = "5.1.0",
    key_words: Sequence[int] | None = None,
) -> str:
    """Encode the 10-field X-Gnarly used by Creator Studio project/post."""
    if timestamp is None:
        timestamp = int(time.time())
    if timestamp_ms is None:
        timestamp_ms = time.time_ns() // 1_000_000
    body_bytes = body if isinstance(body, bytes) else body.encode("utf-8")
    fields: dict[int, int | str] = {
        1: 1,
        2: int(ubcode),
        3: _md5_hex(query_string),
        4: _md5_hex(body_bytes),
        5: _md5_hex(user_agent),
        6: int(timestamp),
        7: int(canvas),
        8: int(timestamp_ms) % 0x80000000,
        9: sdk_version,
    }
    plaintext = _legacy_payload(fields)
    words = tuple(_u32(x) for x in (key_words or _new_key()))
    rounds = (sum(word & 15 for word in words) & 15) + 5
    encrypted = _gnarly_xor(plaintext, words, rounds)
    key_bytes = b"".join(word.to_bytes(4, "little") for word in words)
    insertion = 0
    for value in key_bytes:
        insertion = (insertion + value) % (len(encrypted) + 1)
    for value in encrypted:
        insertion = (insertion + value) % (len(encrypted) + 1)
    raw = bytes([75]) + encrypted[:insertion] + key_bytes + encrypted[insertion:]
    return _custom_b64(raw, _GNARLY_ALPHABET)


def encode_gnarly_current(
    query_string: str,
    body: str | bytes,
    user_agent: str,
    *,
    envcode: int = 65,
    ubcode: int = 14,
    canvas: int = 2894886431,
    timestamp: int | None = None,
    timestamp_ms: int | None = None,
    payload_version: str = "5.3.2",
    sdk_version: str = "1.0.0.417",
    total_requests: int = 2,
    companion_requests: int = 3,
    random_low16: int | None = None,
    random32: int | None = None,
    random_tail: int | None = None,
    key_words: Sequence[int] | None = None,
) -> str:
    """Encode the 17-field X-Gnarly emitted by the current Web API SDK."""
    if timestamp is None:
        timestamp = int(time.time())
    if timestamp_ms is None:
        timestamp_ms = time.time_ns() // 1_000_000
    low16 = secrets.randbits(16) if random_low16 is None else int(random_low16)
    random_a = secrets.randbits(32) if random32 is None else int(random32)
    random_b = secrets.randbits(32) if random_tail is None else int(random_tail)
    if not 0 <= low16 <= 0xFFFF:
        raise ValueError("random_low16 is outside uint16")
    fields: dict[int, int | str] = {
        1: int(envcode),
        2: int(ubcode),
        3: _md5_hex(query_string),
        4: _md5_hex(body if isinstance(body, bytes) else body.encode("utf-8")),
        5: _md5_hex(user_agent),
        6: int(timestamp),
        7: int(canvas),
        8: int(timestamp_ms) % 0x80000000,
        9: str(payload_version),
        10: str(sdk_version),
        11: 1,
        12: int(total_requests),
        13: int(companion_requests),
        14: (int(envcode) << 16) | low16,
        15: random_a,
        16: random_b,
    }
    plaintext = _current_payload(fields)
    words = tuple(_u32(x) for x in (key_words or _new_key()))
    rounds = (sum(word & 15 for word in words) & 15) + 5
    encrypted = _gnarly_xor(plaintext, words, rounds)
    key_bytes = b"".join(word.to_bytes(4, "little") for word in words)
    insertion = 0
    for value in key_bytes:
        insertion = (insertion + value) % (len(encrypted) + 1)
    for value in encrypted:
        insertion = (insertion + value) % (len(encrypted) + 1)
    raw = bytes([75]) + encrypted[:insertion] + key_bytes + encrypted[insertion:]
    return _custom_b64(raw, _GNARLY_ALPHABET)


def encode_dynosaur_current(
    query_string: str,
    user_agent: str,
    *,
    page: str = "",
    envcode: int = 65,
    ubcode: int = 14,
    canvas: int = 2894886431,
    timestamp: int | None = None,
    rand_b: int | None = None,
    payload_version: str = "5.3.2",
    sdk_version: str = "1.0.0.417",
    image_ratio: int = 1,
    text_ratio: int = 2,
    runtime_field8: str = "0",
    runtime_field18: str = "0",
    runtime_field19: str = "0",
    key_words: Sequence[int] | None = None,
) -> str:
    """Encode the current 25-field X-Dynosaur request-binding value."""
    if timestamp is None:
        timestamp = int(time.time())
    if rand_b is None:
        rand_b = (time.time_ns() // 1_000_000) % 0x80000000
    plaintext = _dynosaur_payload(
        ts=int(timestamp), rand_b=int(rand_b), query=query_string,
        user_agent=user_agent, envcode=int(envcode), ubcode=int(ubcode),
        canvas=int(canvas), page=str(page), payload_version=str(payload_version),
        sdk_version=str(sdk_version), image_ratio=int(image_ratio),
        text_ratio=int(text_ratio), runtime_field8=str(runtime_field8),
        runtime_field18=str(runtime_field18), runtime_field19=str(runtime_field19),
    )
    words = tuple(_u32(x) for x in (key_words or _new_key()))
    rounds = (sum(word & 15 for word in words) & 15) + 5
    encrypted = _gnarly_xor(plaintext, words, rounds)
    key_bytes = b"".join(word.to_bytes(4, "little") for word in words)
    insertion = 0
    for value in key_bytes:
        insertion = (insertion + value) % (len(encrypted) + 1)
    for value in encrypted:
        insertion = (insertion + value) % (len(encrypted) + 1)
    raw = bytes([75]) + encrypted[:insertion] + key_bytes + encrypted[insertion:]
    return _custom_b64(raw, _GNARLY_ALPHABET)


def _rc4(data: bytes, key: Sequence[int]) -> bytes:
    box = list(range(256))
    index = 0
    for position in range(256):
        index = (index + box[position] + key[position % len(key)]) % 256
        box[position], box[index] = box[index], box[position]
    out = bytearray()
    a = 0
    index = 0
    for value in data:
        a = (a + 1) % 256
        index = (index + box[a]) % 256
        box[a], box[index] = box[index], box[a]
        out.append(value ^ box[(box[a] + box[index]) % 256])
    return bytes(out)


def _double_md5(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.md5(hashlib.md5(raw).digest()).hexdigest()


def _bogus_b64(data: bytes) -> str:
    return _custom_b64(data, _BOGUS_ALPHABET)


def encode_x_bogus(
    query_string: str,
    user_agent: str,
    body: str | bytes = "",
    *,
    timestamp: int | None = None,
    ubcode: int = 14,
    magic: int = 536919696,
) -> str:
    """Encode a 28-character X-Bogus value.

    The Creator Studio project-post sample uses endpoint-specific values
    ``ubcode=136`` and ``magic=2893450271``.  Older web generations use the
    historical defaults, so both are explicit inputs rather than silently
    conflated constants.
    """
    if timestamp is None:
        timestamp = int(time.time())
    md5_params = _double_md5(query_string)
    md5_data = _double_md5(body)
    # The third RC4 key byte is the same endpoint ubcode carried in the salt
    # list.  The historical implementation used 14 because its endpoint
    # class was 14; Creator Studio project/post currently uses 136.
    ua_cipher = _rc4(user_agent.encode("utf-8"), (0, 1, int(ubcode)))
    md5_ua = _md5_hex(_custom_b64(ua_cipher, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="))
    md5p = bytes.fromhex(md5_params)
    md5d = bytes.fromhex(md5_data)
    md5u = bytes.fromhex(md5_ua)
    salt = [timestamp, int(magic), 64, 0, 1, int(ubcode),
            md5p[-2], md5p[-1], md5d[-2], md5d[-1], md5u[-2], md5u[-1]]
    salt.extend((timestamp >> shift) & 0xFF for shift in (24, 16, 8, 0))
    salt.extend((int(magic) >> shift) & 0xFF for shift in (24, 16, 8, 0))
    checksum = 64
    for value in salt[3:]:
        checksum ^= value
    salt.extend((checksum, 255))
    order = (3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 4, 6, 8, 10, 12, 14, 16, 18, 20)
    filtered = [salt[index - 1] for index in order]
    scramble_order = (0, 10, 1, 11, 2, 12, 3, 13, 4, 14, 5, 15, 6, 16, 7, 17, 8, 18, 9)
    scrambled = bytes(filtered[index] for index in scramble_order)
    encrypted = _rc4(scrambled, (255,))
    return _bogus_b64(bytes((2, 255)) + encrypted)


__all__ = [
    "encode_dynosaur_current", "encode_gnarly_project", "encode_gnarly_current",
    "encode_x_bogus",
]
