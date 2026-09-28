"""Security guards: host injection, subprocess env leakage, gzip bombs."""

import gzip
import json
import subprocess

import pytest

from builder.auth import TiktokAuth
from builder.errors import BrowserEvidenceError
from signing import live_wire
from signing.node_runner import minimal_env
from signing.protobuf import ProtobufWireError


@pytest.mark.parametrize("region", ["evil.com/#", "sg.evil", "", "s", "SG:443", "sg\n"])
def test_im_region_rejects_host_injection(region):
    auth = TiktokAuth(region="x")
    auth.region = region
    with pytest.raises(BrowserEvidenceError):
        _ = auth.im_region


def test_im_region_accepts_labels():
    assert TiktokAuth(region="SG").im_region == "sg"
    assert TiktokAuth(region="useast").im_region == "useast"


def test_minimal_env_drops_secrets(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("TIKTOK_COOKIE", "sessionid=x")
    env = minimal_env(TIKTOK_BSID_QUIET="1")
    assert "GITHUB_TOKEN" not in env and "TIKTOK_COOKIE" not in env
    assert env["TIKTOK_BSID_QUIET"] == "1"
    assert "PATH" in env


def test_frontier_signer_passes_minimal_env(monkeypatch):
    from builder.signer import SignerError, TiktokSigner

    seen = {}

    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SignerError):
        TiktokSigner().frontier_sign(cookie="c", user_agent="ua")
    assert seen.get("env") is not None and "GITHUB_TOKEN" not in seen["env"]


def test_gzip_bomb_is_rejected():
    bomb = gzip.compress(b"\0" * (live_wire.MAX_DECOMPRESSED_BYTES + 1))
    with pytest.raises(ProtobufWireError):
        live_wire.gunzip_bounded(bomb)


def test_bad_gzip_is_protobuf_error():
    with pytest.raises(ProtobufWireError):
        live_wire.gunzip_bounded(b"\x1f\x8bnot-gzip")


def test_truncated_gzip_is_rejected():
    with pytest.raises(ProtobufWireError):
        live_wire.gunzip_bounded(gzip.compress(b"hello world" * 100)[:-10])


def test_gunzip_roundtrip():
    assert live_wire.gunzip_bounded(gzip.compress(b"abc")) == b"abc"


def test_heartbeat_frame_roundtrip():
    assert live_wire.decode_push_frame(live_wire.encode_heartbeat(123))["payload_type"] == "hb"
    json.dumps(live_wire.decode_push_frame(live_wire.encode_heartbeat(1))["headers"])
