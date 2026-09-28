"""Upload/transcode response handling with a fake transport (no network)."""

import pytest

from api.tiktok_web import TiktokWebAPI
from builder.auth import TiktokAuth
from builder.errors import BrowserEvidenceError, BusinessError
from utils import http_client

APPLY = {"Result": {"InnerUploadAddress": {"UploadNodes": [{
    "UploadHost": "tos-sg.example", "SessionKey": "sk",
    "StoreInfos": [{"StoreUri": "tos/abc", "Auth": "AUTH"}]}]}}}


@pytest.fixture
def api():
    return TiktokWebAPI(TiktokAuth("sessionid=x; multi_sids=7000000000000000001%3Aabc"))


@pytest.fixture
def transport(monkeypatch, fake_response):
    calls = []

    def install(*bodies):
        queue = list(bodies)

        def fake(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return fake_response(body=queue.pop(0), url=url)

        monkeypatch.setattr(http_client, "request", fake)
        return calls

    return install


def test_tos_success(api, transport):
    calls = transport({"code": 2000, "message": "Success", "data": {}})
    assert api.upload_tos_bytes(APPLY, b"abc")["code"] == 2000
    assert calls[0][2]["timeout"] > api.timeout - 1


def test_tos_failure_code_raises(api, transport):
    transport({"code": 4001, "message": "crc mismatch"})
    with pytest.raises(BusinessError) as info:
        api.upload_tos_bytes(APPLY, b"abc")
    assert info.value.code == 4001


def test_upload_timeout_scales_with_size(api):
    assert api._upload_timeout(0) == api.timeout
    assert api._upload_timeout(100 * 1024 * 1024) > 300


@pytest.mark.parametrize("name", ['a"b', "a\r\nx: y", "", "x" * 300])
def test_tos_filename_injection_rejected(api, transport, name):
    transport({"code": 2000})
    with pytest.raises(ValueError):
        api.upload_tos_bytes(APPLY, b"abc", filename=name)


def test_transcode_poll_completes(api, monkeypatch):
    seq = iter([{"transcode_result": [{"transcode_status": 1}]},
                {"transcode_result": [{"transcode_status": 3}]}])
    monkeypatch.setattr(api, "get_video_transcode_result", lambda *a, **k: next(seq))
    out = api.wait_video_transcode("v", width=1, height=1, duration_ms=1, file_key="f",
                                   interval=0)
    assert out["transcode_result"][0]["transcode_status"] == 3


def test_transcode_unparseable_status_fails_fast(api, monkeypatch):
    monkeypatch.setattr(api, "get_video_transcode_result",
                        lambda *a, **k: {"transcode_result": [{"transcode_status": "abc"}]})
    with pytest.raises(BrowserEvidenceError):
        api.wait_video_transcode("v", width=1, height=1, duration_ms=1, file_key="f",
                                 timeout=0, interval=0)


def test_transcode_timeout(api, monkeypatch):
    monkeypatch.setattr(api, "get_video_transcode_result",
                        lambda *a, **k: {"transcode_result": [{"transcode_status": 1}]})
    with pytest.raises(TimeoutError):
        api.wait_video_transcode("v", width=1, height=1, duration_ms=1, file_key="f",
                                 timeout=0, interval=0)
