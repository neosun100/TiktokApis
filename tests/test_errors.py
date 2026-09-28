"""Business-code and transport error handling.

Guards: HTTP-200 bodies with a non-zero status_code / VOD ResponseMetadata
error raise instead of returning; verification demands get their own type;
no error string ever contains the signed query.
Does not guard: which concrete codes TikTok uses for captcha (needs captures).
"""

import pytest

from api.tiktok_web import TiktokWebAPI
from builder.errors import BusinessError, TransportError, VerificationRequired, redact_url
from utils import http_client

SECRET = "SECRET"


def test_success_body_is_returned(fake_response):
    body = {"status_code": 0, "data": [1]}
    assert TiktokWebAPI._json_response(fake_response(body=body)) == body


def test_nonzero_status_code_raises_business_error(fake_response):
    resp = fake_response(body={"status_code": 2053, "status_msg": "frequent",
                               "log_pb": {"impr_id": "L1"}})
    with pytest.raises(BusinessError) as info:
        TiktokWebAPI._json_response(resp, path="/api/commit/item/digg/")
    assert info.value.code == 2053
    assert info.value.log_id == "L1"
    assert not isinstance(info.value, VerificationRequired)


def test_string_zero_is_success(fake_response):
    assert TiktokWebAPI._json_response(fake_response(body={"status_code": "0"}))


def test_check_business_can_be_disabled(fake_response):
    body = {"status_code": 8}
    assert TiktokWebAPI._json_response(fake_response(body=body), check_business=False) == body


def test_verify_marker_in_body_raises_verification(fake_response):
    resp = fake_response(body={"status_code": 10000, "verify_center_decision_conf": "{}"})
    with pytest.raises(VerificationRequired):
        TiktokWebAPI._json_response(resp)


def test_verify_marker_in_header_raises_verification(fake_response):
    resp = fake_response(body={"status_code": 0}, headers={"bdturing-verify": "{}"})
    with pytest.raises(VerificationRequired):
        TiktokWebAPI._json_response(resp)


def test_vod_response_metadata_error(fake_response):
    body = {"ResponseMetadata": {"RequestId": "R", "Error": {"Code": "InvalidAuth", "Message": "m"}}}
    with pytest.raises(BusinessError) as info:
        TiktokWebAPI._json_response(fake_response(body=body))
    assert info.value.code == "InvalidAuth"


def test_bodies_without_status_code_pass(fake_response):
    body = {"body": {"consent": {"wid": "1"}}}
    assert TiktokWebAPI._json_response(fake_response(body=body)) == body


def test_empty_allowed_response(fake_response):
    out = TiktokWebAPI._json_response(fake_response(body=None), allow_empty=True)
    assert out["empty_response"] is True


def test_http_error_is_redacted(fake_response):
    with pytest.raises(TransportError) as info:
        TiktokWebAPI._json_response(fake_response(status_code=403, body={"x": 1}))
    assert info.value.http_status == 403
    assert SECRET not in str(info.value)
    assert "www.tiktok.com/api/x/" in str(info.value)


def test_non_json_is_redacted(fake_response):
    resp = fake_response(body=b"<html>token=SECRET</html>", headers={"content-type": "text/html"})
    with pytest.raises(TransportError) as info:
        TiktokWebAPI._json_response(resp)
    assert SECRET not in str(info.value)


def test_business_error_str_never_contains_query(fake_response):
    with pytest.raises(BusinessError) as info:
        TiktokWebAPI._json_response(fake_response(body={"status_code": 1}))
    assert SECRET not in str(info.value)


def test_redact_url():
    assert redact_url("https://a.b/c/d?msToken=x") == "a.b/c/d"
    assert redact_url("/api/x?y=1") == "/api/x"


def test_curl_exception_is_redacted(monkeypatch):
    from curl_cffi.requests.exceptions import ConnectionError as CurlConnError

    class Boom:
        def request(self, *a, **k):
            raise CurlConnError("Failed to connect https://x/?msToken=SECRET")

    monkeypatch.setattr(http_client, "_session", lambda: Boom())
    with pytest.raises(TransportError) as info:
        http_client.request("GET", "https://www.tiktok.com/api/?msToken=SECRET")
    assert SECRET not in str(info.value)
    assert info.value.__cause__ is None


def test_proxy_from_environment(monkeypatch):
    monkeypatch.setenv("TIKTOK_PROXY", "socks5h://127.0.0.1:1080")
    assert http_client._kwargs({})["proxy"] == "socks5h://127.0.0.1:1080"
    monkeypatch.delenv("TIKTOK_PROXY")
    assert "proxy" not in http_client._kwargs({})
