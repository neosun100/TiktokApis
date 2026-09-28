"""SSR / hydration parsers with synthetic pages (layout contract, no network)."""

import json

import pytest

from api import TiktokAPI
from api.tiktok_web import TiktokWebAPI
from builder.auth import TiktokAuth
from builder.errors import BrowserEvidenceError


def page(script_id, payload):
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return f'<html><body><script id="{script_id}" type="application/json">{body}</script></body></html>'


UNIVERSAL = "__UNIVERSAL_DATA_FOR_REHYDRATION__"


def test_user_detail_tolerates_inserted_keys():
    scope = {"webapp.app-context": {}, "webapp.user-detail": {"userInfo": {"user": {"id": "1"}}},
             "webapp.new-key-inserted-by-tiktok": {}, "webapp.a-b": {}}
    out = TiktokWebAPI._user_detail_from_html(page(UNIVERSAL, {"__DEFAULT_SCOPE__": scope}))
    assert out["userInfo"]["user"]["id"] == "1"


def test_user_detail_missing_is_evidence_error():
    with pytest.raises(BrowserEvidenceError):
        TiktokWebAPI._user_detail_from_html(page(UNIVERSAL, {"__DEFAULT_SCOPE__": {}}))


def test_missing_script_names_it():
    with pytest.raises(BrowserEvidenceError, match=UNIVERSAL):
        TiktokWebAPI._user_detail_from_html("<html></html>")


def test_invalid_json_is_evidence_error():
    with pytest.raises(BrowserEvidenceError, match="JSON"):
        TiktokWebAPI._video_detail_from_html(page(UNIVERSAL, "{not json"))


def test_video_detail_id_mismatch():
    data = {"__DEFAULT_SCOPE__": {"webapp.video-detail": {"itemInfo": {"itemStruct": {"id": "5"}}}}}
    assert TiktokWebAPI._video_detail_from_html(page(UNIVERSAL, data), expected_item_id="5")["id"] == "5"
    with pytest.raises(BrowserEvidenceError):
        TiktokWebAPI._video_detail_from_html(page(UNIVERSAL, data), expected_item_id="6")


def test_live_room_missing_state_raises_not_none():
    with pytest.raises(BrowserEvidenceError):
        TiktokWebAPI._live_room_from_html("<html></html>")
    data = {"LiveRoom": {"liveRoomUserInfo": {"user": {
        "id": "1", "secUid": "s", "uniqueId": "u", "roomId": "9", "status": 2}}}}
    assert TiktokWebAPI._live_room_from_html(page("SIGI_STATE", data))["roomId"] == "9"


SHOP = {"loaderData": {"a": None, "b": {"page_config": {"components_map": [
    {"component_name": "product_info", "component_data": {
        "product_info": {"product_model": {"product_id": 123}}, "review_info": {}}}]}}}}


def test_shop_detail_skips_routes_and_normalises_id():
    out = TiktokWebAPI._shop_product_detail_from_html(page("__MODERN_ROUTER_DATA__", SHOP),
                                                      expected_product_id="123")
    assert out["product_info"]["product_model"]["product_id"] == 123


def test_shop_detail_mismatch():
    with pytest.raises(BrowserEvidenceError, match="期望 9"):
        TiktokWebAPI._shop_product_detail_from_html(page("__MODERN_ROUTER_DATA__", SHOP),
                                                    expected_product_id="9")


@pytest.mark.parametrize("url,ok", [
    ("https://shop.tiktok.com/view/product/123", False),
    ("https://shop.tiktok.com/pdp/slug/123", True),
    ("https://shop.tiktok.com/pdp/123/", True),
    ("http://shop.tiktok.com/pdp/123", False),
    ("https://shop.tiktok.com.evil.com/pdp/123", False),
    ("https://shop.tiktok.com/pdp/123?x=1", True),
])
def test_shop_product_id(url, ok):
    if ok:
        assert TiktokWebAPI._shop_product_id(url) == "123"
    else:
        with pytest.raises(BrowserEvidenceError):
            TiktokWebAPI._shop_product_id(url)


def test_short_link_only_for_known_hosts(monkeypatch):
    api = TiktokWebAPI(TiktokAuth("sessionid=x"))
    assert api._resolve_short_link("https://evil/?vt.tiktok.com") == "https://evil/?vt.tiktok.com"


def test_shop_review_page_builds_body_with_product_id(monkeypatch):
    # Regression: the body referenced a removed local `match`.
    api = TiktokWebAPI(TiktokAuth("sessionid=x; oec_lucifer=" + "a" * 160))
    seen = {}

    class Stop(Exception):
        pass

    def fake_sign(**kwargs):
        seen.update(kwargs)
        raise Stop()

    monkeypatch.setattr(api.shop_signer, "sign", fake_sign)
    with pytest.raises(Stop):
        api.get_shop_product_review_page("https://shop.tiktok.com/pdp/x/123", page_start=2)
    assert '"123"' in str(seen.get("body")) or "123" in str(seen)


def test_compat_facade_webcast_user_info_guard():
    # Regression: BrowserEvidenceError import was lost in the legacy cleanup.
    with pytest.raises(BrowserEvidenceError):
        TiktokAPI(TiktokAuth("sessionid=x")).get_webcast_user_info("1", "2", "sessionid=x")


def test_get_live_room_info_wires_parser(monkeypatch, fake_response):
    from utils import http_client

    data = {"LiveRoom": {"liveRoomUserInfo": {"user": {
        "id": "1", "secUid": "s", "uniqueId": "u", "roomId": "9", "status": 2}}}}
    html = page("SIGI_STATE", data).encode()
    monkeypatch.setattr(http_client, "get", lambda url, **k: fake_response(body=html, url=url))
    api = TiktokWebAPI(TiktokAuth("sessionid=x"))
    assert api.get_live_room_info("https://www.tiktok.com/@u/live") == (
        "1", "s", "u", "9", 2, "https://www.tiktok.com/@u/live")
    monkeypatch.setattr(http_client, "get", lambda url, **k: fake_response(body=b"<html/>", url=url))
    with pytest.raises(BrowserEvidenceError):
        api.get_live_room_info("https://www.tiktok.com/@u/live")
