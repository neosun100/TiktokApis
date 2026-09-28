"""BrowserProfile: single fingerprint source, precedence and propagation."""

import pytest

from builder.auth import TiktokAuth
from builder.profile import BrowserProfile
from tests import golden_harness

MAC_HK = {"screen_width": "1512", "screen_height": "982", "browser_language": "en-US",
          "browser_platform": "MacIntel", "tz_name": "Asia/Hong_Kong"}


def test_defaults_are_reported():
    profile = BrowserProfile.resolve()
    assert profile.browser_platform == "Win32" and profile.os == "windows"
    assert "tz_name" in profile.defaulted and "os" in profile.defaulted


def test_precedence_explicit_over_query_over_metrics():
    metrics = {**MAC_HK, "web_query": {"tz_name": "Asia/Tokyo", "app_language": "ja-JP",
                                       "screen_width": "1000"}}
    p = BrowserProfile.resolve(explicit={"tz_name": "UTC"}, metrics=metrics)
    assert p.tz_name == "UTC"
    assert p.app_language == "ja-JP"
    assert p.screen_width == "1000"      # captured query beats navigator metrics
    assert p.screen_height == "982"      # metrics beat defaults
    assert p.os == "mac" and p.creator_os == "mac"
    assert "tz_name" not in p.defaulted and "os" not in p.defaulted


def test_unknown_platform_needs_explicit_os():
    with pytest.raises(ValueError):
        BrowserProfile.resolve(metrics={"browser_platform": "PlayStation"})
    p = BrowserProfile.resolve(explicit={"os": "ps", "creator_os": "ps"},
                               metrics={"browser_platform": "PlayStation"})
    assert p.os == "ps"


def test_auth_profile_follows_metric_updates():
    auth = TiktokAuth("sessionid=x")
    assert auth.profile.tz_name == "Asia/Shanghai"
    auth.browser_metrics["tz_name"] = "Asia/Hong_Kong"
    assert auth.profile.tz_name == "Asia/Hong_Kong"


def test_mac_hk_profile_reaches_every_recorded_request(monkeypatch):
    original = golden_harness.make_auth

    def mac_auth():
        auth = original()
        auth.browser_metrics.update(MAC_HK)
        auth.browser_metrics["web_query"] = {"app_language": "en", "language": "en"}
        return auth

    monkeypatch.setattr(golden_harness, "make_auth", mac_auth)
    wire = golden_harness.record()
    leaks = {}
    for name, req in wire.items():
        if "url" not in req:
            continue
        query = req["url"].split("?", 1)[-1]
        body = str(req.get("body") or "")
        hits = [lit for lit in ("Win32", "Asia%2FShanghai", "Asia/Shanghai", "=2560", "=1440",
                                "zh-CN", "os=windows", '"screen_width":2560') if lit in query or lit in body]
        if hits:
            leaks[name] = hits
    assert leaks == {}
