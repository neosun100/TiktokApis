"""Session capture: pure mapping + a real headless Chrome against a local page."""

import http.server
import json
import os
import stat
import threading

import pytest

from capture import session
from capture.cdp import CDPError, chrome_proxy_arg, find_chrome

def _generated_pem() -> str:
    # Generated per run: the tests need a realistic PKCS#8 blob, never a
    # checked-in key.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


PEM = _generated_pem()


def snapshot():
    return {
        "api_request": {
            "url": "https://www.tiktok.com/api/x/?WebIdLastTime=17&device_id=7000000000000000001"
                   "&odinId=7000000000000000002&region=HK&priority_region=HK"
                   "&app_language=en&os=mac&tz_name=Asia%2FHong_Kong",
            "headers": {"cookie": "sessionid=s; msToken=m", "user-agent": "UA/153",
                        "sec-ch-ua": '"Chrome";v="153"', "sec-ch-ua-platform": '"macOS"',
                        "accept-language": "en-US"},
        },
        "metrics": {"screen_width": "1512", "screen_height": "982", "browser_language": "en-US",
                    "browser_platform": "MacIntel", "tz_name": "Asia/Hong_Kong"},
        "storage": {
            "local": {"security-sdk/s_sdk_crypt_sdk": json.dumps({"data": json.dumps({"ec_privateKey": PEM})}),
                      "security-sdk/s_sdk_sign_data_key/web_protect": json.dumps(
                          {"data": json.dumps({"ts_sign": "ts.1", "encrypt_ticket": "enc"})})},
            "session": {"msToken": "m"},
            "document_cookie": "msToken=m",
        },
    }


def test_profile_mapping_complete():
    out = session.profile_from_snapshot(snapshot())
    p = out["profile"]
    assert out["missing"] == []
    assert p["device_id"] == "7000000000000000001" and p["odin_id"] == "7000000000000000002"
    assert p["region"] == "HK" and p["web_id_last_time"] == "17"
    assert p["browser_metrics"]["tz_name"] == "Asia/Hong_Kong"
    assert p["ticket_guard_private_key"] == PEM
    assert p["ticket_guard_ts_sign"] == "ts.1" and p["ticket_guard_encrypt_ticket"] == "enc"
    assert out["sources"]["ticket_guard_private_key"].startswith("local:security-sdk/")
    assert p["browser_metrics"]["web_query"] == {"app_language": "en", "os": "mac",
                                                 "tz_name": "Asia/Hong_Kong"}


def test_profile_mapping_reports_missing_instead_of_defaulting():
    snap = snapshot()
    snap["api_request"] = {}
    out = session.profile_from_snapshot(snap)
    assert {"cookie", "device_id", "odin_id"} <= set(out["missing"])
    assert "device_id" not in out["profile"]


def test_profile_loads_into_auth():
    from builder.auth import TiktokAuth

    p = dict(session.profile_from_snapshot(snapshot())["profile"])
    auth = TiktokAuth.from_cookie(p.pop("cookie"), **p)
    assert auth.device_id == "7000000000000000001"
    assert auth.browser_metrics["screen_width"] == "1512"
    assert auth.profile.app_language == "en" and auth.profile.os == "mac"
    assert auth.profile.defaulted <= {"language", "cpu_core_number"}


def test_private_json_permissions(tmp_path):
    target = tmp_path / "p.json"
    session.write_private_json(target, {"a": 1})
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


@pytest.mark.parametrize("url,server,creds", [
    ("socks5h://127.0.0.1:1080", "socks5://127.0.0.1:1080", None),
    ("http://u:p@proxy.example:8080", "http://proxy.example:8080", ("u", "p")),
])
def test_chrome_proxy_arg(url, server, creds):
    assert chrome_proxy_arg(url) == (server, creds)


def test_chrome_proxy_arg_rejects_portless():
    with pytest.raises(CDPError):
        chrome_proxy_arg("socks5://host")


# --- real browser ------------------------------------------------------------

try:
    find_chrome()
    HAVE_CHROME = True
except CDPError:
    HAVE_CHROME = False

PAGE = (b"""<html><body><script>
localStorage.setItem('security-sdk/s_sdk_crypt_sdk', JSON.stringify({data: JSON.stringify({ec_privateKey: """
        + json.dumps(PEM).encode() + b"""})}));
sessionStorage.setItem('msToken', 'mtok');
document.cookie = 'msToken=mtok; path=/';
fetch('/api/probe/?device_id=7000000000000000009&odinId=7000000000000000008&region=HK');
</script></body></html>""")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        if self.path == "/":
            self.send_header("Set-Cookie", "sessionid=abc; Path=/")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGE)
        else:
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


@pytest.mark.browser
@pytest.mark.skipif(not HAVE_CHROME, reason="Chrome not installed")
def test_collect_snapshot_real_chrome(tmp_path):
    from capture.cdp import Chrome

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        with Chrome(profile_dir=tmp_path / "profile", headless=True) as chrome:
            snap = session.collect_snapshot(chrome, origin=origin, settle=10)
    finally:
        server.shutdown()
    out = session.profile_from_snapshot(snap)
    p = out["profile"]
    assert p["device_id"] == "7000000000000000009"
    assert "sessionid=abc" in p["cookie"]
    assert p["session_storage"]["msToken"] == "mtok"
    assert p["ticket_guard_private_key"] == PEM
    assert p["browser_metrics"]["tz_name"]
