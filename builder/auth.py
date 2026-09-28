"""TikTok Web authentication and pure browser-signing state."""

from __future__ import annotations

import json
import hashlib
import random
import re
import time
from collections import OrderedDict
from typing import Iterable, Mapping, Optional
from urllib.parse import unquote

from .errors import BrowserEvidenceError
from .signer import SignerError, TiktokSigner, required_signature_keys


class CookieDict(OrderedDict):
    """An ordered cookie mapping understood by :mod:`utils.http_client`."""

    def __init__(self, *args, owner=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_owner = owner


def _cookie_tokens(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, str):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in value.split(";") if item.strip()]


def _cookie_pair(token: str):
    if "=" not in token:
        return token.strip(), ""
    name, value = token.split("=", 1)
    return name.strip(), value.strip()


class TiktokAuth:
    """Reusable TikTok web session state.

    The only supported public acquisition path is ``TiktokAuth.from_cookie``.
    Password, QR-code, SMS and other Passport login flows are intentionally
    reserved in ``api.tiktok_login`` and are not implemented yet.

    ``set_wire_evidence`` remains available as a diagnostic record, but static
    signature injection is deliberately disabled.  Production requests are
    signed by the unmodified local WebMssdk bundle through :class:`TiktokSigner`.
    """

    UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
    )
    SEC_CH_UA = '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"'
    SEC_CH_UA_PLATFORM = '"Windows"'
    ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6"
    CLIENT_AB_VERSIONS = (
        "70508271,72437276,73720540,75360573,75657507,75843653,75878361,"
        "76074824,76122410,76179551,76403724,76499369,76626930,76651230,"
        "76669176,76713103,76740102,76792575,76805936,76813520,76815102,"
        "76826749,76839930,76840792,76887350,76889673,76907405,76933422,"
        "76945954,76950455,77005875,77011497,77014490,77056281,77064650,"
        "77071444,77093404,77120364,77141446,77150562,77155134,70138197,"
        "70156809,70405643,71057832,71200802,71381811,71803300,72360691,"
        "72408100,72854054,72892778,73171280,73208420,73989921,74276218,"
        "74844724,75330961"
    )

    def __init__(self, cookie: str | Mapping[str, str] | None = None, *,
                 device_id: str = "", odin_id: str = "", region: str = "SG",
                 priority_region: str = "SG", signatures: Optional[Mapping] = None,
                 signature_lengths: Optional[Mapping] = None, signer=None, **runtime):
        self._raw_cookie_tokens: list[str] = []
        self.cookie = CookieDict(owner=self)
        self._cookie_str = ""
        # Chrome exposes a smaller document.cookie view than the full Cookie
        # request header (HttpOnly pairs are absent).  WebMssdk fingerprints
        # the former while requests must send the latter.
        self.document_cookie = str(runtime.get("document_cookie") or "")
        self.device_id = str(device_id or "")
        self.odin_id = str(odin_id or "")
        self._device_id_explicit = bool(device_id)
        self._device_id_ambiguous = False
        self._odin_id_explicit = bool(odin_id)
        self.region = region or "SG"
        self.priority_region = priority_region
        self.web_id_last_time = str(runtime.get("web_id_last_time") or int(time.time()))
        self.user_agent = runtime.get("user_agent") or self.UA
        self.sec_ch_ua = runtime.get("sec_ch_ua") or self.SEC_CH_UA
        self.sec_ch_ua_platform = runtime.get("sec_ch_ua_platform") or self.SEC_CH_UA_PLATFORM
        self.accept_language = runtime.get("accept_language") or self.ACCEPT_LANGUAGE
        self.client_ab_versions = runtime.get("client_ab_versions") or self.CLIENT_AB_VERSIONS
        self.signatures = dict(signatures or {})
        self.signature_lengths = dict(signature_lengths or {})
        self.signer = signer or runtime.get("signer") or TiktokSigner()
        self.browser_metrics = dict(runtime.get("browser_metrics") or {})
        self.shared_cache = dict(runtime.get("shared_cache") or {})
        self.local_storage = dict(runtime.get("local_storage") or {})
        self.session_storage = dict(runtime.get("session_storage") or {})
        # ``g_exp`` is the persisted WebIdLastTime source used by the web
        # bootstrap.  A fresh wall-clock value changes the signed URL and is
        # therefore not an acceptable fallback when browser storage has it.
        if not runtime.get("web_id_last_time"):
            g_exp = self.local_storage.get("g_exp") or self.session_storage.get("g_exp")
            try:
                g_exp_int = int(str(g_exp))
                self.web_id_last_time = str(g_exp_int // 1000 if g_exp_int > 10**11 else g_exp_int)
            except (TypeError, ValueError):
                pass
        # Login-only values are kept here for the later passport phase.
        self.x_mssdk_info = runtime.get("x_mssdk_info", "")
        self.ticket_guard_public_key = runtime.get("ticket_guard_public_key", "")
        self.ticket_guard_web_version = runtime.get("ticket_guard_web_version", "")
        self.ticket_guard_version = runtime.get("ticket_guard_version", "")
        self.ticket_guard_iteration_version = runtime.get("ticket_guard_iteration_version", "")
        self.ticket_guard_client_data = runtime.get("ticket_guard_client_data", "")
        # Fresh Web SDK ticket state can be supplied from the browser's
        # security-sdk storage.  It is never printed or used as a static
        # signature; post_project derives a new ECDSA client-data envelope.
        self.ticket_guard_private_key = runtime.get("ticket_guard_private_key", "")
        self.ticket_guard_encrypt_ticket = runtime.get("ticket_guard_encrypt_ticket", "")
        self.ticket_guard_ts_sign = runtime.get("ticket_guard_ts_sign", "")
        self.passport_csrf_token = runtime.get("passport_csrf_token", "")
        # Same-site write requests carry both the normal TikTok CSRF header
        # and the WebMssdk CSRF header.  They are deliberately explicit
        # runtime fields: neither value is guessed or padded when a write is
        # attempted.
        self.tt_csrf_token = runtime.get("tt_csrf_token", "") or self.cookie.get("tt_csrf_token", "")
        self.secsdk_csrf_token = runtime.get("secsdk_csrf_token", "")
        self.ttwid_ticket = runtime.get("ttwid_ticket", "")
        self.strict_browser_alignment = bool(runtime.get("strict_browser_alignment", True))
        if cookie:
            self.set_cookie_header(cookie if isinstance(cookie, str) else None, cookie)
            # ``tt_csrf_token`` is normally HttpOnly in Chrome's full Cookie
            # header, so resolve it after the cookie string has been parsed.
            # Runtime state still wins when callers supplied an explicit
            # current token from the browser security context.
            if not self.tt_csrf_token:
                self.tt_csrf_token = self.cookie.get("tt_csrf_token", "")

    @classmethod
    def from_cookie(cls, cookie_str: str = "", **kwargs) -> "TiktokAuth":
        return cls(cookie_str, **kwargs)

    @property
    def cookie_str(self) -> str:
        return self._cookie_str

    @property
    def ms_token(self) -> str:
        # Chrome may keep two browser-storage copies while rotating the
        # query-token.  The session copy is the value used by the current web
        # request in the captured wire (localStorage can lag one rotation),
        # then localStorage, then the last Cookie pair for cookie-only users.
        return (self.session_storage.get("msToken")
                or self.local_storage.get("msToken")
                or self.cookie.get("msToken", ""))

    @property
    def ttwid(self) -> str:
        """Return the current browser ``ttwid`` in its wire (unquoted) form."""
        # The fpid=9 IM socket can retain a different ttwid from the latest
        # Cookie request header.  An explicitly captured same-page WS value
        # must win; the Cookie pair is only the fallback.
        value = (self.browser_metrics.get("im_ttwid")
                 or self.cookie.get("ttwid", ""))
        return unquote(str(value or ""))

    def build_im_access_key(self, wid: str | None = None) -> str:
        """Purely derive the IM WebSocket access key from the browser wid.

        The current web SDK uses the same formula as the historical helper,
        but the ``wid`` must come from the current unsigned privacy-config
        response (or explicit browser metrics); it is never hard-coded.
        """
        current_wid = str(wid or self.browser_metrics.get("im_wid") or "")
        if not current_wid:
            raise BrowserEvidenceError(
                "私信 WebSocket 缺少当前浏览器 wid；请先读取 privacy-config 并传入 im_wid"
            )
        app_key = "e1bd35ec9db7b8d846de66ed140b1ad9"
        source = f"9{app_key}{current_wid}f8a69f1719916z"
        return hashlib.md5(source.encode("utf-8")).hexdigest()

    @property
    def im_region(self) -> str:
        """Region label for the ``im-api-{r}`` / ``im-ws-{r}`` hosts.

        It is interpolated into a hostname that receives the full Cookie
        header, so anything but a short lowercase label is rejected.
        """
        region = str(self.region or "").lower()
        if not re.fullmatch(r"[a-z]{2,8}", region):
            raise BrowserEvidenceError(
                f"region 必须是 2-8 位字母的区域标签，实际为 {self.region!r}"
            )
        return region

    @property
    def verify_fp(self) -> str:
        return self.cookie.get("s_v_web_id", "")

    @property
    def logged_in(self) -> bool:
        return bool(self.cookie.get("sessionid") or self.cookie.get("sid_tt") or self.cookie.get("multi_sids"))

    def set_cookie_header(self, cookie_header: str | None, cookie: Mapping[str, str] | None = None):
        """Load cookies while preserving duplicate pairs and their order."""
        tokens = _cookie_tokens(cookie_header) if cookie_header is not None else []
        if cookie is not None and not tokens:
            tokens = [f"{key}={value}" for key, value in cookie.items()]
        self._raw_cookie_tokens = list(tokens)
        self.cookie = CookieDict(owner=self)
        for token in tokens:
            name, value = _cookie_pair(token)
            if name:
                self.cookie[name] = value
        self._sync_ids_from_cookies()
        self._sync_cookie_str()
        return self

    def set_document_cookie(self, value: str):
        """Set the browser-visible cookie string used by the signer."""
        self.document_cookie = str(value or "")
        return self

    def _sync_ids_from_cookies(self):
        multi = self.cookie.get("multi_sids", "")
        if not self.device_id:
            # Current Chrome stores the web/device id in the Tea cache.  It is
            # distinct from the logged-in user id encoded in ``multi_sids``;
            # using the latter here produces a valid-looking but wire-different
            # query.  A full browser storage dump can contain several Tea
            # caches from different app surfaces, so silently choosing the
            # first one is unsafe.  Pick only a unique candidate; callers with
            # multiple caches must provide the browser's current device_id.
            candidates = []
            for storage in (self.local_storage, self.session_storage):
                for key, value in storage.items():
                    if not str(key).startswith("__tea_cache_tokens_"):
                        continue
                    try:
                        web_id = str(json.loads(str(value)).get("web_id") or "")
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if re.fullmatch(r"\d{16,20}", web_id):
                        if web_id not in candidates:
                            candidates.append(web_id)
            if len(candidates) == 1:
                self.device_id = candidates[0]
                self._device_id_explicit = True
            elif len(candidates) > 1:
                self._device_id_ambiguous = True
        if not self.device_id and multi:
            self.device_id = multi.split("%3A", 1)[0].split(":", 1)[0]
            self._device_id_explicit = True
        if not self.odin_id and multi:
            self.odin_id = multi.split("%3A", 1)[0].split(":", 1)[0]
            self._odin_id_explicit = True
        if not self.device_id and not self._device_id_ambiguous:
            self.device_id = str(random.randint(10**18, 10**19 - 1))
        if not self.odin_id:
            self.odin_id = self.device_id

    def _sync_cookie_str(self):
        self._cookie_str = "; ".join(self._raw_cookie_tokens)

    def set_cookie(self, name: str, value: str):
        """Update one cookie without dropping unrelated raw pairs."""
        replaced = False
        for index, token in enumerate(self._raw_cookie_tokens):
            token_name, _ = _cookie_pair(token)
            if token_name == name:
                self._raw_cookie_tokens[index] = f"{name}={value}"
                replaced = True
        if not replaced:
            self._raw_cookie_tokens.append(f"{name}={value}")
        self.cookie[name] = value
        if name == "tt_csrf_token":
            self.tt_csrf_token = value
        self._sync_cookie_str()
        return self

    def apply_set_cookie(self, headers):
        """Merge Set-Cookie values from requests/curl_cffi response headers."""
        values = []
        try:
            values = list(headers.get_list("set-cookie"))
        except Exception:
            value = headers.get("set-cookie") if headers else None
            if value:
                values = [value]
        for value in values:
            token = str(value).split(";", 1)[0]
            name, item = _cookie_pair(token)
            if name:
                self.set_cookie(name, item)
        return self

    def set_wire_evidence(self, path: str, *, x_dynosaur: str, x_gnarly: str,
                          ms_token: str = "", x_bogus: str = "1",
                          expected_lengths: Optional[Mapping[str, int]] = None):
        # Kept solely for regression comparison and documentation.  The values
        # are never read by ``signature_for`` and can never be sent on wire.
        self.signatures[path] = {
            "X-Dynosaur": x_dynosaur,
            "X-Gnarly": x_gnarly,
            "msToken": ms_token or self.ms_token,
            "X-Bogus": x_bogus,
        }
        if expected_lengths:
            self.signature_lengths[path] = dict(expected_lengths)
        return self

    def signature_for(self, path: str, *, require: bool = True, url: str | None = None,
                      method: str = "GET", headers: Optional[Mapping[str, str]] = None,
                      body: str | bytes | None = None, referer: str = "https://www.tiktok.com/",
                      expected_lengths: Optional[Mapping[str, int]] = None,
                      signing_timestamp: int | None = None) -> dict[str, str]:
        if url is None:
            raise BrowserEvidenceError(
                f"{path} 必须先提供完整 unsigned URL/body/header 上下文；静态抓包签名已禁用。"
            )
        try:
            sign_kwargs = dict(
                url=url, method=method, headers=headers, body=body,
                cookie=(self.document_cookie or self.cookie_str), user_agent=self.user_agent,
                referer=referer,
                expected_lengths=(dict(expected_lengths) if expected_lengths is not None
                                  else self.signature_lengths.get(path)),
                signing_timestamp=signing_timestamp,
            )
            if self.browser_metrics:
                sign_kwargs["metrics"] = self.browser_metrics
            if self.shared_cache:
                sign_kwargs["shared_cache"] = self.shared_cache
            if self.local_storage:
                sign_kwargs["local_storage"] = self.local_storage
            if self.session_storage:
                sign_kwargs["session_storage"] = self.session_storage
            result = self.signer.sign(**sign_kwargs)
        except SignerError as exc:
            raise BrowserEvidenceError(f"{path} 纯计算签名失败: {exc}") from exc
        values = result.get("values") or {}
        lengths = result.get("lengths") or {}
        required_keys = required_signature_keys(url)
        if require and any(not isinstance(lengths.get(key), int) or lengths[key] != len(str(values.get(key) or ""))
                           for key in required_keys):
            raise BrowserEvidenceError(f"{path} 纯计算结果缺少或错误的字段长度元数据")
        # TikTok's browser wrapper appends the calculated values in this
        # order.  Params preserves insertion order so the final query has
        # `X-Dynosaur`, `msToken`, `X-Bogus`, `X-Gnarly` exactly like Chrome.
        out = {key: str(values.get(key) or "") for key in required_keys}
        missing = [key for key, value in out.items() if not value]
        if require and missing:
            raise BrowserEvidenceError(f"{path} 纯计算后缺少字段: {', '.join(missing)}")
        return out

    def sign_request(self, path: str, *, url: str, method: str = "GET",
                     headers: Optional[Mapping[str, str]] = None,
                     body: str | bytes | None = None, referer: str = "https://www.tiktok.com/",
                     require: bool = True,
                     expected_lengths: Optional[Mapping[str, int]] = None,
                     signing_timestamp: int | None = None) -> dict[str, str]:
        return self.signature_for(
            path, require=require, url=url, method=method, headers=headers,
            body=body, referer=referer, expected_lengths=expected_lengths,
            signing_timestamp=signing_timestamp,
        )

    def require_cookie(self, *names: str):
        missing = [name for name in names if not self.cookie.get(name)]
        if missing:
            raise BrowserEvidenceError(f"缺少 Cookie 字段: {', '.join(missing)}")
        return self

    def require_browser_profile(self):
        # ``msToken`` is a rotating web-storage value in current Chrome.  It
        # may be absent from the request Cookie header even though it is the
        # exact value the browser appends to the signed query, so validate the
        # resolved precedence property rather than requiring a Cookie pair.
        self.require_cookie("s_v_web_id")
        if not self.ms_token:
            raise BrowserEvidenceError(
                "缺少 msToken：请提供当前 sessionStorage/localStorage 或 Cookie 值"
            )
        if self._device_id_ambiguous:
            raise BrowserEvidenceError(
                "浏览器 Tea cache 存在多个 device_id：请显式传入当前请求使用的 device_id"
            )
        if not self._device_id_explicit or not self._odin_id_explicit:
            raise BrowserEvidenceError(
                "缺少浏览器设备证据：请提供 multi_sids Cookie，或显式传入 device_id/odin_id"
            )
        return self

    def build_ticket_guard(self, path: str, *, timestamp: int | None = None) -> dict[str, str]:
        """Pure-calculate ticket-guard headers from fresh browser key state."""
        from signing.ticket_guard import build_headers
        missing = [
            name for name, value in (
                ("ticket_guard_private_key", self.ticket_guard_private_key),
                ("ticket_guard_encrypt_ticket", self.ticket_guard_encrypt_ticket),
                ("ticket_guard_ts_sign", self.ticket_guard_ts_sign),
            ) if not value
        ]
        if missing:
            raise BrowserEvidenceError(
                "缺少可重算 ticket-guard 的浏览器 security-sdk 状态: "
                + ", ".join(missing)
            )
        return build_headers(
            private_key_pem=self.ticket_guard_private_key,
            encrypt_ticket=self.ticket_guard_encrypt_ticket,
            ts_sign=self.ticket_guard_ts_sign,
            path=path,
            timestamp=timestamp,
            version=self.ticket_guard_version or "2",
            iteration_version=self.ticket_guard_iteration_version or "0",
        )
