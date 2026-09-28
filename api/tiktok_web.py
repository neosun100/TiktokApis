"""Evidence-driven TikTok Web API facade.

This module is intentionally evidence-driven: it covers endpoints visible in
the logged-in Chrome capture, plus the Creator Studio upload-authorize and
project-post contracts captured from the real page. New TikTok methods are
added only after the same business action is captured in Chrome; unknown paths
are not guessed.
"""

from __future__ import annotations

import json
import re
import base64
import gzip
import hashlib
import io
import os
import secrets
import string
import subprocess
import tempfile
import time
import uuid
import zlib
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional
from urllib.parse import quote, urlencode, urlparse

from bs4 import BeautifulSoup

from builder.auth import BrowserEvidenceError, TiktokAuth
from builder.header import HeaderBuilder, HeaderType
from builder.params import Params
from signing.protobuf import (
    ProtobufWireError,
    field_bytes,
    field_message,
    field_string,
    field_varint,
)
from signing.aws_v4 import sign as sign_aws_v4
from signing.shop_bsid import ShopBSIDError, ShopBSIDSigner
from signing import live_wire
from utils import http_client


class TiktokWebAPI:
    origin = "https://www.tiktok.com"
    webcast_origin = "https://webcast.tiktok.com"
    PROJECT_POST_PATH = "/tiktok/web/project/post/v1/"
    PROJECT_POST_SIGNATURE_LENGTHS = {"msToken": 160, "X-Bogus": 28, "X-Gnarly": 268}
    COLLECTION_WRITE_HEADER_ORDER = (
        "x-cthulhu-csrf", "sec-ch-ua-platform", "referer", "sec-ch-ua",
        "sec-ch-ua-mobile", "tt-csrf-token", "user-agent", "content-type",
        "accept", "accept-encoding", "accept-language", "content-length",
        "cookie", "origin", "priority", "sec-fetch-dest", "sec-fetch-mode",
        "sec-fetch-site",
    )
    # The browser IM SDK inserts these option headers into Request.headers in
    # this exact order.  They are protobuf map entries, not HTTP headers.
    IM_HEADER_KEYS = (
        "aid", "app_name", "channel", "device_platform", "device_id",
        "region", "priority_region", "os", "referer", "root_referer",
        "cookie_enabled", "screen_width", "screen_height", "browser_language",
        "browser_platform", "browser_name", "browser_version", "browser_online",
        "verifyFp", "app_language", "webcast_language", "tz_name",
        "is_page_visible", "focus_state", "is_fullscreen", "history_len",
        "user_is_login", "data_collection_enabled", "from_appID", "locale",
        "user_agent", "Web-Sdk-Ms-Token",
    )
    # MessageBody.message_type of a plain text DM (Chrome-captured send wire).
    IM_TEXT_MESSAGE_TYPE = 7
    CONFIRMED_READ_ENDPOINTS = {
        "/api/post/item_list/",
        "/tiktok/creator/manage/item_list/v1/",
        "/api/following/item_list/",
        "/api/user/playlist/",
        "/api/story/item_list/",
        "/api/story/user_list/",
        "/api/user/list/",
        "/api/recommend/item_list/",
        "/api/related/item_list/",
        "/api/comment/list/",
        "/api/comment/list/reply/",
        "/api/mention/recent/contact/list/v1/",
        "/api/at/default/list/",
        "/api/search/general/full/",
        "/api/search/general/preview/",
        "/api/search/suggest/guide/",
        "/api/item/availability/",
        "/api/preload/item_list/",
        "/api/prefetch/explore/item_list/",
        "/api/v1/web-cookie-privacy/config",
        "/api-live/user/room",
        "/webcast/feed/",
        "/webcast/feed/drawer_tabs/",
        "/webcast/room/live_podcast/",
        "/webcast/game_feed/api/feed_card/strategy/",
        "/webcast/game_feed/api/feed_component/strategy/",
        "/tiktok/event/feed/v1",
        "/tiktok/event/recommend/v1",
        "/tiktok/event/list/v1",
        "/webcast/room/search/",
        "/webcast/room/enter/",
        "/webcast/room/check_alive/",
        "/webcast/user/",
        "/webcast/ranklist/online_audience/",
        "/webcast/room/create_info/",
        "/webcast/room/push_fetch/",
        "/webcast/setting/",
        "/webcast/gift/list/",
        "/webcast/gift/cpc_prompt/",
        "/webcast/room/quick_chat_list/",
        "/webcast/assets/effects/",
        "/webcast/room/in_room_banner/",
        "/webcast/user/attr/",
        "/webcast/im/fetch/",
        "/api/inbox/notice_list/",
        "/api/inbox/notice_count/",
        "/api/user/following/request/list/",
        "/tiktok/v1/im/user/profile/",
        "/api/feedback/v1/newest_reply/",
        "/api/notice/multi/",
        "/tiktok/popup/dispatch/v1",
        "/tiktok/popup/callback/v1",
        "/tiktok/popup/display/v1/",
        "/tiktok/ppf/api/eligibility/v2",
        "/api/compliance/settings/",
        "/tiktok/v1/compliance/guadig/settings/",
        "/tiktok/v1/csp/pa_prompt",
        "/tiktok/music/tt_to_dsp/platform/list/v1",
        "/api/share/settings/",
        "/api/im/spotlight/relation/",
        "/api/privacy/user/effected_count/v1",
        "/api/privacy/setting/restriction/v1",
        "/aweme/v1/report/inbox/notice/",
        "/tiktok/v1/community_notes/intake/check/",
        "/api/user/settings/",
        "/api/user/detail/",
        "/api/ba/business/suite/permission/list/",
        "/webcast/sub/privilege/get_sub_info",
        "/webcast/wallet_api/fs/diamond_buy/permission_v2",
        "/webcast/wallet_api_tiktok/recharge/check_external_entry",
        "/api/user/collection_list/",
        "/api/user/collect/item_list/",
        "/api/playlist/name_check",
        "/api/collection/candidate/item_list/",
        "/api/collection/detail/",
        "/api/collection/item_list/",
        "/api/collection/create/",
        "/api/collection/modify_info/",
        "/api/collection/modify_items/",
        "/api/collection/move_items/",
        "/api/repost/item_list/",
        "/api/v1/video/upload/auth/",
        "/tiktok/v1/screen_time/upload/",
        "/tiktok/v1/app_open_times/upload/",
        "/api/v1/web/project/get/ab/",
        "/api/v1/user/profile/upload/",
        "/tiktok/v1/creator/publish_setting/",
        "/api/v1/media/get/openid/",
        "/tiktok/v1/screen_time/list/",
    }

    def __init__(self, auth: Optional[TiktokAuth] = None, *, timeout: int = 30,
                 shop_signer=None):
        self.auth = auth
        self.timeout = timeout
        self.shop_signer = shop_signer or ShopBSIDSigner(timeout=timeout)

    def _auth(self, auth_or_cookie=None) -> TiktokAuth:
        if isinstance(auth_or_cookie, TiktokAuth):
            return auth_or_cookie
        if isinstance(auth_or_cookie, str):
            return TiktokAuth.from_cookie(auth_or_cookie)
        if auth_or_cookie is not None:
            return TiktokAuth.from_cookie(auth_or_cookie)
        if self.auth is None:
            raise ValueError("请传入 TiktokAuth 或完整 Cookie 字符串")
        return self.auth

    @staticmethod
    def _json_response(response, *, allow_empty: bool = False):
        response.raise_for_status()
        if allow_empty and not getattr(response, "content", b""):
            # `/webcast/room/chat/` currently returns HTTP 200 with an empty
            # CORS response (Chrome reports net::ERR_FAILED).  Preserve that
            # wire fact instead of inventing a JSON status payload.
            return {
                "http_status": int(getattr(response, "status_code", 0) or 0),
                "status_code": None,
                "empty_response": True,
            }
        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError(f"TikTok 返回的不是 JSON: {response.text[:300]}") from exc

    @staticmethod
    def _ticket_timestamp(client_data: str) -> int:
        """Read the browser ticket timestamp used by the request signature."""
        try:
            token = str(client_data).strip()
            token += "=" * (-len(token) % 4)
            payload = json.loads(base64.urlsafe_b64decode(token.encode("ascii")))
            value = int(payload.get("timestamp"))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError,
                UnicodeDecodeError, base64.binascii.Error) as exc:
            raise ValueError("ticket-guard-client-data 缺少可解析的 timestamp") from exc
        if value <= 0:
            raise ValueError("ticket-guard-client-data timestamp 无效")
        return value

    def _request_response(self, auth: TiktokAuth, *, method: str, path: str,
                          params: Params, referer: str, signed: bool = True,
                          body=None, origin: str = "", form: bool = False,
                          accept: str | None = None,
                          extra_headers: Mapping[str, str] | None = None,
                          expected_lengths: Mapping[str, int] | None = None,
                          ticket_guard: bool = False,
                          ticket_guard_sec_csrf: bool = True,
                          ticket_guard_tt_csrf_header: bool = True,
                          content_type_before_mobile: bool = False,
                          header_order: tuple[str, ...] | None = None):
        # The live event family is also hosted on webcast.tiktok.com even
        # though its path starts with /tiktok/.  Screen-time and Creator
        # Studio /tiktok/v1 paths remain on www.tiktok.com; routing every
        # /tiktok/ path to webcast would be a wire mismatch.
        is_webcast = path.startswith("/webcast/") or path.startswith("/tiktok/event/")
        request_origin = self.webcast_origin if is_webcast else self.origin
        header_type = HeaderType.GET
        if method.upper() == "POST" and body is not None:
            header_type = HeaderType.FORM if form else HeaderType.POST
        # The browser calls webcast.tiktok.com from www.tiktok.com. It sends
        # the www Origin and marks this cross-subdomain request same-site.
        header_origin = origin or (self.origin if is_webcast else "")
        fetch_site = "same-site" if is_webcast else "same-origin"
        headers = HeaderBuilder.build(
            header_type, auth, referer=referer, origin=header_origin,
            content_length=(str(len(body if isinstance(body, bytes)
                                 else str(body).encode("utf-8")))
                            if body is not None and method.upper() in {"POST", "PUT", "PATCH"}
                            else None),
            sec_fetch_site=fetch_site,
        ).get()
        if accept is not None:
            headers["accept"] = accept
        if extra_headers:
            headers.update({str(key): str(value) for key, value in extra_headers.items()})
        if header_order:
            # Some same-origin writes insert their CSRF fields before the
            # normal client hints.  Header order is part of the signer input
            # and of the browser curl evidence, so retain the captured order
            # instead of merely appending otherwise-complete fields.
            ordered = OrderedDict()
            for key in header_order:
                if key in headers:
                    ordered[key] = headers[key]
            for key, value in headers.items():
                if key not in ordered:
                    ordered[key] = value
            headers = ordered
        if content_type_before_mobile and not ticket_guard:
            # The webcast like fetch inserts JSON content-type before
            # sec-ch-ua-mobile; keep this endpoint-specific Chrome order.
            ordered = OrderedDict()
            for key in (
                "sec-ch-ua-platform", "referer", "content-encoding", "user-agent", "sec-ch-ua",
                "content-type", "sec-ch-ua-mobile", "accept", "accept-encoding",
                "accept-language", "content-length", "cookie", "origin", "priority",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
            ):
                if key in headers:
                    ordered[key] = headers[key]
            headers = ordered
        if ticket_guard:
            # Comment publishing is the first captured Web API write that
            # carries the fresh five-field ticket guard.  Some writes also
            # carry the security-sdk CSRF header, while the captured digg and
            # collect writes do not.  Generate the guard from browser
            # security-sdk state; never accept a consumed static header bundle.
            guard = auth.build_ticket_guard(path)
            csrf = auth.tt_csrf_token
            sec_csrf = auth.secsdk_csrf_token if ticket_guard_sec_csrf else ""
            if ticket_guard_tt_csrf_header and not csrf:
                raise ValueError("该写请求需要完整 tt-csrf-token")
            if ticket_guard_sec_csrf and not sec_csrf:
                raise ValueError("该写请求需要完整 x-secsdk-csrf-token")
            headers.update(guard)
            if ticket_guard_tt_csrf_header:
                headers["tt-csrf-token"] = csrf
            if ticket_guard_sec_csrf:
                headers["x-secsdk-csrf-token"] = sec_csrf
            # Match Chrome ExtraInfo's observed order.  HTTP/2 may normalize
            # casing, but preserving insertion order keeps curl evidence and
            # the pure signer input aligned.
            ordered = OrderedDict()
            for key in (
                "tt-ticket-guard-client-data", "sec-ch-ua-platform", "referer",
                "sec-ch-ua", "sec-ch-ua-mobile", "tt-ticket-guard-web-version",
                "tt-csrf-token" if ticket_guard_tt_csrf_header else "__no_tt_csrf__",
                "tt-ticket-guard-version", "user-agent",
                "tt-ticket-guard-public-key", "x-secsdk-csrf-token", "content-type",
                "tt-ticket-guard-iteration-version", "accept", "accept-encoding",
                "accept-language", "content-length", "cookie", "origin", "priority",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
            ):
                if key in headers:
                    ordered[key] = headers[key]
            headers = ordered
        if signed:
            auth.require_browser_profile()
            # The browser carries msToken into the signer input before the SDK
            # calculates the remaining three query values.
            unsigned_query = params.to_query()
            if "msToken=" not in unsigned_query:
                unsigned_query = f"{unsigned_query}&msToken={auth.ms_token}"
            unsigned_url = f"{request_origin}{path}?{unsigned_query}"
            signatures = auth.sign_request(
                path, url=unsigned_url, method=method, headers=headers,
                body=body, referer=referer, require=auth.strict_browser_alignment,
                expected_lengths=expected_lengths,
            )
            params.update(signatures)
        url = f"{request_origin}{path}?{params.to_query()}"
        response = http_client.request(method, url, headers=headers, data=body, timeout=self.timeout)
        auth.apply_set_cookie(response.headers)
        return response

    def _request_json(self, auth: TiktokAuth, *, method: str, path: str,
                      params: Params, referer: str, signed: bool = True,
                      body=None, origin: str = "", form: bool = False,
                      accept: str | None = None,
                      extra_headers: Mapping[str, str] | None = None,
                      expected_lengths: Mapping[str, int] | None = None,
                      ticket_guard: bool = False,
                      ticket_guard_sec_csrf: bool = True,
                      ticket_guard_tt_csrf_header: bool = True,
                      content_type_before_mobile: bool = False,
                      header_order: tuple[str, ...] | None = None,
                      allow_empty: bool = False):
        response = self._request_response(
            auth, method=method, path=path, params=params, referer=referer,
            signed=signed, body=body, origin=origin, form=form, accept=accept,
            extra_headers=extra_headers,
            expected_lengths=expected_lengths,
            ticket_guard=ticket_guard,
            ticket_guard_sec_csrf=ticket_guard_sec_csrf,
            ticket_guard_tt_csrf_header=ticket_guard_tt_csrf_header,
            content_type_before_mobile=content_type_before_mobile,
            header_order=header_order,
        )
        return self._json_response(response, allow_empty=allow_empty)

    def get_upload_auth(self, *, signed: bool = True, auth=None,
                        referer: str = f"{origin}/tiktokstudio/upload?from=webapp&tab=video"):
        """Fetch current Creator STS credentials without replaying a token.

        A first page bootstrap can issue the short unsigned ``aid`` variant;
        the current upload action (Chrome req 596/677/688) uses the signed
        variant in the exact order ``aid, msToken, X-Bogus, X-Gnarly``.  The
        default models that action; ``signed=False`` remains available only
        for an explicitly captured bootstrap call.
        """
        auth = self._auth(auth)
        params = Params([("aid", "1988")])
        return self._request_json(
            auth, method="GET", path="/api/v1/video/upload/auth/",
            params=params, referer=referer, signed=signed,
            accept="application/json, text/plain, */*",
            expected_lengths=(
                {"msToken": len(auth.ms_token), "X-Bogus": 28, "X-Gnarly": 268}
                if signed else None
            ),
            header_order=(
                "sec-ch-ua-platform", "referer", "user-agent", "accept",
                "sec-ch-ua", "sec-ch-ua-mobile", "accept-encoding",
                "accept-language", "cookie", "priority", "sec-fetch-dest",
                "sec-fetch-mode", "sec-fetch-site",
            ),
        )

    def get_creator_item_list(self, *, cursor: int = 0, size: int = 50,
                              auth=None,
                              referer: str = f"{origin}/tiktokstudio/content"):
        """Read TikTok Studio's posted-work list using its captured POST wire.

        The content page sends a JSON POST even for this read.  Its query,
        body key order, CSRF/AGW headers and browser-version space encoding
        differ from the public profile item list.
        """
        if int(cursor) < 0 or not 1 <= int(size) <= 50:
            raise ValueError("Creator 作品列表需要 cursor >= 0 且 1 <= size <= 50")
        auth = self._auth(auth)
        auth.require_browser_profile()
        if not auth.tt_csrf_token:
            raise BrowserEvidenceError("Creator 作品列表缺少 Chrome tt-csrf-token")
        country = str(auth.cookie.get("store-country-code") or auth.region).upper()
        params = Params([
            ("locale", "zh-Hans"), ("aid", "1988"),
            ("priority_region", country), ("region", country),
            ("tz_name", "Asia/Shanghai"),
            ("app_name", "tiktok_creator_center"),
            ("app_language", "zh-Hans"), ("device_platform", "web_pc"),
            ("channel", "tiktok_web"), ("device_id", auth.device_id),
            ("os", "win"), ("screen_width", "2560"),
            ("screen_height", "1440"), ("browser_language", "zh-CN"),
            ("browser_platform", "Win32"), ("browser_name", "Mozilla"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
        ], space_plus_keys=("browser_version",))
        body = json.dumps(OrderedDict((
            ("cursor", int(cursor)), ("size", int(size)),
            ("query", OrderedDict((
                ("sort_orders", [{"field_name": "post_time", "order": 2}]),
                ("conditions", []), ("is_recent_posts", False),
            ))),
        )), ensure_ascii=False, separators=(",", ":"))
        return self._request_json(
            auth, method="POST", path="/tiktok/creator/manage/item_list/v1/",
            params=params, referer=referer, body=body, origin=self.origin,
            accept="application/json, text/plain, */*",
            extra_headers={"agw-js-conv": "str", "tt-csrf-token": auth.tt_csrf_token},
            expected_lengths={"msToken": len(auth.ms_token),
                              "X-Bogus": 28, "X-Gnarly": 268},
            header_order=(
                "sec-ch-ua-platform", "referer", "sec-ch-ua",
                "sec-ch-ua-mobile", "agw-js-conv", "tt-csrf-token",
                "user-agent", "accept", "content-type", "accept-encoding",
                "accept-language", "content-length", "cookie", "origin",
                "priority", "sec-fetch-dest", "sec-fetch-mode",
                "sec-fetch-site",
            ),
        )

    def get_cookie_privacy_config(self, *, locale: str = "zh-Hans",
                                  app_id: str = "1988", theme: str = "default",
                                  tea: str = "1", auth=None,
                                  referer: str = f"{origin}/"):
        """Read the unsigned privacy config used to resolve the web wid."""
        return self.request_captured(
        "/api/v1/web-cookie-privacy/config",
            {"locale": locale, "appId": app_id, "theme": theme, "tea": tea},
            auth=auth, referer=referer, signed=False,
            accept="application/json, text/plain, */*",
        )

    def get_wid(self, *, auth=None, referer: str = f"{origin}/"):
        """Return ``body.consent.wid`` from the captured privacy config."""
        data = self.get_cookie_privacy_config(auth=auth, referer=referer)
        try:
            return data["body"]["consent"]["wid"]
        except (KeyError, TypeError) as exc:
            raise RuntimeError("TikTok privacy config 缺少 body.consent.wid") from exc

    def request_captured(self, path: str, query: Mapping[str, str], *,
                         method: str = "GET", body=None, auth=None,
                         referer: str = f"{origin}/", origin: str = "",
                         form: bool = False, signed: bool = True,
                         accept: str | None = None):
        """Replay a captured endpoint without inventing undocumented fields.

        This is the escape hatch for a newly discovered read-only endpoint: copy
        every unsigned query field from Chrome into ``query``.  The local SDK
        then calculates all signature fields from that exact request context.
        Static signature values are rejected.
        """
        if not path.startswith("/"):
            raise ValueError("path 必须以 / 开头")
        auth = self._auth(auth)
        params = Params(query)
        return self._request_json(
            auth, method=method, path=path, params=params, referer=referer,
            body=body, origin=origin, form=form, signed=signed, accept=accept,
        )

    def get_project_ab(self, ab_param: str, *, auth=None,
                       referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Unsigned Creator Studio AB config request."""
        return self.request_captured(
            "/api/v1/web/project/get/ab/",
            {"browser": "chrome", "ab_param": ab_param, "aid": "1988"},
            auth=auth, referer=referer, signed=False,
            accept="application/json, text/plain, */*",
        )

    def get_profile_upload_config(self, *, enter_post_page_from: str = "1",
                                  auth=None,
                                  referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        auth = self._auth(auth)
        return self.request_captured(
            "/api/v1/user/profile/upload/",
            {"aid": "1988", "enter_post_page_from": enter_post_page_from,
             "verifyFp": auth.verify_fp}, auth=auth, referer=referer,
            signed=False, accept="application/json, text/plain, */*",
        )

    def get_publish_setting(self, *, auth=None,
                            referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        return self.request_captured(
            "/tiktok/v1/creator/publish_setting/", {"aid": "1988"},
            auth=auth, referer=referer, signed=False,
            accept="application/json, text/plain, */*",
        )

    def get_media_openid(self, *, auth=None,
                         referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        return self.request_captured(
            "/api/v1/media/get/openid/", {"aid": "1988"},
            auth=auth, referer=referer, signed=False,
            accept="application/json, text/plain, */*",
        )

    def post_project_create(self, creation_id: str, *, project_type: str = "1",
                            auth=None,
                            referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Create the empty Creator Studio project used before media upload.

        Chrome sends a real POST with an empty body and only
        ``creation_id``, ``type`` and ``aid`` in the query.  The endpoint is
        unsigned; it must not inherit the project-post WebMssdk signature.
        """
        if not creation_id:
            raise ValueError("project/create 需要浏览器 creation_id")
        auth = self._auth(auth)
        headers = HeaderBuilder.build(
            HeaderType.GET, auth, referer=referer, origin=self.origin,
            content_length="0", sec_fetch_site="same-origin",
        ).get()
        headers["accept"] = "application/json, text/plain, */*"
        params = Params([
            ("creation_id", str(creation_id)),
            ("type", str(project_type)),
            ("aid", "1988"),
        ])
        url = f"{self.origin}/api/v1/web/project/create/?{params.to_query()}"
        response = http_client.request(
            "POST", url, headers=headers, data=None, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    def post_creator_poi_list(self, *, page_num: int = 1, page_size: int = 10,
                              search_id: str = "", creation_id: str = "",
                              last_search_id: str = "", history_len: str = "20",
                              auth=None,
                              referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Search Creator Studio locations using the captured JSON contract."""
        auth = self._auth(auth)
        auth.require_browser_profile()
        web_params = OrderedDict((
            ("aid", 1988),
            ("app_name", "tiktok_web"),
            ("channel", "tiktok_web"),
            ("device_platform", "web_pc"),
            ("device_id", str(auth.device_id)),
            ("region", str(auth.region)),
            ("priority_region", str(auth.priority_region)),
            ("referer", ""),
            ("cookie_enabled", True),
            ("screen_width", 2560),
            ("screen_height", 1440),
            ("browser_language", "zh-CN"),
            ("browser_platform", "Win32"),
            ("browser_name", "Mozilla"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("browser_online", True),
            ("verifyFp", auth.verify_fp),
            ("app_language", "zh-Hans"),
            ("webcast_language", "zh-Hans"),
            ("tz_name", "Asia/Shanghai"),
            ("is_fullscreen", False),
            ("history_len", str(history_len)),
        ))
        body = json.dumps(OrderedDict((
            ("page_num", int(page_num)),
            ("page_size", int(page_size)),
            ("search_params", OrderedDict((
                ("search_id", str(search_id)),
                ("creation_id", str(creation_id)),
                ("last_search_id", str(last_search_id)),
            ))),
            ("web_params", web_params),
        )), ensure_ascii=False, separators=(",", ":"))
        params = Params([("aid", "1988")])
        return self._request_json(
            auth, method="POST", path="/tiktok/v1/creator/poi/list",
            params=params, referer=referer, body=body, signed=False,
            accept="application/json, text/plain, */*",
            origin=self.origin,
        )

    @classmethod
    def _im_header_map(cls, auth: TiktokAuth, header_map: Mapping | None) -> OrderedDict:
        """Validate the ordered ``Request.headers`` map captured from Chrome."""
        source = header_map
        if source is None:
            source = auth.browser_metrics.get("im_headers")
        if not isinstance(source, Mapping):
            raise BrowserEvidenceError(
                "私信 protobuf 请求需要 browser_metrics['im_headers'] 的完整浏览器字段"
            )
        missing = [key for key in cls.IM_HEADER_KEYS if key not in source]
        if missing:
            raise BrowserEvidenceError(
                "私信 protobuf header map 缺少浏览器字段: " + ", ".join(missing)
            )
        values = OrderedDict()
        for key in cls.IM_HEADER_KEYS:
            value = source[key]
            if value is None:
                raise BrowserEvidenceError(f"私信 protobuf header map 字段为空: {key}")
            if not isinstance(value, str):
                raise BrowserEvidenceError(
                    f"私信 protobuf header map 字段必须保留浏览器字符串形态: {key}"
                )
            values[key] = value
        # These are copied into the SDK map by the current page.  Refusing a
        # mismatch prevents a caller from accidentally signing one browser
        # state and sending another one.
        if values["device_id"] != str(auth.device_id):
            raise BrowserEvidenceError("私信 protobuf device_id 与浏览器 Tea cache 不一致")
        if values["verifyFp"] != str(auth.verify_fp):
            raise BrowserEvidenceError("私信 protobuf verifyFp 与浏览器 Cookie 不一致")
        if values["user_agent"] != str(auth.user_agent):
            raise BrowserEvidenceError("私信 protobuf user_agent 与浏览器 profile 不一致")
        if values["Web-Sdk-Ms-Token"] != str(auth.ms_token):
            raise BrowserEvidenceError("私信 protobuf Web-Sdk-Ms-Token 不是当前浏览器 msToken")
        return values

    @staticmethod
    def _im_inbox_bytes(inbox: Mapping, index: int) -> bytes:
        if not isinstance(inbox, Mapping):
            raise BrowserEvidenceError(
                f"私信 inbox[{index}] 必须是浏览器对象"
            )
        # The current web SDK maps ``cursorType`` into the object only when it
        # owns a value.  The captured message-page request therefore contains
        # fields 1-4 and omits field 5; callers may provide field 5 when their
        # browser snapshot explicitly contains it, but it is not invented.
        required = ("inbox_type", "cursor", "limit", "scene")
        missing = [key for key in required if key not in inbox]
        if missing:
            raise BrowserEvidenceError(
                f"私信 inbox[{index}] 缺少浏览器字段: {', '.join(missing)}"
            )
        try:
            fields = [
                field_varint(1, inbox["inbox_type"], name="inbox_type"),
                field_varint(2, inbox["cursor"], name="cursor"),
                field_varint(3, inbox["limit"], name="limit"),
                field_varint(4, inbox["scene"], name="scene"),
            ]
            if "cursor_type" in inbox and inbox["cursor_type"] is not None:
                fields.append(field_varint(5, inbox["cursor_type"], name="cursor_type"))
            return b"".join(fields)
        except ProtobufWireError as exc:
            raise BrowserEvidenceError(f"私信 inbox[{index}] 字段无效: {exc}") from exc

    @classmethod
    def _im_outer_request_bytes(cls, *, command: int, body_payload: bytes,
                                sequence_id: int, token: str, refer: int,
                                inbox_type: int, sdk_version: str,
                                build_number: str, device_id: str,
                                channel: str | None, device_platform: str,
                                device_type: str | None, os_version: str | None,
                                version_code: str | None,
                                headers: Mapping[str, str], config_id: int | None,
                                auth_type: int | None = None) -> bytes:
        """Encode the captured IM ``Request`` envelope.

        The generated SDK has two levels here: ``Request.body`` is field 8,
        and the command-specific message (204/301/...) is nested inside that
        body.  Keeping the wrapper explicit is important: putting the command
        message directly at the top level produces a request of a different
        length even though all visible values look correct.
        """
        request_body = field_message(
            8, field_message(command, body_payload, name="command body"),
            name="request body",
        )
        fields = [
            field_varint(1, command, name="cmd"),
            field_varint(2, sequence_id, name="sequence_id"),
            field_string(3, sdk_version, name="sdk_version"),
            field_string(4, token, name="token"),
            field_varint(5, refer, name="refer"),
            field_varint(6, inbox_type, name="inbox_type"),
            field_string(7, build_number, name="build_number"),
            request_body,
            field_string(9, device_id, name="device_id"),
        ]
        if channel is not None:
            fields.append(field_string(10, channel, name="channel"))
        fields.append(field_string(11, device_platform, name="device_platform"))
        for field_number, value, name in (
            (12, device_type, "device_type"),
            (13, os_version, "os_version"),
            (14, version_code, "version_code"),
        ):
            if value is not None:
                fields.append(field_string(field_number, value, name=name))
        for key, value in headers.items():
            entry = field_string(1, key, name="header key") + field_string(
                2, value, name=f"header {key}"
            )
            fields.append(field_message(15, entry, name="headers"))
        if config_id is not None:
            fields.append(field_varint(16, config_id, name="config_id"))
        if auth_type is not None:
            fields.append(field_varint(18, auth_type, name="auth_type"))
        return b"".join(fields)

    @classmethod
    def _im_request_bytes(cls, *, inboxes, status_adapter_map, last_pull_time,
                          sequence_id: int, token: str, refer: int,
                          inbox_type: int, sdk_version: str, build_number: str,
                          device_id: str, channel: str | None,
                          device_platform: str, device_type: str | None,
                          os_version: str | None, version_code: str | None,
                          headers: Mapping[str, str], config_id: int) -> bytes:
        if not inboxes:
            raise BrowserEvidenceError("私信 get_by_user_combo 至少需要一个 inbox")
        combo = b"".join(
            field_message(1, cls._im_inbox_bytes(item, index), name="inbox")
            for index, item in enumerate(inboxes)
        )
        if status_adapter_map is not None:
            combo += field_varint(2, status_adapter_map, name="status_adapter_map")
        if last_pull_time is not None:
            combo += field_varint(3, last_pull_time, name="last_pull_time")
        # The current Chrome capture leaves channel/device_type/os/version
        # unset, while device_platform is explicitly ``web``.  If a future
        # capture owns one of the optional fields the caller can pass it and
        # it is emitted in the same protobuf order.
        return cls._im_outer_request_bytes(
            command=204, body_payload=combo, sequence_id=sequence_id,
            token=token, refer=refer, inbox_type=inbox_type,
            sdk_version=sdk_version, build_number=build_number,
            device_id=device_id, channel=channel,
            device_platform=device_platform, device_type=device_type,
            os_version=os_version, version_code=version_code, headers=headers,
            config_id=config_id,
        )

    def _post_im_protobuf(self, auth: TiktokAuth, *, path: str, raw: bytes,
                          referer: str):
        """Send a captured IM protobuf request with the browser HTTP shape."""
        request_headers = OrderedDict((
            ("sec-ch-ua-platform", auth.sec_ch_ua_platform),
            ("referer", referer),
            ("user-agent", auth.user_agent),
            ("accept", "application/x-protobuf"),
            ("sec-ch-ua", auth.sec_ch_ua),
            ("content-type", "application/x-protobuf"),
            ("sec-ch-ua-mobile", "?0"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", auth.accept_language),
            ("content-length", str(len(raw))),
            ("cookie", auth.cookie_str),
            ("origin", self.origin),
            ("priority", "u=1, i"),
            ("sec-fetch-dest", "empty"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-site", "same-site"),
        ))
        region = str(auth.region or "SG").lower()
        url = f"https://im-api-{region}.tiktok.com{path}"
        response = http_client.request(
            "POST", url, headers=request_headers, data=raw, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        response.raise_for_status()
        if not getattr(response, "content", b""):
            raise BrowserEvidenceError(
                "私信 protobuf 响应为空，拒绝伪造 JSON 或成功状态"
            )
        return bytes(response.content)

    @classmethod
    def _im_send_body_bytes(cls, *, conversation_id: str,
                            conversation_short_id: int,
                            conversation_type: int, text: str,
                            message_type: int, client_message_id: str,
                            ticket: str = "deprecated") -> bytes:
        """Encode the command-100 body observed in the Chrome WebSocket.

        The browser sends a text message as a compact JSON content string,
        followed by the two ``s:`` extension entries, the literal protocol
        ticket, and the UUID again in field 8.  Every field is emitted from
        explicit arguments; no filler bytes are added to reach a target size.
        """
        if not isinstance(conversation_id, str) or not conversation_id:
            raise BrowserEvidenceError("私信发送 conversation_id 必须是非空字符串")
        if not isinstance(text, str):
            raise BrowserEvidenceError("私信发送文本必须是字符串")
        if not isinstance(client_message_id, str) or not re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                client_message_id):
            raise BrowserEvidenceError("私信发送 client_message_id 必须是完整 UUID")
        if ticket != "deprecated":
            raise BrowserEvidenceError(
                "当前 Chrome command-100 的 ticket 必须是浏览器原样的 deprecated"
            )
        try:
            short_id = int(conversation_short_id)
            conv_type = int(conversation_type)
            msg_type = int(message_type)
        except (TypeError, ValueError) as exc:
            raise BrowserEvidenceError("私信发送 protobuf 数字字段无效") from exc
        if short_id < 0 or conv_type < 0 or msg_type < 0:
            raise BrowserEvidenceError("私信发送 protobuf 数字字段不允许为负数")
        content = json.dumps(
            # The current Chrome bundle really spells this field ``aweType``
            # (without the second ``me``); preserve that wire typo exactly.
            {"aweType": 0, "text": text},
            ensure_ascii=False, separators=(",", ":"),
        )
        ext = (
            field_string(1, "s:mentioned_users") + field_string(2, ""),
            field_string(1, "s:client_message_id")
            + field_string(2, client_message_id),
        )
        return b"".join((
            field_string(1, conversation_id, name="conversation_id"),
            field_varint(2, conv_type, name="conversation_type"),
            field_varint(3, short_id, name="conversation_short_id"),
            field_string(4, content, name="content"),
            field_message(5, ext[0], name="ext"),
            field_message(5, ext[1], name="ext"),
            field_varint(6, msg_type, name="message_type"),
            field_string(7, ticket, name="ticket"),
            field_string(8, client_message_id, name="client_message_id"),
        ))

    @classmethod
    def _im_send_frame_bytes(cls, *, body_payload: bytes, sequence_id: int,
                             log_id: int, x_bogus: str,
                             request_headers: Mapping[str, str],
                             frame_headers: Mapping[str, str],
                             token: str, refer: int, inbox_type: int,
                             sdk_version: str, build_number: str,
                             device_id: str, auth_type: int = 1,
                             request_payload: bytes | None = None) -> bytes:
        """Build the complete binary Frame used by ``WebSocket.send``."""
        if not isinstance(x_bogus, str) or len(x_bogus) != 16:
            raise BrowserEvidenceError(
                "私信 WebSocket 缺少当前浏览器 16 位 X-Bogus 协议标记"
            )
        if not isinstance(frame_headers, Mapping):
            raise BrowserEvidenceError("私信 WebSocket frame header map 无效")
        if not isinstance(request_headers, Mapping):
            raise BrowserEvidenceError("私信 WebSocket Request header map 无效")
        if request_payload is None:
            request = cls._im_outer_request_bytes(
                command=100, body_payload=body_payload, sequence_id=sequence_id,
                token=str(token), refer=refer, inbox_type=inbox_type,
                sdk_version=str(sdk_version), build_number=str(build_number),
                device_id=str(device_id), channel=None, device_platform="web",
                device_type=None, os_version=None, version_code=None,
                headers=request_headers, config_id=None, auth_type=auth_type,
            )
        elif isinstance(request_payload, bytes) and request_payload:
            request = request_payload
        else:
            raise BrowserEvidenceError("私信签名 Request payload 必须是非空 bytes")
        frame_fields = [
            field_varint(1, sequence_id, name="frame seqid"),
            field_varint(2, log_id, name="frame logid"),
            field_varint(3, 5, name="frame service"),
            field_varint(4, 1, name="frame method"),
        ]
        frame_fields.append(
            field_message(5, field_string(1, "X-Bogus")
                          + field_string(2, x_bogus), name="frame X-Bogus"),
        )
        for key, value in frame_headers.items():
            frame_fields.append(
                field_message(5, field_string(1, str(key))
                              + field_string(2, str(value)), name="frame header"),
            )
        frame_fields.extend((
            field_string(7, "pb", name="payload_type"),
            field_message(8, request, name="payload"),
        ))
        return b"".join(frame_fields)

    @staticmethod
    def _decode_im_send_response(raw) -> dict:
        """Decode one binary command-100 response without exposing payloads."""
        if isinstance(raw, str):
            if raw == "hi":
                return {"heartbeat": True}
            return {"text_frame": True}
        try:
            from static import Tiktok_Request_pb2 as tiktok_request
            frame = tiktok_request.Frame()
            frame.ParseFromString(bytes(raw))
            response = tiktok_request.Response()
            response.ParseFromString(frame.payload)
        except Exception as exc:  # pragma: no cover - server/schema failure
            raise BrowserEvidenceError("私信 WebSocket 回包不是可解析 protobuf") from exc
        result = {
            "heartbeat": False,
            "frame_seqid": int(frame.seqid),
            "cmd": int(response.cmd),
            "sequence_id": int(response.sequence_id),
            "status_code": int(response.status_code),
            "error_desc": str(response.error_desc),
        }
        if response.cmd == 100 and response.body.HasField("send_message_body"):
            body = response.body.send_message_body
            result.update({
                "message_status": int(body.status),
                "server_message_id": int(body.server_message_id),
                "check_code": int(body.check_code),
                "is_async_send": bool(body.is_async_send),
            })
        return result

    @staticmethod
    def _im_ws_url(auth: TiktokAuth, wid: str | None = None) -> str:
        """One shared browser-exact URL for IM send and receive sockets."""
        access_key = auth.build_im_access_key(wid)
        ttwid = auth.ttwid
        if not ttwid:
            raise BrowserEvidenceError("私信 WebSocket 缺少当前浏览器 ttwid")
        return (
            "wss://im-ws-" + str(auth.region or "SG").lower()
            + ".tiktok.com/ws/v2?device_platform=web"
            + "&version_code=fws_1.0.0&access_key=" + access_key
            + "&fpid=9&aid=1459&ttwid=" + quote(ttwid, safe="|~-._")
            + "&xsack=1&xaack=1&xsqos=0"
        )

    def send_im_message(
        self, conversation_id: str, conversation_short_id: int, text: str, *,
        conversation_type: int = 1, message_type: int = 7,
        client_message_id: str | None = None, ticket: str = "deprecated",
        sequence_id: int | None = None, log_id: int | None = None,
        wid: str | None = None, x_bogus: str | None = None,
        header_map: Mapping | None = None, auth=None,
        token: str = "", refer: int = 3, inbox_type: int = 0,
        sdk_version: str = "1.7.4",
        build_number: str = "cb1a69c:feat/im-core-sdk-ooo-push-v2",
        timeout: float | None = None,
    ):
        """Send a text DM through the current Chrome IM WebSocket contract.

        This is intentionally strict. The 16-character frame marker is
        calculated locally from MD5(serialized Request) via the original
        WebMssdk's ``frontierSign({'X-MS-STUB': ...})`` entry point.
        ``im_headers``, wid and sequence id remain current browser state.
        Ticket-guard values are freshly calculated from the browser's current
        security-sdk key state and inserted into the protobuf Request map.
        """
        auth = self._auth(auth)
        auth.require_browser_profile()
        source_headers = header_map or auth.browser_metrics.get("im_headers")
        normal_headers = self._im_header_map(auth, source_headers)
        sequence = sequence_id
        if sequence is None:
            sequence = auth.browser_metrics.get("im_ws_sequence_id")
        if sequence is None:
            raise BrowserEvidenceError(
                "私信 WebSocket 缺少当前 sequence_id（browser_metrics['im_ws_sequence_id']）"
            )
        try:
            sequence = int(sequence)
            log_value = int(log_id if log_id is not None else time.time() * 1000)
        except (TypeError, ValueError) as exc:
            raise BrowserEvidenceError("私信 WebSocket sequence_id/log_id 无效") from exc
        if sequence < 0 or log_value < 0:
            raise BrowserEvidenceError("私信 WebSocket sequence_id/log_id 不允许为负数")
        if x_bogus is not None:
            raise BrowserEvidenceError(
                "私信发送不接受外部 X-Bogus；签名必须由完整 Request 现场计算"
            )
        guard = auth.build_ticket_guard("/ws/v2")
        request_headers = OrderedDict(normal_headers)
        request_headers.update(guard)
        body = self._im_send_body_bytes(
            conversation_id=conversation_id,
            conversation_short_id=conversation_short_id,
            conversation_type=conversation_type, text=text,
            message_type=message_type,
            client_message_id=client_message_id or str(uuid.uuid4()),
            ticket=ticket,
        )
        request = self._im_outer_request_bytes(
            command=100, body_payload=body, sequence_id=sequence,
            token=str(token), refer=refer, inbox_type=inbox_type,
            sdk_version=str(sdk_version), build_number=str(build_number),
            device_id=str(auth.device_id), channel=None,
            device_platform="web", device_type=None, os_version=None,
            version_code=None, headers=request_headers, config_id=None,
            auth_type=1,
        )
        marker = auth.signer.frontier_sign(
            cookie=auth.document_cookie or auth.cookie_str,
            user_agent=auth.user_agent,
            referer=str(auth.browser_metrics.get("im_page")
                        or f"{self.origin}/messages"),
            metrics=auth.browser_metrics,
            stub=hashlib.md5(request).hexdigest(),
        )
        frame = self._im_send_frame_bytes(
            body_payload=body, sequence_id=sequence, log_id=log_value,
            x_bogus=marker, request_headers=request_headers,
            frame_headers=normal_headers, token=token, refer=refer,
            inbox_type=inbox_type, sdk_version=sdk_version,
            build_number=build_number, device_id=str(auth.device_id),
            request_payload=request,
        )
        # Web-Sdk-Ms-Token lives in the Frame header map, not this URL.
        ws_url = self._im_ws_url(auth, wid)
        try:
            import websocket
            ws = websocket.create_connection(
                ws_url, timeout=float(timeout if timeout is not None else self.timeout),
                origin=self.origin, cookie=auth.cookie_str,
                header=["User-Agent: " + str(auth.user_agent)],
            )
        except Exception as exc:
            raise BrowserEvidenceError("私信 WebSocket 连接失败") from exc
        try:
            ws.send(frame, opcode=websocket.ABNF.OPCODE_BINARY)
            deadline = time.monotonic() + float(
                timeout if timeout is not None else self.timeout
            )
            while time.monotonic() < deadline:
                try:
                    response = self._decode_im_send_response(ws.recv())
                except Exception:
                    continue
                if response.get("heartbeat"):
                    continue
                if response.get("cmd") == 100:
                    response["wire_frame_length"] = len(frame)
                    response["wire_body_length"] = len(body)
                    return response
            raise BrowserEvidenceError("私信 WebSocket 未收到 command-100 回包")
        finally:
            try:
                ws.close()
            except Exception:
                pass

    def get_im_messages_per_user_combo(self, inboxes, *,
                                       status_adapter_map: int | None = None,
                                       last_pull_time: int | None = None,
                                       sequence_id: int | None = None,
                                       token: str = "", refer: int = 3,
                                       inbox_type: int = 0,
                                       sdk_version: str = "1.7.4",
                                       build_number: str =
                                       "cb1a69c:feat/im-core-sdk-ooo-push-v2",
                                       channel: str | None = None,
                                       device_platform: str = "web",
                                       device_type: str | None = None,
                                       os_version: str | None = None,
                                       version_code: str | None = None,
                                       config_id: int | None = None,
                                       header_map: Mapping | None = None,
                                       auth=None,
                                       referer: str = f"{origin}/"):
        """Pull the current web IM inbox-combo protobuf endpoint.

        ``browser_metrics['im_headers']`` is intentionally required.  It is
        the SDK's ordered map of browser runtime fields and is part of the
        protobuf body, so inventing screen/focus/history values would produce
        a request that is not the user's real Chrome request.  The response is
        returned as raw protobuf bytes; no JSON conversion is attempted.
        """
        auth = self._auth(auth)
        auth.require_browser_profile()
        if sequence_id is None:
            sequence_id = auth.browser_metrics.get("im_sequence_id")
        if sequence_id is None:
            raise BrowserEvidenceError(
                "私信 protobuf 缺少当前浏览器 sequence_id（browser_metrics['im_sequence_id']）"
            )
        try:
            sequence_id = int(sequence_id)
        except (TypeError, ValueError) as exc:
            raise BrowserEvidenceError("私信 protobuf sequence_id 无效") from exc
        if not str(auth.device_id):
            raise BrowserEvidenceError("私信 protobuf 缺少浏览器 device_id")
        if config_id is None:
            config_id = auth.browser_metrics.get("im_config_id")
        if config_id is None:
            raise BrowserEvidenceError(
                "私信 protobuf 缺少当前浏览器 config_id（browser_metrics['im_config_id']）"
            )
        headers = self._im_header_map(auth, header_map)
        try:
            raw = self._im_request_bytes(
                inboxes=inboxes, status_adapter_map=status_adapter_map,
                last_pull_time=last_pull_time, sequence_id=sequence_id,
                token=str(token), refer=refer, inbox_type=inbox_type,
                sdk_version=str(sdk_version), build_number=str(build_number),
                device_id=str(auth.device_id), channel=channel,
                device_platform=str(device_platform), device_type=device_type,
                os_version=os_version, version_code=version_code, headers=headers,
                config_id=config_id,
            )
        except ProtobufWireError as exc:
            raise BrowserEvidenceError(f"私信 protobuf 编码失败: {exc}") from exc
        return self._post_im_protobuf(
            auth, path="/v1/message/get_by_user_combo", raw=raw,
            referer=referer,
        )

    @classmethod
    def _im_user_init_v2_bytes(
        cls, *, cursor: int, new_user: int | None,
        init_sub_type: int | None, with_empty_conv: bool | None,
        siderank_keys, sequence_id: int, token: str, refer: int,
        inbox_type: int, sdk_version: str, build_number: str,
        device_id: str, channel: str | None, device_platform: str,
        device_type: str | None, os_version: str | None,
        version_code: str | None, headers: Mapping[str, str], config_id: int,
    ) -> bytes:
        """Encode the captured command-203 user-init protobuf request.

        The current SDK emits only ``cursor=0`` for the initial message-page
        pull.  Optional fields are present only when the browser object owns
        them; no default ``new_user``/``init_sub_type``/feature key is added.
        """
        if cursor is None:
            raise BrowserEvidenceError("私信 get_by_user_init 缺少浏览器 cursor")
        if siderank_keys is not None and isinstance(siderank_keys, (str, bytes)):
            raise BrowserEvidenceError("私信 get_by_user_init siderank_keys 必须是字符串数组")
        if siderank_keys is not None:
            try:
                siderank_keys = iter(siderank_keys)
            except TypeError as exc:
                raise BrowserEvidenceError(
                    "私信 get_by_user_init siderank_keys 必须是字符串数组"
                ) from exc
        try:
            body = [field_varint(1, cursor, name="cursor")]
            if new_user is not None:
                body.append(field_varint(2, new_user, name="new_user"))
            if init_sub_type is not None:
                body.append(field_varint(3, init_sub_type, name="init_sub_type"))
            if with_empty_conv is not None:
                body.append(field_varint(4, with_empty_conv, name="with_empty_conv"))
            if siderank_keys is not None:
                for index, key in enumerate(siderank_keys):
                    if not isinstance(key, str):
                        raise ProtobufWireError(
                            f"siderank_keys[{index}] 必须是字符串"
                        )
                    body.append(field_string(5, key, name="siderank_key"))
            return cls._im_outer_request_bytes(
                command=203, body_payload=b"".join(body),
                sequence_id=sequence_id, token=token, refer=refer,
                inbox_type=inbox_type, sdk_version=sdk_version,
                build_number=build_number, device_id=device_id,
                channel=channel, device_platform=device_platform,
                device_type=device_type, os_version=os_version,
                version_code=version_code, headers=headers,
                config_id=config_id,
            )
        except ProtobufWireError as exc:
            raise BrowserEvidenceError(
                f"私信 get_by_user_init protobuf 编码失败: {exc}"
            ) from exc

    def get_im_messages_per_user_init(
        self, *, cursor: int, new_user: int | None = None,
        init_sub_type: int | None = None, with_empty_conv: bool | None = None,
        siderank_keys=None, sequence_id: int | None = None,
        token: str = "", refer: int = 3, inbox_type: int = 0,
        sdk_version: str = "1.7.4",
        build_number: str = "cb1a69c:feat/im-core-sdk-ooo-push-v2",
        channel: str | None = None, device_platform: str = "web",
        device_type: str | None = None, os_version: str | None = None,
        version_code: str | None = None, config_id: int | None = None,
        header_map: Mapping | None = None, auth=None,
        referer: str = f"{origin}/",
    ):
        """Pull the message-page user-init protobuf (command 203).

        This is the exact read-only request emitted by the current Chrome
        message page.  It requires the same live browser header map,
        sequence/config slots, and device state as the other IM endpoints.
        """
        auth = self._auth(auth)
        auth.require_browser_profile()
        if sequence_id is None:
            sequence_id = auth.browser_metrics.get("im_sequence_id")
        if sequence_id is None:
            raise BrowserEvidenceError(
                "私信 protobuf 缺少当前浏览器 sequence_id（browser_metrics['im_sequence_id']）"
            )
        if config_id is None:
            config_id = auth.browser_metrics.get("im_config_id")
        if config_id is None:
            raise BrowserEvidenceError(
                "私信 protobuf 缺少当前浏览器 config_id（browser_metrics['im_config_id']）"
            )
        headers = self._im_header_map(auth, header_map)
        try:
            raw = self._im_user_init_v2_bytes(
                cursor=cursor, new_user=new_user, init_sub_type=init_sub_type,
                with_empty_conv=with_empty_conv, siderank_keys=siderank_keys,
                sequence_id=int(sequence_id), token=str(token), refer=refer,
                inbox_type=inbox_type, sdk_version=str(sdk_version),
                build_number=str(build_number), device_id=str(auth.device_id),
                channel=channel, device_platform=str(device_platform),
                device_type=device_type, os_version=os_version,
                version_code=version_code, headers=headers,
                config_id=int(config_id),
            )
        except (TypeError, ValueError) as exc:
            raise BrowserEvidenceError(
                "私信 get_by_user_init sequence_id/config_id 无效"
            ) from exc
        return self._post_im_protobuf(
            auth, path="/v2/message/get_by_user_init", raw=raw,
            referer=referer,
        )

    @classmethod
    def _im_conversation_bytes(cls, *, conversation_id: str,
                                conversation_short_id: int,
                                conversation_type: int, anchor_index: int,
                                direction: int, limit: int,
                                ext: Mapping[str, str] | None,
                                sequence_id: int, token: str, refer: int,
                                inbox_type: int, sdk_version: str,
                                build_number: str, device_id: str,
                                channel: str | None, device_platform: str,
                                device_type: str | None, os_version: str | None,
                                version_code: str | None,
                                headers: Mapping[str, str], config_id: int) -> bytes:
        required = {
            "conversation_id": conversation_id,
            "conversation_short_id": conversation_short_id,
            "conversation_type": conversation_type,
            "anchor_index": anchor_index,
            "direction": direction,
            "limit": limit,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise BrowserEvidenceError(
                "私信 get_by_conversation 缺少浏览器字段: " + ", ".join(missing)
            )
        if not isinstance(conversation_id, str) or not conversation_id:
            raise BrowserEvidenceError("私信 conversation_id 必须是非空浏览器字符串")
        if ext is not None and not isinstance(ext, Mapping):
            raise BrowserEvidenceError("私信 conversation ext 必须是 map")
        try:
            inner = b"".join((
                field_string(1, conversation_id, name="conversation_id"),
                field_varint(2, conversation_type, name="conversation_type"),
                field_varint(3, conversation_short_id,
                             name="conversation_short_id"),
                field_varint(4, direction, name="direction"),
                field_varint(5, anchor_index, name="anchor_index"),
                field_varint(6, limit, name="limit"),
            ))
            if ext is not None:
                for key, value in ext.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        raise ProtobufWireError("conversation ext 的 key/value 必须是字符串")
                    inner += field_message(
                        7,
                        field_string(1, key, name="ext key")
                        + field_string(2, value, name="ext value"),
                        name="conversation ext",
                    )
            return cls._im_outer_request_bytes(
                command=301, body_payload=inner, sequence_id=sequence_id,
                token=token, refer=refer, inbox_type=inbox_type,
                sdk_version=sdk_version, build_number=build_number,
                device_id=device_id, channel=channel,
                device_platform=device_platform, device_type=device_type,
                os_version=os_version, version_code=version_code,
                headers=headers, config_id=config_id,
            )
        except ProtobufWireError as exc:
            raise BrowserEvidenceError(f"私信 conversation protobuf 编码失败: {exc}") from exc

    def get_im_messages_by_conversation(
        self, conversation_id: str, conversation_short_id: int,
        conversation_type: int, anchor_index: int, direction: int, limit: int,
        *, ext: Mapping[str, str] | None = None, sequence_id: int | None = None,
        token: str = "", refer: int = 3, inbox_type: int = 0,
        sdk_version: str = "1.7.4",
        build_number: str = "cb1a69c:feat/im-core-sdk-ooo-push-v2",
        channel: str | None = None, device_platform: str = "web",
        device_type: str | None = None, os_version: str | None = None,
        version_code: str | None = None, config_id: int | None = None,
        header_map: Mapping | None = None, auth=None,
        referer: str = f"{origin}/",
    ):
        """Pull a conversation using the current HTTP protobuf contract.

        This is the read request used by the web message list.  Text sending
        uses the separately captured IM transport.
        """
        auth = self._auth(auth)
        auth.require_browser_profile()
        if sequence_id is None:
            sequence_id = auth.browser_metrics.get("im_sequence_id")
        if sequence_id is None:
            raise BrowserEvidenceError(
                "私信 protobuf 缺少当前浏览器 sequence_id（browser_metrics['im_sequence_id']）"
            )
        if config_id is None:
            config_id = auth.browser_metrics.get("im_config_id")
        if config_id is None:
            raise BrowserEvidenceError(
                "私信 protobuf 缺少当前浏览器 config_id（browser_metrics['im_config_id']）"
            )
        headers = self._im_header_map(auth, header_map)
        try:
            sequence_id = int(sequence_id)
            config_id = int(config_id)
        except (TypeError, ValueError) as exc:
            raise BrowserEvidenceError("私信 protobuf sequence_id/config_id 无效") from exc
        raw = self._im_conversation_bytes(
            conversation_id=conversation_id,
            conversation_short_id=conversation_short_id,
            conversation_type=conversation_type,
            anchor_index=anchor_index, direction=direction, limit=limit,
            ext=ext, sequence_id=sequence_id, token=str(token), refer=refer,
            inbox_type=inbox_type, sdk_version=str(sdk_version),
            build_number=str(build_number), device_id=str(auth.device_id),
            channel=channel, device_platform=str(device_platform),
            device_type=device_type, os_version=os_version,
            version_code=version_code, headers=headers, config_id=config_id,
        )
        return self._post_im_protobuf(
            auth, path="/v1/message/get_by_conversation", raw=raw,
            referer=referer,
        )

    @classmethod
    def decode_im_protobuf(cls, raw: bytes) -> dict:
        """Decode an IM pull response while retaining every protobuf field.

        TikTok's web IM bundle does not publish the response descriptor used
        by commands 203/204/301. ``blackboxprotobuf`` preserves the complete
        numeric wire tree; this helper additionally extracts text-message
        objects when their captured MessageBody field layout is present.
        """
        if not isinstance(raw, (bytes, bytearray, memoryview)) or not raw:
            raise BrowserEvidenceError("私信 protobuf 回包必须是非空 bytes")
        try:
            import blackboxprotobuf
            decoded, typedef = blackboxprotobuf.decode_message(bytes(raw))
        except Exception as exc:
            raise BrowserEvidenceError("私信 protobuf 回包无法解码") from exc

        def scalar(value):
            # bbpb returns valid-UTF-8 length-delimited fields as ``str``;
            # older blackboxprotobuf builds returned ``bytes``.  Both carry
            # the MessageBody.content JSON, so both must reach json.loads.
            if isinstance(value, bytes):
                try:
                    text = value.decode("utf-8")
                except UnicodeDecodeError:
                    return value
            elif isinstance(value, str):
                text = value
            else:
                return value
            if text[:1] in ("{", "["):
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    pass
            return text

        def normalize(value):
            if isinstance(value, Mapping):
                return {str(key): normalize(item) for key, item in value.items()}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            return scalar(value)

        self_text_type = cls.IM_TEXT_MESSAGE_TYPE
        wire = normalize(decoded)
        messages = []
        unsupported = []
        seen = set()

        def visit(value):
            if isinstance(value, list):
                for item in value:
                    visit(item)
                return
            if not isinstance(value, Mapping):
                return
            content = value.get("8")
            is_text = (value.get("6") == self_text_type
                       and isinstance(content, Mapping)
                       and isinstance(content.get("text"), str))
            if (not is_text and isinstance(content, Mapping)
                    and isinstance(value.get("6"), int) and "3" in value):
                # A MessageBody of a type outside the confirmed registry.
                # Report it so "no text" is distinguishable from "not parsed".
                marker = {"server_message_id": value.get("3"),
                          "message_type": value.get("6")}
                if marker not in unsupported:
                    unsupported.append(marker)
            if is_text:
                key = (
                    str(value.get("3", "")), str(value.get("5", "")),
                    str(value.get("7", "")), str(value.get("10", "")),
                    content["text"],
                )
                if key not in seen:
                    seen.add(key)
                    messages.append({
                        "conversation_id": value.get("1"),
                        "server_message_id": value.get("3"),
                        "conversation_short_id": value.get("5"),
                        "message_type": value.get("6"),
                        "sender": value.get("7"),
                        "content": content,
                        "text": content["text"],
                        "create_time": value.get("10"),
                    })
            for item in value.values():
                visit(item)

        visit(wire)
        return {
            "raw_length": len(raw),
            "wire": wire,
            "wire_type": typedef,
            "messages": messages,
            "unsupported": unsupported,
        }

    def receive_im_messages(
        self, conversation_id: str, conversation_short_id: int,
        conversation_type: int, anchor_index: int, direction: int, limit: int,
        **kwargs,
    ) -> dict:
        """Pull and decode one conversation without changing its wire shape."""
        raw = self.get_im_messages_by_conversation(
            conversation_id, conversation_short_id, conversation_type,
            anchor_index, direction, limit, **kwargs,
        )
        return self.decode_im_protobuf(raw)

    @staticmethod
    def decode_im_ws_notification(raw) -> dict | None:
        """Decode a Chrome-observed command-500 text push (or heartbeat)."""
        if isinstance(raw, str):
            if raw == "hi":
                return None
            raise BrowserEvidenceError("私信 WS 收到未知文本帧")
        try:
            from static import Tiktok_Request_pb2 as im_proto
            frame = im_proto.Frame()
            frame.ParseFromString(bytes(raw))
            response = im_proto.Response()
            response.ParseFromString(frame.payload)
        except Exception as exc:
            raise BrowserEvidenceError("私信 WS 推送 protobuf 无法解码") from exc
        if response.cmd != 500:
            return None
        if response.status_code:
            raise BrowserEvidenceError(
                f"私信 WS 推送状态异常: {int(response.status_code)}"
            )
        if not response.body.HasField("has_new_message_notify"):
            raise BrowserEvidenceError("私信 command-500 缺少通知 body")
        notify = response.body.has_new_message_notify
        if not notify.HasField("message"):
            return None
        message = notify.message
        if int(message.message_type) != 7:
            return None  # only browser-confirmed text IM is in scope
        try:
            content = json.loads(message.content)
            text = content["text"]
            if not isinstance(text, str):
                raise ValueError("text 非字符串")
        except (ValueError, KeyError, TypeError) as exc:
            raise BrowserEvidenceError("私信文本推送 content 缺少 text") from exc
        return {
            "conversation_id": str(message.conversation_id),
            "conversation_short_id": int(message.conversation_short_id),
            "server_message_id": int(message.server_message_id),
            "message_type": int(message.message_type),
            "sender": int(message.sender),
            "sec_sender": str(message.sec_sender),
            "text": text,
            "content": content,
            "create_time": int(message.create_time),
            "frame_seqid": int(frame.seqid),
        }

    def iter_im_ws_messages(self, *, auth=None, wid: str | None = None,
                            stop_event=None, timeout: float = 2):
        """Yield text DMs from Chrome's fpid=9 IM WebSocket push channel."""
        auth = self._auth(auth)
        auth.require_browser_profile()
        ws_url = self._im_ws_url(auth, wid)
        try:
            import websocket
            ws = websocket.create_connection(
                ws_url, timeout=timeout, origin=self.origin,
                cookie=auth.cookie_str,
                header=["User-Agent: " + str(auth.user_agent)],
            )
        except Exception as exc:
            raise BrowserEvidenceError("私信接收 WS 连接失败") from exc
        seen = set()
        try:
            while stop_event is None or not stop_event.is_set():
                try:
                    raw = ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                if raw == "hi":
                    ws.send("hi")
                    continue
                if raw in ("", b""):
                    raise BrowserEvidenceError("私信接收 WS 已关闭")
                message = self.decode_im_ws_notification(raw)
                if message is None:
                    continue
                key = (message["conversation_id"], message["server_message_id"])
                if key not in seen:
                    seen.add(key)
                    yield message
        finally:
            ws.close()

    @staticmethod
    def _upload_random_s() -> str:
        """Generate the browser's 11-character upload nonce."""
        alphabet = string.ascii_lowercase + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(11))

    @staticmethod
    def _upload_credentials(upload_auth: Mapping, token_name: str) -> Mapping:
        """Return one complete STS credential set from upload/auth."""
        try:
            credentials = upload_auth[token_name]
            required = (
                "access_key_id", "secret_acess_key", "session_token", "space_name",
            )
            missing = [key for key in required if not credentials.get(key)]
        except (KeyError, TypeError, AttributeError) as exc:
            raise BrowserEvidenceError(
                f"upload/auth 缺少完整 {token_name} 临时凭证"
            ) from exc
        if missing:
            raise BrowserEvidenceError(
                f"upload/auth 的 {token_name} 缺少字段: " + ", ".join(missing)
            )
        return credentials

    @staticmethod
    def _upload_token_name(space_name: str) -> str:
        return "vframe_token_v5" if space_name == "tiktok-ai-frame" else "video_token_v5"

    def _vod_headers(self, auth: TiktokAuth, *, method: str, params: Params,
                     credentials: Mapping, referer: str, body: bytes = b"",
                     service: str = "vod",
                     content_type: str = "text/plain;charset=UTF-8") -> OrderedDict:
        """Build the exact browser header order for a signed ``/top/v1`` call.

        Creator Studio uses the same AWS V4/header ordering for the VOD and
        ImageX gateways.  The service name and POST media type are nevertheless
        part of the browser contract, so callers must select them explicitly
        rather than rewriting a VOD signature after it has been calculated.
        """
        aws = sign_aws_v4(
            method=method, path="/top/v1", query=params.pairs,
            access_key_id=str(credentials["access_key_id"]),
            secret_access_key=str(credentials["secret_acess_key"]),
            session_token=str(credentials["session_token"]), body=body,
            service=service,
        )
        base = HeaderBuilder.build(
            HeaderType.POST if method.upper() == "POST" else HeaderType.GET,
            auth, referer=referer,
            origin=self.origin if method.upper() == "POST" else "",
            content_length=str(len(body)) if method.upper() == "POST" else None,
            sec_fetch_site="same-origin",
        ).get()
        if method.upper() == "POST":
            base["content-type"] = content_type
        base["accept"] = "*/*"
        order = []
        if body:
            order.append(("x-amz-content-sha256", aws["x-amz-content-sha256"]))
        order.extend((
            ("sec-ch-ua-platform", base["sec-ch-ua-platform"]),
            ("authorization", aws["authorization"]),
            ("referer", base["referer"]),
            ("sec-ch-ua", base["sec-ch-ua"]),
            ("sec-ch-ua-mobile", base["sec-ch-ua-mobile"]),
            ("x-amz-security-token", aws["x-amz-security-token"]),
            ("x-amz-date", aws["x-amz-date"]),
            ("user-agent", base["user-agent"]),
        ))
        if method.upper() == "POST":
            order.append(("content-type", base["content-type"]))
        order.append(("accept", base["accept"]))
        for key in (
            "accept-encoding", "accept-language", "content-length", "cookie",
            "origin", "priority", "sec-fetch-dest", "sec-fetch-mode",
            "sec-fetch-site",
        ):
            if key in base:
                order.append((key, base[key]))
        return OrderedDict(order)

    def apply_image_upload(self, file_size: int, *, upload_s: str | None = None,
                           upload_auth: Mapping | None = None, auth=None,
                           referer: str = f"{origin}/tiktokstudio/upload/post/photo"):
        """Authorize one Photo Mode image through the captured ImageX API."""
        if int(file_size) <= 0:
            raise ValueError("ApplyImageUpload 的 FileSize 必须大于 0")
        upload_s = self._upload_random_s() if upload_s is None else str(upload_s)
        if not re.fullmatch(r"[a-z0-9]{11}", upload_s):
            raise ValueError("ApplyImageUpload 的 s 必须是浏览器的 11 位小写字母数字串")
        auth = self._auth(auth)
        upload_auth = upload_auth or self.get_upload_auth(
            signed=False, auth=auth, referer=referer,
        )
        # The Photo Mode ImageX gateway signs with upload/auth's
        # video_token_v5 credentials.  The AWS service is imagex even though
        # that credential object's space_name remains ``tiktok``.
        credentials = self._upload_credentials(upload_auth, "video_token_v5")
        params = Params([
            ("Action", "ApplyImageUpload"),
            ("Version", "2018-08-01"),
            ("ServiceId", "photomode"),
            ("FileSize", str(int(file_size))),
            ("s", upload_s),
            ("device_platform", "web"),
        ])
        headers = self._vod_headers(
            auth, method="GET", params=params, credentials=credentials,
            referer=referer, service="imagex",
        )
        response = http_client.request(
            "GET", f"{self.origin}/top/v1?{params.to_query()}",
            headers=headers, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    def commit_image_upload(self, session_key: str, *,
                            upload_auth: Mapping | None = None, auth=None,
                            referer: str = f"{origin}/tiktokstudio/upload/post/photo"):
        """Commit one Photo Mode object with the exact ImageX JSON body."""
        if not session_key:
            raise ValueError("CommitImageUpload 需要 ApplyImageUpload 返回的 SessionKey")
        auth = self._auth(auth)
        upload_auth = upload_auth or self.get_upload_auth(
            signed=False, auth=auth, referer=referer,
        )
        credentials = self._upload_credentials(upload_auth, "video_token_v5")
        body = json.dumps(
            OrderedDict((("SessionKey", str(session_key)),)),
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        params = Params([
            ("Action", "CommitImageUpload"),
            ("Version", "2018-08-01"),
            ("ServiceId", "photomode"),
        ])
        headers = self._vod_headers(
            auth, method="POST", params=params, credentials=credentials,
            referer=referer, body=body, service="imagex",
            content_type="application/json",
        )
        response = http_client.request(
            "POST", f"{self.origin}/top/v1?{params.to_query()}",
            headers=headers, data=body, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    def upload_photo_bytes(self, data: bytes, *, filename: str = "undefined",
                           user_id: str | None = None,
                           upload_auth: Mapping | None = None, auth=None,
                           referer: str = f"{origin}/tiktokstudio/upload/post/photo"):
        """Run ApplyImageUpload -> raw TOS upload -> CommitImageUpload once."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Photo Mode 图片必须是 bytes-like")
        raw = bytes(data)
        if not raw:
            raise ValueError("Photo Mode 图片不能为空")
        auth = self._auth(auth)
        upload_auth = upload_auth or self.get_upload_auth(
            signed=False, auth=auth, referer=referer,
        )
        applied = self.apply_image_upload(
            len(raw), upload_auth=upload_auth, auth=auth, referer=referer,
        )
        uploaded = self.upload_tos_bytes(
            applied, raw, user_id=user_id, filename=filename, auth=auth,
        )
        try:
            node = applied["Result"]["InnerUploadAddress"]["UploadNodes"][0]
            session_key = str(node["SessionKey"])
        except (KeyError, IndexError, TypeError) as exc:
            raise BrowserEvidenceError(
                "ApplyImageUpload 缺少 InnerUploadAddress.UploadNodes[0].SessionKey"
            ) from exc
        committed = self.commit_image_upload(
            session_key, upload_auth=upload_auth, auth=auth, referer=referer,
        )
        try:
            plugin = committed["Result"]["PluginResult"][0]
            uri = str(plugin["ImageUri"])
            width = int(plugin["ImageWidth"])
            height = int(plugin["ImageHeight"])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise BrowserEvidenceError(
                "CommitImageUpload 缺少 PluginResult 的 ImageUri/尺寸"
            ) from exc
        if not uri or width <= 0 or height <= 0:
            raise BrowserEvidenceError("CommitImageUpload 返回的图片 URI/尺寸无效")
        return {
            "apply": applied, "upload": uploaded, "commit": committed,
            "uri": uri, "width": width, "height": height,
        }

    def get_upload_candidates(self, *, upload_auth: Mapping | None = None,
                              auth=None,
                              referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Fetch the current VOD upload nodes using pure AWS V4 signing."""
        auth = self._auth(auth)
        upload_auth = upload_auth or self.get_upload_auth(auth=auth, referer=referer)
        credentials = self._upload_credentials(upload_auth, "video_token_v5")
        params = Params([
            ("Action", "GetUploadCandidates"),
            ("Version", "2020-11-19"),
            ("SpaceName", "tiktok"),
            ("X-Amz-Expires", "604800"),
        ])
        headers = self._vod_headers(
            auth, method="GET", params=params, credentials=credentials,
            referer=referer,
        )
        response = http_client.request(
            "GET", f"{self.origin}/top/v1?{params.to_query()}",
            headers=headers, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    def probe_upload_candidates(self, candidates: Mapping, *, auth=None,
                                referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video") -> list[str]:
        """Run the four 1 MiB browser speed probes and return fastest hosts."""
        auth = self._auth(auth)
        try:
            domains = list(candidates["Result"]["Domains"])
        except (KeyError, TypeError) as exc:
            raise BrowserEvidenceError("GetUploadCandidates 缺少 Result.Domains") from exc
        if not domains:
            raise BrowserEvidenceError("GetUploadCandidates 返回空 Domains")
        payload = b"\0" * 1048576

        def probe(domain):
            try:
                host = str(domain["Name"])
                store_id = str(domain["StoreID"])
                ticket = str(domain["Sign"])
            except (KeyError, TypeError) as exc:
                raise BrowserEvidenceError(
                    "GetUploadCandidates Domain 缺少 Name/StoreID/Sign"
                ) from exc
            if not host or not store_id or not ticket:
                raise BrowserEvidenceError("GetUploadCandidates Domain 字段为空")
            headers = OrderedDict((
                ("sec-ch-ua-platform", auth.sec_ch_ua_platform),
                ("authorization", ticket),
                ("referer", f"{self.origin}/"),
                ("sec-ch-ua", auth.sec_ch_ua),
                ("content-crc32", "ignore"),
                ("sec-ch-ua-mobile", "?0"),
                ("user-agent", auth.user_agent),
                ("content-type", "application/octet-stream"),
                ("content-disposition", 'attachment; filename="undefined"'),
                ("accept", "*/*"),
                ("accept-encoding", "gzip, deflate, br, zstd"),
                ("accept-language", auth.accept_language),
                ("content-length", str(len(payload))),
                ("origin", self.origin),
                ("sec-fetch-dest", "empty"),
                ("sec-fetch-mode", "cors"),
                ("sec-fetch-site", "cross-site"),
            ))
            started = time.perf_counter()
            response = http_client.request(
                "POST", f"https://{host}/upload/v1/{store_id}?speedtest",
                headers=headers, data=payload, timeout=self.timeout,
            )
            response.raise_for_status()
            return time.perf_counter() - started, host

        ranked = []
        with ThreadPoolExecutor(max_workers=min(4, len(domains))) as pool:
            futures = [pool.submit(probe, domain) for domain in domains[:4]]
            for future in as_completed(futures):
                ranked.append(future.result())
        ranked.sort(key=lambda item: item[0])
        return [host for _, host in ranked]

    def apply_upload_inner(self, file_size: int, *, file_type: str = "video",
                           space_name: str = "tiktok", is_inner: str = "1",
                           upload_s: str | None = None, scene: str | None = None,
                           business_tag: str | None = None, auth=None,
                           upload_auth: Mapping | None = None,
                           client_best_hosts=None, x_amz_expires: str = "604800",
                           include_file_size: bool = True,
                           referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Obtain a fresh ``InnerUploadAddress`` using pure AWS V4 signing."""
        if int(file_size) < 0:
            raise ValueError("ApplyUploadInner 的 FileSize 不能为负数")
        if not file_type or not space_name:
            raise ValueError("ApplyUploadInner 需要 FileType 和 SpaceName")
        upload_s = self._upload_random_s() if upload_s is None else str(upload_s)
        if not re.fullmatch(r"[a-z0-9]{11}", upload_s):
            raise ValueError("ApplyUploadInner 的 s 必须是浏览器的 11 位小写字母数字串")
        auth = self._auth(auth)
        upload_auth = upload_auth or self.get_upload_auth(auth=auth, referer=referer)
        token_name = self._upload_token_name(space_name)
        credentials = self._upload_credentials(upload_auth, token_name)
        if str(credentials["space_name"]) != str(space_name):
            raise BrowserEvidenceError(
                f"{token_name}.space_name 与 ApplyUploadInner 的 SpaceName 不一致"
            )
        if file_type == "video" and client_best_hosts is None:
            candidates = self.get_upload_candidates(
                upload_auth=upload_auth, auth=auth, referer=referer,
            )
            client_best_hosts = self.probe_upload_candidates(
                candidates, auth=auth, referer=referer,
            )
        pairs = [
            ("Action", "ApplyUploadInner"),
            ("Version", "2020-11-19"),
            ("SpaceName", str(space_name)),
            ("FileType", str(file_type)),
            ("IsInner", str(is_inner)),
        ]
        if client_best_hosts is not None:
            hosts = (client_best_hosts if isinstance(client_best_hosts, str)
                     else ",".join(str(host) for host in client_best_hosts))
            if not hosts:
                raise BrowserEvidenceError("ApplyUploadInner 的 ClientBestHosts 不能为空")
            pairs.append(("ClientBestHosts", hosts))
        if include_file_size:
            pairs.append(("FileSize", str(int(file_size))))
        if file_type == "video":
            pairs.append(("X-Amz-Expires", str(x_amz_expires)))
        pairs.append(("s", upload_s))
        if scene is not None:
            pairs.append(("Scene", str(scene)))
        pairs.append(("device_platform", "web"))
        if business_tag is None and file_type == "video":
            business_tag = "tiktok_video_submission_web"
        if business_tag is not None:
            pairs.append(("business_tag", str(business_tag)))
        params = Params(pairs)
        headers = self._vod_headers(
            auth, method="GET", params=params, credentials=credentials,
            referer=referer,
        )
        url = f"{self.origin}/top/v1?{params.to_query()}"
        response = http_client.request("GET", url, headers=headers, timeout=self.timeout)
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    @staticmethod
    def _upload_store_info(upload_response: Mapping) -> tuple[str, Mapping]:
        """Extract one fresh node/store pair from ``InnerUploadAddress``."""
        try:
            result = upload_response["Result"]
            node = result["InnerUploadAddress"]["UploadNodes"][0]
            store = node["StoreInfos"][0]
            host = node["UploadHost"]
            uri = str(store["StoreUri"])
            ticket = str(store["Auth"])
        except (KeyError, IndexError, TypeError) as exc:
            raise BrowserEvidenceError(
                "ApplyUploadInner 缺少 InnerUploadAddress.UploadNodes/StoreInfos"
            ) from exc
        if not host or not uri or not ticket:
            raise BrowserEvidenceError("ApplyUploadInner 返回的上传节点字段为空")
        return str(host), node

    def upload_tos_bytes(self, upload_response: Mapping, data: bytes, *,
                         user_id: str | None = None,
                         filename: str = "undefined", auth=None,
                         upload_auth: Mapping | None = None,
                         post_upload: bool = False, functions=None,
                         boundary: str | None = None):
        """Upload bytes to the exact TOS node returned by ApplyUploadInner."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("TOS 上传 data 必须是 bytes-like")
        raw = bytes(data)
        host, node = self._upload_store_info(upload_response)
        store = node["StoreInfos"][0]
        auth = self._auth(auth)
        user_id = str(user_id or auth.odin_id)
        if not user_id:
            raise BrowserEvidenceError("TOS 上传缺少浏览器 user_id/x-storage-u")
        uri = str(store["StoreUri"])
        url = f"https://{host}/upload/v1/{uri}"
        payload = raw
        content_type = "application/octet-stream"
        if post_upload:
            if upload_auth is None:
                raise BrowserEvidenceError("视频 post-upload multipart 缺少本次 upload/auth")
            credentials = self._upload_credentials(upload_auth, "video_token_v5")
            session_key = str(node.get("SessionKey") or "")
            if not session_key:
                raise BrowserEvidenceError("视频 post-upload 缺少 UploadNode.SessionKey")
            if boundary is None:
                alphabet = string.ascii_letters + string.digits
                boundary = "----WebKitFormBoundary" + "".join(
                    secrets.choice(alphabet) for _ in range(16)
                )
            if not re.fullmatch(r"----WebKitFormBoundary[A-Za-z0-9]{16}", boundary):
                raise ValueError("multipart boundary 必须匹配 Chrome WebKit 16 位格式")
            post_body = json.dumps(OrderedDict((
                ("sts2_token", str(credentials["session_token"])),
                ("sts2_secret", str(credentials["secret_acess_key"])),
                ("session_key", session_key),
                ("functions", list(functions or [])),
            )), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            payload = (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="blob"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode("ascii") + raw + (
                f"\r\n--{boundary}\r\n"
                'Content-Disposition: form-data; name="post_upload_req"\r\n\r\n'
            ).encode("ascii") + post_body + f"\r\n--{boundary}--\r\n".encode("ascii")
            content_type = f"multipart/form-data; boundary={boundary}"
        headers = OrderedDict((
            ("sec-ch-ua-platform", auth.sec_ch_ua_platform),
            ("authorization", str(store["Auth"])),
            ("referer", f"{self.origin}/"),
            ("sec-ch-ua", auth.sec_ch_ua),
            ("content-crc32", f"{zlib.crc32(raw) & 0xffffffff:08x}"),
            ("sec-ch-ua-mobile", "?0"),
            *(((("x-upload-with-postupload", "1"),)) if post_upload else ()),
            ("user-agent", auth.user_agent),
            ("x-storage-u", user_id),
            ("content-type", content_type),
            *(((("content-disposition", f'attachment; filename="{filename}"'),))
              if not post_upload else ()),
            ("accept", "*/*"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", auth.accept_language),
            ("content-length", str(len(payload))),
            ("origin", self.origin),
            ("sec-fetch-dest", "empty"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-site", "cross-site"),
        ))
        response = http_client.request(
            "POST", url, headers=headers, data=payload, timeout=self.timeout,
        )
        return self._json_response(response)

    def commit_upload_inner(self, session_key: str, *, functions=None,
                            space_name: str = "tiktok", auth=None,
                            upload_auth: Mapping | None = None,
                            referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Commit an uploaded TOS object using the fresh SessionKey."""
        if not session_key:
            raise ValueError("CommitUploadInner 需要 ApplyUploadInner 返回的 SessionKey")
        auth = self._auth(auth)
        body = json.dumps(OrderedDict((
            ("SessionKey", str(session_key)),
            ("Functions", list(functions or [])),
        )), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        upload_auth = upload_auth or self.get_upload_auth(auth=auth, referer=referer)
        credentials = self._upload_credentials(
            upload_auth, self._upload_token_name(space_name),
        )
        params = Params([
            ("Action", "CommitUploadInner"),
            ("Version", "2020-11-19"),
            ("SpaceName", str(space_name)),
        ])
        headers = self._vod_headers(
            auth, method="POST", params=params, credentials=credentials,
            referer=referer, body=body,
        )
        url = f"{self.origin}/top/v1?{params.to_query()}"
        response = http_client.request(
            "POST", url, headers=headers, data=body, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    def upload_media_bytes(self, data: bytes, *, file_type: str = "video",
                           space_name: str = "tiktok", scene: str | None = None,
                           business_tag: str | None = None, functions=None,
                           user_id: str | None = None, filename: str = "undefined",
                           upload_auth: Mapping | None = None,
                           client_best_hosts=None,
                           auth=None, referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Run the captured video or image TOS flow once."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("media data 必须是 bytes-like")
        auth = self._auth(auth)
        upload_auth = upload_auth or self.get_upload_auth(auth=auth, referer=referer)
        applied = self.apply_upload_inner(
            len(data), file_type=file_type, space_name=space_name,
            scene=scene, business_tag=business_tag, auth=auth, referer=referer,
            upload_auth=upload_auth, client_best_hosts=client_best_hosts,
        )
        uploaded = self.upload_tos_bytes(
            applied, data, user_id=user_id, filename=filename, auth=auth,
            upload_auth=upload_auth, post_upload=(file_type == "video"),
            functions=functions,
        )
        try:
            node = applied["Result"]["InnerUploadAddress"]["UploadNodes"][0]
            video_id = str(node["Vid"])
        except (KeyError, IndexError, TypeError) as exc:
            raise BrowserEvidenceError("ApplyUploadInner 缺少 UploadNode.Vid") from exc
        if file_type == "video":
            # x-upload-with-postupload commits the video in the multipart
            # request. A second CommitUploadInner is not sent by Chrome.
            return {"apply": applied, "upload": uploaded, "video_id": video_id}
        session_key = str(node.get("SessionKey") or "")
        if not session_key:
            raise BrowserEvidenceError("图片 ApplyUploadInner 缺少 SessionKey")
        committed = self.commit_upload_inner(
            session_key, functions=functions, space_name=space_name,
            auth=auth, referer=referer, upload_auth=upload_auth,
        )
        return {
            "apply": applied, "upload": uploaded, "commit": committed,
            "video_id": video_id,
        }

    def bootstrap_transcode_csrf(self, *, auth=None,
                                 referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Run the captured SecSDK HEAD bootstrap for video transcoding."""
        auth = self._auth(auth)
        base = HeaderBuilder.build(
            HeaderType.GET, auth, referer=referer, sec_fetch_site="same-origin",
        ).get()
        headers = OrderedDict((
            ("x-secsdk-csrf-request", "1"),
            ("sec-ch-ua-platform", base["sec-ch-ua-platform"]),
            ("referer", base["referer"]),
            ("user-agent", base["user-agent"]),
            ("x-secsdk-csrf-version", "1.2.22"),
            ("sec-ch-ua", base["sec-ch-ua"]),
            ("sec-ch-ua-mobile", base["sec-ch-ua-mobile"]),
            ("accept", "*/*"),
            ("accept-encoding", base["accept-encoding"]),
            ("accept-language", base["accept-language"]),
            ("cookie", base["cookie"]),
            ("priority", base["priority"]),
            ("sec-fetch-dest", base["sec-fetch-dest"]),
            ("sec-fetch-mode", base["sec-fetch-mode"]),
            ("sec-fetch-site", base["sec-fetch-site"]),
        ))
        response = http_client.request(
            "HEAD", f"{self.origin}/api/v1/video/transcode/enable/",
            headers=headers, timeout=self.timeout,
        )
        response.raise_for_status()
        auth.apply_set_cookie(response.headers)
        value = response.headers.get("x-ware-csrf-token", "")
        parts = str(value).split(",")
        if len(parts) != 5 or not parts[1]:
            raise BrowserEvidenceError(
                "transcode HEAD 缺少五段 x-ware-csrf-token"
            )
        auth.secsdk_csrf_token = parts[1]
        if not auth.tt_csrf_token:
            raise BrowserEvidenceError("transcode HEAD 未写入 tt_csrf_token Cookie")
        return {
            "tt_csrf_token": auth.tt_csrf_token,
            "secsdk_csrf_token": auth.secsdk_csrf_token,
        }

    def enable_video_transcode(self, video_id: str, *, auth=None,
                               referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Enable server transcoding with both current CSRF tokens."""
        if not video_id:
            raise ValueError("transcode/enable 需要 video_id")
        auth = self._auth(auth)
        if not auth.tt_csrf_token or not auth.secsdk_csrf_token:
            self.bootstrap_transcode_csrf(auth=auth, referer=referer)
        base = HeaderBuilder.build(
            HeaderType.GET, auth, referer=referer, origin=self.origin,
            content_length="0", sec_fetch_site="same-origin",
        ).get()
        headers = OrderedDict((
            ("sec-ch-ua-platform", base["sec-ch-ua-platform"]),
            ("referer", base["referer"]),
            ("sec-ch-ua", base["sec-ch-ua"]),
            ("sec-ch-ua-mobile", base["sec-ch-ua-mobile"]),
            ("tt-csrf-token", auth.tt_csrf_token),
            ("user-agent", base["user-agent"]),
            ("accept", "application/json, text/plain, */*"),
            ("x-secsdk-csrf-token", auth.secsdk_csrf_token),
            ("accept-encoding", base["accept-encoding"]),
            ("accept-language", base["accept-language"]),
            ("content-length", "0"),
            ("cookie", base["cookie"]),
            ("origin", base["origin"]),
            ("priority", base["priority"]),
            ("sec-fetch-dest", base["sec-fetch-dest"]),
            ("sec-fetch-mode", base["sec-fetch-mode"]),
            ("sec-fetch-site", base["sec-fetch-site"]),
        ))
        params = Params([("video_id", str(video_id)), ("aid", "1988")])
        response = http_client.request(
            "POST",
            f"{self.origin}/api/v1/video/transcode/enable/?{params.to_query()}",
            headers=headers, data=None, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    def get_video_transcode_result(self, video_id: str, *, width: int,
                                   height: int, duration_ms: int,
                                   file_key: str, scene: int = 0, auth=None,
                                   referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"):
        """Poll one video with the exact Creator JSON body."""
        if not video_id or not file_key:
            raise ValueError("transcode/result 需要 video_id 和 file_key")
        auth = self._auth(auth)
        body = json.dumps(OrderedDict((
            ("scene", int(scene)),
            ("video_info", [OrderedDict((
                ("file_key", str(file_key)),
                ("video_id", str(video_id)),
                ("original_width", int(width)),
                ("original_height", int(height)),
                ("original_duration_ms", int(duration_ms)),
            ))]),
        )), ensure_ascii=False, separators=(",", ":"))
        base = HeaderBuilder.build(
            HeaderType.POST, auth, referer=referer, origin=self.origin,
            content_length=str(len(body.encode("utf-8"))),
            sec_fetch_site="same-origin",
        ).get()
        headers = OrderedDict((
            ("sec-ch-ua-platform", base["sec-ch-ua-platform"]),
            ("referer", base["referer"]),
            ("user-agent", base["user-agent"]),
            ("accept", "application/json, text/plain, */*"),
            ("sec-ch-ua", base["sec-ch-ua"]),
            ("content-type", "application/json"),
            ("sec-ch-ua-mobile", base["sec-ch-ua-mobile"]),
            ("accept-encoding", base["accept-encoding"]),
            ("accept-language", base["accept-language"]),
            ("content-length", str(len(body.encode("utf-8")))),
            ("cookie", base["cookie"]),
            ("origin", base["origin"]),
            ("priority", base["priority"]),
            ("sec-fetch-dest", base["sec-fetch-dest"]),
            ("sec-fetch-mode", base["sec-fetch-mode"]),
            ("sec-fetch-site", base["sec-fetch-site"]),
        ))
        response = http_client.request(
            "POST", f"{self.origin}/api/v1/video/transcode/result/?aid=1988",
            headers=headers, data=body, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        return self._json_response(response)

    def wait_video_transcode(self, video_id: str, *, width: int, height: int,
                             duration_ms: int, file_key: str,
                             timeout: float = 90.0, interval: float = 1.0,
                             auth=None, referer: str | None = None):
        """Poll until Chrome's ``transcode_status == 3`` completion state."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"
        deadline = time.monotonic() + float(timeout)
        while True:
            result = self.get_video_transcode_result(
                video_id, width=width, height=height,
                duration_ms=duration_ms, file_key=file_key,
                auth=auth, referer=referer,
            )
            rows = result.get("transcode_result") or []
            if rows and int(rows[0].get("transcode_status", 0)) == 3:
                return result
            if time.monotonic() >= deadline:
                raise TimeoutError("TikTok 视频转码在限定时间内未完成")
            time.sleep(max(0.05, float(interval)))

    @staticmethod
    def _creator_creation_id() -> str:
        alphabet = string.ascii_letters + string.digits + "-_"
        return "ROO_" + "".join(secrets.choice(alphabet) for _ in range(17))

    @staticmethod
    def _creator_photo_creation_id() -> str:
        """Return the browser's 21-character Photo Mode creation id."""
        alphabet = string.ascii_letters + string.digits + "-_"
        return "".join(secrets.choice(alphabet) for _ in range(21))

    @staticmethod
    def _prepare_creator_media(media, *, filename: str | None = None) -> Mapping:
        """Read video metadata and derive the browser's PNG/JPEG cover assets."""
        try:
            import imageio_ffmpeg
            from PIL import Image
        except ImportError as exc:
            raise RuntimeError(
                "creator_publish 需要 Pillow 和 imageio-ffmpeg"
            ) from exc
        temporary = None
        if isinstance(media, (str, os.PathLike)):
            path = os.path.abspath(os.fspath(media))
            with open(path, "rb") as handle:
                raw = handle.read()
            asset_name = filename or os.path.basename(path)
        elif isinstance(media, (bytes, bytearray, memoryview)):
            raw = bytes(media)
            suffix = os.path.splitext(filename or "upload.mp4")[1] or ".mp4"
            handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            try:
                handle.write(raw)
                path = handle.name
            finally:
                handle.close()
            temporary = path
            asset_name = filename or "upload.mp4"
        else:
            raise TypeError("media 必须是 bytes-like 或本地视频路径")
        if not raw:
            raise ValueError("media 不能为空")
        try:
            process = subprocess.run(
                [
                    imageio_ffmpeg.get_ffmpeg_exe(), "-hide_banner", "-i", path,
                    "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24",
                    "pipe:1",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=30,
            )
            stderr = process.stderr.decode("utf-8", errors="replace")
            dimension = re.search(
                r"Video:.*?\b(\d{2,5})x(\d{2,5})(?:\D|$)", stderr,
            )
            duration = re.search(
                r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", stderr,
            )
            fps_match = re.search(r"(?:,|\s)(\d+(?:\.\d+)?)\s+fps(?:,|\s)", stderr)
            if process.returncode or not dimension or not duration:
                raise BrowserEvidenceError("ffmpeg 未返回完整视频尺寸/时长")
            width, height = int(dimension.group(1)), int(dimension.group(2))
            seconds = (
                int(duration.group(1)) * 3600 + int(duration.group(2)) * 60
                + float(duration.group(3))
            )
            duration_ms = max(1, int(round(seconds * 1000)))
            fps = max(1, int(round(float(fps_match.group(1))))) if fps_match else 24
            frame = process.stdout
            if len(frame) != width * height * 3:
                raise BrowserEvidenceError(
                    "ffmpeg 首帧 bytes 与视频尺寸不一致"
                )
            image = Image.frombytes("RGB", (width, height), frame)
            png_stream = io.BytesIO()
            image.save(png_stream, format="PNG")
            jpeg_stream = io.BytesIO()
            image.save(jpeg_stream, format="JPEG", quality=92)
            zip_stream = io.BytesIO()
            with zipfile.ZipFile(
                zip_stream, "w", compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr("0.jpeg", jpeg_stream.getvalue())
        except (KeyError, ValueError, subprocess.SubprocessError) as exc:
            raise BrowserEvidenceError("无法从视频读取完整首帧/尺寸/时长证据") from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
        return {
            "bytes": raw, "filename": asset_name, "width": width,
            "height": height, "duration_ms": duration_ms, "fps": fps,
            "poster_png": png_stream.getvalue(),
            "ai_frame_zip": zip_stream.getvalue(),
        }

    @staticmethod
    def _prepare_creator_photos(images) -> list[Mapping]:
        """Read Photo Mode inputs without changing their upload bytes.

        Chrome uploads each original image byte-for-byte, then creates one
        auxiliary ``0.jpeg`` ZIP from the cover image for the AI-frame VOD
        branch.  Preserve that separation instead of re-encoding the actual
        Photo Mode objects.
        """
        try:
            from PIL import Image
        except ImportError as exc:
            raise RuntimeError("creator_publish_photos 需要 Pillow") from exc
        if isinstance(images, (str, os.PathLike, bytes, bytearray, memoryview)):
            sources = [images]
        else:
            try:
                sources = list(images)
            except TypeError as exc:
                raise TypeError("images 必须是图片路径/bytes 或其可迭代对象") from exc
        if not sources:
            raise ValueError("Photo Mode 至少需要一张图片")
        prepared = []
        for index, source in enumerate(sources):
            if isinstance(source, (str, os.PathLike)):
                path = os.path.abspath(os.fspath(source))
                with open(path, "rb") as handle:
                    raw = handle.read()
                name = os.path.basename(path)
            elif isinstance(source, (bytes, bytearray, memoryview)):
                raw = bytes(source)
                name = f"photo-{index + 1}.png"
            else:
                raise TypeError("Photo Mode 图片必须是路径或 bytes-like")
            if not raw:
                raise ValueError(f"Photo Mode 第 {index + 1} 张图片为空")
            try:
                with Image.open(io.BytesIO(raw)) as image:
                    width, height = image.size
                    if width <= 0 or height <= 0:
                        raise ValueError("invalid dimensions")
                    if index == 0:
                        cover = image.convert("RGB")
                        jpeg_stream = io.BytesIO()
                        cover.save(jpeg_stream, format="JPEG", quality=92)
                        zip_stream = io.BytesIO()
                        with zipfile.ZipFile(
                            zip_stream, "w", compression=zipfile.ZIP_DEFLATED,
                        ) as archive:
                            archive.writestr("0.jpeg", jpeg_stream.getvalue())
                        ai_frame_zip = zip_stream.getvalue()
            except (OSError, ValueError) as exc:
                raise BrowserEvidenceError(
                    f"无法解析 Photo Mode 第 {index + 1} 张图片"
                ) from exc
            prepared.append({
                "bytes": raw, "filename": name,
                "width": int(width), "height": int(height),
            })
        prepared[0]["ai_frame_zip"] = ai_frame_zip
        return prepared

    @staticmethod
    def _commit_uri(result: Mapping) -> str:
        try:
            uri = str(result["Result"]["Results"][0]["Uri"])
        except (KeyError, IndexError, TypeError) as exc:
            raise BrowserEvidenceError("CommitUploadInner 缺少 Result.Results[0].Uri") from exc
        if not uri:
            raise BrowserEvidenceError("CommitUploadInner 返回空 Uri")
        return uri

    @staticmethod
    def build_creator_project_body(*, creation_id: str, video_id: str,
                                   text: str, cover_uri: str,
                                   play_url: str, filename: str,
                                   width: int, height: int,
                                   duration_ms: int, fps: int = 24,
                                   visibility_type: int = 1,
                                   allow_comment: int = 1,
                                   allow_duet: int = 0,
                                   allow_stitch: int = 0,
                                   allow_content_reuse: int = 1,
                                   allow_ai_remix: int = 1,
                                   text_extra=None) -> str:
        """Build every field and key order from successful Chrome req 1268."""
        required = {
            "creation_id": creation_id, "video_id": video_id,
            "cover_uri": cover_uri, "play_url": play_url,
            "filename": filename,
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            raise BrowserEvidenceError(
                "Creator project body 缺少字段: " + ", ".join(missing)
            )
        width, height, duration_ms, fps = (
            int(width), int(height), int(duration_ms), int(fps),
        )
        if min(width, height, duration_ms, fps) <= 0:
            raise ValueError("Creator 视频尺寸、时长和 fps 必须为正数")
        now = datetime.now(timezone.utc)
        iso = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        updated_ms = str(int(now.timestamp() * 1000))
        cover_blob = f"blob:https://www.tiktok.com/{uuid.uuid4()}"
        frame_blob = f"blob:https://www.tiktok.com/{uuid.uuid4()}"
        cover_asset_id = str(uuid.uuid4())
        video_asset_id = str(uuid.uuid4())
        fonts = (
            ("Noto-KR", "3379517775"), ("Noto-JP", "3379518023"),
            ("Noto-TC", "3379517439"), ("Noto-SC", "3382263014"),
            ("Noto-Arabic", "3380773560"),
            ("Noto-Myanmar", "3380773555"),
            ("Noto-Khmer", "3380773556"),
            ("Noto-Devanagari", "3380773557"),
            ("Noto-Bengali", "3380773558"),
            ("Noto-Thai", "3380773559"),
        )
        font_assets = [OrderedDict((
            ("id", str(uuid.uuid4())), ("name", name), ("type", "font"),
            ("url", OrderedDict((("loki", f"loki://{family}"),))),
            ("metaInfo", OrderedDict((
                ("family", family), ("format", ""), ("role", "FALLBACK"),
            ))),
        )) for name, family in fonts]
        cover_project = OrderedDict((
            ("project", OrderedDict((
                ("id", str(uuid.uuid4())), ("sdkVersion", "0.6.0-alpha.4"),
                ("name", "New Project"), ("created", iso), ("updated", iso),
                ("description", ""),
                ("mediaInfo", OrderedDict((("width", 1152), ("height", 648)))),
                ("tracks", [OrderedDict((
                    ("id", str(uuid.uuid4())), ("type", "image"), ("isMain", True),
                    ("clips", [OrderedDict((
                        ("id", str(uuid.uuid4())), ("type", "image"),
                        ("assetId", cover_asset_id),
                        ("timing", OrderedDict((
                            ("stepIn", 0), ("duration", 1000),
                            ("start", 0), ("speed", 1),
                        ))),
                        ("effects", OrderedDict()),
                        ("props", OrderedDict((
                            ("visual", OrderedDict((
                                ("size", [width, height]),
                                ("layout", OrderedDict((
                                    ("anchor", [0, 0]), ("offset", [0, 0]),
                                    ("position", [0, 0]),
                                    ("scale", [4 / 3, 4 / 3]),
                                ))),
                            ))),
                            ("crop", [0, 0, width, height]),
                        ))),
                    ))]),
                ))]),
                ("scripts", []),
                ("assets", [OrderedDict((
                    ("id", cover_asset_id), ("name", "CoverImage"),
                    ("type", "image"),
                    ("url", OrderedDict((("blob", cover_blob),))),
                    ("metaInfo", OrderedDict((
                        ("width", width), ("height", height), ("format", ""),
                    ))),
                ))]),
            ))),
            ("sourceProject", OrderedDict((
                ("id", str(uuid.uuid4())), ("sdkVersion", "0.6.0-alpha.4"),
                ("name", "add title for your video"), ("created", iso),
                ("updated", updated_ms),
                ("description", "A sample project created with the builder pattern"),
                ("mediaInfo", OrderedDict((
                    ("width", width), ("height", height), ("fps", fps),
                ))),
                ("tracks", [OrderedDict((
                    ("id", str(uuid.uuid4())), ("type", "video"), ("isMain", True),
                    ("clips", [OrderedDict((
                        ("id", str(uuid.uuid4())), ("type", "video"),
                        ("assetId", video_asset_id),
                        ("timing", OrderedDict((
                            ("stepIn", 0), ("duration", duration_ms),
                            ("start", 0), ("speed", 1),
                        ))),
                        ("effects", OrderedDict()),
                        ("props", OrderedDict((
                            ("visual", OrderedDict((
                                ("size", [width, height]),
                                ("layout", OrderedDict((
                                    ("offset", [0, 0]), ("anchor", [0, 0]),
                                    ("position", [0, 0]),
                                ))),
                            ))),
                            ("crop", [0, 0, width, height]),
                        ))),
                    ))]),
                    ("muted", False),
                ))]),
                ("scripts", []),
                ("assets", [OrderedDict((
                    ("id", video_asset_id), ("name", str(filename)),
                    ("type", "video"),
                    ("url", OrderedDict((("http", str(play_url)),))),
                    ("metaInfo", OrderedDict((
                        ("width", width), ("height", height), ("fps", 0),
                        ("duration", duration_ms), ("format", "video/mp4"),
                    ))),
                )), *font_assets]),
            ))),
            ("coverSourceType", "frame"), ("sourceProjectTime", 0),
            ("sourceProjectLastSaveFrame", frame_blob),
        ))
        body = OrderedDict((
            ("post_common_info", OrderedDict((
                ("creation_id", str(creation_id)),
                ("enter_post_page_from", 2), ("post_type", 3),
            ))),
            ("feature_common_info_list", [OrderedDict((
                ("geofencing_regions", []), ("playlist_name", ""),
                ("playlist_id", ""),
                ("tcm_params", '{"commerce_toggle_info":{}}'),
                ("sound_exemption", 0), ("anchors", []),
                ("vedit_common_info", OrderedDict((
                    ("draft", ""), ("video_id", str(video_id)),
                ))),
                ("privacy_setting_info", OrderedDict((
                    ("visibility_type", int(visibility_type)),
                    ("allow_duet", int(allow_duet)),
                    ("allow_stitch", int(allow_stitch)),
                    ("allow_comment", int(allow_comment)),
                    ("allow_content_reuse", int(allow_content_reuse)),
                    ("allow_ai_remix", int(allow_ai_remix)),
                ))),
            ))]),
            ("single_post_req_list", [OrderedDict((
                ("batch_index", 0), ("video_id", str(video_id)),
                ("is_long_video", 0),
                ("single_post_feature_info", OrderedDict((
                    ("text", str(text)), ("text_extra", list(text_extra or [])),
                    ("markup_text", str(text)),
                    ("music_info", OrderedDict((("origin_volume", "100"),))),
                    ("cover_info", OrderedDict((
                        ("cover_type", 1), ("cover_uri", str(cover_uri)),
                        ("cover_width", 486), ("cover_height", 648),
                        ("blob_url", cover_blob), ("frame_duration", 0),
                        ("isAutoCropFirstFrame", True),
                        ("coverProject", cover_project),
                        ("isProcessingInitialCover", False), ("crop_type", 2),
                    ))),
                    ("poster_delay", 0),
                    ("cloud_edit_video_height", height),
                    ("cloud_edit_video_width", width),
                    ("cloud_edit_is_use_video_canvas", False),
                    ("has_original_audio", 1),
                    ("is_upload_audio_track", False),
                    ("video_track_time_range_list", [OrderedDict((
                        ("start_time_in_ms", 0), ("end_time_in_ms", duration_ms),
                    ))]),
                    ("mature_theme_type", 0),
                ))),
            ))]),
        ))
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def build_creator_photo_project_body(*, creation_id: str, photos,
                                         text: str, title: str = "",
                                         visibility_type: int = 1,
                                         allow_comment: int = 1,
                                         allow_duet: int = 1,
                                         allow_stitch: int = 1,
                                         allow_content_reuse: int = 1,
                                         allow_ai_remix: int = 1,
                                         text_extra=None) -> str:
        """Build the exact Photo Mode project body observed in Chrome."""
        if not creation_id or not re.fullmatch(r"[A-Za-z0-9_-]{21}", creation_id):
            raise ValueError("Photo Mode creation_id 必须是 21 位 URL-safe 字符串")
        rows = list(photos)
        if not rows:
            raise ValueError("Photo Mode project body 至少需要一张图片")
        image_rows = []
        for index, row in enumerate(rows):
            try:
                file_id = str(row["id"])
                uri = str(row["uri"])
                width = int(row["width_px"])
                height = int(row["height_px"])
            except (KeyError, TypeError, ValueError) as exc:
                raise BrowserEvidenceError(
                    f"Photo Mode 第 {index + 1} 张图片缺少 id/uri/width_px/height_px"
                ) from exc
            if not file_id or not uri or width <= 0 or height <= 0:
                raise BrowserEvidenceError(
                    f"Photo Mode 第 {index + 1} 张图片字段无效"
                )
            image_rows.append(OrderedDict((
                ("id", file_id), ("uri", uri),
                ("width_px", width), ("height_px", height),
            )))
        body = OrderedDict((
            ("feature_common_info_list", [OrderedDict((
                ("aigc_info", OrderedDict((("aigc_label_type", 0),))),
                ("org_game_post_use_store_region", False),
                ("privacy_setting_info", OrderedDict((
                    ("allow_comment", int(allow_comment)),
                    ("allow_duet", int(allow_duet)),
                    ("allow_stitch", int(allow_stitch)),
                    ("allow_content_reuse", int(allow_content_reuse)),
                    ("allow_ai_remix", int(allow_ai_remix)),
                    ("visibility_type", int(visibility_type)),
                ))),
                ("draft_id", ""),
                ("tcm_params", '{"commerce_toggle_info":{}}'),
                ("anchors", []),
            ))]),
            ("post_common_info", OrderedDict((
                ("creation_id", creation_id),
                ("enter_post_page_from", 1),
                ("post_type", 4),
            ))),
            ("single_post_req_list", [OrderedDict((
                ("batch_index", 0),
                ("aweme_type", 150),
                ("image_post_content", OrderedDict((
                    ("title", str(title)),
                    ("images", image_rows),
                    ("cover", image_rows[0].copy()),
                ))),
                ("single_post_feature_info", OrderedDict((
                    ("text", str(text)),
                    ("text_extra", list(text_extra or [])),
                    ("markup_text", str(text)),
                ))),
            ))]),
        ))
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    def creator_publish_photos(
        self, images, text: str, *, title: str = "",
        visibility_type: int = 1, allow_comment: int = 1,
        allow_duet: int = 1, allow_stitch: int = 1,
        allow_content_reuse: int = 1, allow_ai_remix: int = 1,
        text_extra=None, ticket_guard: Mapping[str, str] | None = None,
        auth=None, referer: str | None = None,
    ):
        """Publish a private-by-default Photo Mode post through one call."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/tiktokstudio/upload/post/photo"
        prepared = self._prepare_creator_photos(images)
        # Chrome obtains one unsigned upload/auth bootstrap when the Photo Mode
        # page opens and reuses its video_token_v5 for all ImageX objects.
        image_upload_auth = self.get_upload_auth(
            signed=False, auth=auth, referer=referer,
        )
        uploaded_photos = []
        for item in prepared:
            uploaded_photos.append(self.upload_photo_bytes(
                item["bytes"], filename="undefined",
                upload_auth=image_upload_auth, auth=auth, referer=referer,
            ))
        # The page performs one fresh signed upload/auth request and uploads an
        # auxiliary 0.jpeg ZIP through the existing tiktok-ai-frame VOD path.
        ai_upload_auth = self.get_upload_auth(
            signed=True, auth=auth, referer=referer,
        )
        ai_frame_upload = self.upload_media_bytes(
            prepared[0]["ai_frame_zip"], file_type="image",
            space_name="tiktok-ai-frame", upload_auth=ai_upload_auth,
            auth=auth, referer=referer,
        )
        creation_id = self._creator_photo_creation_id()
        now_ms = int(time.time() * 1000)
        photo_rows = []
        for index, uploaded in enumerate(uploaded_photos):
            photo_rows.append({
                "id": f"file_{now_ms + index}_{secrets.randbelow(1000000)}",
                "uri": uploaded["uri"],
                "width_px": uploaded["width"],
                "height_px": uploaded["height"],
            })
        body = self.build_creator_photo_project_body(
            creation_id=creation_id, photos=photo_rows, text=text, title=title,
            visibility_type=visibility_type, allow_comment=allow_comment,
            allow_duet=allow_duet, allow_stitch=allow_stitch,
            allow_content_reuse=allow_content_reuse,
            allow_ai_remix=allow_ai_remix, text_extra=text_extra,
        )
        published = self.post_project(
            body, ticket_guard=ticket_guard or {}, auth=auth,
            referer=referer,
        )
        return {
            "creation_id": creation_id,
            "photos": uploaded_photos,
            "ai_frame_upload": ai_frame_upload,
            "project_body": body,
            "publish": published,
        }

    def publish_media(
        self, media, *, project_body: str | Callable[[Mapping], str],
        ticket_guard: Mapping[str, str] | None = None,
        file_type: str = "video", space_name: str = "tiktok",
        scene: str | None = None, business_tag: str | None = None,
        functions=None, user_id: str | None = None,
        filename: str = "undefined", auth=None,
        referer: str | None = None,
    ):
        """Run the evidence-backed Creator upload + project-post flow once.

        This is the lower-level video Creator escape hatch. ``media`` may be raw
        bytes or a local path.  The upload chain is fully assembled here
        (ApplyUploadInner -> multipart TOS post-upload), then the exact
        browser project JSON is posted with a fresh ticket guard.  The project
        JSON is intentionally *not* generated from a guessed schema: callers
        must provide the browser's raw JSON string, or a callback that receives
        the upload result and returns that raw string.  A callback is useful
        when the captured template contains the fresh URI returned by the
        upload step.  In either form the bytes, key order, content length and
        signatures remain exact; missing fields fail before the write.

        Photo-mode's ImageX ``ApplyImageUpload``/AWS credential branch is a
        separate browser contract and is rejected here until its current
        credential/signature evidence is supplied.  This prevents silently
        sending the video upload contract for a photo post.
        """
        if file_type != "video" or space_name != "tiktok":
            raise BrowserEvidenceError(
                "当前高层 Creator 发布仅开放已完整取证的 video/tiktok 上传链；"
                "photo/ImageX 需要当前浏览器 AWS credential/CommitImageUpload 证据"
            )
        if isinstance(media, (bytes, bytearray, memoryview)):
            raw = bytes(media)
        elif isinstance(media, (str, os.PathLike)):
            with open(os.fspath(media), "rb") as handle:
                raw = handle.read()
        else:
            raise TypeError("media 必须是 bytes-like 或本地文件路径")
        if not raw:
            raise ValueError("media 不能为空")
        if not isinstance(project_body, str) and not callable(project_body):
            raise TypeError("project_body 必须是浏览器原样 JSON 字符串或回调")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"
        upload = self.upload_media_bytes(
            raw, file_type=file_type, space_name=space_name, scene=scene,
            business_tag=business_tag, functions=functions, user_id=user_id,
            filename=filename, auth=auth, referer=referer,
        )
        body = project_body(upload) if callable(project_body) else project_body
        if not isinstance(body, str) or not body:
            raise BrowserEvidenceError(
                "project_body 回调必须返回非空的浏览器原样 JSON 字符串"
            )
        published = self.post_project(
            body, ticket_guard=ticket_guard or {}, auth=auth,
            referer=referer,
        )
        return {"upload": upload, "publish": published}

    def creator_publish(
        self, media, text: str, *, filename: str | None = None,
        visibility_type: int = 1, allow_comment: int = 1,
        allow_duet: int = 0, allow_stitch: int = 0,
        allow_content_reuse: int = 1, allow_ai_remix: int = 1,
        text_extra=None, ticket_guard: Mapping[str, str] | None = None,
        transcode_timeout: float = 90.0, auth=None,
        referer: str | None = None,
    ):
        """Publish one private-by-default video through the full Chrome flow.

        This is the ergonomic Creator API: callers provide only media and
        caption (plus optional privacy toggles).  It derives media metadata,
        uploads the video with post-upload multipart, enables/polls transcode,
        creates the project, uploads both browser cover assets, builds every
        nested project field, and finally computes fresh WebMssdk and
        ticket-guard values for project/post.
        """
        auth = self._auth(auth)
        referer = referer or (
            f"{self.origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans&tab=video"
        )
        prepared = self._prepare_creator_media(media, filename=filename)
        video_upload_auth = self.get_upload_auth(auth=auth, referer=referer)
        candidates = self.get_upload_candidates(
            upload_auth=video_upload_auth, auth=auth, referer=referer,
        )
        best_hosts = self.probe_upload_candidates(
            candidates, auth=auth, referer=referer,
        )
        video_upload = self.upload_media_bytes(
            prepared["bytes"], file_type="video", space_name="tiktok",
            business_tag="tiktok_video_submission_web",
            filename=prepared["filename"], upload_auth=video_upload_auth,
            client_best_hosts=best_hosts, auth=auth, referer=referer,
        )
        video_id = video_upload["video_id"]
        media_openid = self.get_media_openid(auth=auth, referer=referer)
        self.enable_video_transcode(video_id, auth=auth, referer=referer)
        creation_id = self._creator_creation_id()
        project_create = self.post_project_create(
            creation_id, auth=auth, referer=referer,
        )
        file_key = (
            f"file_{int(time.time() * 1000)}_"
            f"{secrets.randbelow(1000000):06d}"
        )
        transcode = self.wait_video_transcode(
            video_id, width=prepared["width"], height=prepared["height"],
            duration_ms=prepared["duration_ms"], file_key=file_key,
            timeout=transcode_timeout, auth=auth, referer=referer,
        )
        try:
            transcode_row = transcode["transcode_result"][0]
            play_url = str(transcode_row["play_url"])
        except (KeyError, IndexError, TypeError) as exc:
            raise BrowserEvidenceError(
                "完成的 transcode_result 缺少 play_url"
            ) from exc
        ai_upload_auth = self.get_upload_auth(auth=auth, referer=referer)
        ai_frame_upload = self.upload_media_bytes(
            prepared["ai_frame_zip"], file_type="image",
            space_name="tiktok-ai-frame", upload_auth=ai_upload_auth,
            auth=auth, referer=referer,
        )
        poster_upload_auth = self.get_upload_auth(auth=auth, referer=referer)
        poster_upload = self.upload_media_bytes(
            prepared["poster_png"], file_type="image", space_name="tiktok",
            scene="poster", business_tag="tiktok_video_cover_web",
            upload_auth=poster_upload_auth, auth=auth, referer=referer,
        )
        cover_uri = self._commit_uri(poster_upload["commit"])
        body = self.build_creator_project_body(
            creation_id=creation_id, video_id=video_id, text=text,
            cover_uri=cover_uri, play_url=play_url,
            filename=prepared["filename"], width=prepared["width"],
            height=prepared["height"], duration_ms=prepared["duration_ms"],
            fps=prepared["fps"], visibility_type=visibility_type,
            allow_comment=allow_comment, allow_duet=allow_duet,
            allow_stitch=allow_stitch,
            allow_content_reuse=allow_content_reuse,
            allow_ai_remix=allow_ai_remix, text_extra=text_extra,
        )
        published = self.post_project(
            body, ticket_guard=ticket_guard or {}, auth=auth,
            referer=referer,
        )
        return {
            "creation_id": creation_id,
            "video_id": video_id,
            "media_openid": media_openid,
            "video_upload": video_upload,
            "project_create": project_create,
            "transcode": transcode,
            "ai_frame_upload": ai_frame_upload,
            "poster_upload": poster_upload,
            "project_body": body,
            "publish": published,
        }

    @staticmethod
    def _current_params(auth: TiktokAuth, *, referer: str,
                        from_page: str = "user", root_referer: str | None = None,
                        query_referer: str | None = None,
                        slots: Mapping[str, object] | None = None,
                        aid: str = "1988",
                        device_platform: str = "web_pc",
                        app_language: str = "zh-Hans",
                        history_len: str = "2",
                        include_from_page: bool = True,
                        include_user_is_login: bool = True,
                        include_odin_id: bool = True):
        """Build the 5.3.x query in the order emitted by current Chrome.

        The older helper intentionally models several 2024 endpoints whose
        field order differs.  Current 153 captures place endpoint fields at
        fixed points in the base query; signatures hash this order, so these
        slots are explicit instead of alphabetically sorting or appending
        compatibility fields.
        """
        slots = slots or {}
        query_ref = referer if query_referer is None else query_referer
        root = query_ref if root_referer is None else root_referer
        values = []
        def add(key, value):
            if value is not None:
                values.append((str(key), str(value)))
        def add_slot(name):
            for key, value in slots.get(name, ()) or ():
                add(key, value)

        add("WebIdLastTime", auth.web_id_last_time)
        add_slot("before_aid")
        add("aid", aid)
        add_slot("after_aid")
        add_slot("before_app_language")
        add("app_language", app_language)
        add("app_name", "tiktok_web")
        add_slot("after_app_name")
        add("browser_language", "zh-CN")
        add("browser_name", "Mozilla")
        add("browser_online", "true")
        add_slot("after_browser_online")
        add("browser_platform", "Win32")
        add("browser_version", auth.user_agent.split("Mozilla/", 1)[-1])
        add_slot("after_browser_version")
        add("channel", "tiktok_web")
        add_slot("after_channel")
        add("cookie_enabled", "true")
        add_slot("after_cookie")
        add("data_collection_enabled", "true")
        add_slot("after_data_collection")
        add("device_id", auth.device_id)
        add("device_platform", device_platform)
        add_slot("after_device_platform")
        add("focus_state", "true")
        add_slot("after_focus")
        if include_from_page:
            add("from_page", from_page)
        add_slot("after_from_page")
        add("history_len", history_len)
        add_slot("after_history")
        add("is_fullscreen", "false")
        add_slot("after_fullscreen")
        add("is_page_visible", "true")
        add_slot("after_is_page_visible")
        if include_odin_id:
            add("odinId", auth.odin_id)
        add("os", "windows")
        add_slot("after_os")
        add("priority_region", auth.priority_region)
        add_slot("after_priority_region")
        add("referer", query_ref)
        add("region", auth.region)
        add_slot("after_region")
        add("root_referer", root)
        add_slot("after_root_referer")
        add("screen_height", "1440")
        add("screen_width", "2560")
        add_slot("after_screen")
        add("tz_name", "Asia/Shanghai")
        add_slot("after_tz")
        if include_user_is_login:
            add("user_is_login", "true" if auth.logged_in else "false")
        add("verifyFp", auth.verify_fp)
        add_slot("after_verify_fp")
        add("webcast_language", "zh-Hans")
        add_slot("after_webcast_language")
        return Params(values)

    def post_project(self, body: str, *, ticket_guard: Mapping[str, str], auth=None,
                     referer: str = f"{origin}/tiktokstudio/upload?from=webapp&lang=zh-Hans"):
        """Publish one captured Creator Studio project request.

        ``body`` must be the exact browser JSON string.  The method never
        rebuilds the nested cover/source-project object, because even a
        harmless key reorder changes the signed request.  ``ticket_guard`` is
        the five-header set captured from the same browser post; a missing
        header is rejected before any write is attempted.
        """
        if not isinstance(body, str) or not body:
            raise ValueError("post_project 必须传入浏览器原样 JSON 字符串 body")
        required_guard = (
            "tt-ticket-guard-public-key",
            "tt-ticket-guard-web-version",
            "tt-ticket-guard-version",
            "tt-ticket-guard-iteration-version",
            "tt-ticket-guard-client-data",
        )
        auth = self._auth(auth)
        auth.require_browser_profile()
        # Only fresh security-sdk state is accepted.  A captured five-header
        # set is useful for comparison, but replaying it would violate the
        # ticket's anti-replay contract and is therefore rejected.
        provided_guard = {str(k): str(v) for k, v in (ticket_guard or {}).items()}
        try:
            if all(provided_guard.get(key) for key in
                   ("private_key", "encrypt_ticket", "ts_sign")):
                from signing.ticket_guard import build_headers
                computed_guard = build_headers(
                    private_key_pem=provided_guard["private_key"],
                    encrypt_ticket=provided_guard["encrypt_ticket"],
                    ts_sign=provided_guard["ts_sign"],
                    path=self.PROJECT_POST_PATH,
                    version=provided_guard.get("version", "2"),
                    iteration_version=provided_guard.get("iteration_version", "0"),
                )
            else:
                computed_guard = auth.build_ticket_guard(self.PROJECT_POST_PATH)
        except Exception as exc:
            raise ValueError(
                "post_project 只接受可重算 ticket-guard 的 private_key + "
                "encrypt_ticket + ts_sign；不能复放浏览器已消费的五个 header"
            ) from exc
        params = Params([
            ("app_name", "tiktok_web"),
            ("channel", "tiktok_web"),
            ("device_platform", "web"),
            ("tz_name", "Asia/Shanghai"),
            ("aid", "1988"),
        ])
        body_bytes = body.encode("utf-8")
        headers = HeaderBuilder.build(
            HeaderType.POST, auth, referer=referer, origin=self.origin,
            content_length=str(len(body_bytes)), sec_fetch_site="same-origin",
        ).get()
        # Creator Studio's final XHR uses the axios JSON accept value, not the
        # generic */* value used by older endpoints.
        headers["accept"] = "application/json, text/plain, */*"
        for key in required_guard:
            headers[key] = computed_guard[key]
        # Axios' ticket interceptor inserts its five fields at these exact
        # positions in the Chrome project POST.  Preserve the full order when
        # signing and sending instead of merely appending them after fetch
        # metadata.
        headers = OrderedDict((key, headers[key]) for key in (
            "tt-ticket-guard-client-data", "sec-ch-ua-platform", "referer",
            "sec-ch-ua", "sec-ch-ua-mobile", "tt-ticket-guard-web-version",
            "tt-ticket-guard-version", "user-agent", "accept",
            "tt-ticket-guard-public-key", "content-type",
            "tt-ticket-guard-iteration-version", "accept-encoding",
            "accept-language", "content-length", "cookie", "origin",
            "priority", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
        ))
        unsigned_query = params.to_query() + f"&msToken={auth.ms_token}"
        unsigned_url = f"{self.origin}{self.PROJECT_POST_PATH}?{unsigned_query}"
        signing_timestamp = self._ticket_timestamp(
            computed_guard["tt-ticket-guard-client-data"]
        )
        signatures = auth.sign_request(
            self.PROJECT_POST_PATH, url=unsigned_url, method="POST",
            headers=headers, body=body, referer=referer,
            require=auth.strict_browser_alignment,
            # msToken is a browser cookie and can rotate from the captured
            # 160-byte sample to the current 172-byte value.  Enforce its
            # actual current length while keeping the project algorithm's
            # X-Bogus/X-Gnarly lengths evidence-backed.
            expected_lengths={**self.PROJECT_POST_SIGNATURE_LENGTHS,
                              "msToken": len(auth.ms_token)},
            signing_timestamp=signing_timestamp,
        )
        params.update(signatures)
        url = f"{self.origin}{self.PROJECT_POST_PATH}?{params.to_query()}"
        response = http_client.request(
            "POST", url, headers=headers, data=body, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        result = self._json_response(response)
        if not isinstance(result, Mapping) or str(result.get("status_code")) != "0":
            code = result.get("status_code") if isinstance(result, Mapping) else None
            message = result.get("status_msg", "") if isinstance(result, Mapping) else ""
            raise BrowserEvidenceError(
                f"Creator project-post 业务失败: status_code={code}, "
                f"status_msg={str(message)[:180]}"
            )
        for item in result.get("single_post_resp_list") or ():
            if isinstance(item, Mapping) and item.get("status_code") is not None \
                    and str(item["status_code"]) != "0":
                raise BrowserEvidenceError(
                    "Creator project-post 单作品失败: "
                    f"status_code={item['status_code']}"
                )
        return result

    def get_user_posted(self, sec_uid: str, cursor: str = "0", *, count: str = "24",
                        auth=None, referer: str | None = None):
        """`GET /api/post/item_list/` (Chrome req 104).

        The endpoint is the same path as the legacy class, but its browser
        contract includes `language`, `video_encoding` and current signatures.
        """
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{sec_uid}?lang=zh-Hans"
        p = Params().common(
            auth,
            referer=referer,
            root_referer=referer,
            history_len="2",
            include_from_page=False,
            include_user_is_login=True,
            early={"count": count, "coverFormat": "2", "cursor": cursor},
            before_tz={"secUid": sec_uid},
            late={"video_encoding": "dash"},
        )
        return self._request_json(auth, method="GET", path="/api/post/item_list/",
                                  params=p, referer=referer)

    def get_recommend_feed(self, *, auth=None, count: str = "6",
                           referer: str | None = None,
                           cover_format: str = "2",
                           pull_type: str = "1",
                           watch_live_last_time: str | None = None,
                           day_of_week: str = "0", time_of_day: str = "5"):
        """Fetch the current FYP recommendation request captured in Chrome.

        This is the GET follow-up emitted after the homepage's initial POST.
        Every query field from the GET wire sample is retained, including the
        seemingly redundant counters and ad flags; callers may override the
        time bucket/counter values when replaying a fresh browser context.
        """
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/"
        if watch_live_last_time is None:
            watch_live_last_time = str(int(time.time() * 1000))
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2", include_user_is_login=False,
            slots={
                "after_channel": [("clientABVersions", auth.client_ab_versions)],
                "after_cookie": [
                    ("count", count), ("coverFormat", cover_format),
                    ("cpu_core_number", "20"), ("dark_mode", "false"),
                ],
                "after_data_collection": [("day_of_week", day_of_week)],
                "after_device_platform": [("enable_cache", "false")],
                "after_history": [("isNonPersonalized", "false")],
                "after_fullscreen": [("is_new_user", "true")],
                "after_is_page_visible": [("language", "zh-Hans")],
                "after_screen": [
                    ("showAboutThisAd", "true"), ("showAds", "true"),
                    ("time_of_day", time_of_day),
                ],
                "after_verify_fp": [
                    ("video_encoding", "dash"), ("vv_count", "0"),
                    ("vv_count_fyp", "0"),
                    ("watchLiveLastTime", str(watch_live_last_time)),
                ],
            },
        )
        # ``pullType`` is between priority_region and referer in the captured
        # request, so insert it directly rather than appending a guessed field.
        items = []
        for key, value in p.params.items():
            items.append((key, value))
            if key == "priority_region":
                items.append(("pullType", str(pull_type)))
        p = Params(items)
        return self._request_json(
            auth, method="GET", path="/api/recommend/item_list/",
            params=p, referer=referer,
        )

    def post_recommend_feed(
        self, *, body: bytes, watch_live_last_time: str, auth=None,
        referer: str | None = None, count: str = "6",
        cover_format: str = "2", day_of_week: str = "1",
        time_of_day: str = "0", device_score: str = "8.79",
        device_type: str = "web_h265", enable_cache: str = "false",
        is_new_user: str = "false", item_id: str = "", launch_mode: str = "direct",
        network: str = "1.45", show_about_this_ad: str = "true",
        show_ads: str = "true", vv_count: str = "8", vv_count_fyp: str = "8",
        window_height: str = "800", window_width: str = "1297",
        pull_type: str = "1", expected_signature_lengths: Mapping[str, int] | None = None,
    ):
        """Send the homepage's gzip recommendation POST.

        Chrome supplies a fresh telemetry object under ``realTimeClientInfo``
        and compresses the exact JSON bytes before signing.  The compressed
        bytes are therefore required as an argument: Python validates the
        gzip/JSON envelope but never fabricates or replays a stale telemetry
        object, and the signer hashes the bytes that will actually be sent.
        """
        if not isinstance(body, (bytes, bytearray, memoryview)):
            raise BrowserEvidenceError(
                "recommend/item_list POST 需要当前浏览器 gzip body bytes"
            )
        if watch_live_last_time in (None, ""):
            raise BrowserEvidenceError(
                "recommend/item_list POST 需要当前浏览器 watchLiveLastTime"
            )
        try:
            decoded = gzip.decompress(bytes(body))
            decoded_obj = json.loads(decoded.decode("utf-8"))
        except (OSError, EOFError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserEvidenceError(
                "recommend/item_list POST body 不是有效的 Chrome gzip JSON"
            ) from exc
        if not isinstance(decoded_obj, Mapping) or set(decoded_obj) != {"realTimeClientInfo"}:
            raise BrowserEvidenceError(
                "recommend/item_list POST body 必须只有 realTimeClientInfo"
            )
        if not isinstance(decoded_obj.get("realTimeClientInfo"), Mapping):
            raise BrowserEvidenceError(
                "recommend/item_list POST realTimeClientInfo 必须是对象"
            )
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/?lang=zh-Hans"
        lengths = (dict(expected_signature_lengths)
                   if expected_signature_lengths is not None else {
                       "X-Dynosaur": 408, "msToken": len(auth.ms_token),
                       "X-Bogus": 1, "X-Gnarly": 332,
                   })
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2", include_user_is_login=False,
            slots={
                "after_channel": [("clientABVersions", auth.client_ab_versions)],
                "after_cookie": [
                    ("count", count), ("coverFormat", cover_format),
                    ("cpu_core_number", "20"), ("dark_mode", "false"),
                ],
                "after_data_collection": [("day_of_week", day_of_week)],
                "after_device_platform": [
                    ("device_score", device_score), ("device_type", device_type),
                ],
                "after_history": [("isNonPersonalized", "false")],
                "after_fullscreen": [("is_new_user", is_new_user)],
                "after_is_page_visible": [
                    ("language", "zh-Hans"), ("itemID", item_id),
                    ("launch_mode", launch_mode), ("network", network),
                ],
                "after_screen": [
                    ("showAboutThisAd", show_about_this_ad),
                    ("showAds", show_ads), ("time_of_day", time_of_day),
                ],
                "after_verify_fp": [
                    ("video_encoding", "dash"), ("vv_count", vv_count),
                    ("vv_count_fyp", vv_count_fyp),
                    ("watchLiveLastTime", str(watch_live_last_time)),
                ],
                "after_webcast_language": [
                    ("window_height", window_height),
                    ("window_width", window_width),
                ],
            },
        )
        items = []
        for key, value in p.params.items():
            items.append((key, value))
            if key == "priority_region":
                items.append(("pullType", str(pull_type)))
        p = Params(items)
        return self._request_json(
            auth, method="POST", path="/api/recommend/item_list/", params=p,
            referer=referer, body=bytes(body), origin=self.origin,
            extra_headers={"content-encoding": "gzip", "content-type": "application/json"},
            content_type_before_mobile=True, expected_lengths=lengths,
        )

    def get_user_playlist(self, sec_uid: str, *, cursor: str = "0", count: str = "20",
                          auth=None, referer: str | None = None):
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{sec_uid}?lang=zh-Hans"
        p = Params().common(
            auth, referer=referer, root_referer=referer, history_len="2",
            include_user_is_login=True, include_language=False,
            early={"count": count, "cursor": cursor},
            before_tz={"secUid": sec_uid},
        )
        return self._request_json(auth, method="GET", path="/api/user/playlist/",
                                  params=p, referer=referer)

    def get_story_items(self, author_id: str, *, cursor: str = "0", count: str = "20",
                        auth=None, referer: str | None = None):
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{author_id}?lang=zh-Hans"
        p = Params().after_app_name({"authorId": author_id}).common(
            auth, referer=referer, root_referer=referer, history_len="2",
            include_from_page=True, from_page="user", include_user_is_login=True,
            include_language=False,
            early={"count": count, "cursor": cursor, "loadBackward": "false"},
        )
        return self._request_json(auth, method="GET", path="/api/story/item_list/",
                                  params=p, referer=referer)

    def get_story_users(self, *, cursor: str = "0", count: str = "10", auth=None,
                        referer: str = f"{origin}/"):
        auth = self._auth(auth)
        p = Params().common(
            auth, referer=referer, query_referer="", root_referer="", history_len="2",
            include_from_page=True, from_page="user", include_user_is_login=True,
            include_language=False,
            early={"count": count, "cursor": cursor, "isNonPersonalized": "false"},
            before_tz={"storyFeedScene": "3"},
        )
        return self._request_json(auth, method="GET", path="/api/story/user_list/",
                                  params=p, referer=referer)

    def get_user_list(self, *, max_cursor: str = "0", min_cursor: str = "0",
                      count: str = "5", scene: str = "21", auth=None,
                      referer: str = f"{origin}/"):
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2",
            slots={
                "after_channel": [("clientABVersions", auth.client_ab_versions)],
                "after_cookie": [("count", count)],
                "after_is_page_visible": [
                    ("maxCursor", max_cursor), ("minCursor", min_cursor),
                ],
                "after_root_referer": [("scene", scene)],
            },
        )
        return self._request_json(auth, method="GET", path="/api/user/list/",
                                  params=p, referer=referer)

    def _get_profile_user_list(self, sec_uid: str, *, scene: str,
                               max_cursor: str = "0", min_cursor: str = "0",
                               count: str = "30", auth=None,
                               referer: str | None = None,
                               expected_signature_lengths: Mapping[str, int] | None = None):
        """Fetch one profile follow-list page using the captured wire shape.

        TikTok uses one ``/api/user/list/`` endpoint for both profile tabs.  The
        tab is selected by the numeric ``scene`` (21 = following, 67 =
        followers); the profile's ``secUid`` is placed after screen dimensions
        in the query, exactly as emitted by Chrome.  The endpoint is a normal
        signed GET and does not carry the ticket-guard header bundle.
        """
        if not isinstance(sec_uid, str) or not sec_uid.strip():
            raise ValueError("sec_uid 不能为空")
        if not re.fullmatch(r"\d+", str(scene)):
            raise ValueError("scene 必须是浏览器捕获的数字值")
        for name, value in (("count", count), ("max_cursor", max_cursor),
                            ("min_cursor", min_cursor)):
            if not isinstance(value, (str, int)) or not str(value).lstrip("-").isdigit():
                raise ValueError(f"{name} 必须是数字字符串")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{sec_uid}?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={
                "after_channel": [("clientABVersions", auth.client_ab_versions)],
                "after_cookie": [("count", str(count))],
                "after_is_page_visible": [
                    ("maxCursor", str(max_cursor)),
                    ("minCursor", str(min_cursor)),
                ],
                "after_root_referer": [("scene", str(scene))],
                "after_screen": [("secUid", sec_uid)],
            },
        )
        lengths = (dict(expected_signature_lengths)
                   if expected_signature_lengths is not None else
                   {"X-Dynosaur": 468, "msToken": len(auth.ms_token),
                    "X-Bogus": 1, "X-Gnarly": 332})
        return self._request_json(
            auth, method="GET", path="/api/user/list/", params=p,
            referer=referer, expected_lengths=lengths,
        )

    def get_profile_followers(self, sec_uid: str, *, max_cursor: str = "0",
                              min_cursor: str = "0", count: str = "30",
                              auth=None, referer: str | None = None,
                              expected_signature_lengths: Mapping[str, int] | None = None):
        """Return the profile's followers (Chrome ``scene=67``)."""
        return self._get_profile_user_list(
            sec_uid, scene="67", max_cursor=max_cursor, min_cursor=min_cursor,
            count=count, auth=auth, referer=referer,
            expected_signature_lengths=expected_signature_lengths,
        )

    def get_profile_following(self, sec_uid: str, *, max_cursor: str = "0",
                              min_cursor: str = "0", count: str = "30",
                              auth=None, referer: str | None = None,
                              expected_signature_lengths: Mapping[str, int] | None = None):
        """Return the profile's following accounts (Chrome ``scene=21``)."""
        return self._get_profile_user_list(
            sec_uid, scene="21", max_cursor=max_cursor, min_cursor=min_cursor,
            count=count, auth=auth, referer=referer,
            expected_signature_lengths=expected_signature_lengths,
        )

    def get_following_item_list(self, *, cursor: str = "0", count: str = "9",
                                cover_format: str = "2",
                                is_non_personalized: str = "false",
                                is_reset_counter_used: str = "true",
                                level: str = "1", pull_type: str = "1",
                                auth=None,
                                referer: str | None = None):
        """Fetch the logged-in ``/following`` feed with Chrome's full query.

        This is the concrete TikTok counterpart captured from the ``已关注``
        page.  It is a following *feed* (``/api/following/item_list/``), not a
        guessed profile follower/following-list endpoint.  Chrome attaches a
        fresh ticket-guard envelope even for this GET and does not send either
        CSRF header; both details are therefore explicit below.
        """
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/following?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="following", history_len="2",
            slots={
                "after_channel": [("clientABVersions", auth.client_ab_versions)],
                "after_cookie": [
                    ("count", count), ("coverFormat", cover_format),
                    ("cursor", cursor),
                ],
                "after_history": [
                    ("isNonPersonalized", is_non_personalized),
                    ("isResetCounterUsed", is_reset_counter_used),
                ],
                "after_is_page_visible": [("language", "zh-Hans"),
                                            ("level", level)],
                "after_priority_region": [("pullType", pull_type)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/following/item_list/",
            params=p, referer=referer,
            ticket_guard=True, ticket_guard_sec_csrf=False,
            ticket_guard_tt_csrf_header=False,
        )

    def get_inbox_notice_list(self, *, group_list=None, auth=None,
                              referer: str = f"{origin}/",
                              from_page: str = "fyp",
                              history_len: str = "2"):
        """Read inbox notices using the page context captured by Chrome.

        TikTok uses the same path from the FYP and the dedicated messages
        page, but the ``from_page`` and ``history_len`` pairs are part of the
        signed query.  They therefore remain explicit instead of being
        silently normalized to one global value.
        """
        auth = self._auth(auth)
        if group_list is None:
            group_list = [{"count": 1, "is_mark_read": 0, "group": 661,
                           "max_time": 0, "min_time": 0}]
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page=from_page, history_len=history_len,
            slots={"after_from_page": [("group_list", json.dumps(
                group_list, separators=(",", ":"))) ]},
        )
        return self._request_json(auth, method="GET", path="/api/inbox/notice_list/",
                                  params=p, referer=referer)

    def get_notice_count(self, *, auth=None, referer: str = f"{origin}/",
                         from_page: str = "fyp",
                         history_len: str = "2"):
        """Read notice counts for the FYP or the dedicated messages page."""
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page=from_page, history_len=history_len,
        )
        return self._request_json(
            auth, method="GET", path="/api/inbox/notice_count/",
            params=p, referer=referer,
        )

    def get_message_notice_count(self, *, auth=None,
                                 referer: str = f"{origin}/messages?lang=zh-Hans"):
        """Convenience wrapper for the dedicated messages-page context."""
        return self.get_notice_count(
            auth=auth, referer=referer, from_page="message", history_len="4",
        )

    def get_message_notice_list(self, *, group_list=None, auth=None,
                                referer: str = f"{origin}/messages?lang=zh-Hans"):
        """Read message-page notices without silently using FYP fields."""
        return self.get_inbox_notice_list(
            group_list=group_list, auth=auth, referer=referer,
            from_page="message", history_len="4",
        )

    def get_notice_multi(self, *, group_list=None, auth=None,
                         referer: str | None = None):
        """Read the current web notification groups.

        Chrome places ``group_list`` between ``from_page`` and
        ``history_len`` and sends the four WebMssdk fields afterwards.
        """
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        if group_list is None:
            group_list = [{"count": 20, "is_mark_read": 0, "group": 500,
                           "max_time": 0, "min_time": 0}]
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2",
            slots={"after_from_page": [("group_list", json.dumps(
                group_list, separators=(",", ":"))) ]},
        )
        return self._request_json(auth, method="GET", path="/api/notice/multi/",
                                  params=p, referer=referer)

    def get_popup_dispatch(self, *, scene: str = "0", auth=None,
                           referer: str = f"{origin}/"):
        """Read the unsigned popup dispatch contract emitted on profile load."""
        auth = self._auth(auth)
        return self.request_captured(
            "/tiktok/popup/dispatch/v1",
            {
                "region": auth.region,
                "priority_region": auth.priority_region,
                "aid": "1988",
                "device_id": auth.device_id,
                "app_language": "zh-Hans",
                "device_platform": "web_pc",
                "WebIdLastTime": auth.web_id_last_time,
                "scene": scene,
            },
            auth=auth, referer=referer, signed=False,
        )

    def get_ppf_eligibility(self, *, referer: str | None = None, auth=None):
        """Read the unsigned PPF eligibility query captured on a profile."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
        )
        return self._request_json(
            auth, method="POST", path="/tiktok/ppf/api/eligibility/v2",
            params=p, referer=referer, signed=False, body=b"", form=True,
            extra_headers={"tt-csrf-token": ""},
        )

    def get_compliance_settings(self, *, from_web: str = "1",
                                referer: str | None = None, auth=None):
        """Read the unsigned account compliance settings query."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={"after_focus": [("fromWeb", from_web)]},
        )
        return self._request_json(
            auth, method="GET", path="/api/compliance/settings/",
            params=p, referer=referer, signed=False,
        )

    def get_popup_display(self, *, permission_type: str = "10",
                          referer: str | None = None, auth=None):
        """Read the unsigned popup display decision for a permission type."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={"after_is_page_visible": [("permission_type", permission_type)]},
        )
        return self._request_json(
            auth, method="POST", path="/tiktok/popup/display/v1/",
            params=p, referer=referer, signed=False, body=b"", form=True,
        )

    def get_compliance_guadig_settings(self, *, date: str,
                                       referer: str | None = None, auth=None):
        """Read the unsigned daily compliance/guadig settings query."""
        if not date:
            raise ValueError("compliance guadig settings 需要 date")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={"after_data_collection": [("date", date)]},
        )
        return self._request_json(
            auth, method="GET", path="/tiktok/v1/compliance/guadig/settings/",
            params=p, referer=referer, signed=False,
        )

    def get_share_settings(self, *, mode: str = "1",
                           referer: str | None = None, auth=None):
        """Read the unsigned share-settings mode used by profile pages."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            device_platform="webapp_pc",
            slots={"after_is_page_visible": [("mode", mode)]},
        )
        return self._request_json(
            auth, method="GET", path="/api/share/settings/",
            params=p, referer=referer, signed=False,
        )

    def get_im_spotlight_relation(self, *, count: str = "90",
                                  max_time: str = "0", min_time: str = "0",
                                  source: str = "web", with_fstatus: str = "1",
                                  referer: str | None = None, auth=None):
        """Read the unsigned IM spotlight relation list."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            device_platform="webapp_pc",
            slots={
                "after_cookie": [("count", count)],
                "after_is_page_visible": [("max_time", max_time), ("min_time", min_time)],
                "after_screen": [("source", source)],
                "after_webcast_language": [("with_fstatus", with_fstatus)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/im/spotlight/relation/",
            params=p, referer=referer, signed=False,
        )

    def get_privacy_effected_count(self, *, referer: str | None = None, auth=None):
        """Read the unsigned privacy effected-count query."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
        )
        return self._request_json(
            auth, method="GET", path="/api/privacy/user/effected_count/v1",
            params=p, referer=referer, signed=False,
        )

    def get_report_inbox_notice(self, *, carrier_region: str | None = None,
                                current_region: str | None = None,
                                locale: str = "zh-Hans",
                                request_tag_from: str = "pc",
                                sys_region: str | None = None,
                                referer: str | None = None, auth=None):
        """Read the unsigned legacy report/inbox notice bridge request."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        carrier_region = carrier_region or auth.region
        current_region = current_region or auth.region
        sys_region = sys_region or auth.region
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={
                "after_browser_version": [("carrier_region", carrier_region)],
                "after_cookie": [("current_region", current_region)],
                "after_is_page_visible": [("locale", locale)],
                "after_region": [("request_tag_from", request_tag_from)],
                "after_screen": [("sys_region", sys_region)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/aweme/v1/report/inbox/notice/",
            params=p, referer=referer, signed=False,
        )

    def get_community_notes_intake(self, *, referer: str | None = None, auth=None):
        """Read the unsigned Community Notes intake check."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
        )
        return self._request_json(
            auth, method="GET", path="/tiktok/v1/community_notes/intake/check/",
            params=p, referer=referer, signed=False,
        )

    def get_privacy_setting_restriction(self, *, referer: str | None = None, auth=None):
        """Read the signed privacy restriction settings payload."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
        )
        return self._request_json(
            auth, method="GET", path="/api/privacy/setting/restriction/v1",
            params=p, referer=referer,
        )

    def get_user_settings(self, *, enable_v2: str = "true",
                          referer: str | None = None, auth=None):
        """Read the signed current user settings payload."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={"after_device_platform": [("enable_v2", enable_v2)]},
        )
        return self._request_json(
            auth, method="GET", path="/api/user/settings/",
            params=p, referer=referer,
        )

    def get_business_permission_list(self, *, permission_list: str,
                                     referer: str | None = None, auth=None):
        """Read the signed Business Suite permission list."""
        if not permission_list:
            raise ValueError("business permission list 需要 permission_list")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={"after_root_referer": [("permissionList", permission_list)]},
        )
        return self._request_json(
            auth, method="GET", path="/api/ba/business/suite/permission/list/",
            params=p, referer=referer,
        )

    def get_live_sub_info(self, sec_anchor_id: str, *, need_current_state: str = "true",
                          referer: str | None = None, auth=None):
        """Read the signed live subscription privilege state."""
        if not sec_anchor_id:
            raise ValueError("get_sub_info 需要 sec_anchor_id")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={
                "after_is_page_visible": [("need_current_state", need_current_state)],
                "after_screen": [("sec_anchor_id", sec_anchor_id)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/webcast/sub/privilege/get_sub_info",
            params=p, referer=referer, origin=self.origin,
        )

    def get_diamond_buy_permission(self, *, user_id: str, live_id: str = "12",
                                   local_country: str | None = None,
                                   source: str = "www.tiktok.com/@tiktok",
                                   referer: str | None = None, auth=None):
        """Read the signed live wallet diamond-buy permission state."""
        if not user_id:
            raise ValueError("diamond_buy permission 需要 user_id")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        local_country = local_country or auth.region
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            slots={
                "after_is_page_visible": [("live_id", live_id),
                                            ("local_country", local_country)],
                "after_root_referer": [("source", source)],
                "after_tz": [("user_id", user_id)],
            },
        )
        return self._request_json(
            auth, method="GET",
            path="/webcast/wallet_api/fs/diamond_buy/permission_v2",
            params=p, referer=referer, origin=self.origin,
        )

    def get_following_request_list(self, user_id: str, *, count: str = "20",
                                   max_time: str = "0", auth=None,
                                   referer: str | None = None):
        """Read pending follow requests using the captured account context."""
        if not user_id:
            raise ValueError("following request list 需要浏览器 user_id")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2", aid="1988",
            slots={
                "after_cookie": [("count", count)],
                "after_is_page_visible": [("max_time", max_time)],
                "after_tz": [("user_id", user_id)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/user/following/request/list/",
            params=p, referer=referer,
        )

    def get_im_user_profile(self, user_ids, *, auth=None,
                            referer: str = f"{origin}/messages?lang=zh-Hans"):
        """Read IM profile cards from the messages micro-frontend.

        Chrome sends only ``aid`` and a compact JSON ``user_ids`` query value
        for this endpoint.  It is intentionally unsigned; adding the normal
        WebMssdk query quartet would no longer match the browser request.
        """
        if isinstance(user_ids, (str, int)):
            values = [str(user_ids)]
        else:
            try:
                values = [str(value) for value in user_ids]
            except TypeError as exc:
                raise ValueError("user_ids 必须是用户 ID 或 ID 序列") from exc
        if not values or any(not value for value in values):
            raise ValueError("user_ids 不能为空")
        auth = self._auth(auth)
        params = Params([
            ("aid", "1988"),
            ("user_ids", json.dumps(values, ensure_ascii=False,
                                     separators=(",", ":"))),
        ])
        return self._request_json(
            auth, method="GET", path="/tiktok/v1/im/user/profile/",
            params=params, referer=referer, signed=False,
        )

    def get_feedback_newest_reply(self, *, clear_unread: str = "false",
                                  auth=None, referer: str | None = None):
        """Read the unsigned feedback notification cursor used by the profile."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2", aid="1284",
            slots={
                "before_app_language": [("app_key", "tiktok-web")],
                "after_app_name": [("appkey", "tiktok-web")],
                "after_channel": [("clear_unread", clear_unread)],
                "after_history": [("iid", "0")],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/feedback/v1/newest_reply/",
            params=p, referer=referer, signed=False,
        )

    def get_collection_list(self, sec_uid: str, *, cursor: str = "0", count: str = "30",
                            auth=None, referer: str | None = None):
        if not sec_uid:
            raise ValueError("collection_list 需要 sec_uid")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{sec_uid}?lang=zh-Hans"
        p = self._profile_item_list_params(
            auth, sec_uid=sec_uid, cursor=cursor, count=count,
            root_referer=referer, include_app_id=True, include_public_only=True,
        )
        return self._request_json(auth, method="GET", path="/api/user/collection_list/",
                                  params=p, referer=referer,
                                  expected_lengths={"X-Dynosaur": 472,
                                                     "msToken": len(auth.ms_token),
                                                     "X-Bogus": 1, "X-Gnarly": 332})

    def get_repost_list(self, sec_uid: str, *, cursor: str = "0", count: str = "30",
                        auth=None, referer: str | None = None):
        if not sec_uid:
            raise ValueError("repost/item_list 需要 sec_uid")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{sec_uid}?lang=zh-Hans"
        p = self._profile_item_list_params(
            auth, sec_uid=sec_uid, cursor=cursor, count=count,
            root_referer=referer, include_client_ab=True,
        )
        return self._request_json(auth, method="GET", path="/api/repost/item_list/",
                                  params=p, referer=referer,
                                  expected_lengths={"X-Dynosaur": 472,
                                                     "msToken": len(auth.ms_token),
                                                     "X-Bogus": 1, "X-Gnarly": 332})

    def get_collected_item_list(self, sec_uid: str, *, cursor: str = "0",
                                count: str = "16", auth=None,
                                referer: str | None = None):
        """Read the profile's collected-video tab."""
        if not sec_uid:
            raise ValueError("user/collect/item_list 需要 sec_uid")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{sec_uid}?lang=zh-Hans"
        p = self._profile_item_list_params(
            auth, sec_uid=sec_uid, cursor=cursor, count=count,
            root_referer=referer, include_client_ab=True,
        )
        return self._request_json(
            auth, method="GET", path="/api/user/collect/item_list/",
            params=p, referer=referer,
            expected_lengths={"X-Dynosaur": 472, "msToken": len(auth.ms_token),
                               "X-Bogus": 1, "X-Gnarly": 332},
        )

    def check_playlist_name(self, name: str, *, auth=None,
                            referer: str | None = None,
                            history_len: str = "7"):
        """Check a collection name with the captured signed request."""
        if not name:
            raise ValueError("playlist/name_check 需要非空 name")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer="", from_page="user", history_len=str(history_len),
            slots={"after_is_page_visible": [("name", str(name))]},
        )
        return self._request_json(
            auth, method="GET", path="/api/playlist/name_check",
            params=p, referer=referer,
            expected_lengths={"X-Dynosaur": 472, "msToken": len(auth.ms_token),
                               "X-Bogus": 1, "X-Gnarly": 332},
        )

    def post_collection_create(self, name: str, *, collection_status: str = "1",
                               auth=None, referer: str | None = None):
        """Create a collection using Chrome's empty form body."""
        if not name:
            raise ValueError("collection/create 需要非空 collectionName")
        if len(str(name)) > 30:
            raise ValueError("collectionName 不能超过浏览器的 30 字符限制")
        auth = self._auth(auth)
        csrf_headers = self._collection_write_headers(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer="", from_page="user", history_len="6",
            slots={
                "after_channel": [("collectionName", str(name)),
                                   ("collectionStatus", str(collection_status))],
                "after_is_page_visible": [("language", "zh-Hans")],
            },
        )
        return self._request_json(
            auth, method="POST", path="/api/collection/create/",
            params=p, referer=referer, origin=self.origin,
            body="", form=True, extra_headers=csrf_headers,
            header_order=self.COLLECTION_WRITE_HEADER_ORDER,
            expected_lengths={"X-Dynosaur": 472, "msToken": len(auth.ms_token),
                               "X-Bogus": 1, "X-Gnarly": 332},
        )

    def post_collection_modify_info(
        self, collection_id: str, collection_name: str, *,
        collection_status: str = "1", auth=None, referer: str | None = None,
    ):
        """Rename/toggle visibility with the captured collection write."""
        if not collection_id or not collection_name:
            raise ValueError("collection/modify_info 需要 collectionId/collectionName")
        if len(str(collection_name)) > 30:
            raise ValueError("collectionName 不能超过浏览器的 30 字符限制")
        auth = self._auth(auth)
        csrf_headers = self._collection_write_headers(auth)
        referer = referer or f"{self.origin}/@tiktok/collection/{collection_id}"
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer="", from_page="user", history_len="7",
            slots={
                "after_channel": [("collectionId", str(collection_id)),
                                   ("collectionName", str(collection_name)),
                                   ("collectionStatus", str(collection_status))],
                "after_is_page_visible": [("language", "zh-Hans")],
            },
        )
        return self._request_json(
            auth, method="POST", path="/api/collection/modify_info/",
            params=p, referer=referer, origin=self.origin,
            body="", form=True, extra_headers=csrf_headers,
            header_order=self.COLLECTION_WRITE_HEADER_ORDER,
            expected_lengths={"X-Dynosaur": 508, "msToken": len(auth.ms_token),
                               "X-Bogus": 1, "X-Gnarly": 332},
        )

    def post_collection_modify_items(
        self, collection_id: str, commit_ids: str, *, referer: str,
        profile_url: str, auth=None,
    ):
        """Add captured item IDs to a collection with the real empty POST.

        ``commit_ids`` is deliberately a raw wire string.  The only Chrome
        sample contains one item, so this method does not guess a delimiter
        for a Python list of multiple IDs.
        """
        collection_id = self._raw_wire_scalar("collectionId", collection_id)
        commit_ids = self._raw_wire_scalar("commitIds", commit_ids)
        referer, profile_url = self._collection_item_write_pages(referer, profile_url)
        auth = self._auth(auth)
        headers = self._collection_write_headers(auth)
        params = self._collection_item_write_params(
            auth, operation="modify", collection_id=collection_id,
            item_ids=commit_ids, profile_url=profile_url,
        )
        return self._request_json(
            auth, method="POST", path="/api/collection/modify_items/",
            params=params, referer=referer, origin=self.origin,
            body="", form=True, extra_headers=headers,
            header_order=self.COLLECTION_WRITE_HEADER_ORDER,
            expected_lengths={"X-Dynosaur": 504, "msToken": len(auth.ms_token),
                              "X-Bogus": 1, "X-Gnarly": 332},
        )

    def post_collection_move_items(
        self, from_collection_id: str, target_collection_id: str,
        item_ids: str, *, referer: str, profile_url: str, auth=None,
    ):
        """Move captured item IDs between two collections.

        Chrome sends all business fields in the signed query and a zero-byte
        form body.  ``item_ids`` stays a raw wire string for the same reason
        as :meth:`post_collection_modify_items`.
        """
        source = self._raw_wire_scalar("fromCollectionID", from_collection_id)
        target = self._raw_wire_scalar("targetCollectionID", target_collection_id)
        item_ids = self._raw_wire_scalar("itemIDs", item_ids)
        referer, profile_url = self._collection_item_write_pages(referer, profile_url)
        auth = self._auth(auth)
        headers = self._collection_write_headers(auth)
        params = self._collection_item_write_params(
            auth, operation="move", collection_id=source,
            target_collection_id=target, item_ids=item_ids,
            profile_url=profile_url,
        )
        return self._request_json(
            auth, method="POST", path="/api/collection/move_items/",
            params=params, referer=referer, origin=self.origin,
            body="", form=True, extra_headers=headers,
            header_order=self.COLLECTION_WRITE_HEADER_ORDER,
            expected_lengths={"X-Dynosaur": 504, "msToken": len(auth.ms_token),
                              "X-Bogus": 1, "X-Gnarly": 332},
        )

    @staticmethod
    def _raw_wire_scalar(name: str, value) -> str:
        if isinstance(value, (list, tuple, set, dict)):
            raise BrowserEvidenceError(
                f"{name} 仅接受 Chrome 原样字符串；当前证据不足以拼接多个 ID"
            )
        text = str(value or "")
        if not text or text != text.strip():
            raise ValueError(f"请求需要非空且未改写的 {name}")
        return text

    @staticmethod
    def _collection_item_write_pages(referer: str, profile_url: str) -> tuple[str, str]:
        referer = str(referer or "")
        profile_url = str(profile_url or "")
        if not referer or not profile_url:
            raise BrowserEvidenceError(
                "收藏夹作品写入需要显式提供 Chrome 视频页 referer 与 profile_url"
            )
        for name, value in (("referer", referer), ("profile_url", profile_url)):
            parsed = urlparse(value)
            if parsed.scheme != "https" or parsed.netloc != "www.tiktok.com":
                raise BrowserEvidenceError(f"{name} 必须是完整的 https://www.tiktok.com 页面 URL")
        if "/video/" not in urlparse(referer).path:
            raise BrowserEvidenceError("referer 必须是触发该请求的 TikTok 视频详情页")
        if not urlparse(profile_url).path.startswith("/@"):
            raise BrowserEvidenceError("profile_url 必须是触发该请求的 TikTok 主页 URL")
        return referer, profile_url

    @staticmethod
    def _collection_write_headers(auth: TiktokAuth) -> OrderedDict:
        auth.require_browser_profile()
        if not auth.tt_csrf_token:
            raise BrowserEvidenceError("收藏夹作品写入缺少当前 Chrome tt-csrf-token")
        return OrderedDict((
            ("x-cthulhu-csrf", "1"),
            ("tt-csrf-token", auth.tt_csrf_token),
        ))

    @staticmethod
    def _collection_item_write_params(
        auth: TiktokAuth, *, operation: str, collection_id: str,
        item_ids: str, profile_url: str, target_collection_id: str = "",
    ) -> Params:
        pairs = [
            ("WebIdLastTime", auth.web_id_last_time), ("aid", "1988"),
            ("app_language", "zh-Hans"), ("app_name", "tiktok_web"),
            ("browser_language", "zh-CN"), ("browser_name", "Mozilla"),
            ("browser_online", "true"), ("browser_platform", "Win32"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("channel", "tiktok_web"),
        ]
        if operation == "modify":
            pairs.extend((("collectionId", collection_id), ("commitIds", item_ids)))
        elif operation != "move":
            raise ValueError(f"未知 collection item write operation: {operation}")
        pairs.extend((
            ("cookie_enabled", "true"), ("data_collection_enabled", "true"),
            ("device_id", auth.device_id), ("device_platform", "web_pc"),
            ("focus_state", "true"),
        ))
        if operation == "move":
            pairs.append(("fromCollectionID", collection_id))
        pairs.extend((
            ("from_page", "video"), ("history_len", "3"),
            ("is_fullscreen", "false"), ("is_page_visible", "true"),
        ))
        if operation == "move":
            pairs.append(("itemIDs", item_ids))
        pairs.extend((
            ("language", "zh-Hans"), ("odinId", auth.odin_id),
            ("os", "windows"), ("priority_region", auth.priority_region),
            ("referer", profile_url), ("region", auth.region),
            ("root_referer", profile_url), ("screen_height", "1440"),
            ("screen_width", "2560"),
        ))
        if operation == "move":
            pairs.append(("targetCollectionID", target_collection_id))
        pairs.extend((
            ("tz_name", "Asia/Shanghai"),
            ("user_is_login", "true" if auth.logged_in else "false"),
            ("verifyFp", auth.verify_fp), ("webcast_language", "zh-Hans"),
        ))
        return Params(pairs)

    def get_collection_candidate_item_list(
        self, sec_uid: str, *, cursor: str = "0", count: str = "30",
        scene: str = "155", auth=None, referer: str | None = None,
    ):
        """List favorited videos eligible for adding to a collection."""
        if not sec_uid:
            raise ValueError("collection/candidate/item_list 需要 sec_uid")
        if scene in (None, ""):
            raise BrowserEvidenceError("collection candidate 需要浏览器 scene")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{sec_uid}?lang=zh-Hans"
        p = self._profile_item_list_params(
            auth, sec_uid=sec_uid, cursor=cursor, count=count,
            root_referer=referer, include_app_id=True,
            extra_after_root=[("scene", str(scene))],
        )
        return self._request_json(
            auth, method="GET", path="/api/collection/candidate/item_list/",
            params=p, referer=referer,
            expected_lengths={"X-Dynosaur": 472, "msToken": len(auth.ms_token),
                               "X-Bogus": 1, "X-Gnarly": 332},
        )

    def get_collection_detail(self, collection_id: str, *, scene: str = "116",
                              auth=None, referer: str | None = None):
        """Read collection metadata from its detail page."""
        if not collection_id:
            raise ValueError("collection/detail 需要 collectionId")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok/collection/{collection_id}"
        p = self._collection_folder_params(
            auth, collection_id=collection_id, history_len="7",
            scene=scene, referer=referer,
        )
        return self._request_json(
            auth, method="GET", path="/api/collection/detail/", params=p,
            referer=referer,
            expected_lengths={"X-Dynosaur": 508, "msToken": len(auth.ms_token),
                               "X-Bogus": 1, "X-Gnarly": 332},
        )

    def get_collection_item_list(self, collection_id: str, *, cursor: str = "0",
                                 count: str = "30", source_type: str = "113",
                                 auth=None, referer: str | None = None):
        """Read the videos inside one collection folder."""
        if not collection_id:
            raise ValueError("collection/item_list 需要 collectionId")
        if source_type in (None, ""):
            raise BrowserEvidenceError("collection item_list 需要浏览器 sourceType")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok/collection/{collection_id}"
        p = self._collection_folder_params(
            auth, collection_id=collection_id, history_len="7", scene=None,
            referer=referer, cursor=cursor, count=count, source_type=source_type,
        )
        return self._request_json(
            auth, method="GET", path="/api/collection/item_list/", params=p,
            referer=referer,
            expected_lengths={"X-Dynosaur": 508, "msToken": len(auth.ms_token),
                               "X-Bogus": 1, "X-Gnarly": 332},
        )

    @staticmethod
    def _collection_folder_params(auth: TiktokAuth, *, collection_id: str,
                                   history_len: str, scene: str | None,
                                   referer: str, cursor: str = "0",
                                   count: str = "30", source_type: str | None = None):
        """Build the captured detail/item collection query order."""
        pairs = [
            ("WebIdLastTime", auth.web_id_last_time), ("aid", "1988"),
            ("app_language", "zh-Hans"), ("app_name", "tiktok_web"),
            ("browser_language", "zh-CN"), ("browser_name", "Mozilla"),
            ("browser_online", "true"), ("browser_platform", "Win32"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("channel", "tiktok_web"), ("clientABVersions", auth.client_ab_versions),
            ("collectionId", str(collection_id)), ("cookie_enabled", "true"),
        ]
        if source_type is not None:
            pairs.extend([("count", str(count)), ("cursor", str(cursor))])
        pairs.extend([
            ("data_collection_enabled", "true"), ("device_id", auth.device_id),
            ("device_platform", "web_pc"), ("focus_state", "true"),
            ("from_page", "user"), ("history_len", str(history_len)),
            ("is_fullscreen", "false"), ("is_page_visible", "true"),
            ("language", "zh-Hans"),
            ("odinId", auth.odin_id), ("os", "windows"),
            ("priority_region", auth.priority_region), ("referer", referer),
            ("region", auth.region), ("root_referer", ""),
        ])
        if scene is not None:
            pairs.append(("scene", str(scene)))
        pairs.extend([
            ("screen_height", "1440"), ("screen_width", "2560"),
        ])
        if source_type is not None:
            pairs.append(("sourceType", str(source_type)))
        pairs.extend([
            ("tz_name", "Asia/Shanghai"),
            ("user_is_login", "true" if auth.logged_in else "false"),
            ("verifyFp", auth.verify_fp), ("webcast_language", "zh-Hans"),
        ])
        return Params(pairs)

    @staticmethod
    def _profile_item_list_params(auth: TiktokAuth, *, sec_uid: str,
                                  cursor: str, count: str,
                                  root_referer: str,
                                  include_app_id: bool = False,
                                  include_public_only: bool = False,
                                  include_client_ab: bool = False,
                                  extra_after_root=None):
        """Build the profile collection/repost query in the captured order.

        These profile tabs look like ``post/item_list`` but Chrome emits a
        distinct wire: ``appId`` (collection only) sits directly after ``aid``;
        ``clientABVersions`` (repost only) sits directly after ``channel``;
        the query ``referer`` is the profile URL while ``root_referer`` is
        empty.  Keeping this separate from ``Params.common`` prevents
        those fields from drifting into the wrong signed positions.
        """
        pairs = [
            ("WebIdLastTime", auth.web_id_last_time),
            ("aid", "1988"),
        ]
        if include_app_id:
            pairs.append(("appId", "1988"))
        pairs.extend([
            ("app_language", "zh-Hans"),
            ("app_name", "tiktok_web"),
            ("browser_language", "zh-CN"),
            ("browser_name", "Mozilla"),
            ("browser_online", "true"),
            ("browser_platform", "Win32"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("channel", "tiktok_web"),
        ])
        if include_client_ab:
            pairs.append(("clientABVersions", auth.client_ab_versions))
        pairs.extend([
            ("cookie_enabled", "true"),
            ("count", count),
            ("coverFormat", "2"),
            ("cursor", cursor),
            ("data_collection_enabled", "true"),
            ("device_id", auth.device_id),
            ("device_platform", "web_pc"),
            ("focus_state", "true"),
            ("from_page", "user"),
            ("history_len", "6"),
            ("is_fullscreen", "false"),
            ("is_page_visible", "true"),
            ("language", "zh-Hans"),
            ("needPinnedItemIds", "true"),
            ("odinId", auth.odin_id),
            ("os", "windows"),
            ("post_item_list_request_type", "0"),
            ("priority_region", auth.priority_region),
        ])
        if include_public_only:
            pairs.append(("publicOnly", "true"))
        pairs.extend([
            ("referer", root_referer),
            ("region", auth.region),
            ("root_referer", ""),
            ("screen_height", "1440"),
            ("screen_width", "2560"),
            ("secUid", sec_uid),
            ("tz_name", "Asia/Shanghai"),
            ("user_is_login", "true" if auth.logged_in else "false"),
            ("verifyFp", auth.verify_fp),
            ("video_encoding", "dash"),
            ("webcast_language", "zh-Hans"),
        ])
        for key, value in extra_after_root or ():
            index = next(i for i, (name, _value) in enumerate(pairs)
                         if name == "screen_height")
            pairs.insert(index, (str(key), str(value)))
        return Params(pairs)

    def search_live_room(self, keyword: str, offset: int = 0, *, auth=None,
                         referer: str = f"{origin}/live"):
        # Current Chrome uses webcast/room/search; the old /api/search/live/full/
        # path is kept only by the legacy class and is not emitted here.
        if str(offset) != "0":
            raise ValueError("当前 Chrome /webcast/room/search/ 请求没有 offset 字段")
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="search", history_len="2",
            slots={
                "after_from_page": [("get_hot_event_rooms", "v0")],
                "after_priority_region": [("query", keyword)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/webcast/room/search/", params=p,
            referer=referer, origin=self.origin,
        )

    def search_general(self, keyword: str, *, auth=None, offset: str = "0",
                       cursor: str = "0", count: str = "12",
                       referer: str | None = None):
        """`GET /api/search/general/full/` captured from `/search?q=...`."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/search?q={keyword}&lang=zh-Hans"
        web_search_code = json.dumps(
            {"tiktok": {"client_params_x": {"search_engine": {
                "ies_mt_user_live_video_card_use_libra": 1,
                "mt_search_general_user_live_card": 1,
            }}, "search_server": {}}}, separators=(",", ":"),
        )
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="search", history_len="2",
            slots={
                "after_channel": [("client_ab_versions", auth.client_ab_versions)],
                "after_cookie": [("count", count), ("cursor", cursor)],
                "after_device_platform": [("device_type", "web_h265")],
                "after_fullscreen": [("is_non_personalized_search", "0")],
                "after_is_page_visible": [("keyword", keyword)],
                "after_os": [("offset", offset)],
                "after_verify_fp": [("web_search_code", web_search_code)],
            },
        )
        return self._request_json(auth, method="GET", path="/api/search/general/full/",
                                  params=p, referer=referer)

    def get_search_suggest(self, keyword: str, *, auth=None,
                           referer: str | None = None,
                           req_source: str = "related_search"):
        """Read search-guide suggestions from the captured search page request.

        The browser sends this endpoint without WebMssdk signatures.  The
        query keeps the empty ``referer``/``root_referer`` values and places
        ``keyword``/``req_source`` at the exact current Chrome slots.
        """
        if not keyword:
            raise ValueError("搜索建议需要非空 keyword")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/search?q={keyword}"
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="search", history_len="2",
            slots={
                "after_is_page_visible": [("keyword", keyword)],
                "after_region": [("req_source", req_source)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/search/suggest/guide/",
            params=p, referer=referer, signed=False,
        )

    def get_search_preview(self, keyword: str, *, auth=None,
                           referer: str | None = None):
        """Fetch the signed search preview request emitted before results."""
        if not keyword:
            raise ValueError("搜索预览需要非空 keyword")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/search?q={keyword}"
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="search", history_len="2",
            slots={"after_is_page_visible": [("keyword", keyword)]},
        )
        return self._request_json(
            auth, method="GET", path="/api/search/general/preview/",
            params=p, referer=referer,
        )

    def get_item_availability(self, item_ids, *, auth=None,
                              referer: str = f"{origin}/"):
        """Check availability for one or more item IDs from the FYP request."""
        if isinstance(item_ids, (list, tuple, set)):
            item_ids = ",".join(str(item) for item in item_ids)
        if not str(item_ids):
            raise ValueError("itemIds 不能为空")
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2",
            slots={"after_is_page_visible": [("itemIds", str(item_ids))]},
        )
        return self._request_json(
            auth, method="GET", path="/api/item/availability/",
            params=p, referer=referer,
        )

    def get_preload_item_list(self, *, auth=None, count: str = "3",
                              referer: str = f"{origin}/",
                              day_of_week: str = "0", time_of_day: str = "5"):
        """Fetch the signed homepage preload list with all captured fields."""
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2",
            slots={
                "after_channel": [("clientABVersions", auth.client_ab_versions)],
                "after_cookie": [
                    ("count", count), ("coverFormat", "2"),
                    ("cpu_core_number", "20"), ("dark_mode", "false"),
                ],
                "after_data_collection": [("day_of_week", day_of_week)],
                "after_history": [("isNonPersonalized", "false")],
                "after_is_page_visible": [("language", "zh-Hans")],
                "after_screen": [("time_of_day", time_of_day)],
                "after_verify_fp": [
                    ("video_encoding", "dash"), ("vv_count", "0"),
                    ("vv_count_fyp", "0"),
                ],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/preload/item_list/",
            params=p, referer=referer,
        )

    def post_prefetch_explore_item_list(
        self, *, auth=None, referer: str | None = None,
        category_type: str = "120", pull_type: str = "1",
        is_new_user: str = "false", language: str = "zh-Hans",
        video_encoding: str = "dash",
        expected_signature_lengths: Mapping[str, int] | None = None,
    ):
        """Prefetch the profile Explore card list using the captured POST.

        Chrome sends an empty URL-encoded body.  All business values live in
        the signed query, including ``categoryType``, ``pullType`` and the
        profile page context; the method therefore never invents a JSON body.
        """
        auth = self._auth(auth)
        if not referer:
            raise BrowserEvidenceError(
                "prefetch/explore/item_list 需要当前浏览器 profile_url"
            )
        lengths = (dict(expected_signature_lengths)
                   if expected_signature_lengths is not None else {
                       "X-Dynosaur": 472, "msToken": len(auth.ms_token),
                       "X-Bogus": 1, "X-Gnarly": 332,
                   })
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=referer, from_page="user", history_len="2",
            include_odin_id=True, include_user_is_login=True,
            slots={
                "after_browser_version": [("categoryType", category_type)],
                "after_channel": [("clientABVersions", auth.client_ab_versions)],
                "after_fullscreen": [("is_new_user", is_new_user)],
                "after_is_page_visible": [("language", language)],
                "after_priority_region": [("pullType", pull_type)],
                "after_verify_fp": [("video_encoding", video_encoding)],
            },
        )
        return self._request_json(
            auth, method="POST", path="/api/prefetch/explore/item_list/",
            params=p, referer=referer, origin=self.origin, body="", form=True,
            content_type_before_mobile=True, expected_lengths=lengths,
        )

    def get_comments(self, aweme_id: str, cursor: str = "0", *, count: str = "20",
                     auth=None, referer: str | None = None):
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        # The video page currently sends ja-JP as app_language and includes
        # four endpoint fields that the older generic helper omitted.
        p = self._current_params(
            auth, referer=referer, from_page="video", history_len="3",
            app_language="ja-JP",
            slots={
                "after_app_name": [("aweme_id", aweme_id)],
                "after_cookie": [
                    ("count", count), ("current_region", auth.region),
                    ("cursor", cursor),
                ],
                "after_device_platform": [("enter_from", "tiktok_web")],
                "after_focus": [("fromWeb", "1")],
                "after_fullscreen": [("is_non_personalized", "false")],
            },
        )
        return self._request_json(auth, method="GET", path="/api/comment/list/",
                                  params=p, referer=referer)

    def get_comment_replies(
        self, item_id: str, comment_id: str, cursor: str = "1", *,
        count: str = "3", auth=None, referer: str, root_referer: str,
    ):
        """Read child comments using the video page's captured reply wire.

        ``referer`` is the active video document and ``root_referer`` is the
        current tab's root-navigation page.  Chrome can keep an older video
        there, so deriving or blanking it would change the signed request.
        """
        item_id = self._raw_wire_scalar("item_id", item_id)
        comment_id = self._raw_wire_scalar("comment_id", comment_id)
        cursor = self._raw_wire_scalar("cursor", cursor)
        count = self._raw_wire_scalar("count", count)
        referer = str(referer or "")
        root_referer = str(root_referer or "")
        for name, value in (("referer", referer), ("root_referer", root_referer)):
            parsed = urlparse(value)
            if (parsed.scheme != "https" or parsed.netloc != "www.tiktok.com"
                    or "/video/" not in parsed.path):
                raise BrowserEvidenceError(
                    f"comment/list/reply 的 {name} 必须是完整 TikTok 视频页 URL"
                )
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer=root_referer, from_page="video", history_len="6",
            slots={
                "after_channel": [("comment_id", comment_id)],
                "after_cookie": [("count", count), ("cursor", cursor)],
                "after_is_page_visible": [("item_id", item_id)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/comment/list/reply/",
            params=p, referer=referer,
            expected_lengths={"X-Dynosaur": 504, "msToken": len(auth.ms_token),
                              "X-Bogus": 1, "X-Gnarly": 332},
        )

    @staticmethod
    def _comment_page_values(response: Mapping, *, endpoint: str):
        """Validate one captured comment page without inventing cursors.

        Both comment list endpoints return ``comments``, ``cursor`` and
        ``has_more``.  The high-level pagination helpers deliberately consume
        those response-owned values instead of deriving a cursor from item
        counts or timestamps.
        """
        if not isinstance(response, Mapping):
            raise BrowserEvidenceError(f"{endpoint} 返回的不是 JSON 对象")
        comments = response.get("comments")
        if comments is None:
            comments = []
        if not isinstance(comments, list):
            raise BrowserEvidenceError(f"{endpoint} 的 comments 不是数组")
        has_more = response.get("has_more")
        if has_more not in (False, True, 0, 1):
            raise BrowserEvidenceError(f"{endpoint} 缺少可验证的 has_more")
        cursor = response.get("cursor")
        if bool(has_more) and (cursor is None or str(cursor) == ""):
            raise BrowserEvidenceError(f"{endpoint} 声明 has_more 但没有 cursor")
        return comments, cursor, bool(has_more)

    def get_all_comments(
        self, aweme_id: str, *, cursor: str = "0", count: str = "20",
        max_pages: int | None = None, auth=None, referer: str | None = None,
    ) -> dict:
        """Read every top-level work comment through the captured list API."""
        if max_pages is not None and int(max_pages) <= 0:
            raise ValueError("max_pages 必须大于 0")
        current = str(cursor)
        seen = set()
        rows = []
        pages = 0
        while True:
            if current in seen:
                raise BrowserEvidenceError("comment/list 返回了重复 cursor")
            seen.add(current)
            response = self.get_comments(
                aweme_id, cursor=current, count=count, auth=auth,
                referer=referer,
            )
            comments, next_cursor, has_more = self._comment_page_values(
                response, endpoint="comment/list",
            )
            rows.extend(comments)
            pages += 1
            if not has_more or (max_pages is not None and pages >= int(max_pages)):
                return {
                    "comments": rows,
                    "page_count": pages,
                    "cursor": next_cursor,
                    "has_more": has_more,
                }
            current = str(next_cursor)

    def get_all_comment_replies(
        self, item_id: str, comment_id: str, *, cursor: str = "1",
        count: str = "3", max_pages: int | None = None, auth=None,
        referer: str, root_referer: str,
    ) -> dict:
        """Read every child reply while preserving the captured reply wire."""
        if max_pages is not None and int(max_pages) <= 0:
            raise ValueError("max_pages 必须大于 0")
        current = str(cursor)
        seen = set()
        rows = []
        pages = 0
        while True:
            if current in seen:
                raise BrowserEvidenceError("comment/list/reply 返回了重复 cursor")
            seen.add(current)
            response = self.get_comment_replies(
                item_id, comment_id, cursor=current, count=count, auth=auth,
                referer=referer, root_referer=root_referer,
            )
            comments, next_cursor, has_more = self._comment_page_values(
                response, endpoint="comment/list/reply",
            )
            rows.extend(comments)
            pages += 1
            if not has_more or (max_pages is not None and pages >= int(max_pages)):
                return {
                    "comments": rows,
                    "page_count": pages,
                    "cursor": next_cursor,
                    "has_more": has_more,
                }
            current = str(next_cursor)

    def post_comment(self, aweme_id: str, text: str, *, text_extra: str = "[]",
                     auth=None, referer: str | None = None,
                         query_referer: str | None = None):
        """Publish a top-level video comment using the captured wire contract.

        Chrome sends an empty ``application/x-www-form-urlencoded`` body and
        places both ``text`` and ``text_extra`` in the signed query.  The
        write also requires fresh ticket-guard storage plus the two CSRF
        headers; callers without those browser values fail before any request
        leaves Python.
        """
        if not aweme_id:
            raise ValueError("comment/publish 需要 aweme_id")
        if text is None or text == "":
            raise ValueError("comment/publish 需要非空 text")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok/video/{aweme_id}?lang=zh-Hans"
        query_referer = query_referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=query_referer, from_page="video", history_len="3",
            slots={
                "after_app_name": [("aweme_id", aweme_id)],
                "after_screen": [("text", text), ("text_extra", text_extra)],
            },
        )
        return self._request_json(
            auth, method="POST", path="/api/comment/publish/", params=p,
            referer=referer, origin=self.origin, body="", form=True,
            ticket_guard=True,
        )

    def post_comment_reply(self, aweme_id: str, reply_id: str, text: str, *,
                           reply_to_reply_id: str = "0", text_extra: str = "[]",
                           auth=None, referer: str | None = None,
                           query_referer: str | None = None):
        """Publish a reply to an existing comment using the live wire order.

        The browser uses the same empty form body as a top-level comment, but
        inserts ``reply_id`` and ``reply_to_reply_id`` between ``region`` and
        ``root_referer``.  Keeping those pairs in the ordered query is
        important because they are covered by both current signatures.
        """
        if not aweme_id:
            raise ValueError("comment/publish reply 需要 aweme_id")
        if not reply_id:
            raise ValueError("comment/publish reply 需要 reply_id")
        if text is None or text == "":
            raise ValueError("comment/publish reply 需要非空 text")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok/video/{aweme_id}?lang=zh-Hans"
        query_referer = query_referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=query_referer, from_page="video", history_len="3",
            slots={
                "after_app_name": [("aweme_id", aweme_id)],
                "after_region": [
                    ("reply_id", reply_id),
                    ("reply_to_reply_id", reply_to_reply_id),
                ],
                "after_screen": [("text", text), ("text_extra", text_extra)],
            },
        )
        return self._request_json(
            auth, method="POST", path="/api/comment/publish/", params=p,
            referer=referer, origin=self.origin, body="", form=True,
            ticket_guard=True,
        )

    def post_item_digg(self, aweme_id: str, *, digg_type: str = "1",
                       auth=None, referer: str | None = None,
                       query_referer: str | None = None):
        """Like/unlike a video with the captured ``commit/item/digg`` wire."""
        if not aweme_id:
            raise ValueError("item/digg 需要 aweme_id")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok/video/{aweme_id}?lang=zh-Hans"
        query_referer = query_referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=query_referer, from_page="video", history_len="3",
            slots={"after_app_name": [("aweme_id", aweme_id)],
                   "after_screen": [("type", digg_type)]},
        )
        return self._request_json(
            auth, method="POST", path="/api/commit/item/digg/", params=p,
            referer=referer, origin=self.origin, body="", form=True,
            ticket_guard=True, ticket_guard_sec_csrf=False,
        )

    def post_item_collect(self, item_id: str, sec_uid: str, *, action: str = "1",
                          auth=None, referer: str | None = None,
                          query_referer: str | None = None):
        """Add/remove a video from Favorites using the captured wire contract."""
        if not item_id:
            raise ValueError("item/collect 需要 item_id")
        if not sec_uid:
            raise ValueError("item/collect 需要 sec_uid")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok/video/{item_id}?lang=zh-Hans"
        query_referer = query_referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=query_referer, from_page="video", history_len="3",
            slots={
                "before_aid": [("action", action)],
                "after_is_page_visible": [("itemId", item_id)],
                "after_screen": [("secUid", sec_uid)],
            },
        )
        return self._request_json(
            auth, method="POST", path="/api/item/collect/", params=p,
            referer=referer, origin=self.origin, body="", form=True,
            ticket_guard=True, ticket_guard_sec_csrf=False,
        )

    def post_follow_user(self, user_id: str, sec_user_id: str, *,
                         action_type: str = "1", follow_type: str = "1",
                         from_code: str = "18", channel_id: str = "0",
                         from_web: str = "1", from_pre: str = "0",
                         auth=None, referer: str | None = None,
                         query_referer: str | None = None):
        """Follow/unfollow a user using the captured video-page request."""
        if not user_id:
            raise ValueError("follow/user 需要 user_id")
        if not sec_user_id:
            raise ValueError("follow/user 需要 sec_user_id")
        auth = self._auth(auth)
        if not referer or not query_referer:
            raise ValueError("follow/user 必须传入当前浏览器 referer 和 query_referer")
        p = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=query_referer, from_page="video", history_len="3",
            slots={
                "before_aid": [("action_type", action_type)],
                "after_channel": [("channel_id", channel_id)],
                "after_focus": [("from", from_code), ("fromWeb", from_web)],
                "after_from_page": [("from_pre", from_pre)],
                "after_screen": [("sec_user_id", sec_user_id),
                                  ("type", follow_type)],
                "after_tz": [("user_id", user_id)],
            },
        )
        return self._request_json(
            auth, method="POST", path="/api/commit/follow/user/", params=p,
            referer=referer, origin=self.origin, body="", form=True,
            ticket_guard=True,
        )

    def get_related_items(self, item_id: str, *, cursor: str = "0",
                          count: str = "16", category_type: str = "101",
                          cover_format: str = "2", launch_mode: str = "direct",
                          video_encoding: str = "dash", auth=None,
                          referer: str | None = None,
                          query_referer: str | None = None):
        """Fetch the video-page related-item list from a captured request.

        This endpoint has a different current query layout from the generic
        ``_current_params`` helper: ``CategoryType`` is the first pair and the
        ``language`` field sits after ``itemID``.  The browser currently may
        answer with a bdturing challenge, but the Python request is still
        built with every observed field and exact pair order.
        """
        if not item_id:
            raise ValueError("related/item_list 需要 item_id")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok/video/{item_id}?lang=zh-Hans"
        if query_referer is None:
            match = re.match(r"^(https?://[^/]+/@[^/?]+)", referer)
            query_referer = f"{match.group(1)}?lang=zh-Hans" if match else referer
        pairs = [
            ("CategoryType", category_type),
            ("WebIdLastTime", auth.web_id_last_time),
            ("aid", "1988"),
            ("app_language", "zh-Hans"),
            ("app_name", "tiktok_web"),
            ("browser_language", "zh-CN"),
            ("browser_name", "Mozilla"),
            ("browser_online", "true"),
            ("browser_platform", "Win32"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("channel", "tiktok_web"),
            ("clientABVersions", auth.client_ab_versions),
            ("cookie_enabled", "true"),
            ("count", count),
            ("coverFormat", cover_format),
            ("cursor", cursor),
            ("data_collection_enabled", "true"),
            ("device_id", auth.device_id),
            ("device_platform", "web_pc"),
            ("focus_state", "true"),
            ("from_page", "video"),
            ("history_len", "3"),
            ("isNonPersonalized", "false"),
            ("is_fullscreen", "false"),
            ("is_page_visible", "true"),
            ("itemID", item_id),
            ("language", "zh-Hans"),
            ("launch_mode", launch_mode),
            ("odinId", auth.odin_id),
            ("os", "windows"),
            ("priority_region", auth.priority_region),
            ("referer", referer),
            ("region", auth.region),
            ("root_referer", query_referer),
            ("screen_height", "1440"),
            ("screen_width", "2560"),
            ("tz_name", "Asia/Shanghai"),
            ("user_is_login", "true" if auth.logged_in else "false"),
            ("verifyFp", auth.verify_fp),
            ("video_encoding", video_encoding),
            ("webcast_language", "zh-Hans"),
        ]
        return self._request_json(
            auth, method="GET", path="/api/related/item_list/",
            params=Params(pairs), referer=referer,
        )

    def get_recent_mention_contacts(self, sec_uid: str, *, mention_type: str = "3",
                                    auth=None, referer: str | None = None):
        """Read recent @-mention contacts from the video composer."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, from_page="video", history_len="3",
            slots={
                "after_is_page_visible": [("mentionType", mention_type)],
                "after_screen": [("secUid", sec_uid)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/mention/recent/contact/list/v1/",
            params=p, referer=referer,
        )

    def get_default_at_list(self, *, cursor: str = "0", count: str = "25",
                            auth=None, referer: str | None = None):
        """Read the default @-mention list used by the comment composer."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer, from_page="video", history_len="3",
            slots={
                "after_cookie": [("count", count), ("cursor", cursor)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/at/default/list/",
            params=p, referer=referer,
        )

    def post_recharge_check_external_entry(
        self, profile_url: str, *, auth=None, page_source: str = "0",
        is_experiment_group: str = "false", referer: str = f"{origin}/",
        expected_signature_lengths: Mapping[str, int] | None = None,
    ):
        """Check the captured live-wallet external-entry eligibility.

        This is a cross-subdomain form POST emitted while a profile is open;
        Chrome sends an empty body, while the profile URL is repeated in both
        query referer fields.  ``profile_url`` is required so callers cannot
        silently send a guessed page context.
        """
        if not profile_url:
            raise BrowserEvidenceError(
                "recharge/check_external_entry 需要当前浏览器 profile_url"
            )
        auth = self._auth(auth)
        lengths = (dict(expected_signature_lengths)
                   if expected_signature_lengths is not None else {
                       "X-Dynosaur": 420, "msToken": len(auth.ms_token),
                       "X-Bogus": 1, "X-Gnarly": 332,
                   })
        p = self._current_params(
            auth, referer=profile_url, query_referer=profile_url,
            root_referer=profile_url, from_page="user", history_len="2",
            include_odin_id=True, include_user_is_login=True,
            slots={
                "after_history": [("is_experiment_group", is_experiment_group)],
                "after_os": [("page_source", page_source)],
            },
        )
        return self._request_json(
            auth, method="POST",
            path="/webcast/wallet_api_tiktok/recharge/check_external_entry",
            params=p, referer=referer, origin=self.origin, body="", form=True,
            content_type_before_mobile=True, expected_lengths=lengths,
        )

    def post_popup_callback(
        self, *, business: str, policy_version: str, style: str,
        extra: Mapping[str, object], operation: int | str = 100,
        auth=None, referer: str | None = None,
    ):
        """Acknowledge the currently displayed policy popup.

        This is the exact unsigned form POST observed on the logged-in
        messages page.  The nested ``extra`` object is rebuilt in Chrome's
        insertion order rather than serialized from an arbitrary mapping, so
        an omitted or additional field cannot silently change the body.
        """
        if not business or not policy_version or not style:
            raise ValueError("popup/callback 需要 business、policy_version、style")
        if not isinstance(extra, Mapping):
            raise ValueError("popup/callback extra 必须是对象")
        required = ("operation", "approve_type", "re_popup_cycle_days",
                    "user_id", "device_id")
        missing = [key for key in required if key not in extra]
        unknown = [key for key in extra if key not in required]
        if missing or unknown:
            detail = []
            if missing:
                detail.append("缺少 " + ", ".join(missing))
            if unknown:
                detail.append("多余 " + ", ".join(map(str, unknown)))
            raise BrowserEvidenceError("popup/callback extra 字段不完整（" + "；".join(detail) + "）")
        if str(extra["operation"]) != str(operation):
            raise BrowserEvidenceError("popup/callback body 与 extra.operation 不一致")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/messages?lang=zh-Hans"
        body_obj = OrderedDict((
            ("business", str(business)),
            ("policy_version", str(policy_version)),
            ("style", str(style)),
            ("extra", json.dumps(OrderedDict((
                ("operation", extra["operation"]),
                ("approve_type", extra["approve_type"]),
                ("re_popup_cycle_days", extra["re_popup_cycle_days"]),
                ("user_id", extra["user_id"]),
                ("device_id", extra["device_id"]),
            )), ensure_ascii=False, separators=(",", ":"))),
            ("operation", str(operation)),
        ))
        body = urlencode(body_obj)
        params = Params((
            ("region", auth.region),
            ("priority_region", auth.priority_region),
            ("aid", "1988"),
            ("device_id", auth.device_id),
            ("app_language", "zh-Hans"),
            ("device_platform", "web_pc"),
            ("WebIdLastTime", auth.web_id_last_time),
        ))
        return self._request_json(
            auth, method="POST", path="/tiktok/popup/callback/v1",
            params=params, referer=referer, origin=self.origin, body=body,
            form=True, signed=False, accept="application/json, text/plain, */*",
            content_type_before_mobile=True,
        )

    def post_csp_pa_prompt(
        self, *, history_len: str, query_referer: str, root_referer: str,
        auth=None, referer: str | None = None,
    ):
        """Send the unsigned privacy-assistant prompt probe from Chrome."""
        if history_len in (None, "") or not query_referer or not root_referer:
            raise BrowserEvidenceError(
                "csp/pa_prompt 需要浏览器 history_len、query_referer、root_referer"
            )
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/"
        params = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=root_referer, from_page="fyp",
            history_len=str(history_len), include_odin_id=True,
            include_user_is_login=True,
        )
        return self._request_json(
            auth, method="POST", path="/tiktok/v1/csp/pa_prompt",
            params=params, referer=referer, origin=self.origin, body="", form=True,
            signed=False, content_type_before_mobile=True,
        )

    def get_music_dsp_platform_list(
        self, *, history_len: str, query_referer: str, root_referer: str,
        auth=None, referer: str | None = None,
    ):
        """Read the unsigned TikTok-to-DSP music platform list."""
        if history_len in (None, "") or not query_referer or not root_referer:
            raise BrowserEvidenceError(
                "music/platform/list 需要浏览器 history_len、query_referer、root_referer"
            )
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/"
        params = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=root_referer, from_page="fyp",
            history_len=str(history_len), include_odin_id=True,
            include_user_is_login=True,
        )
        return self._request_json(
            auth, method="GET",
            path="/tiktok/music/tt_to_dsp/platform/list/v1",
            params=params, referer=referer, signed=False,
        )

    def get_user_detail(
        self, unique_id: str, *, sec_uid: str = "",
        user: str = "[object Object]",
        ab_test_version: str = "[object Object]", app_type: str = "t",
        need_audience_control: str = "true", language: str = "zh-Hans",
        history_len: str, query_referer: str, root_referer: str,
        auth=None, referer: str | None = None,
        expected_signature_lengths: Mapping[str, int] | None = None,
    ):
        """Fetch ``/api/user/detail/`` with the profile page's signed slots."""
        if not unique_id:
            raise ValueError("user/detail 需要 unique_id")
        if history_len in (None, "") or not query_referer or not root_referer:
            raise BrowserEvidenceError(
                "user/detail 需要浏览器 history_len、query_referer、root_referer"
            )
        auth = self._auth(auth)
        if not referer:
            raise BrowserEvidenceError(
                "user/detail 需要当前浏览器 profile 页面 referer"
            )
        lengths = (dict(expected_signature_lengths)
                   if expected_signature_lengths is not None else {
                       "X-Dynosaur": 476, "msToken": len(auth.ms_token),
                       "X-Bogus": 1, "X-Gnarly": 332,
                   })
        params = self._current_params(
            auth, referer=referer, query_referer=query_referer,
            root_referer=root_referer, from_page="user",
            history_len=str(history_len), include_odin_id=True,
            include_user_is_login=True,
            slots={
                "before_aid": [("abTestVersion", ab_test_version)],
                "after_aid": [("appType", app_type)],
                "after_is_page_visible": [
                    ("language", language),
                    ("needAudienceControl", need_audience_control),
                ],
                "after_screen": [("secUid", sec_uid)],
                "after_tz": [("uniqueId", unique_id), ("user", user)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api/user/detail/", params=params,
            referer=referer, expected_lengths=lengths,
        )

    def get_webcast_feed(self, *, auth=None, referer: str = f"{origin}/live"):
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="2",
            slots={
                "after_channel": [("channel_id", "42"), ("content_type", "1")],
                "after_cookie": [("cpu_number", "20")],
                "after_device_platform": [("device_type", "web_h264")],
                "after_fullscreen": [("is_non_personalized", "0")],
                "after_is_page_visible": [("max_time", "0")],
                "after_region": [("req_from", "pc_web_side_follow_default")],
            },
        )
        return self._request_json(auth, method="GET", path="/webcast/feed/",
                                  params=p, referer=referer)

    @staticmethod
    def _live_signature_lengths(auth: TiktokAuth) -> dict[str, int]:
        """Lengths observed on the current Chrome live-room read family.

        These are validation gates, not padding values.  A signer result with
        a different width is rejected before the request is sent.
        """
        return {
            "X-Dynosaur": 476,
            "msToken": len(auth.ms_token),
            "X-Bogus": 1,
            "X-Gnarly": 332,
        }

    def get_live_user_room(self, unique_id: str, *, source_type: str = "54",
                           stale_time: str = "600000", auth=None,
                           referer: str | None = None):
        """Read the signed ``/api-live/user/room`` room/user payload.

        This is the JSON endpoint emitted after opening a creator's live URL;
        it is distinct from the SSR tuple returned by ``get_live_room_info``.
        ``unique_id``, ``sourceType`` and ``staleTime`` are explicit browser
        fields and are never inferred from a guessed room id.
        """
        if not unique_id:
            raise ValueError("api-live/user/room 需要浏览器 uniqueId")
        if source_type in (None, "") or stale_time in (None, ""):
            raise BrowserEvidenceError(
                "api-live/user/room 需要浏览器 sourceType/staleTime"
            )
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@{unique_id}/live"
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="4", include_odin_id=False,
            slots={
                "after_screen": [
                    ("sourceType", str(source_type)),
                    ("staleTime", str(stale_time)),
                ],
                "after_tz": [("uniqueId", str(unique_id))],
            },
        )
        return self._request_json(
            auth, method="GET", path="/api-live/user/room", params=params,
            referer=referer, expected_lengths=self._live_signature_lengths(auth),
        )

    def get_webcast_room_create_info(self, *, auth=None,
                                     referer: str = f"{origin}/live",
                                     history_len: str = "2",
                                     expected_signature_lengths: Mapping[str, int] | None = None):
        """Read the Creator Studio/live ``room/create_info`` contract.

        Chrome sends this as a signed cross-subdomain GET with no body.  The
        endpoint is easy to confuse with ``room/enter``; keeping it separate
        prevents callers from silently dropping the live-page context or
        routing it to ``www.tiktok.com``.  The defaults are the lengths from
        the current Chrome capture; callers with a freshly captured browser
        branch may override them explicitly, but never pad or truncate a
        generated value.
        """
        auth = self._auth(auth)
        lengths = (dict(expected_signature_lengths)
                   if expected_signature_lengths is not None else {
                       "X-Dynosaur": 468,
                       "msToken": len(auth.ms_token),
                       "X-Bogus": 1,
                       "X-Gnarly": 332,
                   })
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len=str(history_len),
        )
        return self._request_json(
            auth, method="GET", path="/webcast/room/create_info/", params=p,
            referer=referer, origin=self.webcast_origin,
            expected_lengths=lengths,
        )

    def get_webcast_push_fetch(self, *, scene: str = "live_ongoing_push",
                               auth=None, referer: str | None = None):
        """Poll the live push stream with the exact current query order."""
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        p = self._current_params(
            auth, referer=referer,
            slots={"after_root_referer": [("scene", scene)]},
        )
        return self._request_json(
            auth, method="GET", path="/webcast/room/push_fetch/",
            params=p, referer=referer, origin=self.origin,
        )

    def post_screen_time_upload(self, *, upload_timestamp: int,
                                time_usage, upload_type: int = 3,
                                dual_channel_enabled: bool = True,
                                auth=None, referer: str | None = None):
        """Send the captured screen-time telemetry JSON contract.

        This endpoint is deliberately unsigned in Chrome.  The body and the
        duplicate query fields are kept explicit so callers cannot silently
        omit a field or substitute a form encoding.
        """
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        body_obj = {
            "upload_timestamp": int(upload_timestamp),
            "upload_type": int(upload_type),
            "time_usage": time_usage,
            "dual_channel_enabled": bool(dual_channel_enabled),
        }
        body = json.dumps(body_obj, ensure_ascii=False, separators=(",", ":"))
        usage_query = json.dumps(time_usage, ensure_ascii=False, separators=(",", ":"))
        p = self._current_params(
            auth, referer=referer,
            slots={
                "after_device_platform": [("dual_channel_enabled", str(bool(dual_channel_enabled)).lower())],
                "after_screen": [("time_usage", usage_query)],
                "after_tz": [("upload_timestamp", str(int(upload_timestamp))),
                              ("upload_type", str(int(upload_type)))],
            },
        )
        return self._request_json(
            auth, method="POST", path="/tiktok/v1/screen_time/upload/",
            params=p, referer=referer, origin=self.origin, body=body,
            signed=False,
        )

    def get_screen_time_list(self, *, date: str, count: str = "1",
                             auth=None, referer: str | None = None):
        """Read daily screen-time data with the captured unsigned query."""
        if not str(date):
            raise ValueError("screen_time/list 需要 date")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/"
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="fyp", history_len="2",
            slots={"after_cookie": [("count", count), ("date", str(date))]},
        )
        return self._request_json(
            auth, method="GET", path="/tiktok/v1/screen_time/list/",
            params=p, referer=referer, signed=False,
        )

    def post_app_open_times_upload(self, *, upload_timestamp: int,
                                   upload_type: int,
                                   app_open_times, auth=None,
                                   referer: str | None = None,
                                   root_referer: str | None = None):
        """Upload the messages-page app-open telemetry contract.

        Chrome sends this POST without WebMssdk signatures.  The same
        ``app_open_times`` object is present twice: the query deliberately
        serializes it through the browser's ``[object Object]`` coercion,
        while the JSON body contains the compact, ordered telemetry object.
        Every body entry must carry all three browser fields; no defaults or
        padding are introduced.
        """
        if not isinstance(upload_timestamp, int) or upload_timestamp <= 0:
            raise ValueError("upload_timestamp 必须是正整数")
        if not isinstance(upload_type, int) or upload_type < 0:
            raise ValueError("upload_type 必须是非负整数")
        if isinstance(app_open_times, Mapping):
            entries = [app_open_times]
        else:
            try:
                entries = list(app_open_times)
            except TypeError as exc:
                raise ValueError("app_open_times 必须是对象或对象序列") from exc
        if not entries:
            raise ValueError("app_open_times 不能为空")
        normalized = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ValueError("app_open_times 每项必须是对象")
            missing = [key for key in ("upload_date", "day_open_times",
                                       "night_open_times") if key not in entry]
            if missing:
                raise ValueError("app_open_times 缺少字段: " + ", ".join(missing))
            normalized.append(OrderedDict((key, entry[key]) for key in (
                "upload_date", "day_open_times", "night_open_times")))
        body_obj = OrderedDict((
            ("upload_timestamp", upload_timestamp),
            ("upload_type", upload_type),
            ("app_open_times", normalized),
        ))
        body = json.dumps(body_obj, ensure_ascii=False, separators=(",", ":"))
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/messages?lang=zh-Hans"
        root = root_referer or f"{self.origin}/@tiktok?lang=zh-Hans"
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer=root,
            from_page="message", history_len="4",
            slots={
                "after_app_name": [("app_open_times", "[object Object]")],
                "after_tz": [
                    ("upload_timestamp", str(upload_timestamp)),
                    ("upload_type", str(upload_type)),
                ],
            },
        )
        return self._request_json(
            auth, method="POST", path="/tiktok/v1/app_open_times/upload/",
            params=params, referer=referer, body=body, signed=False,
            origin=self.origin, content_type_before_mobile=True,
        )

    def enter_live_room(self, room_id: str, *, auth=None,
                        enter_source: str = "recommend-suggested_others_photo",
                        referer: str = f"{origin}/live"):
        """`POST /webcast/room/enter/` with the captured form body."""
        auth = self._auth(auth)
        params = Params().common(
            auth, referer=referer, query_referer="", root_referer="", history_len="4",
            include_from_page=True, from_page="", include_user_is_login=True,
            include_language=False, after_device_platform={"device_type": "web_h265"},
        )
        body = f"enter_source={enter_source}&room_id={room_id}"
        return self._request_json(
            auth, method="POST", path="/webcast/room/enter/", params=params,
            referer=referer, body=body, form=True,
        )

    def check_live_rooms(self, room_ids, *, auth=None,
                         referer: str = f"{origin}/live"):
        if isinstance(room_ids, (list, tuple, set)):
            room_ids = ",".join(str(item) for item in room_ids)
        auth = self._auth(auth)
        params = Params().common(
            auth, referer=referer, query_referer="", root_referer="", history_len="2",
            include_from_page=True, from_page="", include_user_is_login=True,
            include_language=False, after_region={"room_ids": str(room_ids)},
        )
        return self._request_json(auth, method="GET", path="/webcast/room/check_alive/",
                                  params=params, referer=referer)

    def get_webcast_drawer_tabs(self, *, auth=None, referer: str = f"{origin}/live",
                                scene: str = "1"):
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="2",
            slots={"after_root_referer": [("scene", scene)]},
        )
        return self._request_json(
            auth, method="GET", path="/webcast/feed/drawer_tabs/", params=p,
            referer=referer, origin=self.origin,
        )

    def get_live_podcast(self, *, auth=None, referer: str = f"{origin}/live"):
        return self._get_live_read(auth, "/webcast/room/live_podcast/", referer)

    def get_live_game_feed(self, *, auth=None, referer: str = f"{origin}/live"):
        return self._get_live_read(auth, "/webcast/game_feed/api/feed_card/strategy/", referer)

    def get_live_game_feed_component(self, *, auth=None,
                                     referer: str = f"{origin}/live"):
        """Read the room-page game component strategy request.

        Chrome currently emits this path in addition to the older
        ``feed_card/strategy`` path.  Keeping both routes separate preserves
        the captured URL instead of silently substituting one for the other.
        """
        return self._get_live_read(
            auth, "/webcast/game_feed/api/feed_component/strategy/", referer
        )

    def get_live_setting(self, *, auth=None, referer: str = f"{origin}/live"):
        """Read the signed room settings payload emitted on live entry."""
        return self._get_live_read(auth, "/webcast/setting/", referer)

    def get_live_gift_list(self, room_id: str, *, auth=None,
                           referer: str = f"{origin}/live"):
        """Read the signed gift catalog for the current room."""
        if not room_id:
            raise ValueError("gift/list 需要浏览器 room_id")
        auth = self._auth(auth)
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="4", include_odin_id=False,
            slots={"after_region": [("room_id", str(room_id))]},
        )
        return self._request_json(
            auth, method="GET", path="/webcast/gift/list/", params=params,
            referer=referer, expected_lengths=self._live_signature_lengths(auth),
        )

    def get_live_gift_cpc_prompt(self, *, auth=None,
                                 referer: str = f"{origin}/live"):
        """Read the signed gift/CPC prompt flags emitted by a live room."""
        return self._get_live_read(auth, "/webcast/gift/cpc_prompt/", referer)

    def get_live_quick_chat_list(self, room_id: str, *, scenes_list: str = "12",
                                 auth=None, referer: str = f"{origin}/live"):
        """Read the room quick-chat list with captured field placement."""
        if not room_id:
            raise ValueError("quick_chat_list 需要浏览器 room_id")
        if scenes_list in (None, ""):
            raise BrowserEvidenceError(
                "quick_chat_list 需要浏览器 scenes_list"
            )
        auth = self._auth(auth)
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="4", include_odin_id=False,
            slots={
                "after_region": [("room_id", str(room_id))],
                "after_root_referer": [("scenes_list", str(scenes_list))],
            },
        )
        return self._request_json(
            auth, method="GET", path="/webcast/room/quick_chat_list/",
            params=params, referer=referer,
            expected_lengths=self._live_signature_lengths(auth),
        )

    def post_live_effect_assets(self, effect_ids, *, download_assets_from: int = 3,
                                video_types: str = "h264_encrypt", auth=None,
                                referer: str = f"{origin}/live"):
        """Download the explicitly captured live-effect asset batch.

        Effects are auxiliary live-page resources, not a replacement for the
        TikTok work/media APIs.  The caller must provide the exact browser
        effect-id list; this method never invents or truncates it.
        """
        if isinstance(effect_ids, (str, bytes)):
            ids = str(effect_ids)
        else:
            try:
                values = [str(value) for value in effect_ids]
            except TypeError as exc:
                raise ValueError("effects 需要浏览器 effect_ids 序列") from exc
            if not values:
                raise ValueError("effects 需要非空 effect_ids")
            ids = ",".join(values)
        if not ids or video_types in (None, ""):
            raise BrowserEvidenceError(
                "effects 需要浏览器 effect_ids/video_types"
            )
        auth = self._auth(auth)
        body = urlencode(OrderedDict((
            ("download_assets_from", str(download_assets_from)),
            ("effect_ids", ids),
            ("video_types", str(video_types)),
        )))
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="4", include_odin_id=False,
        )
        return self._request_json(
            auth, method="POST", path="/webcast/assets/effects/",
            params=params, referer=referer, origin=self.webcast_origin,
            body=body, form=True,
            expected_lengths=self._live_signature_lengths(auth),
        )

    def get_event_feed(self, *, auth=None, referer: str = f"{origin}/live",
                       count: str = "5", query_type: str = "3"):
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="2",
            slots={
                "after_cookie": [("count", count)],
                "after_priority_region": [("query_type", query_type)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/tiktok/event/feed/v1", params=p,
            referer=referer, origin=self.origin,
        )

    def get_event_recommendations(self, *, auth=None, referer: str = f"{origin}/live",
                                  count: str = "4"):
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="2",
            slots={"after_cookie": [("count", count)]},
        )
        return self._request_json(
            auth, method="GET", path="/tiktok/event/recommend/v1", params=p,
            referer=referer, origin=self.origin,
        )

    def get_event_list(self, *, user_id: str, host_user_id: str,
                       count: str = "5", offset: str = "0",
                       query_event_list_scene: str = "3", query_type: str = "2",
                       auth=None, referer: str = f"{origin}/live"):
        """Read the live-event list captured after entering a room."""
        if not user_id or not host_user_id:
            raise ValueError("event/list 需要浏览器 user_id 和 host_user_id")
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="4",
            slots={
                "after_cookie": [("count", count)],
                "after_history": [("host_user_id", host_user_id)],
                "after_is_page_visible": [("offset", offset)],
                "after_priority_region": [
                    ("query_event_list_scene", query_event_list_scene),
                    ("query_type", query_type),
                ],
                "after_tz": [("user_id", user_id)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/tiktok/event/list/v1", params=p,
            referer=referer, origin=self.origin,
        )

    def get_in_room_banner(self, room_id: str, *, auth=None,
                           referer: str = f"{origin}/live",
                           live_ad_type: str = "0",
                           version_code: str = "430900"):
        """Read the room banner request with its captured mobile platform fields."""
        if not room_id:
            raise ValueError("in_room_banner 需要 room_id")
        auth = self._auth(auth)
        p = self._current_params(
            auth, aid="1180", device_platform="android", referer=referer,
            query_referer="", root_referer="", from_page="", history_len="4",
            slots={
                "after_is_page_visible": [("live_ad_type", live_ad_type)],
                "after_region": [("room_id", room_id)],
                "after_tz": [("version_code", version_code)],
            },
        )
        return self._request_json(
            auth, method="GET", path="/webcast/room/in_room_banner/",
            params=p, referer=referer, origin=self.origin,
        )

    def get_webcast_user_attr(self, *, attr_types: str = "6", auth=None,
                              referer: str = f"{origin}/live"):
        """Read the live user attribute flags emitted by the room page."""
        auth = self._auth(auth)
        p = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="4",
            slots={"after_app_name": [("attr_types", attr_types)]},
        )
        return self._request_json(
            auth, method="GET", path="/webcast/user/attr/", params=p,
            referer=referer, origin=self.origin,
        )

    def get_webcast_im_fetch(self, live_id: str, room_id: str, *, auth=None,
                             history_comment_count: str = "6",
                             cursor: str = "0",
                             referer: str = f"{origin}/live") -> bytes:
        """Fetch the live protobuf stream using the captured duplicate query.

        Chrome sends two ``version_code`` pairs in this request.  ``Params``
        keeps both pairs so the signed URL is not silently normalized.
        """
        if not live_id or not room_id:
            raise ValueError("webcast/im/fetch 需要 live_id 和 room_id")
        auth = self._auth(auth)
        pairs = [
            ("version_code", "180800"),
            ("device_platform", "web"),
            ("cookie_enabled", "true"),
            ("screen_width", "2560"),
            ("screen_height", "1440"),
            ("browser_language", "zh-CN"),
            ("browser_platform", "Win32"),
            ("browser_name", "Mozilla"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("browser_online", "true"),
            ("tz_name", "Asia/Shanghai"),
            ("ws_direct", "1"),
            ("aid", "1988"),
            ("app_name", "tiktok_web"),
            ("live_id", live_id),
            ("version_code", "270000"),
            ("app_language", "zh-Hans"),
            ("client_enter", "1"),
            ("room_id", room_id),
            ("identity", "audience"),
            ("history_comment_count", history_comment_count),
            ("fetch_rule", "1"),
            ("last_rtt", "-1"),
            ("cursor", cursor),
            ("internal_ext", "0"),
            ("sup_ws_ds_opt", "1"),
            ("resp_content_type", "protobuf"),
            ("did_rule", "3"),
            ("webcast_language", "zh-Hans"),
        ]
        params = Params()
        for key, value in pairs:
            params.add_pair(key, value)
        response = self._request_response(
            auth, method="GET", path="/webcast/im/fetch/", params=params,
            referer=referer, origin=self.origin, accept="*/*",
        )
        response.raise_for_status()
        return response.content

    @staticmethod
    def decode_live_response(raw: bytes) -> dict:
        """Decode Chrome's protobuf live fetch into chat/like/gift events."""
        return live_wire.decode_response(raw)

    def receive_live_events(self, live_id: str, room_id: str, *, auth=None,
                            cursor: str = "0", referer: str | None = None) -> dict:
        """Receive one browser-shaped HTTP live protobuf batch."""
        page = referer or f"{self.origin}/live"
        raw = self.get_webcast_im_fetch(live_id, room_id, auth=auth,
                                        cursor=cursor, referer=page)
        return self.decode_live_response(raw)

    @staticmethod
    def _live_ws_url(auth: TiktokAuth, live_id: str, room_id: str,
                     marker: str) -> str:
        """Preserve the exact ordered/duplicate Chrome WS query contract."""
        if len(marker) != 16:
            raise BrowserEvidenceError("直播 WS X-Bogus 长度必须为 16")
        metrics = auth.browser_metrics
        required = ("screen_width", "screen_height", "browser_language",
                    "browser_platform", "tz_name")
        missing = [key for key in required if not metrics.get(key)]
        if missing:
            raise BrowserEvidenceError("直播 WS 缺少浏览器运行时字段: " + ", ".join(missing))
        pairs = [
            ("version_code", "180800"), ("device_platform", "web"),
            ("cookie_enabled", "true"), ("screen_width", metrics["screen_width"]),
            ("screen_height", metrics["screen_height"]),
            ("browser_language", metrics["browser_language"]),
            ("browser_platform", metrics["browser_platform"]),
            ("browser_name", "Mozilla"),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("browser_online", "true"), ("tz_name", metrics["tz_name"]),
            ("app_name", "tiktok_web"), ("sup_ws_ds_opt", "1"),
            ("update_version_code", "2.0.0"), ("compress", "gzip"),
            ("webcast_language", "zh-Hans"), ("ws_direct", "1"),
            ("aid", "1988"), ("live_id", live_id),
            ("version_code", "270000"), ("app_language", "zh-Hans"),
            ("client_enter", "1"), ("room_id", room_id),
            ("identity", "audience"), ("history_comment_count", "6"),
            ("last_rtt", "0"), ("heartbeat_duration", "10000"),
            ("resp_content_type", "protobuf"), ("did_rule", "3"),
            ("X-Bogus", marker),
        ]
        # The SDK concatenates a 752-byte raw URL, then WebSocket/WHATWG URL
        # normalization turns only its 11 spaces into %20. Chrome's actual
        # ws.url is 774 bytes; urlencode() reaches the same length by chance
        # but wrongly changes slashes, punctuation and spaces into +.
        raw_url = ("wss://webcast-ws.tiktok.com/webcast/im/ws_proxy/"
                   "ws_reuse_supplement/?"
                   + "&".join(f"{key}={value}" for key, value in pairs))
        return raw_url.replace(" ", "%20")

    def iter_live_ws_events(self, live_id: str, room_id: str, *, auth=None,
                            referer: str | None = None, stop_event=None,
                            include_history: bool = True):
        """Yield live chat, like and gift events from the captured WS protocol.

        HTTP fetch supplies the browser cursor, while the local WebMssdk
        calculates a fresh 16-character frontier marker. Incoming ACKs echo
        the server's own internal_ext instead of inventing JSON fields.
        """
        auth = self._auth(auth)
        auth.require_browser_profile()
        page = referer or f"{self.origin}/live"
        initial = self.receive_live_events(live_id, room_id, auth=auth,
                                           referer=page)
        if not initial["cursor"]:
            raise BrowserEvidenceError("直播初始 protobuf 缺少 WS cursor")
        marker = auth.signer.frontier_sign(
            cookie=auth.document_cookie or auth.cookie_str,
            user_agent=auth.user_agent, referer=page,
            metrics=auth.browser_metrics,
        )
        ws_url = self._live_ws_url(auth, live_id, room_id, marker)
        try:
            import websocket
            ws = websocket.create_connection(
                ws_url, timeout=2, origin=self.origin, cookie=auth.cookie_str,
                header=["User-Agent: " + auth.user_agent],
            )
        except Exception as exc:
            raise BrowserEvidenceError("直播 WS 连接失败") from exc
        seen = set()
        try:
            ws.send(live_wire.encode_heartbeat(int(room_id)),
                    opcode=websocket.ABNF.OPCODE_BINARY)
            ws.send(live_wire.encode_enter_room(int(room_id), int(live_id),
                                                initial["cursor"]),
                    opcode=websocket.ABNF.OPCODE_BINARY)
            if include_history:
                for event in initial["events"]:
                    seen.add((event["method"], event["message_id"]))
                    if event["type"] in ("chat", "like", "gift"):
                        yield event
            next_heartbeat = time.monotonic() + 10
            while stop_event is None or not stop_event.is_set():
                if time.monotonic() >= next_heartbeat:
                    ws.send(live_wire.encode_heartbeat(int(room_id)),
                            opcode=websocket.ABNF.OPCODE_BINARY)
                    next_heartbeat = time.monotonic() + 10
                try:
                    raw = ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                if not isinstance(raw, bytes):
                    continue
                frame = live_wire.decode_push_frame(raw)
                response = frame["response"]
                if response is None:
                    continue
                if response["need_ack"]:
                    ws.send(live_wire.encode_frame(
                        "ack", response["internal_ext"].encode("utf-8"),
                        log_id=frame["log_id"]),
                        opcode=websocket.ABNF.OPCODE_BINARY)
                for event in response["events"]:
                    key = (event["method"], event["message_id"])
                    if key in seen:
                        continue
                    seen.add(key)
                    if event["type"] in ("chat", "like", "gift"):
                        yield event
        finally:
            ws.close()

    def post_live_chat(self, room_id: str, content: str, *, auth=None,
                       emotes_with_index: str = "", input_type: int = 0,
                       client_start_timestamp_millisecond: int | None = None,
                       history_len: str = "6",
                       referer: str = f"{origin}/"):
        """Send one live-room chat message using the captured browser wire.

        Chrome sends the message in a JSON body while repeating the same
        values in the signed query (``room_id`` and ``content`` included).
        The ticket-guard and both CSRF headers are fresh browser state, so the
        method refuses to run when that state cannot be recomputed locally.
        """
        if not room_id:
            raise ValueError("room/chat 需要 room_id")
        if not isinstance(content, str) or not content:
            raise ValueError("room/chat 需要非空 content")
        if len(content) > 150:
            raise ValueError("room/chat content 不能超过浏览器 maxlength=150")
        auth = self._auth(auth)
        # The live page sends HTTP Referer `/`, but WebMssdk binds Dynosaur to
        # the actual document URL.  Do not silently sign against `/` when the
        # caller has not supplied that browser runtime input.
        page_metric = auth.browser_metrics.get("dynosaur_page") or auth.browser_metrics.get("page")
        if auth.strict_browser_alignment and not page_metric and urlparse(referer).path in ("", "/"):
            raise BrowserEvidenceError(
                "room/chat 需要当前浏览器文档 URL：请在 browser_metrics 传 dynosaur_page"
            )
        timestamp = int(client_start_timestamp_millisecond or (time.time() * 1000))
        # Keep JSON insertion order and compact separators exactly as Chrome's
        # fetch() body.  Reordering these keys changes X-Gnarly.
        body = json.dumps(OrderedDict((
            ("room_id", str(room_id)),
            ("content", content),
            ("emotes_with_index", str(emotes_with_index)),
            ("input_type", int(input_type)),
            ("client_start_timestamp_millisecond", timestamp),
        )), ensure_ascii=False, separators=(",", ":"))
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len=history_len,
            include_odin_id=False,
            slots={
                "after_channel": [
                    ("client_start_timestamp_millisecond", timestamp),
                    ("content", content),
                ],
                "after_device_platform": [("emotes_with_index", emotes_with_index)],
                "after_history": [("input_type", input_type)],
                "after_region": [("room_id", room_id)],
            },
        )
        return self._request_json(
            auth, method="POST", path="/webcast/room/chat/", params=params,
            referer=referer, origin=self.origin, body=body,
            extra_headers={"content-type": "application/json; charset=UTF-8"},
            ticket_guard=True, ticket_guard_sec_csrf=True,
            ticket_guard_tt_csrf_header=False,
            allow_empty=True,
        )

    def post_live_like(self, to_uid: str, room_id: str, *, count: int = 1,
                       enter_from: str = "live", auth=None,
                       referer: str = f"{origin}/"):
        """Send the captured live-room like request.

        Unlike chat, Chrome sends this JSON POST without ticket-guard or CSRF
        headers.  The body contains ``to_uid``, ``count``, ``room_id`` and
        ``enter_from`` in that exact order; the signed query is the common
        webcast context and deliberately omits ``odinId``.
        """
        if not to_uid or not room_id:
            raise ValueError("room/like 需要 to_uid 和 room_id")
        try:
            count_value = int(count)
        except (TypeError, ValueError) as exc:
            raise ValueError("room/like count 必须是正整数") from exc
        if count_value <= 0:
            raise ValueError("room/like count 必须是正整数")
        auth = self._auth(auth)
        page_metric = auth.browser_metrics.get("dynosaur_page") or auth.browser_metrics.get("page")
        if auth.strict_browser_alignment and not page_metric and urlparse(referer).path in ("", "/"):
            raise BrowserEvidenceError(
                "room/like 需要当前浏览器文档 URL：请在 browser_metrics 传 dynosaur_page"
            )
        body = json.dumps(OrderedDict((
            ("to_uid", str(to_uid)),
            ("count", count_value),
            ("room_id", str(room_id)),
            ("enter_from", str(enter_from)),
        )), ensure_ascii=False, separators=(",", ":"))
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            from_page="", history_len="6", include_odin_id=False,
        )
        return self._request_json(
            auth, method="POST", path="/webcast/room/like/", params=params,
            referer=referer, origin=self.origin, body=body,
            extra_headers={"content-type": "application/json; charset=UTF-8"},
            content_type_before_mobile=True,
            allow_empty=True,
        )

    def post_epiphron_feature_upload(
            self, room_id: str, owner_id: str, user_id: str,
            local_timeregi_stamp: str | int, *,
            webapp_watch_duration: str | int,
            durationc: str | int = "30000",
            history_len: str = "6", auth=None,
            referer: str | None = None,
            expected_signature_lengths: Mapping[str, int] | None = None):
        """Upload the live-page watch feature telemetry captured by Chrome.

        This is the real ``POST /webcast/epiphron/feature/upload/`` contract,
        not a generic analytics fallback.  Chrome signs the complete live-page
        query (without ``odinId``) and sends the two nested JSON objects in the
        exact insertion order below.  The timestamp and watch duration are
        required arguments because silently generating them would make the
        signed request differ from the browser capture.
        """
        if not room_id or not owner_id or not user_id:
            raise ValueError("epiphron/feature/upload 需要 room_id、owner_id、user_id")
        if local_timeregi_stamp in (None, ""):
            raise ValueError("epiphron/feature/upload 需要 local_timeregi_stamp")
        if webapp_watch_duration in (None, ""):
            raise ValueError("epiphron/feature/upload 需要 webapp_watch_duration")
        auth = self._auth(auth)
        referer = referer or f"{self.origin}/live"
        body = json.dumps(OrderedDict((
            ("base_info", OrderedDict((
                ("room_id", str(room_id)),
                ("owner_id", str(owner_id)),
                ("user_id", str(user_id)),
                ("local_timeregi_stamp", str(local_timeregi_stamp)),
                ("device_id", str(auth.device_id)),
                ("durationc", str(durationc)),
            ))),
            ("biz_params", OrderedDict((
                ("webapp_watch_duration", str(webapp_watch_duration)),
            ))),
        )), ensure_ascii=False, separators=(",", ":"))
        lengths = (dict(expected_signature_lengths)
                   if expected_signature_lengths is not None else {
                       "X-Dynosaur": 484,
                       "msToken": len(auth.ms_token),
                       "X-Bogus": 1,
                       "X-Gnarly": 332,
                   })
        params = self._current_params(
            auth, referer=referer, query_referer=referer,
            root_referer="", from_page="", history_len=str(history_len),
            include_odin_id=False,
        )
        return self._request_json(
            auth, method="POST", path="/webcast/epiphron/feature/upload/",
            params=params, referer=self.origin + "/", origin=self.origin,
            body=body, accept="*/*",
            extra_headers={"content-type": "application/json"},
            expected_lengths=lengths,
        )

    def _get_live_read(self, auth, path: str, referer: str, *, early=None,
                       before_tz=None, from_page: str = ""):
        auth = self._auth(auth)
        params = self._current_params(
            auth, referer=referer, query_referer="", root_referer="",
            history_len="2", from_page=from_page, include_from_page=True,
            include_user_is_login=True, include_odin_id=False,
            slots={
                "early": early or (),
                "before_tz": before_tz or (),
            },
        )
        return self._request_json(
            auth, method="GET", path=path, params=params, referer=referer,
            expected_lengths=self._live_signature_lengths(auth),
        )

    def get_webcast_user_info(self, target_uid: str, room_id: str, *, owner_user_id: str,
                              auth=None, current_room_id: str | None = None,
                              request_from: str = "profile_card_v2",
                              referer: str = f"{origin}/"):
        """`GET /webcast/user/` captured from a live-room profile card."""
        auth = self._auth(auth)
        current_room_id = str(current_room_id or room_id)
        p = Params().common(
            auth, referer=referer, query_referer="", root_referer="", history_len="2",
            include_from_page=True, from_page="", include_user_is_login=True,
            include_language=False,
            after_cookie={"current_room_id": current_room_id},
            after_os={"owner_user_id": owner_user_id},
            after_region={"request_from": request_from},
            before_tz={"target_uid": target_uid},
        )
        return self._request_json(auth, method="GET", path="/webcast/user/",
                                  params=p, referer=referer)

    def get_webcast_rank_list(self, anchor_id: str, room_id: str, *, auth=None,
                              source: str = "0", referer: str = f"{origin}/"):
        """`GET /webcast/ranklist/online_audience/` from a live room."""
        auth = self._auth(auth)
        p = Params().common(
            auth, referer=referer, query_referer="", root_referer="", history_len="2",
            include_from_page=True, from_page="", include_user_is_login=True,
            include_language=False,
            after_aid={"anchor_id": anchor_id},
            after_region={"room_id": room_id},
            after_root_referer={"source": source},
        )
        return self._request_json(
            auth, method="GET", path="/webcast/ranklist/online_audience/",
            params=p, referer=referer,
        )

    def get_user_html(self, user_url: str, *, auth=None) -> str:
        auth = self._auth(auth)
        response = http_client.get(
            user_url,
            headers=HeaderBuilder.build(HeaderType.DOC, auth, referer=user_url).get(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.text

    @staticmethod
    def _shop_product_detail_from_html(
        html: str, *, expected_product_id: str | None = None,
    ) -> dict:
        """Extract the complete Shop PDP component from its SSR payload.

        The current desktop Shop document embeds product/SKU, promotion,
        logistics, seller, rating and initial review data in
        ``__MODERN_ROUTER_DATA__``.  This is the browser's actual product
        detail source; it does not require replaying the later OEC BSID-signed
        recommendation request.
        """
        soup = BeautifulSoup(html, "html.parser")
        state = soup.find("script", attrs={"id": "__MODERN_ROUTER_DATA__"})
        state_text = state.string if state is not None else None
        if not state_text and state is not None:
            state_text = state.get_text()
        if not state_text:
            raise RuntimeError(
                "TikTok Shop 页面中没有 __MODERN_ROUTER_DATA__"
            )
        try:
            payload = json.loads(state_text)
            loader_data = payload["loaderData"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError("TikTok Shop SSR loaderData 无法解析") from exc
        if not isinstance(loader_data, Mapping):
            raise RuntimeError("TikTok Shop SSR loaderData 不是对象")
        component = None
        for route_data in loader_data.values():
            if not isinstance(route_data, Mapping):
                continue
            page_config = route_data.get("page_config")
            if not isinstance(page_config, Mapping):
                continue
            components = page_config.get("components_map")
            if not isinstance(components, list):
                continue
            component = next(
                (item for item in components
                 if isinstance(item, Mapping)
                 and item.get("component_name") == "product_info"),
                None,
            )
            if component is not None:
                break
        data = component.get("component_data") if component else None
        if not isinstance(data, Mapping):
            raise RuntimeError("TikTok Shop SSR 中没有 product_info.component_data")
        try:
            product_id = str(data["product_info"]["product_model"]["product_id"])
        except (KeyError, TypeError) as exc:
            raise RuntimeError("TikTok Shop 商品数据缺少 product_id") from exc
        if expected_product_id is not None and product_id != str(expected_product_id):
            raise RuntimeError(
                "TikTok Shop SSR product_id 与 URL 不一致："
                f"期望 {expected_product_id}，实际 {product_id}"
            )
        return dict(data)

    def get_shop_product_detail(self, product_url: str, *, auth=None) -> dict:
        """Read a TikTok Shop PDP using the exact captured document shape."""
        parsed = urlparse(str(product_url))
        if parsed.scheme != "https" or parsed.netloc != "shop.tiktok.com":
            raise BrowserEvidenceError("商品 URL 必须来自 https://shop.tiktok.com")
        match = re.search(r"/pdp/(?:[^/?]+/)?(\d+)(?:/)?$", parsed.path)
        if not match:
            raise BrowserEvidenceError("商品 URL 缺少 PDP product_id")
        auth = self._auth(auth)
        # Chrome 153 direct navigation (req 52): pseudo headers are generated
        # by HTTP/2; these are all normal headers in their captured order.
        headers = OrderedDict((
            ("upgrade-insecure-requests", "1"),
            ("user-agent", str(auth.user_agent)),
            ("sec-ch-ua", str(auth.sec_ch_ua)),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", str(auth.sec_ch_ua_platform)),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8,"
                       "application/signed-exchange;v=b3;q=0.7"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", str(auth.accept_language)),
            ("cookie", str(auth.cookie_str)),
            ("priority", "u=0, i"),
            ("sec-fetch-dest", "document"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-site", "none"),
            ("sec-fetch-user", "?1"),
        ))
        response = http_client.get(
            str(product_url), headers=headers, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        response.raise_for_status()
        return self._shop_product_detail_from_html(
            response.text, expected_product_id=match.group(1),
        )

    def get_shop_product_reviews(self, product_url: str, *, auth=None) -> dict:
        """Return the evidence-backed initial Shop review page from SSR."""
        detail = self.get_shop_product_detail(product_url, auth=auth)
        reviews = detail.get("review_info")
        if not isinstance(reviews, Mapping):
            raise RuntimeError("TikTok Shop 商品数据缺少 review_info")
        return dict(reviews)

    def get_shop_product_review_page(
        self, product_url: str, *, page_start: int = 2, page_size: int = 3,
        sort_rule: int = 1, filter_type: int = 1, filter_value: int = 6,
        component_name: str = "pdp_left_reviews", auth=None,
    ) -> dict:
        """Read one Shop review page with a freshly computed OEC BSID.

        The JSON key order, compact serialization, normal-header order and
        382-byte query signature follow the captured Chrome request.  The
        signer executes the immutable official unisec loader/core locally;
        no captured signature is accepted or replayed.
        """
        parsed = urlparse(str(product_url))
        if parsed.scheme != "https" or parsed.netloc != "shop.tiktok.com":
            raise BrowserEvidenceError("商品 URL 必须来自 https://shop.tiktok.com")
        match = re.search(r"/pdp/(?:[^/?]+/)?(\d+)(?:/)?$", parsed.path)
        if not match:
            raise BrowserEvidenceError("商品 URL 缺少 PDP product_id")
        if int(page_start) < 2:
            raise ValueError("page_start=1 来自 PDP SSR；翻页接口从 2 开始")
        if int(page_size) != 3:
            raise BrowserEvidenceError("Chrome 证据只支持 page_size=3")
        auth = self._auth(auth)
        body_map = OrderedDict((
            ("product_id", match.group(1)),
            ("page_start", int(page_start)),
            ("page_size", 3),
            ("sort_rule", int(sort_rule)),
            ("review_filter", OrderedDict((
                ("filter_type", int(filter_type)),
                ("filter_value", int(filter_value)),
            ))),
            ("component_name", str(component_name)),
        ))
        body = json.dumps(body_map, ensure_ascii=False, separators=(",", ":"))
        endpoint = "https://shop.tiktok.com/api/shop/pdp_desktop/get_product_reviews"
        sdk_headers = OrderedDict((
            ("accept", "application/json,*/*;q=0.8"),
            ("content-type", "application/json"),
        ))
        document_cookie = str(auth.document_cookie or auth.cookie_str)
        try:
            signed = self.shop_signer.sign(
                url=endpoint,
                method="POST",
                headers=sdk_headers,
                body=body,
                cookie=document_cookie,
                user_agent=str(auth.user_agent),
            )
        except ShopBSIDError as exc:
            raise BrowserEvidenceError(str(exc)) from exc
        signed_url = str(signed.get("signed_url") or "")
        signature = str(signed.get("bsid") or "")
        signed_parsed = urlparse(signed_url)
        query_match = re.fullmatch(
            r"msToken=([^&]+)&X-Bogus=([^&]+)&_signature=([^&]+)"
            r"&X-Tts-Oec-Bsid=([0-9a-f]{382})",
            signed_parsed.query,
        )
        if (signed_parsed.scheme != "https"
                or signed_parsed.netloc != "shop.tiktok.com"
                or signed_parsed.path != "/api/shop/pdp_desktop/get_product_reviews"
                or query_match is None
                or len(query_match.group(1)) not in ShopBSIDSigner.BROWSER_MS_TOKEN_LENGTHS
                or len(query_match.group(2)) != 28
                or len(query_match.group(3)) != 47
                or query_match.group(4) != signature
                or len(signature) != 382
                or not re.fullmatch(r"[0-9a-f]+", signature)):
            raise BrowserEvidenceError("Shop 四字段签名结果未通过 Chrome wire 校验")
        body_bytes = body.encode("utf-8")
        headers = OrderedDict((
            ("sec-ch-ua-platform", str(auth.sec_ch_ua_platform)),
            ("referer", str(product_url)),
            ("user-agent", str(auth.user_agent)),
            ("accept", "application/json,*/*;q=0.8"),
            ("sec-ch-ua", str(auth.sec_ch_ua)),
            ("content-type", "application/json"),
            ("sec-ch-ua-mobile", "?0"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", str(auth.accept_language)),
            ("content-length", str(len(body_bytes))),
            ("cookie", str(auth.cookie_str)),
            ("origin", "https://shop.tiktok.com"),
            ("priority", "u=1, i"),
            ("sec-fetch-dest", "empty"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-site", "same-origin"),
        ))
        response = http_client.post(
            signed_url, headers=headers, data=body_bytes, timeout=self.timeout,
        )
        auth.apply_set_cookie(response.headers)
        result = self._json_response(response)
        if result.get("code") != 0 or not isinstance(result.get("data"), Mapping):
            raise RuntimeError(
                "TikTok Shop 评价接口未返回 code=0 data："
                f"code={result.get('code')!r}, message={result.get('message')!r}"
            )
        return dict(result["data"])

    def get_all_shop_product_reviews(
        self, product_url: str, *, auth=None, max_pages: int | None = None,
        page_size: int = 3, sort_rule: int = 1, filter_type: int = 1,
        filter_value: int = 6,
    ) -> dict:
        """Read SSR page 1 and every response-owned Shop review page."""
        auth = self._auth(auth)
        initial = self.get_shop_product_reviews(product_url, auth=auth)
        initial_reviews = initial.get("product_reviews")
        if not isinstance(initial_reviews, list):
            raise RuntimeError("TikTok Shop 首屏评价缺少 product_reviews")
        reviews = list(initial_reviews)
        pages = [dict(initial)]
        has_more = initial.get("has_more")
        if not isinstance(has_more, bool):
            raise RuntimeError("TikTok Shop 首屏评价缺少布尔 has_more")
        page_start = 2
        while has_more and (max_pages is None or len(pages) < int(max_pages)):
            page = self.get_shop_product_review_page(
                product_url,
                page_start=page_start,
                page_size=page_size,
                sort_rule=sort_rule,
                filter_type=filter_type,
                filter_value=filter_value,
                auth=auth,
            )
            current = page.get("product_reviews")
            if not isinstance(current, list):
                raise RuntimeError("TikTok Shop 翻页评价缺少 product_reviews")
            next_has_more = page.get("has_more")
            if not isinstance(next_has_more, bool):
                raise RuntimeError("TikTok Shop 翻页评价缺少布尔 has_more")
            reviews.extend(current)
            pages.append(dict(page))
            has_more = next_has_more
            page_start += 1
        return {
            "product_reviews": reviews,
            "review_ratings": initial.get("review_ratings"),
            "total_reviews": initial.get("total_reviews"),
            "has_more": has_more,
            "pages": pages,
        }

    @staticmethod
    def _video_detail_from_html(html: str, *, expected_item_id: str | None = None) -> dict:
        """Extract the current video item from the page hydration contract.

        TikTok's standalone ``/@user/video/<id>`` page does not make a
        separate ``/api/item/detail`` request.  The full item is embedded in
        ``__UNIVERSAL_DATA_FOR_REHYDRATION__`` at
        ``webapp.video-detail.itemInfo.itemStruct``.  Keep this parser tied to
        that observed structure instead of treating ``related/item_list`` as
        the detail endpoint.
        """
        soup = BeautifulSoup(html, "html.parser")
        state = soup.find(
            "script", attrs={"id": "__UNIVERSAL_DATA_FOR_REHYDRATION__"}
        )
        state_text = state.string if state is not None else None
        if not state_text and state is not None:
            state_text = state.get_text()
        if not state_text:
            raise RuntimeError(
                "视频页中没有 __UNIVERSAL_DATA_FOR_REHYDRATION__；"
                "请保存该页面后再分析新的 hydration 数据结构"
            )
        try:
            data = json.loads(state_text)
            item = data["__DEFAULT_SCOPE__"]["webapp.video-detail"][
                "itemInfo"
            ]["itemStruct"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError(
                "视频页 hydration 中没有 webapp.video-detail.itemInfo.itemStruct"
            ) from exc
        if not isinstance(item, dict) or not item.get("id"):
            raise RuntimeError("视频页 hydration 的 itemStruct 缺少 id")
        if expected_item_id is not None and str(item["id"]) != str(expected_item_id):
            raise RuntimeError(
                "视频页 hydration 的 item id 与 URL 不一致："
                f"期望 {expected_item_id}，实际 {item.get('id')}"
            )
        return item

    def get_video_detail(self, video_url: str, *, auth=None) -> dict:
        """Read a standalone TikTok video page's complete hydrated item."""
        auth = self._auth(auth)
        html = self.get_user_html(video_url, auth=auth)
        match = re.search(r"/video/(\d+)", urlparse(video_url).path)
        expected_item_id = match.group(1) if match else None
        return self._video_detail_from_html(html, expected_item_id=expected_item_id)

    def get_user_info(self, user_url: str, *, auth=None) -> dict:
        html = self.get_user_html(user_url, auth=auth)
        match = re.search(r'"webapp\.user-detail":(.*?),"webapp\.a-b"', html)
        if not match:
            raise RuntimeError("页面中没有 webapp.user-detail；请保存该页面后再分析新的 SSR 数据结构")
        return json.loads(match.group(1))

    def get_live_room_info(self, live_url: str, *, auth=None):
        auth = self._auth(auth)
        if "vt.tiktok.com" in live_url:
            response = http_client.get(live_url, allow_redirects=False, timeout=self.timeout)
            live_url = response.headers.get("location", live_url)
        response = http_client.get(
            live_url,
            headers=HeaderBuilder.build(HeaderType.DOC, auth, referer=live_url).get(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        state = soup.find("script", attrs={"id": "SIGI_STATE"})
        if not state or not state.text:
            return None
        data = json.loads(state.text)
        try:
            user = data["LiveRoom"]["liveRoomUserInfo"]["user"]
            return (user["id"], user["secUid"], user["uniqueId"],
                    user["roomId"], user["status"], live_url)
        except (KeyError, TypeError):
            return None


# A spelling-compatible alias for callers that prefer the shorter name.
TikTokWebAPI = TiktokWebAPI
