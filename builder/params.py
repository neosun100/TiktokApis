"""Ordered TikTok web query builder."""

from __future__ import annotations

import json
from collections import OrderedDict
from urllib.parse import quote, quote_plus


class Params:
    """Keep query insertion order and TikTok's browser escaping rules."""

    _signature_safe = {"X-Dynosaur", "X-Gnarly", "msToken"}

    def __init__(self, values=None, *, space_plus_keys=()):
        self.params = OrderedDict()
        self._pairs = []
        self._space_plus_keys = frozenset(space_plus_keys)
        source = values.items() if hasattr(values, "items") else (values or ())
        for key, value in source:
            self.add_param(key, value)

    def add_param(self, key, value):
        key = str(key)
        value = "" if value is None else str(value)
        # Normal fields are unique.  Replacing an existing key also removes
        # any earlier duplicate pairs so signer updates cannot accidentally
        # retain stale values; callers that need browser duplicates use
        # add_pair explicitly.
        self._pairs = [(old_key, old_value) for old_key, old_value in self._pairs
                       if old_key != key]
        self.params[key] = value
        self._pairs.append((key, value))
        return self

    def add_pair(self, key, value):
        """Append a query pair even when the key already exists.

        A few live endpoints deliberately send duplicate keys (for example
        two ``version_code`` values).  Keeping those pairs is part of the
        signed browser wire and cannot be represented by a plain dict.
        """
        key = str(key)
        value = "" if value is None else str(value)
        self.params[key] = value
        self._pairs.append((key, value))
        return self

    def update(self, values):
        for key, value in values.items():
            self.add_param(key, value)
        return self

    def common(self, auth, *, referer="https://www.tiktok.com/", from_page="",
               history_len="2", user_is_login=None, data_collection_enabled="true",
               language=None, root_referer=None, include_language=True,
               include_from_page=False, include_user_is_login=False,
               include_root_referer=True, early=None, before_tz=None, late=None,
               query_referer=None, after_aid=None, after_cookie=None,
               after_device_platform=None, after_is_page_visible=None,
               after_os=None, after_region=None, after_root_referer=None):
        query_referer = referer if query_referer is None else query_referer
        root_referer = query_referer if root_referer is None else root_referer
        def emit(values):
            return [(str(key), str(value)) for key, value in (values or {}).items()]

        values = OrderedDict([
            ("WebIdLastTime", auth.web_id_last_time),
            ("aid", "1988"),
            *emit(after_aid),
            ("app_language", auth.profile.app_language),
            ("app_name", "tiktok_web"),
            *[(str(key), str(value)) for key, value in (getattr(self, "_after_app_name", {}) or {}).items()],
            ("browser_language", auth.profile.browser_language),
            ("browser_name", "Mozilla"),
            ("browser_online", "true"),
            ("browser_platform", auth.profile.browser_platform),
            ("browser_version", auth.user_agent.split("Mozilla/", 1)[-1]),
            ("channel", "tiktok_web"),
            ("cookie_enabled", "true"),
            *emit(after_cookie),
            *emit(early),
            ("data_collection_enabled", data_collection_enabled),
            ("device_id", auth.device_id),
            ("device_platform", "web_pc"),
            *emit(after_device_platform),
            ("focus_state", "true"),
            *([("from_page", from_page)] if include_from_page else []),
            ("history_len", history_len),
            ("is_fullscreen", "false"),
            ("is_page_visible", "true"),
            *emit(after_is_page_visible),
            ("language", language or auth.profile.language),
            ("odinId", auth.odin_id),
            ("os", auth.profile.os),
            *emit(after_os),
            ("priority_region", auth.priority_region),
            ("referer", query_referer),
            ("region", auth.region),
            *emit(after_region),
            *([("root_referer", root_referer)] if include_root_referer else []),
            *emit(after_root_referer),
            ("screen_height", auth.profile.screen_height),
            ("screen_width", auth.profile.screen_width),
            *[(str(key), str(value)) for key, value in (before_tz or {}).items()],
            ("tz_name", auth.profile.tz_name),
            *([("user_is_login", "true" if auth.logged_in else "false")] if include_user_is_login else []),
            ("verifyFp", auth.verify_fp),
            *[(str(key), str(value)) for key, value in (late or {}).items()],
            ("webcast_language", auth.profile.webcast_language),
        ])
        if not include_language:
            values.pop("language", None)
        return self.update(values)

    def after_app_name(self, values):
        """Insert endpoint fields immediately after ``app_name``."""
        self._after_app_name = values
        return self

    def with_signatures(self, auth, path, *, url=None, method="GET", headers=None,
                        body=None, referer="https://www.tiktok.com/", require=True):
        if url is None:
            raise ValueError("with_signatures 需要完整 unsigned url，不能注入静态签名")
        self.update(auth.sign_request(
            path, url=url, method=method, headers=headers, body=body,
            referer=referer, require=require,
        ))
        return self

    def with_json(self, key, value):
        return self.add_param(key, json.dumps(value, ensure_ascii=False, separators=(",", ":")))

    def to_query(self):
        parts = []
        for key, value in self._pairs:
            key_text = quote(str(key), safe="-_.~")
            if key in self._signature_safe:
                safe = "/=+.-_~"
            elif key == "next":
                safe = ":"
            else:
                safe = "-_.~"
            encode = quote_plus if key in self._space_plus_keys else quote
            parts.append(f"{key_text}={encode(str(value), safe=safe)}")
        return "&".join(parts)

    @property
    def pairs(self):
        """Immutable ordered query pairs for signature canonicalization."""
        return tuple(self._pairs)

    def get(self):
        return self.params
