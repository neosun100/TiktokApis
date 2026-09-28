"""The single source of the browser fingerprint declared in request queries.

Screen size, locale, platform, OS and time zone appear in almost every web
query, in the live/IM URLs and in several JSON bodies.  They used to be
string literals repeated ~90 times, so a Mac/Hong Kong session still claimed
to be a Windows machine in Shanghai.  Every builder now reads
``auth.profile``.

Precedence, per field:
1. ``TiktokAuth(profile={...})`` — explicit caller values;
2. ``browser_metrics["web_query"]`` — the query of a real same-origin request
   captured from the user's browser (see ``python -m capture``);
3. top-level ``browser_metrics`` keys (navigator/screen snapshot);
4. the historical capture defaults (a Windows Chrome 153 zh-CN profile).

Fields that fell through to (4) are listed in ``defaulted`` so a caller can
tell "measured" from "assumed" (degradation must leave a trace).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields

# The capture these literals came from: Chrome 153 on Windows, zh-CN UI.
_DEFAULTS = {
    "screen_width": "2560",
    "screen_height": "1440",
    "browser_language": "zh-CN",
    "browser_platform": "Win32",
    "tz_name": "Asia/Shanghai",
    "app_language": "zh-Hans",
    "language": "zh-Hans",
    "cpu_core_number": "20",
}

# navigator.platform -> the `os` query value.  Win32 -> windows/win is
# captured evidence; the other rows follow TikTok's web bundle naming and
# must be confirmed by a capture on that platform.
_OS_BY_PLATFORM = {
    "Win32": ("windows", "win"),
    "MacIntel": ("mac", "mac"),
    "Linux x86_64": ("linux", "linux"),
}


@dataclass(frozen=True)
class BrowserProfile:
    screen_width: str
    screen_height: str
    browser_language: str
    browser_platform: str
    tz_name: str
    app_language: str
    language: str
    cpu_core_number: str
    os: str
    creator_os: str
    defaulted: frozenset[str] = field(default=frozenset(), compare=False)

    @property
    def webcast_language(self) -> str:
        return self.app_language

    @classmethod
    def resolve(cls, *, explicit: Mapping | None = None,
                metrics: Mapping | None = None) -> BrowserProfile:
        explicit = dict(explicit or {})
        metrics = dict(metrics or {})
        query = metrics.get("web_query") if isinstance(metrics.get("web_query"), Mapping) else {}
        values: dict[str, str] = {}
        defaulted = set()
        for key, default in _DEFAULTS.items():
            for source in (explicit, query, metrics):
                if source.get(key) not in (None, ""):
                    values[key] = str(source[key])
                    break
            else:
                values[key] = default
                defaulted.add(key)
        web_os, creator_os = _OS_BY_PLATFORM.get(values["browser_platform"], (None, None))
        for key, derived in (("os", web_os), ("creator_os", creator_os)):
            for source in (explicit, query):
                if source.get(key) not in (None, ""):
                    values[key] = str(source[key])
                    break
            else:
                if derived is None:
                    raise ValueError(
                        f"无法从 browser_platform={values['browser_platform']!r} 推出 {key}；"
                        f"请在 profile 中显式提供")
                values[key] = derived
                if "browser_platform" in defaulted:
                    defaulted.add(key)
        return cls(**values, defaulted=frozenset(defaulted))

    def as_dict(self) -> dict[str, str]:
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "defaulted"}
