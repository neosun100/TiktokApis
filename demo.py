"""Safely preview or publish one TikTok Creator post from a browser session.

See README.md for the ignored ``.tiktok-runtime.json`` profile format.
Nothing is uploaded unless ``--publish`` is explicitly supplied.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from api.tiktok_web import TiktokWebAPI
from builder.auth import TiktokAuth
from builder.errors import BrowserEvidenceError, TiktokError


PROFILE_FIELDS = frozenset({
    "device_id", "odin_id", "region", "priority_region",
    "document_cookie", "web_id_last_time", "user_agent", "sec_ch_ua",
    "sec_ch_ua_platform", "accept_language", "client_ab_versions",
    "browser_metrics", "shared_cache", "local_storage", "session_storage",
    "x_mssdk_info", "ticket_guard_public_key", "ticket_guard_web_version",
    "ticket_guard_version", "ticket_guard_iteration_version",
    "ticket_guard_private_key",
    "ticket_guard_encrypt_ticket", "ticket_guard_ts_sign",
    "passport_csrf_token", "tt_csrf_token", "secsdk_csrf_token",
    "ttwid_ticket", "profile",
})
REQUIRED_PROFILE_FIELDS = (
    "document_cookie", "device_id", "odin_id", "user_agent",
    "local_storage", "session_storage", "browser_metrics",
    "ticket_guard_public_key", "ticket_guard_web_version",
    "ticket_guard_version", "ticket_guard_iteration_version",
    "ticket_guard_private_key", "ticket_guard_encrypt_ticket",
    "ticket_guard_ts_sign",
)


def load_auth(profile_path: Path) -> TiktokAuth:
    """Build strict auth from the current Chrome session, never from signatures."""
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("浏览器资料必须是 JSON 对象")
    profile = dict(profile)
    file_cookie = profile.pop("cookie", "")
    cookie = os.environ.get("TIKTOK_COOKIE") or file_cookie
    if not isinstance(cookie, str) or not cookie.strip():
        raise ValueError("缺少完整 Cookie：在 profile 的 cookie 或 TIKTOK_COOKIE 中提供")
    unknown = sorted(set(profile) - PROFILE_FIELDS)
    if unknown:
        raise ValueError("浏览器资料包含未知字段: " + ", ".join(unknown))
    missing = [
        name for name in REQUIRED_PROFILE_FIELDS
        if name not in profile or profile[name] is None
        or profile[name] == "" or profile[name] == {}
    ]
    if missing:
        raise ValueError("浏览器资料缺少当前会话字段: " + ", ".join(missing))
    for name in ("local_storage", "session_storage", "browser_metrics"):
        if not isinstance(profile[name], dict):
            raise ValueError(f"{name} 必须是当前浏览器导出的对象")
    profile["strict_browser_alignment"] = True
    auth = TiktokAuth.from_cookie(cookie, **profile)
    if not auth.logged_in:
        raise BrowserEvidenceError("Cookie 缺少已登录的 sessionid/sid_tt/multi_sids")
    auth.require_browser_profile()
    # Validate the security-sdk material before any media upload begins.
    # This result is deliberately discarded; post_project calculates a fresh
    # five-header envelope when it sends the final browser-shaped request.
    try:
        guard = auth.build_ticket_guard(TiktokWebAPI.PROJECT_POST_PATH)
    except Exception as exc:
        raise BrowserEvidenceError(
            f"当前 security-sdk 材料无法重算 ticket-guard ({type(exc).__name__})"
        ) from None
    for field, header in (
        ("ticket_guard_public_key", "tt-ticket-guard-public-key"),
        ("ticket_guard_web_version", "tt-ticket-guard-web-version"),
        ("ticket_guard_version", "tt-ticket-guard-version"),
        ("ticket_guard_iteration_version", "tt-ticket-guard-iteration-version"),
    ):
        if str(profile[field]) != guard[header]:
            raise BrowserEvidenceError(f"{field} 与当前本地纯算的浏览器 header 不一致")
    return auth


def _media_files(paths: list[Path]) -> list[Path]:
    checked = []
    for path in paths:
        resolved = path.expanduser().resolve()
        if not resolved.is_file() or resolved.stat().st_size == 0:
            raise ValueError(f"媒体文件不存在或为空: {path}")
        checked.append(resolved)
    return checked


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从当前 Chrome 会话发布视频或图集（默认仅自己可见）",
    )
    parser.add_argument(
        "--profile", type=Path, default=Path(".tiktok-runtime.json"),
        help="当前浏览器会话 JSON；默认 .tiktok-runtime.json（已被 Git 忽略）",
    )
    parser.add_argument(
        "--publish", action="store_true",
        help="真正上传并发布；不加此参数时只做本地预检",
    )
    subcommands = parser.add_subparsers(dest="kind", required=True)
    video = subcommands.add_parser("video", help="发布一个视频")
    video.add_argument("media", type=Path, help="本地视频路径")
    video.add_argument("--text", required=True, help="作品文案")
    photos = subcommands.add_parser("photos", help="发布一个图集")
    photos.add_argument("images", nargs="+", type=Path, help="本地图片路径")
    photos.add_argument("--text", required=True, help="作品文案")
    photos.add_argument("--title", default="", help="图集标题")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        paths = _media_files([args.media] if args.kind == "video" else args.images)
        auth = load_auth(args.profile)
    except (OSError, ValueError, BrowserEvidenceError) as exc:
        print(f"本地预检失败：{exc}", file=sys.stderr)
        return 2

    if not args.publish:
        print(f"本地预检通过：{args.kind}，{len(paths)} 个媒体文件，默认仅自己可见。")
        print("没有发送网络请求；确认当前浏览器资料后，添加 --publish 才会上传。")
        return 0

    api = TiktokWebAPI(auth)
    try:
        if args.kind == "video":
            result = api.creator_publish(paths[0], args.text)
        else:
            result = api.creator_publish_photos(paths, args.text, title=args.title)
    except TiktokError as exc:
        # TiktokError messages are redacted by construction (host/path only).
        print(f"发布未完成：{exc}。媒体可能已部分上传；请检查后再决定是否重试。",
              file=sys.stderr)
        return 1
    except Exception as exc:
        # Foreign exceptions may embed signed URLs, request bodies or key
        # material; print only the type.
        print(
            f"发布未完成（{type(exc).__name__}）。媒体可能已部分上传；"
            "请私下检查错误后再决定是否重试。",
            file=sys.stderr,
        )
        return 1

    published = result.get("publish") or {}
    print(json.dumps({
        "creation_id": result.get("creation_id"),
        "video_id": result.get("video_id"),
        "status_code": published.get("status_code"),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
