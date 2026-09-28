"""Browser-assisted TikTok login and session export.

    uv run python -m capture login   [--out .tiktok-runtime.json]
    uv run python -m capture export  [--out .tiktok-runtime.json]

``login`` opens a dedicated, visible Chrome profile (through TIKTOK_PROXY
when set) on the TikTok login page.  Log in any way the page offers — QR
code, SMS, password — and complete any captcha yourself; the tool never
touches the challenge.  Once a session cookie appears it exports the
session.  ``export`` re-exports an already logged-in profile.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .cdp import CDPError, Chrome
from .session import (
    ORIGIN,
    collect_snapshot,
    logged_in,
    profile_from_snapshot,
    wait_for_login,
    write_private_json,
)

DEFAULT_PROFILE_DIR = Path("~/.tiktok-apis/chrome-profile")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m capture", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("login", "export"))
    parser.add_argument("--out", type=Path, default=Path(".tiktok-runtime.json"))
    parser.add_argument("--profile-dir", type=Path, default=DEFAULT_PROFILE_DIR)
    parser.add_argument("--timeout", type=float, default=600.0, help="等待登录的秒数")
    parser.add_argument("--snapshot", type=Path,
                        help="同时保存原始证据（含 Cookie，权限 0600）以便调试映射")
    args = parser.parse_args(argv)

    proxy = (os.environ.get("TIKTOK_PROXY") or "").strip()
    try:
        with Chrome(profile_dir=args.profile_dir, proxy_url=proxy) as chrome:
            if args.command == "login":
                chrome.navigate(ORIGIN + "/login")
                if not logged_in(chrome):
                    print("请在打开的 Chrome 窗口中登录（扫码 / 短信 / 账密均可，验证码请手动完成）…",
                          file=sys.stderr)
                    wait_for_login(chrome, timeout=args.timeout)
            elif not logged_in(chrome):
                print("该 profile 尚未登录；请先运行 `python -m capture login`", file=sys.stderr)
                return 2
            snapshot = collect_snapshot(chrome)
    except CDPError as exc:
        print(f"采集失败：{exc}", file=sys.stderr)
        return 1

    result = profile_from_snapshot(snapshot)
    write_private_json(args.out, result["profile"])
    if args.snapshot:
        write_private_json(args.snapshot, snapshot)
    print(f"已写入 {args.out}（{len(result['profile'])} 个字段，权限 0600）", file=sys.stderr)
    for field, source in sorted(result["sources"].items()):
        print(f"  ✓ {field:<32} ← {source}", file=sys.stderr)
    for field in result["missing"]:
        print(f"  ✗ {field:<32} 未找到", file=sys.stderr)
    return 0 if not result["missing"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
