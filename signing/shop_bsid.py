"""Pure local bridge for TikTok Shop's official OEC unisec signer."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Iterable, Mapping
from urllib.parse import quote, unquote

from .node_runner import minimal_env

from .pure import encode_x_bogus


class ShopBSIDError(RuntimeError):
    """The local OEC SDK could not produce a Chrome-aligned BSID."""


class ShopBSIDSigner:
    """Run the immutable official OEC loader/core in the local Node shim.

    No captured BSID is accepted as input.  Each call supplies the current
    URL, ordered request headers, exact body bytes and browser cookie state,
    then validates the official SDK's fresh output against the captured wire.
    """

    EXPECTED_LENGTH = 382
    BROWSER_MS_TOKEN_LENGTHS = (144, 152)
    _OEC_COOKIE = re.compile(r"(?:^|;\s*)oec_lucifer=([^;]+)")
    _MS_COOKIE = re.compile(r"(?:^|;\s*)msToken=([^;]+)")

    def __init__(self, *, node: str | None = None,
                 script: str | os.PathLike[str] | None = None,
                 timeout: int = 30):
        self.node = node or shutil.which("node") or ""
        self.script = Path(script) if script else (
            Path(__file__).resolve().parents[1]
            / "reverse" / "tiktok_shop_bsid" / "env" / "sign.js"
        )
        self.timeout = int(timeout)

    @staticmethod
    def _ordered_headers(headers: Mapping[str, str] | Iterable[tuple[str, str]]):
        values = headers.items() if isinstance(headers, Mapping) else headers
        return [[str(name), str(value)] for name, value in values]

    def sign(self, *, url: str, method: str,
             headers: Mapping[str, str] | Iterable[tuple[str, str]],
             body: str | bytes | None, cookie: str, user_agent: str = "",
             include_diagnostics: bool = False) -> dict:
        if not self.node:
            raise ShopBSIDError("Shop BSID 纯算需要本机 Node.js")
        if not self.script.is_file():
            raise ShopBSIDError("Shop BSID 本地运行器不存在")
        match = self._OEC_COOKIE.search(str(cookie or ""))
        if not match or not re.fullmatch(r"[0-9a-fA-F]{160}", match.group(1)):
            raise ShopBSIDError(
                "当前 Cookie 缺少浏览器生成的 160 字节 oec_lucifer；"
                "请从已登录的 shop.tiktok.com 页面更新 Cookie"
            )
        tokens = [unquote(value) for value in self._MS_COOKIE.findall(str(cookie or ""))]
        ms_token = next(
            (value for value in tokens
             if len(value) in self.BROWSER_MS_TOKEN_LENGTHS),
            "",
        )
        if not re.fullmatch(r"[0-9A-Za-z_-]+={0,2}", ms_token):
            raise ShopBSIDError(
                "当前 Cookie 缺少浏览器请求使用的 144/152 字节 msToken"
            )
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ShopBSIDError("Shop BSID 请求体必须是 UTF-8") from exc
        if not str(user_agent or ""):
            raise ShopBSIDError("Shop X-Bogus 纯算需要完整 user-agent")
        separator = "&" if "?" in str(url) else "?"
        # Chrome leaves the base64 padding in the Shop pre-sign URL verbatim.
        # Encoding the trailing ``==`` as ``%3D%3D`` changes Lucifer's input
        # by four bytes and produces a structurally valid but rejected BSID.
        signing_url = f"{url}{separator}msToken={quote(ms_token, safe='-._~=')}"
        x_bogus = encode_x_bogus(
            f"msToken={ms_token}", str(user_agent), body or "",
            ubcode=14, magic=2894886431,
        )
        payload = {
            "url": signing_url,
            "method": str(method).upper(),
            "headers": self._ordered_headers(headers),
            "body": body,
            "cookie": str(cookie),
            "expected_length": self.EXPECTED_LENGTH,
            "expected_ms_token_length": len(ms_token),
            "x_bogus": x_bogus,
        }
        environment = minimal_env(TIKTOK_BSID_QUIET="1")
        try:
            completed = subprocess.run(
                [self.node, str(self.script)],
                input=json.dumps(payload, ensure_ascii=False),
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=self.timeout,
                check=False,
                env=environment,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ShopBSIDError("Shop BSID 本地计算进程启动失败") from exc
        if completed.returncode != 0:
            # Vendor failures must not echo stdin/cookies into application logs.
            lines = (completed.stderr or "").strip().splitlines()
            reason = next(
                (line.strip() for line in reversed(lines)
                 if re.search(r"(?:ReferenceError|TypeError|Error):", line)),
                "",
            )
            suffix = f"：{reason}" if reason else ""
            raise ShopBSIDError(f"Shop BSID 本地计算失败{suffix}")
        try:
            result = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ShopBSIDError("Shop BSID 运行器返回了非 JSON 数据") from exc
        bsid = str(result.get("bsid") or "")
        if len(bsid) != self.EXPECTED_LENGTH or not re.fullmatch(r"[0-9a-f]+", bsid):
            raise ShopBSIDError("Shop BSID 输出格式或长度与 Chrome 不一致")
        if str(result.get("length")) != str(self.EXPECTED_LENGTH):
            raise ShopBSIDError("Shop BSID 运行器长度声明不一致")
        output = {
            "signed_url": str(result.get("signed_url") or ""),
            "bsid": bsid,
            "length": self.EXPECTED_LENGTH,
            "pre_sign_lengths": dict(result.get("pre_sign_lengths") or {}),
            "pre_sign_url_length": int(result.get("pre_sign_url_length") or 0),
            "pre_sign_order": list(result.get("pre_sign_order") or []),
        }
        if include_diagnostics:
            output["pre_sign_url"] = str(result.get("pre_sign_url") or "")
        return output


__all__ = ["ShopBSIDError", "ShopBSIDSigner"]
