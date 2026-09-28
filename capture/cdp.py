"""Minimal Chrome DevTools Protocol client for session capture.

Only what the capture tool needs: launch a dedicated Chrome profile, attach
to one page target (flatten sessions), send commands, and collect events.
The ``websocket-client`` dependency is already required by the runtime.
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path
from urllib.request import urlopen

import websocket

from builder.errors import TiktokError

MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


class CDPError(TiktokError):
    """Chrome could not be launched or a DevTools command failed."""


def find_chrome() -> str:
    for candidate in (os.environ.get("CHROME_PATH"), MAC_CHROME,
                      shutil.which("google-chrome"), shutil.which("chromium"),
                      shutil.which("chrome")):
        if candidate and Path(candidate).exists():
            return candidate
    raise CDPError("找不到 Chrome；请设置 CHROME_PATH")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def chrome_proxy_arg(proxy_url: str) -> tuple[str, tuple[str, str] | None]:
    """Split a proxy URL into Chrome's --proxy-server value and credentials.

    Chrome ignores user:pass in --proxy-server; credentials are answered via
    Fetch.authRequired instead.  ``socks5h`` is spelled ``socks5`` in Chrome
    (which always resolves DNS through a SOCKS5 proxy).
    """
    from urllib.parse import urlsplit

    parts = urlsplit(proxy_url)
    if not parts.scheme or not parts.hostname or not parts.port:
        raise CDPError("TIKTOK_PROXY 需要形如 scheme://host:port")
    scheme = {"socks5h": "socks5", "socks": "socks5"}.get(parts.scheme, parts.scheme)
    creds = (parts.username or "", parts.password or "") if parts.username else None
    return f"{scheme}://{parts.hostname}:{parts.port}", creds


class Chrome:
    """A Chrome process on a dedicated profile with one attached page."""

    def __init__(self, *, profile_dir: Path, proxy_url: str = "", headless: bool = False,
                 extra_args: list[str] | None = None):
        self.profile_dir = Path(profile_dir).expanduser()
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        self.proxy_creds = None
        args = [
            find_chrome(),
            f"--remote-debugging-port={self.port}",
            "--remote-debugging-address=127.0.0.1",
            f"--user-data-dir={self.profile_dir}",
            "--no-first-run", "--no-default-browser-check",
            "--disable-back-forward-cache",
        ]
        if proxy_url:
            server, self.proxy_creds = chrome_proxy_arg(proxy_url)
            args.append(f"--proxy-server={server}")
        if headless:
            args.append("--headless=new")
        args.extend(extra_args or [])
        args.append("about:blank")
        self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._ws = None
        self._ids = itertools.count(1)
        self._pending: dict[int, dict] = {}
        self._cond = threading.Condition()
        self._events: dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        self._listeners: list[Callable[[dict], None]] = []
        self.session_id = ""
        self._connect()

    # -- connection ---------------------------------------------------------

    def _connect(self, timeout: float = 20.0):
        deadline = time.monotonic() + timeout
        info = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise CDPError("Chrome 进程启动后立即退出（profile 可能被另一个 Chrome 占用）")
            try:
                with urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=1) as resp:
                    info = json.loads(resp.read())
                if info.get("webSocketDebuggerUrl"):
                    break
            except OSError:
                time.sleep(0.2)
        if not info or not info.get("webSocketDebuggerUrl"):
            raise CDPError("Chrome DevTools 端点未就绪")
        # suppress_origin: Chrome rejects the Origin header native clients add
        # by default; the fix is not to send it, not --remote-allow-origins=*.
        self._ws = websocket.create_connection(info["webSocketDebuggerUrl"], suppress_origin=True,
                                               timeout=None)
        threading.Thread(target=self._reader, daemon=True).start()
        targets = self.call("Target.getTargets", browser=True)["targetInfos"]
        page = next((t for t in targets if t["type"] == "page"), None)
        target_id = page["targetId"] if page else self.call(
            "Target.createTarget", {"url": "about:blank"}, browser=True)["targetId"]
        self.session_id = self.call("Target.attachToTarget",
                                    {"targetId": target_id, "flatten": True},
                                    browser=True)["sessionId"]
        if self.proxy_creds:
            self.on_event(self._answer_proxy_auth)
            self.call("Fetch.enable", {"handleAuthRequests": True,
                                       "patterns": [{"urlPattern": "*"}]})

    def _reader(self):
        while True:
            try:
                message = json.loads(self._ws.recv())
            except (websocket.WebSocketException, OSError, ValueError):
                with self._cond:
                    self._closed = True
                    self._cond.notify_all()
                return
            if "id" in message:
                with self._cond:
                    self._pending[message["id"]] = message
                    self._cond.notify_all()
                continue
            self._events[message.get("method", "")].append(message)
            for listener in list(self._listeners):
                listener(message)

    def _answer_proxy_auth(self, message: dict):
        # Fetch.enable pauses every request; each must be continued or the
        # page hangs forever.  Auth challenges get the proxy credentials.
        method, params = message.get("method"), message.get("params", {})
        if method == "Fetch.requestPaused":
            self.send_nowait("Fetch.continueRequest", {"requestId": params["requestId"]})
        elif method == "Fetch.authRequired":
            user, password = self.proxy_creds
            self.send_nowait("Fetch.continueWithAuth", {
                "requestId": params["requestId"],
                "authChallengeResponse": {"response": "ProvideCredentials",
                                          "username": user, "password": password}})

    # -- commands -----------------------------------------------------------

    def send_nowait(self, method: str, params: dict | None = None, *, browser: bool = False) -> int:
        message_id = next(self._ids)
        message = {"id": message_id, "method": method, "params": params or {}}
        if not browser:
            message["sessionId"] = self.session_id
        self._ws.send(json.dumps(message))
        return message_id

    def call(self, method: str, params: dict | None = None, *, browser: bool = False,
             timeout: float = 30.0) -> dict:
        message_id = self.send_nowait(method, params, browser=browser)
        deadline = time.monotonic() + timeout
        with self._cond:
            while message_id not in self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or getattr(self, "_closed", False):
                    raise CDPError(f"CDP 命令超时或连接已关闭: {method}")
                self._cond.wait(remaining)
            reply = self._pending.pop(message_id)
        if "error" in reply:
            raise CDPError(f"CDP {method} 失败: {reply['error'].get('message')}")
        return reply.get("result", {})

    def evaluate(self, expression: str, *, await_promise: bool = False):
        result = self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                                "awaitPromise": await_promise})
        if result.get("exceptionDetails"):
            raise CDPError("页面脚本执行失败: " + str(result["exceptionDetails"].get("text")))
        return result.get("result", {}).get("value")

    def navigate(self, url: str, *, wait: float = 30.0):
        self.call("Page.enable")
        self._events["Page.loadEventFired"].clear()
        self.call("Page.navigate", {"url": url})
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if self._events["Page.loadEventFired"]:
                return
            time.sleep(0.1)
        raise CDPError(f"页面加载超时: {url}")

    def on_event(self, listener: Callable[[dict], None]):
        self._listeners.append(listener)

    def events(self, method: str) -> list[dict]:
        return list(self._events[method])

    def close(self):
        try:
            self.call("Browser.close", browser=True, timeout=5)
        except CDPError:
            pass
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
