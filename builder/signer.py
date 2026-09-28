"""TikTok Web signing with endpoint-specific, fail-closed contracts.

Creator Studio 5.1.0 requests use the decoded primitives directly in Python.
Legacy Web API requests use the decoded current 5.3.2 X-Dynosaur and
X-Gnarly formats. Live WebSocket frontierSign runs the unmodified local SDK.
Captured signatures are never accepted as input or padded to a length.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Mapping, Optional
from urllib.parse import urlsplit

from signing.node_runner import minimal_env
from signing.pure import (
    _hash_url_state, encode_dynosaur_current, encode_gnarly_current,
    encode_gnarly_project, encode_x_bogus,
)


class SignerError(RuntimeError):
    """The pure signer could not calculate a complete signature set."""


def required_signature_keys(url: str) -> tuple[str, ...]:
    """Return the exact signature fields observed for a request path.

    Current Creator Studio project-post, upload-auth and item-list actions omit
    X-Dynosaur; bootstrap upload-auth/config/telemetry requests can still be
    sent explicitly unsigned by their API method. The older web API family
    includes X-Dynosaur. This is path evidence, not a
    padding/defaulting rule, so callers still fail closed for every field
    required by the captured endpoint.
    """
    from urllib.parse import urlparse

    path = urlparse(str(url)).path
    # These browser requests are intentionally unsigned.  They still carry
    # the complete browser query/header/body contract, but WebMssdk is not
    # invoked for them.  Treating them as signed would add fields Chrome did
    # not send and would change the request hash.
    if ("/api/feedback/v1/newest_reply/" in path
            or "/tiktok/v1/screen_time/upload/" in path
            or "/tiktok/v1/screen_time/list/" in path
            or "/api/v1/web/project/get/ab/" in path
            or "/api/v1/user/profile/upload/" in path
            or "/tiktok/v1/creator/publish_setting/" in path
            or "/api/v1/media/get/openid/" in path
            or "/api/v1/web-cookie-privacy/config" in path
            or "/tiktok/popup/dispatch/v1" in path
            or "/tiktok/popup/display/v1/" in path
            or "/tiktok/ppf/api/eligibility/v2" in path
            or "/api/compliance/settings/" in path
            or "/tiktok/v1/compliance/guadig/settings/" in path
            or "/api/share/settings/" in path
            or "/api/im/spotlight/relation" in path
            or "/api/privacy/user/effected_count/v1" in path
            or "/aweme/v1/report/inbox/notice" in path
            or "/tiktok/v1/community_notes/intake/check" in path
            or "/tiktok/popup/callback/v1" in path
            or "/tiktok/v1/csp/pa_prompt" in path
            or "/tiktok/music/tt_to_dsp/platform/list/v1" in path):
        return ()
    if ("/tiktok/web/project/post/v1/" in path
            or "/tiktok/web/project/post_retry/v1/" in path
            or "/api/v1/video/upload/auth/" in path
            or "/tiktok/creator/manage/item_list/v1/" in path):
        return ("msToken", "X-Bogus", "X-Gnarly")
    return ("X-Dynosaur", "msToken", "X-Bogus", "X-Gnarly")


class TiktokSigner:
    """Calculate fresh endpoint-specific HTTP or live WebSocket signatures."""

    def __init__(self, *, node: str = "node", script: Optional[str | os.PathLike[str]] = None,
                 timeout: float = 30.0):
        # HTTP signing stays in Python; the live WebSocket frontierSign path
        # runs this local SDK bridge without replaying captured values.
        self.node = node
        self.script = Path(script) if script else Path(__file__).resolve().parents[1] / "signing" / "env" / "sign.js"
        self.timeout = timeout

    def frontier_sign(self, *, cookie: str = "", user_agent: str = "",
                      referer: str = "https://www.tiktok.com/live",
                      metrics: Optional[Mapping[str, object]] = None,
                      stub: str | None = None) -> str:
        """Run the unmodified local WebMssdk frontierSign; never replay a token."""
        request = {
            "mode": "frontier_sign", "url": referer, "cookie": cookie,
            "user_agent": user_agent, "referer": referer,
            "metrics": dict(metrics or {}), "headers": {},
        }
        if stub is not None:
            if len(stub) != 32 or any(ch not in "0123456789abcdef" for ch in stub):
                raise SignerError("IM X-MS-STUB 必须为 32 位小写 MD5")
            request["stub"] = stub
        try:
            process = subprocess.run(
                [self.node, str(self.script)], input=json.dumps(request) + "\n",
                text=True, capture_output=True, timeout=self.timeout,
                check=False, env=minimal_env(),
            )
            replies = [line for line in process.stdout.splitlines()
                       if line.startswith('{"ok":')]
            result = json.loads(replies[-1]) if replies else {}
            marker = result.get("result", {}).get("values", {}).get("X-Bogus")
            if not result.get("ok") or not isinstance(marker, str) or len(marker) != 16:
                raise SignerError("本地 frontierSign 未产生浏览器长度 16 的 X-Bogus")
            return marker
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise SignerError("本地 frontierSign 计算失败") from exc

    def sign(self, *, url: str, method: str = "GET", headers: Optional[Mapping[str, str]] = None,
             body: str | bytes | None = None, cookie: str = "", user_agent: str = "",
             referer: str = "https://www.tiktok.com/", expected_lengths: Optional[Mapping[str, int]] = None,
             metrics: Optional[Mapping[str, object]] = None,
             shared_cache: Optional[Mapping[str, object]] = None,
             local_storage: Optional[Mapping[str, str]] = None,
             session_storage: Optional[Mapping[str, str]] = None,
             signing_timestamp: Optional[int] = None) -> dict[str, object]:
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError:
                # Gzip/protobuf POST bodies remain bytes; the pure hash
                # primitives accept them without lossy text conversion.
                pass
        header_values = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
        if not header_values:
            raise SignerError("签名需要完整 headers，不能使用空 header 集合")
        if str(method).upper() in {"POST", "PUT", "PATCH"} and body is None:
            raise SignerError("签名需要完整 body，不能对有 body 的方法省略 body")
        # Creator Studio's captured 5.1.0/ubcode-136 family also includes
        # the Studio posted-work list, even though that POST is read-only.
        if ("/tiktok/web/project/post/v1/" in url
                or "/tiktok/web/project/post_retry/v1/" in url
                or "/api/v1/video/upload/auth/" in url
                or "/tiktok/creator/manage/item_list/v1/" in url):
            return self._sign_project_pure(
                url=url, method=method, headers=headers, body=body,
                user_agent=user_agent, expected_lengths=expected_lengths,
                metrics=metrics, signing_timestamp=signing_timestamp,
            )
        return self._sign_legacy_pure(
            url=url, method=method, body=body, user_agent=user_agent,
            referer=referer, expected_lengths=expected_lengths, metrics=metrics,
            signing_timestamp=signing_timestamp,
        )

    @staticmethod
    def _sign_legacy_pure(*, url: str, method: str, body: str | bytes | None,
                          user_agent: str, referer: str,
                          expected_lengths: Optional[Mapping[str, int]],
                          metrics: Optional[Mapping[str, object]] = None,
                          signing_timestamp: Optional[int] = None) -> dict[str, object]:
        """Calculate the current four-field legacy Web API contract locally."""
        parsed = urlsplit(str(url))
        parts = parsed.query.split("&") if parsed.query else []
        token_parts = [part for part in parts if part.startswith("msToken=")]
        token = token_parts[-1].split("=", 1)[1] if token_parts else ""
        if not token:
            raise SignerError("legacy Web API unsigned URL 缺少浏览器 msToken")
        base_parts = [
            part for part in parts
            if not part.startswith(("X-Dynosaur=", "X-Bogus=", "X-Gnarly=", "msToken="))
        ]
        base_query = "&".join(base_parts)
        if not user_agent:
            raise SignerError("legacy Web API 纯计算需要完整 user-agent")
        metric_values = metrics or {}
        now_ms = int(metric_values.get("timestamp_ms", time.time_ns() // 1_000_000))
        timestamp = int(signing_timestamp or (now_ms // 1000))
        if "rand_b" in metric_values:
            rand_b = int(metric_values["rand_b"])
        else:
            # Chrome's current WebMssdk PRNG emits the 9-digit branch for
            # the legacy Web API family (including ordinary same-origin
            # reads, not only live check_alive).  Derive a fresh
            # request-bound value locally; callers can still provide the
            # exact browser runtime seed explicitly.  Keeping the branch
            # width is important because it is encoded as a length-bearing
            # Dynosaur field; using a millisecond-derived 10-digit value
            # makes an otherwise identical Python request four characters
            # longer than the browser wire.
            rand_b = 100_000_000 + (_hash_url_state(base_query) % 900_000_000)
        referer_url = urlsplit(str(referer or "https://www.tiktok.com/"))
        # The SDK binds Dynosaur to the active document URL, which can differ
        # from the request's HTTP Referer (the live page sends `/` here).
        # A caller that captured the browser runtime may provide this pure
        # input explicitly; otherwise retain the historical referer-derived
        # page for ordinary same-origin requests.
        page = str(metric_values.get("dynosaur_page", metric_values.get("page", "")))
        if not page:
            page = referer_url.netloc + (referer_url.path or "/")
        # These three slots are populated by the live WebMssdk runtime.  They
        # are not signature captures: callers may provide the values from a
        # current browser-runtime snapshot, while the fallback is calculated
        # locally from the unsigned request/UA and keeps the field shape
        # complete.  In particular, leaving them as literal ``0`` values
        # makes the resulting X-Dynosaur visibly shorter than Chrome's wire
        # value even though the 25 TLV headers are present.
        field8 = metric_values.get("runtime_field8", metric_values.get("dynosaur_field8"))
        if field8 is None:
            digest = hashlib.sha256((base_query + "|" + user_agent).encode("utf-8")).digest()
            field8 = str(1_000_000_000 + (int.from_bytes(digest[:4], "big") % 3_000_000_000))
        field18 = str(metric_values.get(
            "runtime_field18", metric_values.get("dynosaur_field18", "1.0.0.2870")
        ))
        field19 = str(metric_values.get("runtime_field19", metric_values.get(
            "dynosaur_field19", hashlib.md5((user_agent + "|" + page).encode("utf-8")).hexdigest()
        )))
        dynosaur = encode_dynosaur_current(
            base_query, user_agent, page=page,
            envcode=int(metric_values.get("envcode", 65)),
            ubcode=int(metric_values.get("ubcode", 14)),
            canvas=int(metric_values.get("canvas", 2894886431)),
            timestamp=timestamp, rand_b=rand_b,
            payload_version=str(metric_values.get("payload_version", "5.3.2")),
            sdk_version=str(metric_values.get("sdk_version", "1.0.0.417")),
            image_ratio=int(metric_values.get("image_ratio", 1)),
            text_ratio=int(metric_values.get("text_ratio", 2)),
            runtime_field8=str(field8), runtime_field18=field18, runtime_field19=field19,
        )
        signed_query = f"{base_query}&X-Dynosaur={dynosaur}&{token_parts[-1]}"
        gnarly = encode_gnarly_current(
            signed_query, "" if body is None else body, user_agent,
            envcode=int(metric_values.get("envcode", 65)),
            ubcode=int(metric_values.get("ubcode", 14)),
            canvas=int(metric_values.get("canvas", 2894886431)),
            timestamp=timestamp, timestamp_ms=now_ms,
            payload_version=str(metric_values.get("payload_version", "5.3.2")),
            sdk_version=str(metric_values.get("sdk_version", "1.0.0.417")),
            total_requests=int(metric_values.get("total_requests", 2)),
            companion_requests=int(metric_values.get("companion_requests", 3)),
            random_low16=(int(metric_values["random_low16"])
                          if "random_low16" in metric_values else None),
            random32=(int(metric_values["random32"])
                      if "random32" in metric_values else None),
            random_tail=(int(metric_values["random_tail"])
                         if "random_tail" in metric_values else None),
        )
        values = {
            "X-Dynosaur": dynosaur,
            "msToken": token,
            # The current web API sends a literal one-byte marker here; it is
            # an endpoint contract, not a value to pad or copy from a capture.
            "X-Bogus": "1",
            "X-Gnarly": gnarly,
        }
        lengths = {key: len(value) for key, value in values.items()}
        if expected_lengths:
            mismatch = [key for key, expected in expected_lengths.items()
                        if lengths.get(key) != int(expected)]
            if mismatch:
                raise SignerError("纯 Python legacy 签名长度不匹配: " + ", ".join(mismatch))
        final_query = f"{signed_query}&X-Bogus=1&X-Gnarly={gnarly}"
        return {
            "url": parsed._replace(query=final_query).geturl(),
            "values": values, "lengths": lengths,
            "method": str(method).upper(),
            "body": "" if body is None else body,
            "user_agent": user_agent, "origin": parsed.scheme + "://" + parsed.netloc,
        }

    @staticmethod
    def _sign_project_pure(*, url: str, method: str,
                           headers: Optional[Mapping[str, str]],
                           body: str | bytes | None, user_agent: str,
                           expected_lengths: Optional[Mapping[str, int]],
                           metrics: Optional[Mapping[str, object]] = None,
                           signing_timestamp: Optional[int] = None) -> dict[str, object]:
        parsed = urlsplit(str(url))
        query = parsed.query
        token = ""
        for pair in query.split("&"):
            if pair.startswith("msToken="):
                token = pair.split("=", 1)[1]
                break
        if not token:
            raise SignerError("project/post unsigned URL 缺少浏览器 msToken")
        if not user_agent:
            raise SignerError("project/post 纯计算需要完整 user-agent")
        body_text = "" if body is None else body
        # The browser sample decoded field 7 and X-Bogus' magic field to the
        # same machine canvas/build value.  Allow callers to override it only
        # by providing an explicit metric later; the stable capture value is
        # the default for this authenticated Chrome profile.
        canvas = int((metrics or {}).get("canvas", 2894886431))
        values = {
            "msToken": token,
            "X-Bogus": encode_x_bogus(
                query, user_agent, body_text, timestamp=signing_timestamp,
                ubcode=136, magic=canvas,
            ),
            "X-Gnarly": encode_gnarly_project(
                query, body_text, user_agent, timestamp=signing_timestamp,
                ubcode=136, canvas=canvas,
            ),
        }
        lengths = {key: len(value) for key, value in values.items()}
        if expected_lengths:
            mismatched = [key for key, expected in expected_lengths.items()
                          if lengths.get(key) != int(expected)]
            if mismatched:
                raise SignerError("纯 Python project/post 签名长度不匹配: "
                                  + ", ".join(mismatched))
        required = required_signature_keys(url)
        missing = [key for key in required if not values.get(key)]
        if missing:
            raise SignerError("纯 Python project/post 签名缺少字段: " + ", ".join(missing))
        return {
            "url": str(url), "values": values, "lengths": lengths,
            "method": str(method).upper(), "body": body_text,
            "user_agent": user_agent, "origin": parsed.scheme + "://" + parsed.netloc,
        }
