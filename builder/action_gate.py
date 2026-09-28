"""Rate limits, quotas, dry-run and an audit trail for every write action.

Every method that changes remote state (comment, like, follow, DM, live chat,
publish, collection edits …) passes through an :class:`ActionGate` before it
touches the network.  The gate is on by default with human-scale ceilings:
automation on one's own account should look like one person using it, and a
runaway loop must stop at a quota instead of at an account ban.

TikTok publishes no numeric limits; the defaults below are deliberately
conservative policy, not measured thresholds.  Override per action via
``ActionGate(policies={...})`` or disable with ``ActionGate.unlimited()``.
"""

from __future__ import annotations

import functools
import json
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from .errors import TiktokError


@dataclass(frozen=True)
class ActionPolicy:
    per_minute: int | None = None
    per_hour: int | None = None
    per_day: int | None = None
    min_interval_s: float = 0.0


# Windows are sliding: "per_hour" counts attempts in the last 3600 s.
DEFAULT_POLICIES: dict[str, ActionPolicy] = {
    "comment": ActionPolicy(per_minute=3, per_hour=20, per_day=100, min_interval_s=15),
    "like": ActionPolicy(per_minute=10, per_hour=60, per_day=300, min_interval_s=2),
    "collect": ActionPolicy(per_minute=10, per_hour=60, per_day=300, min_interval_s=2),
    "follow": ActionPolicy(per_minute=3, per_hour=20, per_day=100, min_interval_s=10),
    "dm": ActionPolicy(per_minute=5, per_hour=30, per_day=150, min_interval_s=5),
    "live_chat": ActionPolicy(per_minute=6, per_hour=120, per_day=500, min_interval_s=3),
    "live_like": ActionPolicy(per_minute=30, per_hour=600, per_day=3000),
    "publish": ActionPolicy(per_hour=3, per_day=10, min_interval_s=300),
    "collection": ActionPolicy(per_minute=10, per_hour=60, per_day=300, min_interval_s=1),
}
_FALLBACK = ActionPolicy(per_minute=5, per_hour=30, per_day=150, min_interval_s=5)

_WINDOWS = (("per_minute", 60), ("per_hour", 3600), ("per_day", 86400))


class RateLimited(TiktokError):
    """The gate refused a write; nothing was sent."""

    def __init__(self, *, action: str, rule: str, count: int, limit, retry_after_s: float):
        self.action, self.rule, self.count, self.limit = action, rule, count, limit
        self.retry_after_s = max(0.0, retry_after_s)
        super().__init__(
            f"写操作被闸门拒绝: action={action} rule={rule} "
            f"(当前 {count}，上限 {limit})，{self.retry_after_s:.0f}s 后可重试")


@dataclass
class ActionGate:
    policies: Mapping[str, ActionPolicy] = field(default_factory=lambda: dict(DEFAULT_POLICIES))
    dry_run: bool = False
    # Optional append-only JSONL ledger; makes quotas hold across processes
    # and leaves an audit trail of every attempted write.
    ledger_path: Path | None = None
    clock: Callable[[], float] = time.time
    enabled: bool = True

    def __post_init__(self):
        self._lock = threading.Lock()
        self._history: dict[str, list[float]] = {}
        if self.ledger_path is not None:
            self.ledger_path = Path(self.ledger_path).expanduser()
            self._load_ledger()

    @classmethod
    def unlimited(cls, **kwargs) -> ActionGate:
        return cls(enabled=False, **kwargs)

    def policy(self, action: str) -> ActionPolicy:
        return self.policies.get(action, _FALLBACK)

    def with_policy(self, action: str, **changes) -> ActionGate:
        """Return a copy with one action's policy adjusted."""
        policies = dict(self.policies)
        policies[action] = replace(self.policy(action), **changes)
        return ActionGate(policies=policies, dry_run=self.dry_run, ledger_path=self.ledger_path,
                          clock=self.clock, enabled=self.enabled)

    # -- ledger ---------------------------------------------------------------

    def _load_ledger(self):
        if not self.ledger_path.exists():
            return
        horizon = self.clock() - 86400
        with self.ledger_path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    # A torn last line from a crashed writer; the rest is valid.
                    continue
                if row.get("sent") and row.get("ts", 0) >= horizon:
                    self._history.setdefault(row["action"], []).append(float(row["ts"]))

    def _append(self, row: Mapping):
        if self.ledger_path is None:
            return
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    # -- decision -------------------------------------------------------------

    def check(self, action: str) -> None:
        """Raise :class:`RateLimited` if ``action`` may not run now."""
        if not self.enabled:
            return
        now = self.clock()
        policy = self.policy(action)
        stamps = [t for t in self._history.get(action, []) if now - t < 86400]
        self._history[action] = stamps
        if stamps and policy.min_interval_s and now - stamps[-1] < policy.min_interval_s:
            raise RateLimited(action=action, rule="min_interval_s", count=1,
                              limit=policy.min_interval_s,
                              retry_after_s=policy.min_interval_s - (now - stamps[-1]))
        for name, seconds in _WINDOWS:
            limit = getattr(policy, name)
            if limit is None:
                continue
            recent = [t for t in stamps if now - t < seconds]
            if len(recent) >= limit:
                # limit == 0 disables the action outright (no retry window).
                retry = seconds - (now - recent[0]) if recent else float(seconds)
                raise RateLimited(action=action, rule=name, count=len(recent), limit=limit,
                                  retry_after_s=retry)

    def run(self, action: str, target: str, send: Callable[[], object]):
        """Gate, then call ``send()``; record the attempt either way."""
        with self._lock:
            self.check(action)
            now = self.clock()
            if self.dry_run:
                self._append({"ts": now, "action": action, "target": target, "sent": False,
                              "outcome": "dry_run"})
                return {"dry_run": True, "action": action, "target": target}
            # Count the attempt before sending: a request that fails after
            # leaving the machine may still have landed server-side.
            self._history.setdefault(action, []).append(now)
        try:
            result = send()
        except TiktokError as exc:
            self._append({"ts": now, "action": action, "target": target, "sent": True,
                          "outcome": type(exc).__name__, "code": getattr(exc, "code", None)})
            raise
        self._append({"ts": now, "action": action, "target": target, "sent": True,
                      "outcome": "ok"})
        return result


_depth = threading.local()


def gated(action: str):
    """Route a ``TiktokWebAPI`` write method through ``self.gate``.

    Re-entrant: when a gated method calls another gated method (e.g.
    ``creator_publish`` -> ``post_project``) only the outermost call is
    counted, so one publish is one publish.
    """
    def decorate(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            if getattr(_depth, "value", 0):
                return method(self, *args, **kwargs)
            label = str(args[0]) if args and isinstance(args[0], (str, int)) else method.__name__

            def send():
                _depth.value = getattr(_depth, "value", 0) + 1
                try:
                    return method(self, *args, **kwargs)
                finally:
                    _depth.value -= 1

            return self.gate.run(action, label, send)
        wrapper.__gated_action__ = action
        return wrapper
    return decorate
