"""ActionGate: quotas, intervals, dry-run, ledger persistence, API wiring."""

import json

import pytest

from api.tiktok_web import TiktokWebAPI
from builder.action_gate import ActionGate, ActionPolicy, RateLimited
from builder.auth import TiktokAuth
from builder.errors import BusinessError


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def gate(**policy):
    clock = Clock()
    return ActionGate(policies={"x": ActionPolicy(**policy)}, clock=clock), clock


def test_min_interval():
    g, clock = gate(min_interval_s=10)
    g.run("x", "t", lambda: 1)
    with pytest.raises(RateLimited) as info:
        g.run("x", "t", lambda: 1)
    assert info.value.rule == "min_interval_s" and 9 <= info.value.retry_after_s <= 10
    clock.t += 10
    assert g.run("x", "t", lambda: 2) == 2


def test_sliding_hour_window():
    g, clock = gate(per_hour=2)
    g.run("x", "a", lambda: 1)
    clock.t += 1000
    g.run("x", "b", lambda: 1)
    with pytest.raises(RateLimited) as info:
        g.run("x", "c", lambda: 1)
    assert info.value.rule == "per_hour" and info.value.count == 2
    clock.t += 2601  # first attempt leaves the window
    g.run("x", "d", lambda: 1)


def test_refused_call_is_not_sent():
    g, _ = gate(per_day=0)
    sent = []
    with pytest.raises(RateLimited):
        g.run("x", "t", lambda: sent.append(1))
    assert sent == []


def test_failed_send_still_counts():
    g, _ = gate(per_day=1)

    def boom():
        raise BusinessError(path="/p", code=5)

    with pytest.raises(BusinessError):
        g.run("x", "t", boom)
    with pytest.raises(RateLimited):
        g.run("x", "t", lambda: 1)


def test_dry_run_sends_nothing_and_does_not_consume_quota():
    clock = Clock()
    g = ActionGate(policies={"x": ActionPolicy(per_day=1)}, clock=clock, dry_run=True)
    sent = []
    assert g.run("x", "t", lambda: sent.append(1))["dry_run"] is True
    assert g.run("x", "t", lambda: sent.append(1))["dry_run"] is True
    assert sent == []


def test_ledger_survives_restart(tmp_path):
    path = tmp_path / "ledger.jsonl"
    clock = Clock()
    ActionGate(policies={"x": ActionPolicy(per_day=1)}, clock=clock, ledger_path=path).run(
        "x", "t", lambda: 1)
    with path.open("a") as handle:
        handle.write("{torn line\n")
    fresh = ActionGate(policies={"x": ActionPolicy(per_day=1)}, clock=clock, ledger_path=path)
    with pytest.raises(RateLimited):
        fresh.run("x", "t", lambda: 1)
    rows = [json.loads(line) for line in path.read_text().splitlines()[:1]]
    assert rows[0]["outcome"] == "ok" and rows[0]["sent"] is True


def test_unlimited():
    g = ActionGate.unlimited(policies={"x": ActionPolicy(per_day=0)})
    assert g.run("x", "t", lambda: 1) == 1


def test_default_gate_is_on_for_api():
    api = TiktokWebAPI(TiktokAuth("sessionid=x"))
    assert api.gate.enabled and api.gate.policy("comment").per_hour


GATED = {
    "post_comment": "comment", "post_comment_reply": "comment", "post_item_digg": "like",
    "post_item_collect": "collect", "post_follow_user": "follow", "send_im_message": "dm",
    "post_live_chat": "live_chat", "post_live_like": "live_like", "creator_publish": "publish",
    "creator_publish_photos": "publish", "post_project": "publish",
    "post_collection_create": "collection",
}


@pytest.mark.parametrize("name,action", sorted(GATED.items()))
def test_write_methods_are_gated(name, action):
    assert getattr(getattr(TiktokWebAPI, name), "__gated_action__", None) == action


def test_dry_run_api_write_never_builds_request(monkeypatch):
    api = TiktokWebAPI(TiktokAuth("sessionid=x"), gate=ActionGate(dry_run=True))
    monkeypatch.setattr(api, "_request_json", lambda *a, **k: pytest.fail("network reached"))
    out = api.post_item_digg("123")
    assert out == {"dry_run": True, "action": "like", "target": "123"}


def test_nested_gated_calls_count_once(monkeypatch):
    clock = Clock()
    g = ActionGate(policies={"publish": ActionPolicy(per_day=1)}, clock=clock)
    api = TiktokWebAPI(TiktokAuth("sessionid=x"), gate=g)

    from builder.action_gate import gated

    @gated("publish")
    def inner(self, x):
        return "inner"

    @gated("publish")
    def outer(self, x):
        return inner(self, x)

    assert outer(api, "v") == "inner"
    with pytest.raises(RateLimited):
        outer(api, "v")
