"""Cursor pagination stop conditions (generic helper + its two users)."""

import pytest

from api.tiktok_web import TiktokWebAPI
from builder.auth import TiktokAuth
from builder.limits import Limits
from builder.pagination import PaginationError, paginate


def page(rows, cursor, more):
    return {"comments": rows, "cursor": cursor, "has_more": more}


def run(pages, **kw):
    it = iter(pages)
    return paginate(lambda c: next(it), lambda p: TiktokWebAPI._comment_page_values(p, endpoint="t"),
                    start="0", endpoint="t", rows_key="comments", **kw)


def test_follows_cursors_to_end():
    out = run([page([1], 10, 1), page([2], 20, 0)], max_pages=None)
    assert out == {"comments": [1, 2], "page_count": 2, "cursor": 20, "has_more": False}


def test_max_pages_stops_cleanly():
    out = run([page([1], 10, 1), page([2], 20, 1)], max_pages=1)
    assert out["page_count"] == 1 and out["has_more"] is True


def test_duplicate_cursor_keeps_partial():
    with pytest.raises(PaginationError) as info:
        run([page([1], 10, 1), page([2], 0, 1)], max_pages=None)
    assert info.value.reason == "duplicate_cursor"
    assert info.value.partial["comments"] == [1, 2]


def test_endless_empty_pages_stop():
    pages = [page([], i + 1, 1) for i in range(50)]
    with pytest.raises(PaginationError) as info:
        run(pages, max_pages=None)
    assert info.value.reason == "empty_pages"
    assert info.value.partial["page_count"] == Limits.MAX_CONSECUTIVE_EMPTY_PAGES


def test_global_cap(monkeypatch):
    monkeypatch.setattr(Limits, "MAX_PAGES", 5)
    with pytest.raises(PaginationError) as info:
        run([page([i], i + 1, 1) for i in range(20)], max_pages=None)
    assert info.value.reason == "page_cap"


def test_zero_max_pages_rejected():
    with pytest.raises(ValueError):
        run([], max_pages=0)


def test_shop_reviews_pagination(monkeypatch):
    api = TiktokWebAPI(TiktokAuth("sessionid=x"))
    monkeypatch.setattr(api, "get_shop_product_reviews",
                        lambda *a, **k: {"product_reviews": [1], "has_more": True, "total_reviews": 3})
    later = iter([{"product_reviews": [2], "has_more": True}, {"product_reviews": [3], "has_more": False}])
    starts = []

    def page_fn(url, *, page_start, **kw):
        starts.append(page_start)
        return next(later)

    monkeypatch.setattr(api, "get_shop_product_review_page", page_fn)
    out = api.get_all_shop_product_reviews("https://shop.tiktok.com/view/product/1")
    assert out["product_reviews"] == [1, 2, 3] and starts == [2, 3] and len(out["pages"]) == 3


def test_shop_reviews_endless_empty_stops(monkeypatch):
    api = TiktokWebAPI(TiktokAuth("sessionid=x"))
    monkeypatch.setattr(api, "get_shop_product_reviews",
                        lambda *a, **k: {"product_reviews": [], "has_more": True})
    monkeypatch.setattr(api, "get_shop_product_review_page",
                        lambda *a, **k: {"product_reviews": [], "has_more": True})
    with pytest.raises(PaginationError):
        api.get_all_shop_product_reviews("u")
