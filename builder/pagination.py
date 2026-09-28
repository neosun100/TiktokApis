"""Response-owned cursor pagination with hard stop conditions."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .errors import TiktokError
from .limits import Limits


class PaginationError(TiktokError):
    """Pagination stopped abnormally; ``partial`` keeps what was collected."""

    def __init__(self, message: str, *, reason: str, partial: dict):
        self.reason = reason
        self.partial = partial
        super().__init__(f"{message} (reason={reason}, 已取 {partial['page_count']} 页)")


def paginate(fetch: Callable[[str], Any], validate: Callable[[Any], tuple[list, Any, bool]], *,
             start: str, max_pages: int | None, endpoint: str, rows_key: str) -> dict:
    """Follow server cursors until ``has_more`` is false.

    ``fetch(cursor)`` returns one raw page, ``validate(page)`` returns
    ``(rows, next_cursor, has_more)``.  Stops with :class:`PaginationError`
    (carrying the rows so far) on a repeated cursor, a run of empty pages, or
    the global page cap.
    """
    if max_pages is not None and int(max_pages) <= 0:
        raise ValueError("max_pages 必须大于 0")
    cap = min(int(max_pages), Limits.MAX_PAGES) if max_pages is not None else Limits.MAX_PAGES
    current, seen, rows, pages, empty_run = str(start), set(), [], 0, 0

    def result(cursor, has_more):
        return {rows_key: rows, "page_count": pages, "cursor": cursor, "has_more": has_more}

    while True:
        if current in seen:
            raise PaginationError(f"{endpoint} 返回了重复 cursor", reason="duplicate_cursor",
                                  partial=result(current, True))
        seen.add(current)
        page_rows, next_cursor, has_more = validate(fetch(current))
        rows.extend(page_rows)
        pages += 1
        empty_run = 0 if page_rows else empty_run + 1
        if not has_more:
            return result(next_cursor, False)
        if pages >= cap:
            if max_pages is not None and pages >= int(max_pages):
                return result(next_cursor, True)
            raise PaginationError(f"{endpoint} 超过全局页数上限 {Limits.MAX_PAGES}",
                                  reason="page_cap", partial=result(next_cursor, True))
        if empty_run >= Limits.MAX_CONSECUTIVE_EMPTY_PAGES:
            raise PaginationError(f"{endpoint} 连续 {empty_run} 页为空却声明 has_more",
                                  reason="empty_pages", partial=result(next_cursor, True))
        current = str(next_cursor)
