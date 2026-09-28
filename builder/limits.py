"""Every numeric safety threshold of the client, in one place.

Each value states what it protects against.  Browser-wire constants (field
lengths, SDK versions) are *not* here — they are evidence, not policy.
"""

from __future__ import annotations


class Limits:
    # Pagination: TikTok's anti-crawl answer can be an endless run of empty
    # pages with fresh cursors and has_more=1.
    MAX_PAGES = 500
    MAX_CONSECUTIVE_EMPTY_PAGES = 3

    # Live WS: (method, message_id) dedup window; a busy room pushes tens of
    # events per second for hours.
    LIVE_SEEN_WINDOW = 20_000
    # Used only when neither the fetch nor a frame supplies heartbeat_duration.
    LIVE_DEFAULT_HEARTBEAT_S = 10.0

    # A LiveResponse batch is KiB..hundreds of KiB; more is a gzip bomb.
    MAX_DECOMPRESSED_FRAME_BYTES = 16 * 1024 * 1024

    # Upload budget = request timeout + payload / this rate, so a large clip
    # on a slow uplink is not cut off by curl's whole-request timeout.
    UPLOAD_MIN_BYTES_PER_SECOND = 256 * 1024
