"""Bundled WebMssdk runner smoke tests (need Node; skipped without it)."""

import hashlib
import shutil

import pytest

from builder.signer import SignerError, TiktokSigner

pytestmark = [
    pytest.mark.node,
    pytest.mark.skipif(shutil.which("node") is None, reason="node not installed"),
]

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")


def test_frontier_sign_marker_shape():
    marker = TiktokSigner().frontier_sign(cookie="a=b", user_agent=UA,
                                          referer="https://www.tiktok.com/live")
    assert len(marker) == 16


def test_frontier_sign_with_im_stub():
    stub = hashlib.md5(b"request").hexdigest()
    marker = TiktokSigner().frontier_sign(cookie="a=b", user_agent=UA,
                                          referer="https://www.tiktok.com/messages", stub=stub)
    assert len(marker) == 16


@pytest.mark.parametrize("stub", ["ABC", "g" * 32, "A" * 32])
def test_frontier_rejects_bad_stub(stub):
    with pytest.raises(SignerError):
        TiktokSigner().frontier_sign(cookie="", user_agent=UA, stub=stub)


def test_missing_node_binary_is_signer_error():
    with pytest.raises(SignerError):
        TiktokSigner(node="/nonexistent/node").frontier_sign(cookie="", user_agent=UA)
