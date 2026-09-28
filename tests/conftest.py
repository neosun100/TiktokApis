import json

import pytest


class FakeResponse:
    """Minimal stand-in for a curl_cffi response."""

    def __init__(self, status_code=200, body=None, *, headers=None,
                 url="https://www.tiktok.com/api/x/?msToken=SECRET&X-Bogus=SIG"):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.url = url
        if body is None:
            self.content = b""
        elif isinstance(body, bytes):
            self.content = body
        else:
            self.content = json.dumps(body).encode()

    def json(self):
        return json.loads(self.content)

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")


@pytest.fixture
def fake_response():
    return FakeResponse
