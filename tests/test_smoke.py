"""Import-graph smoke test: the public entry points load with the locked deps."""

import importlib

import pytest


@pytest.mark.parametrize("module", ["api", "builder", "signing", "utils", "demo"])
def test_public_modules_import(module):
    importlib.import_module(module)


def test_public_api_surface():
    import api

    assert set(api.__all__) == {"TikTokWebAPI", "TiktokAPI", "TiktokLoginAPI", "TiktokWebAPI"}
    assert issubclass(api.TiktokAPI, api.TiktokWebAPI)
