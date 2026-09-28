"""Process environment for the bundled vendor-JavaScript runners.

The runners execute obfuscated TikTok SDK code (``vm.runInThisContext`` has
full ``process`` access; Node's vm is not a security boundary).  They must
never inherit the parent environment, which typically holds GitHub/AWS/proxy
tokens and possibly ``TIKTOK_COOKIE``.
"""

from __future__ import annotations

import os

# Only what Node itself needs to start and locate temp/locale files.
_PASSTHROUGH = ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SYSTEMROOT")


def minimal_env(**extra: str) -> dict[str, str]:
    env = {key: os.environ[key] for key in _PASSTHROUGH if key in os.environ}
    env.update({key: str(value) for key, value in extra.items()})
    return env
