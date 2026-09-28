"""Local media preparation for Creator publishing (ffmpeg + Pillow, no network).

Guards: display (post-rotation) dimensions, poster orientation, temp-file
hygiene, error typing. Does not guard: what TikTok accepts server-side.
"""

import glob
import io
import os
import subprocess
import tempfile

import imageio_ffmpeg
import pytest
from PIL import Image

from api.tiktok_web import TiktokWebAPI
from builder.errors import BrowserEvidenceError

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()


def _make_video(tmp_path, name="plain.mp4", *, rotation=None, size="320x180"):
    plain = tmp_path / "src.mp4"
    subprocess.run([FFMPEG, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
                    "-i", f"testsrc=size={size}:duration=1:rate=10", "-pix_fmt", "yuv420p",
                    str(plain)], check=True)
    if rotation is None:
        return plain
    out = tmp_path / name
    subprocess.run([FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
                    "-display_rotation", str(rotation), "-i", str(plain), "-c", "copy",
                    str(out)], check=True)
    return out


def test_plain_video_metadata(tmp_path):
    info = TiktokWebAPI._prepare_creator_media(_make_video(tmp_path))
    assert (info["width"], info["height"]) == (320, 180)
    assert info["fps"] == 10
    assert 900 <= info["duration_ms"] <= 1100
    assert Image.open(io.BytesIO(info["poster_png"])).size == (320, 180)


def test_rotated_video_uses_display_dimensions(tmp_path):
    # Phone portrait clips are stored landscape + a 90-degree display matrix.
    info = TiktokWebAPI._prepare_creator_media(_make_video(tmp_path, rotation=90))
    assert (info["width"], info["height"]) == (180, 320)
    assert Image.open(io.BytesIO(info["poster_png"])).size == (180, 320)


def test_bytes_input_leaves_no_temp_file(tmp_path):
    raw = _make_video(tmp_path).read_bytes()
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "*.mp4")))
    TiktokWebAPI._prepare_creator_media(raw)
    assert set(glob.glob(os.path.join(tempfile.gettempdir(), "*.mp4"))) == before


def test_empty_bytes_rejected_without_temp_file():
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "*.mp4")))
    with pytest.raises(ValueError):
        TiktokWebAPI._prepare_creator_media(b"")
    assert set(glob.glob(os.path.join(tempfile.gettempdir(), "*.mp4"))) == before


def test_not_a_video_is_evidence_error(tmp_path):
    bogus = tmp_path / "x.mp4"
    bogus.write_bytes(b"not a video at all")
    with pytest.raises(BrowserEvidenceError):
        TiktokWebAPI._prepare_creator_media(bogus)


def test_wrong_type_rejected():
    with pytest.raises(TypeError):
        TiktokWebAPI._prepare_creator_media(123)
