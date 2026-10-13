"""Test safe archive handling without Docker or an external scanner."""

import importlib.util
import io
import tarfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "layer_scan", Path(__file__).resolve().parents[1] / "scripts/scan_image_layers.py"
)
layer_scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layer_scan)


@pytest.mark.parametrize("name", ["../escape", "/absolute/escape"])
def test_layer_traversal_rejected(tmp_path, name):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    data.seek(0)
    with tarfile.open(fileobj=data) as archive, pytest.raises(ValueError):
        layer_scan.regular_files(archive, tmp_path / "layer")


def test_layer_regular_files_only(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        member = tarfile.TarInfo("etc/public-config")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"safe"))
        link = tarfile.TarInfo("unsafe-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../escape"
        archive.addfile(link)
    data.seek(0)
    with tarfile.open(fileobj=data) as archive:
        layer_scan.regular_files(archive, tmp_path)
    assert (tmp_path / "etc/public-config").read_bytes() == b"safe"
    assert not (tmp_path / "unsafe-link").exists()
