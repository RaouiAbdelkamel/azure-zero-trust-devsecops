"""Scan every saved image layer separately, including files deleted by later layers."""

import argparse
import json
import shutil

# Local CLI orchestration is required; every subprocess uses argv and shell=False.
import subprocess  # nosec B404
import tarfile
import tempfile
from pathlib import Path


def regular_files(archive: tarfile.TarFile, destination: Path) -> None:
    """Only regular bytes: no traversal, hardlinks, symlinks, devices or tar extraction."""
    root = destination.resolve()
    for member in archive:
        if not member.isfile():
            continue
        target = (root / member.name).resolve()
        if not target.is_relative_to(root):
            raise ValueError("Unsafe archive member")
        target.parent.mkdir(parents=True, exist_ok=True)
        content = archive.extractfile(member)
        if content is not None:
            with content, target.open("wb") as output:
                shutil.copyfileobj(content, output)


def run() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="secure-fastapi:phase2")
    parser.add_argument(
        "--scanner", type=Path, help="Explicit verified Gitleaks binary for Linux CI"
    )
    args = parser.parse_args()
    if args.image.startswith("-"):
        raise ValueError("Invalid image reference")
    app_root = Path(__file__).resolve().parents[1]
    scanner = (args.scanner or (app_root / "tools/gitleaks.exe")).resolve()
    if not scanner.is_file():
        raise RuntimeError("Run scripts/Install-Gitleaks.ps1 first")
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker executable not found")
    with tempfile.TemporaryDirectory(prefix="secure-api-layer-check-") as scratch:
        root = Path(scratch)
        saved_image = root / "image.tar"
        # Explicit argv, no shell, local Docker engine. No credential arguments.
        subprocess.run(  # noqa: S603  # nosec B603
            [docker, "image", "save", "--output", str(saved_image), args.image],
            check=True,
        )
        scan_root = root / "scan"
        scan_root.mkdir()
        with tarfile.open(saved_image) as archive:
            manifest_file = archive.extractfile("manifest.json")
            if manifest_file is None:
                raise ValueError("Docker save manifest missing")
            manifest = json.load(manifest_file)
            for image in manifest:
                config_file = archive.extractfile(image["Config"])
                if config_file is None:
                    raise ValueError("Image config missing")
                (scan_root / "image-config.json").write_bytes(config_file.read())
                for number, layer_name in enumerate(image["Layers"]):
                    layer_file = archive.extractfile(layer_name)
                    if layer_file is None:
                        raise ValueError("Image layer missing")
                    with layer_file, tarfile.open(fileobj=layer_file) as layer:
                        regular_files(layer, scan_root / f"layer-{number}")
        subprocess.run(  # noqa: S603  # nosec B603
            [str(scanner), "dir", str(scan_root), "--redact", "--no-banner"], check=True
        )
    print("All regular files in every saved layer and image config scanned by Gitleaks")


if __name__ == "__main__":
    run()
