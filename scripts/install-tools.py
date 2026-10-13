"""Install only explicitly locked binaries; no curl-to-shell or unverified extraction."""

import argparse
import hashlib
import io
import json
import os
import platform
import tarfile
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def install(name, locked, destination, target):
    entry = locked["tools"][name]
    asset = entry["platforms"][target]
    url = urlsplit(asset["url"])
    if (
        url.scheme != "https"
        or url.hostname != "github.com"
        or not url.path.startswith(f"/{entry['repository']}/releases/download/")
    ):
        raise ValueError("Unapproved tool download URL")
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "secure-api-ci"})
    with urllib.request.urlopen(request, timeout=120) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != asset["sha256"]:
        raise ValueError("Tool checksum mismatch")
    binary = "notation-azure-kv" if name == "azure-kv" else name
    if target.startswith("windows"):
        binary += ".exe"
    if asset["url"].endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            matches = [info for info in package.infolist() if Path(info.filename).name == binary]
            if len(matches) != 1:
                raise ValueError("Missing/ambiguous tool binary")
            content = package.read(matches[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(archive)) as package:
            matches = [m for m in package.getmembers() if m.isfile() and Path(m.name).name == binary]
            if len(matches) != 1:
                raise ValueError("Missing/ambiguous tool binary")
            content = package.extractfile(matches[0]).read()
    output = destination / binary
    output.write_bytes(content)
    if os.name != "nt":
        output.chmod(0o755)
    return {"tool": name, "version": entry["version"], "archive_sha256": asset["sha256"]}


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", nargs="+")
    args = parser.parse_args()
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("Toolchain currently qualified for amd64 only")
    target = "windows-amd64" if os.name == "nt" else "linux-amd64"
    locked = json.loads((ROOT / "security/toolchain.lock.json").read_text())
    destination = ROOT / ".tools/bin"
    destination.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda name: install(name, locked, destination, target), args.tools))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    run()
