"""Resolve an official Docker Hub manifest and verify its digest, without Docker."""

import hashlib
import json
import urllib.request
from pathlib import Path

TAG = "3.11-slim-bookworm"
ROOT = Path(__file__).resolve().parents[1]
auth_endpoint = (
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull"
)
# Both requests target literal HTTPS URLs at the official Docker registry only.
with urllib.request.urlopen(auth_endpoint, timeout=30) as response:  # noqa: S310  # nosec B310
    token = json.load(response)["token"]
request = urllib.request.Request(
    f"https://registry-1.docker.io/v2/library/python/manifests/{TAG}",
    headers={
        "Authorization": f"Bearer {token}",
        "Accept": (
            "application/vnd.oci.image.index.v1+json,"
            "application/vnd.docker.distribution.manifest.list.v2+json"
        ),
    },
)
with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310  # nosec B310
    manifest = response.read()
    digest = response.headers["Docker-Content-Digest"]
if digest != "sha256:" + hashlib.sha256(manifest).hexdigest():
    raise RuntimeError("Registry manifest digest mismatch")
reference = f"python:{TAG}@{digest}"
(ROOT / "base-image.json").write_text(
    json.dumps(
        {
            "reference": reference,
            "registry": "registry-1.docker.io",
            "manifest": json.loads(manifest),
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
print(reference)
