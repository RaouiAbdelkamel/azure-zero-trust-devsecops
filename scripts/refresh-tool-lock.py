"""Explicit reviewed versions -> immutable Action refs and verified release hashes."""

import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = {
    "actions/checkout": "v7.0.1",
    "actions/setup-python": "v7.0.0",
    "actions/upload-artifact": "v7.0.2",
    "actions/download-artifact": "v8.0.2",
    "docker/setup-buildx-action": "v4.4.1",
    "docker/build-push-action": "v7.4.0",
    "github/codeql-action": "v4.38.3",
    "Azure/login": "v3.1.0",
}
TOOLS = {
    "trivy": ("aquasecurity/trivy", "0.75.0", "trivy_{v}_Linux-64bit.tar.gz", "trivy_{v}_windows-64bit.zip"),
    "syft": ("anchore/syft", "1.54.1", "syft_{v}_linux_amd64.tar.gz", "syft_{v}_windows_amd64.zip"),
    "gitleaks": (
        "gitleaks/gitleaks",
        "8.30.1",
        "gitleaks_{v}_linux_x64.tar.gz",
        "gitleaks_{v}_windows_x64.zip",
    ),
    "oras": ("oras-project/oras", "1.3.4", "oras_{v}_linux_amd64.tar.gz", "oras_{v}_windows_amd64.zip"),
    "notation": (
        "notaryproject/notation",
        "1.3.2",
        "notation_{v}_linux_amd64.tar.gz",
        "notation_{v}_windows_amd64.zip",
    ),
    "azure-kv": (
        "Azure/notation-azure-kv",
        "1.2.1",
        "notation-azure-kv_{v}_linux_amd64.tar.gz",
        "notation-azure-kv_{v}_windows_amd64.zip",
    ),
    "actionlint": (
        "rhysd/actionlint",
        "1.7.12",
        "actionlint_{v}_linux_amd64.tar.gz",
        "actionlint_{v}_windows_amd64.zip",
    ),
}


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "secure-supply-chain-lock"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


previous = json.loads((ROOT / "security/toolchain.lock.json").read_text(encoding="utf-8"))
# Builder digest changes require an explicit registry-manifest review.
result = {
    "actions": {},
    "tools": {},
    "buildx_version": "v0.38.0",
    "buildkit_image": previous["buildkit_image"],
}
for repository, tag in ACTIONS.items():
    data = json.loads(fetch(f"https://api.github.com/repos/{repository}/commits/{tag}"))
    result["actions"][repository.lower()] = {
        "tag": tag,
        "sha": data["sha"],
        "github_commit_verified": data["commit"]["verification"]["verified"],
    }
for name, (repository, version, linux, windows) in TOOLS.items():
    checksums_name = f"{repository.split('/')[-1]}_{version}_checksums.txt"
    if name == "actionlint":
        checksums_name = f"actionlint_{version}_checksums.txt"
    base = f"https://github.com/{repository}/releases/download/v{version}"
    checksum_bytes = fetch(f"{base}/{checksums_name}")
    entries = {}
    for line in checksum_bytes.decode().splitlines():
        parts = line.split()
        if len(parts) == 2:
            entries[parts[1].lstrip("*")] = parts[0]
    result["tools"][name] = {
        "version": version,
        "repository": repository,
        "checksums_sha256": hashlib.sha256(checksum_bytes).hexdigest(),
        "platforms": {
            platform: {"url": f"{base}/{asset}", "sha256": entries[asset]}
            for platform, asset in [
                ("linux-amd64", linux.format(v=version)),
                ("windows-amd64", windows.format(v=version)),
            ]
        },
    }
(ROOT / "security").mkdir(exist_ok=True)
(ROOT / "security/toolchain.lock.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print("Action commits and seven tool releases resolved from official upstreams")
