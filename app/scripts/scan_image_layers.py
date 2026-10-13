"""Scan every saved image layer separately, including files deleted by later layers."""

import argparse
import hashlib
import json
import shutil

# Local CLI orchestration is required; every subprocess uses argv and shell=False.
import subprocess  # nosec B404
import tarfile
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path


def review_findings(report: Path, scan_root: Path, policy: Path) -> None:
    """Classify only reviewed public fixtures bound to exact bytes and expiry."""
    data = json.loads(report.read_text(encoding="utf-8"))
    reviews = json.loads(policy.read_text(encoding="utf-8"))
    today = datetime.now(UTC).date()
    for review in reviews["reviews"]:
        expiry = datetime.strptime(review["expires"], "%Y-%m-%d").date()
        if not today < expiry <= today + timedelta(days=reviews["max_duration_days"]):
            raise ValueError("Expired layer false-positive review")
        if not all(
            review.get(field) for field in ("owner", "justification", "compensating_control")
        ):
            raise ValueError("Incomplete layer false-positive review")
    if not isinstance(data, list) or not data:
        raise ValueError("Scanner failed without a valid findings report")
    unresolved = 0
    for finding in data:
        path = Path(finding["File"]).resolve()
        if not path.is_relative_to(scan_root.resolve()) or not path.is_file():
            raise ValueError("Unexpected layer finding source")
        content = path.read_bytes()
        approved = None
        for review in reviews["reviews"]:
            if finding["RuleID"] != review["rule"] or not path.as_posix().endswith(
                review["suffix"]
            ):
                continue
            if "file_sha256" in review:
                if (
                    hashlib.sha256(content).hexdigest() == review["file_sha256"]
                    and finding["StartLine"] == finding["EndLine"]
                    and finding["StartLine"] in review["lines"]
                ):
                    approved = review
            elif "match_sha256" in review and path.name == "image-config.json":
                if finding["StartLine"] == finding["EndLine"]:
                    line = content.splitlines()[finding["StartLine"] - 1]
                    match = line[finding["StartColumn"] - 1 : finding["EndColumn"]]
                    if hashlib.sha256(match).hexdigest() == review["match_sha256"]:
                        approved = review
        if approved:
            finding["FalsePositiveReview"] = {
                field: approved[field] for field in ("id", "owner", "expires", "justification")
            }
        else:
            unresolved += 1
    report.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if unresolved:
        raise ValueError(f"Unreviewed layer findings: {unresolved}")
    print(f"Reviewed public fixtures only: {len(data)}; no unreviewed layer findings")


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
    parser.add_argument("--report", type=Path, help="Preserve a redacted JSON findings report")
    parser.add_argument(
        "--config", type=Path, help="Reviewed Gitleaks rules without library path exclusions"
    )
    parser.add_argument(
        "--finding-policy", type=Path, help="Exact, expiring public-fixture classifications"
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
        command = [str(scanner), "dir", str(scan_root), "--redact", "--no-banner"]
        if args.config:
            command.extend(["--config", str(args.config.resolve())])
        if args.report:
            report = args.report.resolve()
            report.parent.mkdir(parents=True, exist_ok=True)
            report.unlink(missing_ok=True)
            command.extend(["--report-format", "json", "--report-path", str(report)])
        result = subprocess.run(command, check=False)  # noqa: S603  # nosec B603
        if result.returncode == 1 and args.finding_policy and args.report:
            review_findings(report, scan_root, args.finding_policy)
        elif result.returncode:
            raise ValueError("Layer scanner failed")
    print("All regular files in every saved layer and image config scanned by Gitleaks")


if __name__ == "__main__":
    run()
