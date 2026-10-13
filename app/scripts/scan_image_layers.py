"""Scan every saved image layer separately, including files deleted by later layers."""

import argparse
import gzip
import hashlib
import json
import shutil

# Local CLI orchestration is required; every subprocess uses argv and shell=False.
import subprocess  # nosec B404
import tarfile
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path


def json_string_spans(text: str) -> dict[tuple, tuple[str, int, int]]:
    """Parse JSON and retain exact string-value offsets and semantic paths."""
    json.loads(text)  # Validate complete JSON grammar before collecting token spans.
    decoder = json.JSONDecoder()
    spans = {}

    def whitespace(position):
        while position < len(text) and text[position].isspace():
            position += 1
        return position

    def walk(position, path):
        position = whitespace(position)
        if text[position] == "{":
            position = whitespace(position + 1)
            keys = set()
            while text[position] != "}":
                key, position = decoder.raw_decode(text, position)
                if not isinstance(key, str) or key in keys:
                    raise ValueError("Duplicate or invalid JSON key")
                keys.add(key)
                position = whitespace(position)
                if text[position] != ":":
                    raise ValueError("Invalid JSON object")
                position = whitespace(walk(position + 1, (*path, key)))
                if text[position] == "}":
                    break
                if text[position] != ",":
                    raise ValueError("Invalid JSON object separator")
                position = whitespace(position + 1)
            return position + 1
        if text[position] == "[":
            position = whitespace(position + 1)
            index = 0
            while text[position] != "]":
                position = whitespace(walk(position, (*path, index)))
                index += 1
                if text[position] == "]":
                    break
                if text[position] != ",":
                    raise ValueError("Invalid JSON array separator")
                position = whitespace(position + 1)
            return position + 1
        value, end = decoder.raw_decode(text, position)
        if isinstance(value, str):
            spans[path] = (value, position, end)
        return end

    if whitespace(walk(0, ())) != len(text):
        raise ValueError("Trailing image config data")
    return spans


def occurrence_matches(finding: dict, content: bytes, occurrence: dict) -> bool:
    """Bind coordinates to full file bytes or an exact JSON scalar and path."""
    start, end = finding["StartLine"], finding["EndLine"]
    if start != end or start != occurrence["line"]:
        return False
    first, last = finding["StartColumn"], finding["EndColumn"]
    if not isinstance(first, int) or not isinstance(last, int) or not 0 < first <= last:
        return False
    lines = content.splitlines(keepends=True)
    if not 0 < start <= len(lines) or last > len(lines[start - 1]):
        return False
    match = lines[start - 1][first - 1 : last]
    if hashlib.sha256(match).hexdigest() != occurrence["match_sha256"]:
        return False
    if "json_path" not in occurrence:
        return (
            first == occurrence["start_column"]
            and last == occurrence["end_column"]
            and hashlib.sha256(lines[start - 1]).hexdigest() == occurrence["line_sha256"]
        )
    # JSON token offsets may move as build labels change; semantic path cannot move.
    text = content.decode("utf-8")
    scalar = json_string_spans(text).get(tuple(occurrence["json_path"]))
    if scalar is None:
        return False
    value, offset, stop = scalar
    if hashlib.sha256(value.encode()).hexdigest() != occurrence["scalar_sha256"]:
        return False
    match_start = offset + occurrence["token_start_offset"]
    match_end = offset + occurrence["token_end_offset"]
    if not offset < match_start < match_end <= stop:
        return False
    prefix = text[:match_start].encode()
    expected_line = prefix.count(b"\n") + 1
    expected_column = len(prefix.rsplit(b"\n", 1)[-1]) + 1
    return (
        start == expected_line
        and first == expected_column
        and last == expected_column + len(text[match_start:match_end].encode()) - 1
    )


def validate_review_scope(review: dict) -> None:
    """Reject incomplete policy scopes instead of weakening matcher constraints."""
    path = review["path"]
    if (
        not isinstance(path, str)
        or "\\" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise ValueError("Invalid exact review path")
    config = path == "image-config.json"
    if not config and not (
        path.startswith("layer-") and path.split("/", 1)[0].removeprefix("layer-").isdigit()
    ):
        raise ValueError("Missing exact OCI layer ordinal")
    hashes = [] if config else [review.get("file_sha256", "")]
    slots = set()
    for occurrence in review["occurrences"]:
        if type(occurrence.get("line")) is not int or occurrence["line"] < 1:
            raise ValueError("Invalid occurrence line")
        hashes.append(occurrence.get("match_sha256", ""))
        if config:
            if not occurrence.get("json_path"):
                raise ValueError("Missing exact image-config context")
            hashes.append(occurrence.get("scalar_sha256", ""))
            first, last = occurrence.get("token_start_offset"), occurrence.get("token_end_offset")
            slot = tuple(occurrence["json_path"])
        else:
            hashes.append(occurrence.get("line_sha256", ""))
            first, last = occurrence.get("start_column"), occurrence.get("end_column")
            slot = (occurrence["line"], first, last)
        if type(first) is not int or type(last) is not int or not 0 < first <= last:
            raise ValueError("Invalid occurrence columns or offsets")
        if slot in slots:
            raise ValueError("Duplicate policy occurrence")
        slots.add(slot)
    if any(
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
        for value in hashes
    ):
        raise ValueError("Missing or invalid SHA-256 context binding")


def review_findings(report: Path, scan_root: Path, policy: Path) -> None:
    """Fail closed on unknown, displaced, modified, expired or excess occurrences."""
    data = json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        report.write_text("[]\n", encoding="utf-8")
        raise ValueError("Scanner failed without a valid findings report")
    # Persist only safe coordinates and rule IDs, even when policy validation fails.
    safe_fields = ("RuleID", "File", "StartLine", "EndLine", "StartColumn", "EndColumn")
    data = [{key: item[key] for key in safe_fields if key in item} for item in data]
    for finding in data:
        finding.update(dict.fromkeys(("Secret", "Match"), "REDACTED"))
    report.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    reviews = json.loads(policy.read_text(encoding="utf-8"))
    if reviews.get("schema_version") != 2:
        raise ValueError("Unsupported layer review schema")
    duration = reviews.get("max_duration_days")
    if type(duration) is not int or not 0 < duration <= 30:
        raise ValueError("Invalid review maximum duration")
    today = datetime.now(UTC).date()
    identifiers = set()
    for review in reviews["reviews"]:
        expiry = datetime.strptime(review["expires"], "%Y-%m-%d").date()
        if not today < expiry <= today + timedelta(days=reviews["max_duration_days"]):
            raise ValueError("Expired layer false-positive review")
        if not all(
            review.get(field)
            for field in (
                "id",
                "owner",
                "justification",
                "compensating_control",
                "path",
                "rule",
                "occurrences",
            )
        ):
            raise ValueError("Incomplete layer false-positive review")
        if review["id"] in identifiers:
            raise ValueError("Duplicate review identifier")
        identifiers.add(review["id"])
        validate_review_scope(review)
        if type(review.get("max_occurrences")) is not int or not (
            0 < review["max_occurrences"] <= len(review["occurrences"])
        ):
            raise ValueError("Invalid review occurrence limit")
    used = set()
    counts = {}
    unresolved = 0
    for finding in data:
        path = Path(finding["File"]).resolve()
        if not path.is_relative_to(scan_root.resolve()) or not path.is_file():
            raise ValueError("Unexpected layer finding source")
        relative = path.relative_to(scan_root.resolve()).as_posix()
        content = path.read_bytes()
        candidates = []
        for review in reviews["reviews"]:
            if finding["RuleID"] != review["rule"] or relative != review["path"]:
                continue
            if (
                "file_sha256" in review
                and hashlib.sha256(content).hexdigest() != review["file_sha256"]
            ):
                continue
            for index, occurrence in enumerate(review["occurrences"]):
                if occurrence_matches(finding, content, occurrence):
                    candidates.append((review, index))
        if len(candidates) == 1:
            approved, index = candidates[0]
            identity = (approved["id"], index)
            count = counts.get(approved["id"], 0)
            if identity not in used and count < approved["max_occurrences"]:
                used.add(identity)
                counts[approved["id"]] = count + 1
                finding["FalsePositiveReview"] = {
                    field: approved[field] for field in ("id", "owner", "expires", "justification")
                }
                continue
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


def verify_layer_digest(stream, expected: str) -> None:
    """Bind extracted bytes to the image rootfs uncompressed OCI diff ID."""
    prefix = stream.read(2)
    stream.seek(0)
    reader = gzip.GzipFile(fileobj=stream) if prefix == b"\x1f\x8b" else stream
    digest = hashlib.sha256()
    try:
        while chunk := reader.read(1024 * 1024):
            digest.update(chunk)
    finally:
        if reader is not stream:
            reader.close()
        stream.seek(0)
    if "sha256:" + digest.hexdigest() != expected:
        raise ValueError("OCI layer diff ID mismatch")


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
            if len(manifest) != 1:
                raise ValueError("Expected exactly one saved image")
            for image in manifest:
                config_file = archive.extractfile(image["Config"])
                if config_file is None:
                    raise ValueError("Image config missing")
                config_bytes = config_file.read()
                config = json.loads(config_bytes)
                diff_ids = config["rootfs"]["diff_ids"]
                if len(diff_ids) != len(image["Layers"]):
                    raise ValueError("Image layer inventory mismatch")
                (scan_root / "image-config.json").write_bytes(config_bytes)
                for number, layer_name in enumerate(image["Layers"]):
                    layer_file = archive.extractfile(layer_name)
                    if layer_file is None:
                        raise ValueError("Image layer missing")
                    verify_layer_digest(layer_file, diff_ids[number])
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
