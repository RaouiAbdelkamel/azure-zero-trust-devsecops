"""Test safe archive handling without Docker or an external scanner."""

import copy
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
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


@pytest.fixture
def reviewed_gpg(tmp_path):
    value = "GPG_KEY=" + "A" * 40
    text = json.dumps({"config": {"Env": [value]}}, separators=(",", ":"))
    source = tmp_path / "image-config.json"
    source.write_text(text, encoding="utf-8")
    start = text.index(value)
    fragment = text[start : start + len(value) + 1]
    review = {
        "id": "public-gpg",
        "owner": "security",
        "rule": "generic-api-key",
        "path": "image-config.json",
        "max_occurrences": 1,
        "expires": (datetime.now(UTC).date() + timedelta(days=10)).isoformat(),
        "justification": "Public test fingerprint",
        "compensating_control": "Exact scope",
        "occurrences": [
            {
                "line": 1,
                "json_path": ["config", "Env", 0],
                "scalar_sha256": hashlib.sha256(value.encode()).hexdigest(),
                "token_start_offset": 1,
                "token_end_offset": len(value) + 2,
                "match_sha256": hashlib.sha256(fragment.encode()).hexdigest(),
            }
        ],
    }
    policy = {"schema_version": 2, "max_duration_days": 30, "reviews": [review]}
    finding = {
        "File": str(source),
        "RuleID": "generic-api-key",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": start + 1,
        "EndColumn": start + len(fragment),
    }
    return source, policy, finding


def apply_review(tmp_path, policy, findings):
    report = tmp_path / "report.json"
    policy_file = tmp_path / "policy.json"
    report.write_text(json.dumps(findings), encoding="utf-8")
    policy_file.write_text(json.dumps(policy), encoding="utf-8")
    layer_scan.review_findings(report, tmp_path, policy_file)
    return json.loads(report.read_text(encoding="utf-8"))


def test_gpg_authorized_occurrence_accepted(tmp_path, reviewed_gpg):
    _, policy, finding = reviewed_gpg
    assert apply_review(tmp_path, policy, [finding])[0]["FalsePositiveReview"]["id"] == "public-gpg"


@pytest.mark.parametrize(
    "mutation",
    [
        "line",
        "extra",
        "unknown",
        "fingerprint",
        "expired",
        "column",
        "path",
        "context",
        "forged_approval",
    ],
)
def test_unapproved_occurrence_rejected(tmp_path, reviewed_gpg, mutation):
    source, policy, finding = reviewed_gpg
    findings = [copy.deepcopy(finding)]
    if mutation == "line":
        source.write_text("\n" + source.read_text(), encoding="utf-8")
        findings[0].update(StartLine=2, EndLine=2)
    elif mutation == "extra":
        findings.append(copy.deepcopy(finding))
    elif mutation == "unknown":
        findings[0]["RuleID"] = "github-pat"
    elif mutation == "fingerprint":
        source.write_text(source.read_text().replace("A" * 40, "B" * 40), encoding="utf-8")
    elif mutation == "expired":
        policy["reviews"][0]["expires"] = datetime.now(UTC).date().isoformat()
    elif mutation == "column":
        findings[0]["StartColumn"] += 1
    elif mutation == "path":
        other = tmp_path / "unapproved" / "image-config.json"
        other.parent.mkdir()
        other.write_bytes(source.read_bytes())
        findings[0]["File"] = str(other)
    elif mutation == "context":
        source.write_text(source.read_text().replace('"Env"', '"Bad"'), encoding="utf-8")
    else:
        findings[0].update(RuleID="github-pat", FalsePositiveReview={"id": "public-gpg"})
    with pytest.raises(ValueError):
        apply_review(tmp_path, policy, findings)
    saved = json.loads((tmp_path / "report.json").read_text())
    assert "FalsePositiveReview" not in saved[-1]


def test_json_duplicate_context_rejected():
    with pytest.raises(ValueError):
        layer_scan.json_string_spans('{"Env":"public","Env":"unexpected"}')


def test_real_gitleaks_oci_layer_secret_fails_and_reports_are_redacted(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    scanner = repository / ".tools" / "bin" / "gitleaks"
    if not scanner.is_file():
        scanner = scanner.with_suffix(".exe")
    if not scanner.is_file():
        scanner = Path(shutil.which("gitleaks") or "missing-gitleaks")
    assert scanner.is_file(), "Install the locked Gitleaks tool before running layer tests"
    token = "ghp_" + "Ab9Xy7Zq2Wp4Mn6Rs8Tu0Vc3De5Fg1Hi9Jk7L"
    content = ("access_token=" + token + "\n").encode()
    layer_path = tmp_path / "layer.tar"
    with tarfile.open(layer_path, "w") as archive:
        member = tarfile.TarInfo("etc/leaked-token")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    scan = tmp_path / "scan"
    with tarfile.open(layer_path) as archive:
        layer_scan.regular_files(archive, scan / "layer-0")
    report = tmp_path / "report.json"
    result = subprocess.run(  # noqa: S603
        [
            str(scanner.resolve()),
            "dir",
            str(scan),
            "--redact",
            "--no-banner",
            "--config",
            str(repository / "security/gitleaks/layers.gitleaks.toml"),
            "--report-format",
            "json",
            "--report-path",
            str(report),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert token not in result.stdout + result.stderr + report.read_text()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema_version": 2, "max_duration_days": 30, "reviews": []}))
    with pytest.raises(ValueError, match="Unreviewed"):
        layer_scan.review_findings(report, scan, policy)
    assert token not in report.read_text()
    assert all(f["Secret"] == f["Match"] == "REDACTED" for f in json.loads(report.read_text()))


def test_untrusted_report_values_redacted_even_with_expired_policy(tmp_path, reviewed_gpg):
    _, policy, finding = reviewed_gpg
    secret = "synthetic-sensitive-value"
    finding.update(Secret=secret, Match=secret, Description=secret, Extra=secret)
    policy["reviews"][0]["expires"] = datetime.now(UTC).date().isoformat()
    with pytest.raises(ValueError):
        apply_review(tmp_path, policy, [finding])
    assert secret not in (tmp_path / "report.json").read_text()


def test_oci_layer_digest_substitution_rejected():
    content = b"expected layer bytes"
    stream = io.BytesIO(content)
    layer_scan.verify_layer_digest(stream, "sha256:" + hashlib.sha256(content).hexdigest())
    assert stream.tell() == 0
    with pytest.raises(ValueError, match="diff ID"):
        layer_scan.verify_layer_digest(stream, "sha256:" + "0" * 64)


@pytest.fixture
def reviewed_file(tmp_path):
    content = b"public-key-symbol\n" * 9
    source = tmp_path / "layer-5" / "opt" / "fixture.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(content)
    line = content.splitlines(keepends=True)[0]
    occurrences = [
        {
            "line": n,
            "start_column": 1,
            "end_column": len(line),
            "line_sha256": hashlib.sha256(line).hexdigest(),
            "match_sha256": hashlib.sha256(line).hexdigest(),
        }
        for n in range(1, 10)
    ]
    review = {
        "id": "public-api",
        "owner": "security",
        "rule": "generic-api-key",
        "path": "layer-5/opt/fixture.py",
        "file_sha256": hashlib.sha256(content).hexdigest(),
        "max_occurrences": 9,
        "occurrences": occurrences,
        "expires": (datetime.now(UTC).date() + timedelta(days=10)).isoformat(),
        "justification": "Public API fixture",
        "compensating_control": "Exact occurrence bounds",
    }
    findings = [
        {
            "File": str(source),
            "RuleID": review["rule"],
            "StartLine": n,
            "EndLine": n,
            "StartColumn": 1,
            "EndColumn": len(line),
        }
        for n in range(1, 10)
    ]
    return source, {"schema_version": 2, "max_duration_days": 30, "reviews": [review]}, findings


def test_exact_nine_file_occurrences_accepted(tmp_path, reviewed_file):
    _, policy, findings = reviewed_file
    assert len(apply_review(tmp_path, policy, findings)) == 9


@pytest.mark.parametrize("mutation", ["tenth", "limit", "layer", "file_hash", "column", "context"])
def test_file_exception_exact_scope_rejected(tmp_path, reviewed_file, mutation):
    source, policy, findings = reviewed_file
    if mutation == "tenth":
        findings.append(copy.deepcopy(findings[-1]))
    elif mutation == "limit":
        policy["reviews"][0]["max_occurrences"] = 8
    elif mutation == "layer":
        other = tmp_path / "layer-6/opt/fixture.py"
        other.parent.mkdir(parents=True)
        other.write_bytes(source.read_bytes())
        findings[0]["File"] = str(other)
    elif mutation == "file_hash":
        source.write_bytes(source.read_bytes() + b"modified")
    elif mutation == "column":
        findings[0]["EndColumn"] -= 1
    else:
        policy["reviews"][0]["occurrences"][0]["line_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="Unreviewed"):
        apply_review(tmp_path, policy, findings)


@pytest.mark.parametrize("field", ["file_sha256", "line_sha256", "start_column"])
def test_incomplete_file_policy_rejected(tmp_path, reviewed_file, field):
    _, policy, findings = reviewed_file
    review = policy["reviews"][0]
    if field == "file_sha256":
        review.pop(field)
    else:
        review["occurrences"][0].pop(field)
    with pytest.raises(ValueError):
        apply_review(tmp_path, policy, findings)
