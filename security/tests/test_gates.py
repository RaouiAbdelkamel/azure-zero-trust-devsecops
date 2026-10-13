import copy
import importlib.util
import json
from datetime import UTC, datetime, timedelta

import policy
import pytest
import yaml


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.fixture
def exception_policy(tmp_path):
    path = tmp_path / "exceptions.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "required_fields": [
                    "id",
                    "package",
                    "justification",
                    "owner",
                    "expires",
                    "compensating_control",
                ],
                "max_duration_days": 30,
                "exceptions": [],
            }
        )
    )
    return path


@pytest.mark.parametrize(
    "severity,blocked", [("CRITICAL", True), ("HIGH", True), ("MEDIUM", False), ("LOW", False)]
)
def test_trivy_threshold(tmp_path, exception_policy, severity, blocked):
    report = write(
        tmp_path / "scan.json",
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "Severity": severity,
                            "VulnerabilityID": "SYNTHETIC-TEST-ADVISORY",
                            "PkgName": "fixture",
                        }
                    ]
                }
            ],
        },
    )
    if blocked:
        with pytest.raises(ValueError):
            policy.trivy_gate(report, exception_policy)
    else:
        policy.trivy_gate(report, exception_policy)


def test_secret_blocked_and_redacted(tmp_path, exception_policy):
    report = write(
        tmp_path / "scan.json",
        {
            "SchemaVersion": 2,
            "Results": [{"Secrets": [{"Severity": "LOW", "ID": "test-secret", "Match": "SYNTHETIC-SECRET"}]}],
        },
    )
    with pytest.raises(ValueError):
        policy.trivy_gate(report, exception_policy)
    assert "SYNTHETIC-SECRET" not in report.read_text()


@pytest.mark.parametrize("delta", [-1, 0, 31])
def test_expired_or_excessive_exception(tmp_path, delta):
    today = datetime.now(UTC).date()
    path = tmp_path / "policy.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "max_duration_days": 30,
                "required_fields": ["id", "package", "owner", "expires"],
                "exceptions": [
                    {
                        "id": "SYNTHETIC-TEST-ADVISORY",
                        "package": "fixture",
                        "owner": "unit-test",
                        "expires": str(today + timedelta(days=delta)),
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError):
        policy.exceptions(path, today)


def test_exception_exact_package_only(tmp_path, exception_policy):
    document = yaml.safe_load(exception_policy.read_text())
    document["exceptions"] = [
        {
            "id": "SYNTHETIC-TEST-ADVISORY",
            "package": "approved",
            "owner": "unit-test",
            "justification": "Synthetic unit-test exception",
            "compensating_control": "Test only",
            "expires": str(datetime.now(UTC).date() + timedelta(days=1)),
        }
    ]
    exception_policy.write_text(yaml.safe_dump(document))
    report = write(
        tmp_path / "scan.json",
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "Severity": "HIGH",
                            "VulnerabilityID": "SYNTHETIC-TEST-ADVISORY",
                            "PkgName": "different",
                        }
                    ]
                }
            ],
        },
    )
    with pytest.raises(ValueError):
        policy.trivy_gate(report, exception_policy)


def test_unknown_dependency_and_missing_hash(tmp_path):
    lock, approved = tmp_path / "lock", tmp_path / "approved.json"
    write(approved, {"approved": "1.0"})
    lock.write_text("approved==1.0\n    --hash=sha256:" + "a" * 64 + "\n")
    policy.dependencies(lock, approved)
    lock.write_text(lock.read_text() + "unapproved==1.0\n --hash=sha256:" + "b" * 64)
    with pytest.raises(ValueError):
        policy.dependencies(lock, approved)
    lock.write_text("approved==1.0\n")
    with pytest.raises(ValueError):
        policy.dependencies(lock, approved)


@pytest.mark.parametrize("format", ["missing", "empty", "wrong"])
def test_mandatory_sbom(tmp_path, format):
    cdx = write(tmp_path / "cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": "fixture"}]})
    spdx = write(tmp_path / "spdx.json", {"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]})
    if format == "missing":
        cdx.unlink()
    elif format == "empty":
        write(cdx, {"bomFormat": "CycloneDX", "components": []})
    else:
        write(spdx, {"spdxVersion": "unknown", "packages": []})
    with pytest.raises((ValueError, OSError)):
        policy.sbom_gate(cdx, spdx)


@pytest.fixture
def release():
    value = {
        "commit": "a" * 40,
        "digest": "sha256:" + "b" * 64,
        "reference": "fixture.azurecr.io/secure-api@sha256:" + "b" * 64,
    }
    value.update(
        {
            name: "verified"
            for name in (
                "tests",
                "sast",
                "sca",
                "secrets",
                "runtime",
                "sbom",
                "notation_image",
                "notation_evidence",
                "provenance",
            )
        }
    )
    return value


@pytest.mark.parametrize(
    "field",
    [
        "tests",
        "sast",
        "sca",
        "secrets",
        "runtime",
        "sbom",
        "notation_image",
        "notation_evidence",
        "provenance",
    ],
)
def test_release_mandatory_control_blocks(release, field):
    # Synthetic metadata tests; do not assert an actual image/signature exists.
    release[field] = "failed"
    with pytest.raises(ValueError):
        policy.release_gate(release, "a" * 40, "sha256:" + "b" * 64)


def test_digest_substitution_blocks(release):
    with pytest.raises(ValueError):
        policy.release_gate(release, "a" * 40, "sha256:" + "c" * 64)
    release["reference"] = "fixture.azurecr.io/secure-api:latest"
    with pytest.raises(ValueError):
        policy.release_gate(release, "a" * 40, "sha256:" + "b" * 64)


def test_codeql_finding_blocks(tmp_path):
    path = write(tmp_path / "scan.sarif", {"version": "2.1.0", "runs": [{"results": [{"level": "warning"}]}]})
    with pytest.raises(ValueError):
        policy.sarif_gate(path)
    write(path, {"version": "2.1.0", "runs": [{"results": []}]})
    policy.sarif_gate(path)


def test_workflow_permissions_and_sha_mutation(tmp_path):
    directory = tmp_path / ".github/workflows"
    directory.mkdir(parents=True)
    (tmp_path / "security").mkdir()
    write(tmp_path / "security/toolchain.lock.json", {"actions": {"actions/checkout": {"sha": "a" * 40}}})
    workflow = {
        "on": {"pull_request": {}},
        "permissions": {"contents": "read"},
        "concurrency": {"group": "test"},
        "jobs": {
            "test": {
                "timeout-minutes": "5",
                "steps": [{"uses": "actions/checkout@" + "a" * 40, "with": {"persist-credentials": "false"}}],
            }
        },
    }
    path = directory / "ci-security.yml"
    path.write_text(yaml.safe_dump(workflow))
    policy.workflows(tmp_path)
    for change in ("mutable", "oidc", "bypass", "privileged_pr"):
        altered = copy.deepcopy(workflow)
        if change == "mutable":
            altered["jobs"]["test"]["steps"][0]["uses"] = "actions/checkout@v7"
        elif change == "oidc":
            altered["jobs"]["test"]["permissions"] = {"id-token": "write"}
        elif change == "bypass":
            altered["jobs"]["test"]["steps"][0]["continue-on-error"] = "true"
        else:
            altered["on"] = {"pull_request_target": {}}
        path.write_text(yaml.safe_dump(altered))
        with pytest.raises(ValueError):
            policy.workflows(tmp_path)


@pytest.fixture
def github_evidence():
    spec = importlib.util.spec_from_file_location(
        "github_evidence", policy.ROOT / "scripts/github-evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "change",
    [
        {"event": "pull_request"},
        {"head_branch": "attacker"},
        {"conclusion": "failure"},
        {"head_sha": "b" * 40},
    ],
)
def test_untrusted_source_ci_blocked(github_evidence, change):
    value = {
        "status": "completed",
        "conclusion": "success",
        "event": "push",
        "head_branch": "main",
        "head_sha": "a" * 40,
        "repository": {"full_name": "owner/repo"},
        "path": ".github/workflows/ci-security.yml",
    }
    with pytest.raises(ValueError):
        github_evidence.trusted_run(
            value | change, "a" * 40, "owner/repo", ".github/workflows/ci-security.yml"
        )


def test_azure_not_ready_blocks():
    config = policy.read_json(policy.ROOT / "security/azure-config.json")
    with pytest.raises(ValueError, match="not enabled"):
        policy.azure_config(config)


def test_actual_configuration_is_secure():
    policy.workflows()
    policy.dependencies(
        policy.ROOT / "app/requirements.lock", policy.ROOT / "security/approved-dependencies.json"
    )
