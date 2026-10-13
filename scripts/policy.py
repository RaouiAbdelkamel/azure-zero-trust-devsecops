"""Fail-closed security and artifact gates. No cloud success is synthesized here."""

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def redact(value):
    if isinstance(value, dict):
        return {
            key: "<redacted>"
            if key.lower() in {"match", "secret", "code", "snippet", "content"}
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def exceptions(path, today=None):
    import yaml

    policy = yaml.safe_load(Path(path).read_text())
    today = today or datetime.now(UTC).date()
    values = policy.get("exceptions", [])
    for exception in values:
        for field in policy["required_fields"]:
            require(bool(exception.get(field)), "Incomplete security exception")
        expiry = datetime.strptime(str(exception["expires"]), "%Y-%m-%d").date()
        require(
            today < expiry <= today + timedelta(days=policy["max_duration_days"]),
            "Expired or excessive security exception",
        )
    return values


def trivy_gate(path, exception_path):
    import yaml

    report = read_json(path)
    require(isinstance(report, dict) and report.get("SchemaVersion") == 2, "Missing/invalid Trivy report")
    approved = exceptions(exception_path)
    deviations = yaml.safe_load((ROOT / "security/policies/misconfiguration-deviations.yml").read_text())[
        "deviations"
    ]
    for deviation in deviations:
        expiry = datetime.strptime(str(deviation["expires"]), "%Y-%m-%d").date()
        require(datetime.now(UTC).date() < expiry, "Expired misconfiguration deviation")
        require(
            digest_file(ROOT / deviation["target"]) == deviation["source_sha256"],
            "Misconfiguration deviation source changed; review required",
        )
    blocked = []
    for result in report.get("Results", []) or []:
        for finding in result.get("Vulnerabilities", []) or []:
            if finding.get("Severity") not in {"HIGH", "CRITICAL"}:
                continue
            exempt = any(
                e["id"] == finding["VulnerabilityID"] and e["package"] == finding["PkgName"] for e in approved
            )
            if not exempt:
                blocked.append(finding["VulnerabilityID"])
        for field in ("Secrets", "Misconfigurations"):
            for finding in result.get(field, []) or []:
                if field == "Secrets" or finding.get("Severity") in {"HIGH", "CRITICAL"}:
                    if finding.get("Status", "FAIL") != "PASS":
                        reviewed = field == "Misconfigurations" and any(
                            d["id"] == finding.get("ID")
                            and d["target"] == result["Target"].replace("\\", "/")
                            and d["resource"] == finding.get("CauseMetadata", {}).get("Resource")
                            for d in deviations
                        )
                        if not reviewed:
                            blocked.append(finding.get("ID", "security-finding"))
    Path(path).write_text(json.dumps(redact(report), indent=2) + "\n", encoding="utf-8")
    require(not blocked, f"Security policy blocked {len(blocked)} finding(s): {', '.join(blocked)}")


def sarif_gate(path):
    report = read_json(path)
    require(
        report.get("version") == "2.1.0" and isinstance(report.get("runs"), list) and len(report["runs"]) > 0,
        "Missing/invalid SARIF report",
    )
    blocked = [
        r
        for run in report["runs"]
        for r in run.get("results", [])
        if r.get("level", "warning") in {"error", "warning"}
    ]
    Path(path).write_text(json.dumps(redact(report), indent=2) + "\n", encoding="utf-8")
    require(not blocked, f"CodeQL blocked {len(blocked)} finding(s)")


def dependencies(lock, approved):
    text = Path(lock).read_text()
    entries = re.findall(r"^([a-zA-Z0-9_.-]+)==([^\s\\]+)", text, re.M)
    pins = {name.lower().replace("_", "-"): version for name, version in entries}
    require(bool(pins) and len(pins) == len(entries), "Missing/duplicate dependency pins")
    require(pins == read_json(approved), "Unapproved dependency or version")
    blocks = re.split(r"(?m)^(?=[a-zA-Z0-9_.-]+==)", text)[1:]
    require(all("--hash=sha256:" in block for block in blocks), "Missing dependency integrity hash")
    require(
        not re.search(r"(?m)^\s*(?:--extra-index-url|--trusted-host|https?://|-e\s)", text),
        "Unapproved dependency source",
    )


def workflows(root=ROOT):
    import yaml

    lock = read_json(root / "security/toolchain.lock.json")["actions"]
    for path in (root / ".github/workflows").glob("*.yml"):
        data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        require(data.get("permissions") == {"contents": "read"}, "Excessive default permissions")
        require("pull_request_target" not in data.get("on", {}), "Privileged PR event prohibited")
        require(bool(data.get("concurrency")), "Missing concurrency control")
        for job in data["jobs"].values():
            require(
                bool(job.get("timeout-minutes"))
                or job.get("uses") == "./.github/workflows/container-build.yml",
                "Missing job timeout",
            )
            permissions = job.get("permissions", {})
            if permissions.get("id-token") == "write":
                require(
                    path.name in {"azure-publish-sign.yml", "verify-release.yml"}
                    and bool(job.get("environment")),
                    "OIDC outside protected Azure job",
                )
            for step in job.get("steps", []):
                require(step.get("continue-on-error") != "true", "Mandatory control bypass")
                action = step.get("uses", "")
                if not action:
                    continue
                repository = "/".join(action.split("/")[:2]).split("@")[0].lower()
                require(
                    "@" in action and COMMIT.fullmatch(action.rsplit("@", 1)[1]),
                    "Action not pinned to full commit",
                )
                require(
                    repository in lock and action.rsplit("@", 1)[1] == lock[repository]["sha"],
                    "Action commit not in reviewed lock",
                )
                if repository == "actions/checkout":
                    require(
                        step.get("with", {}).get("persist-credentials") == "false",
                        "Persisted checkout credentials",
                    )


def azure_config(config, root=ROOT):
    require(config["enabled"] is True, "Azure publication is not enabled/qualified")
    for name in ("subscription_id", "tenant_id", "build_client_id", "sign_client_id", "verify_client_id"):
        require(re.fullmatch(r"[0-9a-fA-F-]{36}", config.get(name, "")), f"Missing Azure {name}")
    require(
        len({config[n] for n in ("build_client_id", "sign_client_id", "verify_client_id")}) == 3,
        "Azure identities must be distinct",
    )
    require(re.fullmatch(r"[a-z0-9]+\.azurecr\.io", config["registry"]), "Invalid private registry")
    require(config["image_repository"] == "secure-api", "Unapproved image repository")
    require(
        re.fullmatch(
            r"https://[a-z0-9-]+\.vault\.azure\.net/keys/[a-zA-Z0-9-]+/[0-9a-f]{32}", config["key_id"]
        ),
        "Signing key must specify approved Key Vault version",
    )
    policy = read_json(root / "security/notation/trustpolicy.json")
    rules = policy.get("trustPolicies", [])
    require(len(rules) == 1, "Notation production trust is not provisioned")
    rule = rules[0]
    require(rule["registryScopes"] == [config["registry"] + "/secure-api"], "Overbroad registry trust")
    require(rule["signatureVerification"] == {"level": "strict"}, "Permissive verification policy")
    require(
        rule["trustedIdentities"] == ["x509.subject: " + config["trusted_subject"]]
        and "*" not in config["trusted_subject"],
        "Unapproved signing identity",
    )
    require(rule["trustStores"] == ["ca:production"], "Invalid trust store")
    certificate = root / config["root_certificate"]
    require(
        certificate.is_file() and digest_file(certificate) == config["root_certificate_sha256"],
        "Missing/unapproved trust root file",
    )
    require((root / config["ca_bundle"]).is_file(), "Missing approved public CA chain")


def sbom_gate(cyclonedx, spdx):
    cdx, spdx_data = read_json(cyclonedx), read_json(spdx)
    require(
        cdx.get("bomFormat") == "CycloneDX" and len(cdx.get("components", [])) > 0,
        "Missing/empty CycloneDX SBOM",
    )
    require(
        str(spdx_data.get("spdxVersion", "")).startswith("SPDX-") and len(spdx_data.get("packages", [])) > 0,
        "Missing/empty SPDX SBOM",
    )


def release_gate(record, expected_commit, expected_digest):
    require(COMMIT.fullmatch(expected_commit) and SHA.fullmatch(expected_digest), "Invalid release identity")
    require(
        record["commit"] == expected_commit and record["digest"] == expected_digest,
        "Release artifact substitution",
    )
    for field in (
        "tests",
        "sast",
        "sca",
        "secrets",
        "runtime",
        "sbom",
        "notation_image",
        "notation_evidence",
        "provenance",
    ):
        require(record.get(field) == "verified", f"Unverified mandatory release control: {field}")
    require(record["reference"].endswith("@" + expected_digest), "Mutable or mismatched release reference")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["workflows", "dependencies", "trivy", "sarif", "azure", "sbom", "release"]
    )
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    if args.command == "workflows":
        workflows()
        exceptions(ROOT / "security/policies/exception-policy.yml")
    elif args.command == "dependencies":
        dependencies(ROOT / "app/requirements.lock", ROOT / "security/approved-dependencies.json")
    elif args.command == "azure":
        azure_config(read_json(ROOT / "security/azure-config.json"))
    elif args.command == "trivy":
        trivy_gate(args.paths[0], ROOT / "security/policies/exception-policy.yml")
    elif args.command == "sarif":
        sarif_gate(args.paths[0])
    elif args.command == "sbom":
        sbom_gate(*args.paths)
    elif args.command == "release":
        release_gate(read_json(args.paths[0]), args.paths[1], args.paths[2])
    print(f"Policy gate passed: {args.command}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(f"BLOCK: {error}", file=sys.stderr)
        sys.exit(1)
