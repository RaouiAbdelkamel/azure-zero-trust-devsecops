"""Release metadata is emitted only after real CLI verification in the calling job."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from policy import COMMIT, ROOT, SHA, digest_file, read_json, release_gate, require, sbom_gate


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def candidate(path, output):
    build = read_json(path)
    require(build["commit"] == os.environ["GITHUB_SHA"], "Candidate source mismatch")
    record = {
        "version": build["version"],
        "commit": build["commit"],
        "digest": build["digest"],
        "reference": os.environ["IMAGE_REFERENCE"],
        "evidence_digest": os.environ["EVIDENCE_DIGEST"],
        "source_ci_run_id": build["run_id"],
        "repository": build["repository"],
        "sbom": "signed OCI evidence",
        "provenance": "signed OCI evidence",
        "notation_image": "verified",
        "notation_evidence": "verified",
    }
    require(SHA.fullmatch(record["evidence_digest"]), "Invalid evidence digest")
    Path(output).write_text(json.dumps(record, indent=2) + "\n")


def source(run_id):
    require(run_id.isdigit() and int(run_id) > 0, "Invalid signing workflow run")
    repository, commit = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    run = api(f"repos/{repository}/actions/runs/{run_id}")
    require(
        run["conclusion"] == "success"
        and run["status"] == "completed"
        and run["head_sha"] == commit
        and run["head_branch"] == "main"
        and run["event"] == "workflow_dispatch"
        and run["repository"]["full_name"] == repository
        and run["path"] == ".github/workflows/azure-publish-sign.yml",
        "Untrusted signing source",
    )
    jobs = api(f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100")
    signing = [
        job
        for job in jobs["jobs"]
        if job["name"] == "Sign image and provenance evidence" and job["conclusion"] == "success"
    ]
    require(len(signing) == 1, "No successful signing job")
    log = subprocess.check_output(
        ["gh", "api", f"repos/{repository}/actions/jobs/{signing[0]['id']}/logs"], text=True
    )
    anchors = re.findall(r"RELEASE_ANCHOR (\{[^\r\n]*\})", log)
    require(len(anchors) == 1, "Missing signing artifact anchor")
    anchor = json.loads(anchors[0])
    artifact = api(f"repos/{repository}/actions/artifacts/{anchor['id']}")
    require(
        artifact["workflow_run"]["id"] == int(run_id)
        and not artifact["expired"]
        and artifact["digest"] == "sha256:" + anchor["sha256"]
        and artifact["name"] == "signed-candidate-" + commit,
        "Signing artifact substitution",
    )
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"artifact_id={anchor['id']}\nartifact_sha={anchor['sha256']}\n")


def validate(record):
    config = read_json(ROOT / "security/azure-config.json")
    require(
        record["commit"] == os.environ["GITHUB_SHA"] and COMMIT.fullmatch(record["commit"]),
        "Release commit mismatch",
    )
    require(record["repository"] == os.environ["GITHUB_REPOSITORY"], "Release repository mismatch")
    require(
        SHA.fullmatch(record["digest"]) and SHA.fullmatch(record["evidence_digest"]),
        "Release digest malformed",
    )
    require(
        record["reference"] == config["registry"] + "/secure-api@" + record["digest"],
        "Release registry or digest mismatch",
    )


def finalize(candidate_file, evidence_directory, manifest_file, output):
    record = read_json(candidate_file)
    validate(record)
    manifest = read_json(manifest_file)
    require(
        digest_file(manifest_file) == record["evidence_digest"]
        and manifest["subject"]["digest"] == record["digest"],
        "Signed evidence subject mismatch",
    )
    directory = Path(evidence_directory)
    build = read_json(directory / "build.json")
    require(
        build["commit"] == record["commit"]
        and build["digest"] == record["digest"]
        and build["repository"] == record["repository"]
        and build["run_id"] == record["source_ci_run_id"],
        "Signed provenance source mismatch",
    )
    for name in ("sbom.cdx.json", "sbom.spdx.json", "qualification.json", "provenance.buildkit.json"):
        require(digest_file(directory / name) == build["files"][name], "Signed evidence hash mismatch")
    sbom_gate(directory / "sbom.cdx.json", directory / "sbom.spdx.json")
    qualification = read_json(directory / "qualification.json")
    require(
        all(qualification.get(name) is True for name in ("runtime", "image_scan", "layers_secrets", "sbom")),
        "Signed qualification incomplete",
    )
    provenance = read_json(directory / "provenance.buildkit.json")
    require(
        any(
            subject.get("digest", {}).get("sha256") == build["platform_manifest"].split(":")[1]
            for subject in provenance["subject"]
        ),
        "Signed provenance subject mismatch",
    )
    record.update(
        {
            name: "verified"
            for name in (
                "tests",
                "sast",
                "sca",
                "secrets",
                "runtime",
                "sbom",
                "provenance",
                "notation_image",
                "notation_evidence",
            )
        }
    )
    record["sbom_references"] = build["files"]
    record["provenance_reference"] = record["reference"].split("@")[0] + "@" + record["evidence_digest"]
    release_gate(record, record["commit"], record["digest"])
    Path(output).write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["candidate", "source", "validate-candidate", "finalize"])
    parser.add_argument("values", nargs="+")
    args = parser.parse_args()
    if args.command == "candidate":
        candidate(*args.values)
    elif args.command == "source":
        source(*args.values)
    elif args.command == "validate-candidate":
        validate(read_json(args.values[0]))
    else:
        finalize(*args.values)
