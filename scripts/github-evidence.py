"""Bind promotion to a successful main CI run and its original immutable artifact ID."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

from policy import COMMIT, SHA, require


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def trusted_run(run, commit, repository, workflow):
    require(run["conclusion"] == "success" and run["status"] == "completed", "CI not successful")
    require(run["event"] == "push" and run["head_branch"] == "main", "Untrusted CI event/ref")
    require(
        run["head_sha"] == commit and run["repository"]["full_name"] == repository, "CI source substitution"
    )
    require(run["path"] == workflow, "Unapproved CI workflow")


def environment(name, repository):
    data = api(f"repos/{repository}/environments/{name}")
    reviewers = [rule for rule in data.get("protection_rules", []) if rule["type"] == "required_reviewers"]
    require(
        len(reviewers) == 1
        and reviewers[0].get("reviewers")
        and reviewers[0].get("prevent_self_review") is True,
        "Protected reviewer environment required",
    )
    require(
        data.get("deployment_branch_policy", {}).get("custom_branch_policies") is True,
        "Explicit environment branch restriction required",
    )
    branches = api(f"repos/{repository}/environments/{name}/deployment-branch-policies")
    require(
        branches["total_count"] == 1
        and branches["branch_policies"][0]["name"] == "main"
        and branches["branch_policies"][0].get("type", "branch") == "branch",
        "main-only environment required",
    )


def output(values):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as target:
            for key, value in values.items():
                require("\n" not in str(value), "Unsafe job output")
                target.write(f"{key}={value}\n")


def source(run_id, commit, repository):
    require(run_id.isdigit() and int(run_id) > 0 and COMMIT.fullmatch(commit), "Invalid CI source")
    run = api(f"repos/{repository}/actions/runs/{run_id}")
    trusted_run(run, commit, repository, ".github/workflows/ci-security.yml")
    jobs = api(f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100")
    qualified = [
        job
        for job in jobs["jobs"]
        if job["name"].endswith("Container qualification") and job["conclusion"] == "success"
    ]
    require(len(qualified) == 1, "No uniquely successful container qualification")
    logs = subprocess.check_output(
        ["gh", "api", f"repos/{repository}/actions/jobs/{qualified[0]['id']}/logs"], text=True
    )
    anchors = re.findall(r"RELEASE_ANCHOR (\{[^\r\n]*\})", logs)
    require(len(anchors) == 1, "Missing/ambiguous original artifact anchor")
    anchor = json.loads(anchors[0])
    require(
        anchor["commit"] == commit
        and anchor["repository"] == repository
        and re.fullmatch(r"[0-9a-f]{64}", anchor["sha256"]),
        "Invalid artifact anchor",
    )
    artifact = api(f"repos/{repository}/actions/artifacts/{anchor['id']}")
    require(
        not artifact["expired"] and artifact["name"] == "ci-candidate-" + commit,
        "Missing original candidate artifact",
    )
    require(
        artifact["workflow_run"]["id"] == int(run_id) and artifact["workflow_run"]["head_sha"] == commit,
        "Artifact source mismatch",
    )
    require(artifact["digest"] == "sha256:" + anchor["sha256"], "Artifact digest mismatch")
    output({"artifact_id": anchor["id"], "artifact_sha": anchor["sha256"], "commit": commit})


def download(artifact_id, expected, repository, directory):
    require(artifact_id.isdigit() and SHA.fullmatch("sha256:" + expected), "Invalid artifact request")
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive_path = directory.parent / "candidate.zip"
    with archive_path.open("wb") as target:
        subprocess.run(
            ["gh", "api", f"repos/{repository}/actions/artifacts/{artifact_id}/zip"],
            stdout=target,
            check=True,
        )
    require(
        hashlib.sha256(archive_path.read_bytes()).hexdigest() == expected, "Downloaded artifact substituted"
    )
    allowed = {
        "release-candidate.json",
        "build.json",
        "qualification.json",
        "provenance.buildkit.json",
        "sbom.cdx.json",
        "sbom.spdx.json",
        "image-layout/index.json",
        "image-layout/oci-layout",
    }
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            name = member.filename
            require(
                name in allowed or re.fullmatch(r"image-layout/blobs/sha256/[0-9a-f]{64}", name),
                "Unexpected candidate archive file",
            )
            target = (directory / name).resolve()
            require(target.is_relative_to(directory), "Unsafe artifact archive")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["anchor", "source", "download", "environments"])
    parser.add_argument("values", nargs="*")
    args = parser.parse_args()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    try:
        if args.command == "anchor":
            values = {
                "id": int(os.environ["ARTIFACT_ID"]),
                "sha256": os.environ["ARTIFACT_SHA"],
                "commit": os.environ["GITHUB_SHA"],
                "repository": repository,
            }
            require(re.fullmatch(r"[0-9a-f]{64}", values["sha256"]), "Invalid uploaded artifact digest")
            print("RELEASE" + "_ANCHOR " + json.dumps(values))
        elif args.command == "source":
            source(args.values[0], os.environ["GITHUB_SHA"], repository)
        elif args.command == "download":
            download(args.values[0], args.values[1], repository, args.values[2])
        else:
            for name in ("build-production", "sign-production", "release-production"):
                environment(name, repository)
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"BLOCK: {error}", file=sys.stderr)
        sys.exit(1)
