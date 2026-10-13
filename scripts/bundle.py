"""OCI graph integrity, immutable build identity, evidence hashes; no image rebuilding."""

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

from policy import COMMIT, SHA, digest_file, read_json, require, sbom_gate


def graph(layout, descriptor, visited=None):
    visited = visited or set()
    digest = descriptor["digest"]
    require(SHA.fullmatch(digest), "Invalid OCI digest")
    if digest in visited:
        return
    visited.add(digest)
    path = layout / "blobs/sha256" / digest.split(":")[1]
    require(path.is_file() and digest_file(path) == digest, "OCI blob digest mismatch")
    require(path.stat().st_size == descriptor["size"], "OCI blob size mismatch")
    media = descriptor["mediaType"]
    if media in {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }:
        value = read_json(path)
        for child in value.get("manifests", []) + value.get("layers", []):
            graph(layout, child, visited)
        if "config" in value:
            graph(layout, value["config"], visited)


def prepare(directory, commit, repository):
    require(COMMIT.fullmatch(commit), "Invalid source commit")
    layout = directory / "image-layout"
    # Save the unmodified BuildKit index as a content-addressed blob. Local wrapper
    # adds a deterministic name for ORAS; registry content digest stays unchanged.
    index_bytes = (layout / "index.json").read_bytes()
    index = json.loads(index_bytes)
    # OCI exporters may wrap the actual image index with a layout index.
    if (
        len(index["manifests"]) == 1
        and index["manifests"][0]["mediaType"] == "application/vnd.oci.image.index.v1+json"
    ):
        existing = index["manifests"][0]
        graph(layout, existing)
        index_bytes = (layout / "blobs/sha256" / existing["digest"].split(":")[1]).read_bytes()
        index = json.loads(index_bytes)
    digest = "sha256:" + hashlib.sha256(index_bytes).hexdigest()
    (layout / "blobs/sha256" / digest.split(":")[1]).write_bytes(index_bytes)
    descriptor = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "digest": digest,
        "size": len(index_bytes),
        "annotations": {"org.opencontainers.image.ref.name": "ci"},
    }
    (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [descriptor]}))
    graph(layout, descriptor)
    platforms = [
        entry
        for entry in index["manifests"]
        if entry.get("platform") == {"architecture": "amd64", "os": "linux"}
    ]
    require(len(platforms) == 1, "Expected one Linux amd64 image")
    image = read_json(layout / "blobs/sha256" / platforms[0]["digest"].split(":")[1])
    attestations = []
    for entry in index["manifests"]:
        if entry.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
            manifest = read_json(layout / "blobs/sha256" / entry["digest"].split(":")[1])
            for layer in manifest["layers"]:
                statement = read_json(layout / "blobs/sha256" / layer["digest"].split(":")[1])
                if statement.get("predicateType", "").startswith("https://slsa.dev/provenance/"):
                    require(
                        any(
                            s.get("digest", {}).get("sha256") == platforms[0]["digest"].split(":")[1]
                            for s in statement["subject"]
                        ),
                        "Provenance subject mismatch",
                    )
                    attestations.append(statement)
    require(len(attestations) == 1, "BuildKit provenance is mandatory")
    (directory / "provenance.buildkit.json").write_text(json.dumps(attestations[0], indent=2) + "\n")
    metadata = {
        "version": "1.0.0",
        "commit": commit,
        "repository": repository,
        "digest": digest,
        "platform_manifest": platforms[0]["digest"],
        "config_digest": image["config"]["digest"],
        "workflow": ".github/workflows/ci-security.yml",
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "files": {},
    }
    (directory / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(digest)


def runtime_export(directory, output):
    """Convert the qualified OCI platform into a Docker-save tar without rebuilding."""
    record = read_json(directory / "build.json")
    layout = directory / "image-layout"
    graph(layout, read_json(layout / "index.json")["manifests"][0])
    manifest = read_json(layout / "blobs/sha256" / record["platform_manifest"].split(":")[1])
    config_path = layout / "blobs/sha256" / record["config_digest"].split(":")[1]
    require(manifest["config"]["digest"] == record["config_digest"], "Runtime config mismatch")
    config = read_json(config_path)
    diff_ids = config["rootfs"]["diff_ids"]
    require(len(diff_ids) == len(manifest["layers"]), "Runtime layer count mismatch")
    config_name = record["config_digest"].split(":")[1] + ".json"
    layers = []
    with tarfile.open(output, "w") as archive:
        archive.add(config_path, arcname=config_name, recursive=False)
        for number, layer in enumerate(manifest["layers"]):
            compressed = layout / "blobs/sha256" / layer["digest"].split(":")[1]
            media = layer["mediaType"]
            require(
                media
                in {
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "application/vnd.oci.image.layer.v1.tar",
                },
                "Unsupported runtime layer encoding",
            )
            source = (
                gzip.open(compressed, "rb") if media.endswith(("+gzip", ".gzip")) else compressed.open("rb")
            )
            with source, tempfile.TemporaryFile() as unpacked:
                shutil.copyfileobj(source, unpacked)
                size = unpacked.tell()
                unpacked.seek(0)
                actual = hashlib.file_digest(unpacked, "sha256").hexdigest()
                require("sha256:" + actual == diff_ids[number], "Uncompressed runtime layer mismatch")
                unpacked.seek(0)
                name = f"{actual}/layer.tar"
                info = tarfile.TarInfo(name)
                info.size = size
                archive.addfile(info, unpacked)
                layers.append(name)
        docker_manifest = json.dumps(
            [{"Config": config_name, "RepoTags": ["secure-fastapi:ci"], "Layers": layers}]
        ).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(docker_manifest)
        archive.addfile(info, io.BytesIO(docker_manifest))
    print("Docker runtime archive derived from verified OCI config and layer diff IDs")


def seal(directory):
    sbom_gate(directory / "sbom.cdx.json", directory / "sbom.spdx.json")
    record = read_json(directory / "build.json")
    record["files"] = {
        name: digest_file(directory / name)
        for name in ("sbom.cdx.json", "sbom.spdx.json", "provenance.buildkit.json", "qualification.json")
    }
    (directory / "build.json").write_text(json.dumps(record, indent=2) + "\n")


def verify(directory, commit):
    record = read_json(directory / "build.json")
    require(record["commit"] == commit and COMMIT.fullmatch(commit), "Source commit mismatch")
    require(SHA.fullmatch(record["digest"]), "Invalid registry digest")
    index = read_json(directory / "image-layout/index.json")
    require(
        len(index["manifests"]) == 1 and index["manifests"][0]["digest"] == record["digest"],
        "OCI index substitution",
    )
    graph(directory / "image-layout", index["manifests"][0])
    require(
        set(record["files"])
        == {"sbom.cdx.json", "sbom.spdx.json", "provenance.buildkit.json", "qualification.json"},
        "Missing mandatory build evidence",
    )
    for name, digest in record["files"].items():
        require(digest_file(directory / name) == digest, "Evidence integrity mismatch")
    qualification = read_json(directory / "qualification.json")
    require(
        all(qualification.get(name) is True for name in ("runtime", "image_scan", "layers_secrets", "sbom")),
        "Incomplete qualification",
    )
    sbom_gate(directory / "sbom.cdx.json", directory / "sbom.spdx.json")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "runtime-export", "seal", "verify"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.directory, args.commit, args.repository)
        elif args.command == "runtime-export":
            require(args.output is not None, "Runtime archive output required")
            runtime_export(args.directory, args.output)
        elif args.command == "seal":
            seal(args.directory)
        else:
            print(json.dumps(verify(args.directory, args.commit)))
    except (ValueError, KeyError, OSError) as error:
        print(f"BLOCK: {error}", file=sys.stderr)
        sys.exit(1)
