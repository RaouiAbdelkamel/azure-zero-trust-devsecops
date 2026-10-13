"""Exercise OCI content integrity against corrupted blobs and altered descriptors."""

import hashlib
import json
import tarfile

import bundle
import pytest


def blob(layout, value, media):
    content = json.dumps(value).encode()
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    path = layout / "blobs/sha256" / digest.split(":")[1]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {"digest": digest, "size": len(content), "mediaType": media}, path


@pytest.fixture
def graph(tmp_path):
    config, config_path = blob(
        tmp_path, {"config": {"User": "10001:10001"}}, "application/vnd.oci.image.config.v1+json"
    )
    manifest, _ = blob(
        tmp_path, {"config": config, "layers": []}, "application/vnd.oci.image.manifest.v1+json"
    )
    index, _ = blob(tmp_path, {"manifests": [manifest]}, "application/vnd.oci.image.index.v1+json")
    return tmp_path, index, config_path


def test_valid_recursive_graph(graph):
    layout, descriptor, _ = graph
    bundle.graph(layout, descriptor)


def test_corrupted_nested_config_is_rejected(graph):
    layout, descriptor, config = graph
    config.write_bytes(b"substituted")
    with pytest.raises(ValueError, match="digest mismatch"):
        bundle.graph(layout, descriptor)


def test_missing_nested_blob_is_rejected(graph):
    layout, descriptor, config = graph
    config.unlink()
    with pytest.raises(ValueError, match="digest mismatch"):
        bundle.graph(layout, descriptor)


def test_descriptor_size_mismatch_is_rejected(graph):
    layout, descriptor, _ = graph
    descriptor["size"] += 1
    with pytest.raises(ValueError, match="size mismatch"):
        bundle.graph(layout, descriptor)


def test_non_sha256_digest_is_rejected(graph):
    layout, descriptor, _ = graph
    descriptor["digest"] = "sha512:" + "a" * 128
    with pytest.raises(ValueError, match="Invalid OCI digest"):
        bundle.graph(layout, descriptor)


@pytest.mark.parametrize("substituted", [False, True])
def test_runtime_export_preserves_config_and_checks_diff_ids(tmp_path, substituted):
    layout = tmp_path / "image-layout"
    content = b"synthetic uncompressed layer fixture"
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    layer_path = layout / "blobs/sha256" / digest.split(":")[1]
    layer_path.parent.mkdir(parents=True)
    layer_path.write_bytes(content)
    config, _ = blob(
        layout,
        {"rootfs": {"diff_ids": ["sha256:" + "0" * 64 if substituted else digest]}},
        "application/vnd.oci.image.config.v1+json",
    )
    descriptor, _ = blob(
        layout,
        {
            "config": config,
            "layers": [
                {
                    "digest": digest,
                    "size": len(content),
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                }
            ],
        },
        "application/vnd.oci.image.manifest.v1+json",
    )
    (layout / "index.json").write_text(json.dumps({"manifests": [descriptor]}))
    (tmp_path / "build.json").write_text(
        json.dumps({"platform_manifest": descriptor["digest"], "config_digest": config["digest"]})
    )
    output = tmp_path / "runtime.tar"
    if substituted:
        with pytest.raises(ValueError, match="Uncompressed runtime layer mismatch"):
            bundle.runtime_export(tmp_path, output)
    else:
        bundle.runtime_export(tmp_path, output)
        with tarfile.open(output) as archive:
            manifest = json.load(archive.extractfile("manifest.json"))[0]
            assert (
                "sha256:" + hashlib.sha256(archive.extractfile(manifest["Config"]).read()).hexdigest()
                == config["digest"]
            )
            assert archive.extractfile(manifest["Layers"][0]).read() == content
