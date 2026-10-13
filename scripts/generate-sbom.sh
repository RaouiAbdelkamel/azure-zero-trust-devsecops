#!/usr/bin/env bash
set -euo pipefail
directory="${1:-out}"
.tools/bin/syft scan "oci-dir:$directory/image-layout" --platform linux/amd64 \
  -o "cyclonedx-json=$directory/sbom.cdx.json" -o "spdx-json=$directory/sbom.spdx.json"
python scripts/policy.py sbom "$directory/sbom.cdx.json" "$directory/sbom.spdx.json"
