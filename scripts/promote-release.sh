#!/usr/bin/env bash
set -euo pipefail
python scripts/policy.py azure
python scripts/release.py validate-candidate .reports/release-candidate.json
bash scripts/check-azure-readiness.sh
az acr login --name "$ACR_NAME" --expose-token --query accessToken -o tsv \
  | .tools/bin/oras login "$ACR_LOGIN_SERVER" --username 00000000-0000-0000-0000-000000000000 \
      --password-stdin --registry-config "$DOCKER_CONFIG/config.json"
reference="$(python -c 'import json; print(json.load(open(".reports/release-candidate.json"))["reference"])')"
evidence="$(python -c 'import json; print(json.load(open(".reports/release-candidate.json"))["evidence_digest"])')"
.tools/bin/notation policy import security/notation/trustpolicy.json
.tools/bin/notation cert add --type ca --store production security/notation/certificates/root.pem
bash scripts/verify-image.sh "$reference"
evidence_reference="$ACR_LOGIN_SERVER/secure-api@$evidence"
.tools/bin/notation verify "$evidence_reference" > .reports/notation-evidence.txt
.tools/bin/oras manifest fetch --registry-config "$DOCKER_CONFIG/config.json" \
  --output .reports/evidence-manifest.json "$evidence_reference"
.tools/bin/oras pull --registry-config "$DOCKER_CONFIG/config.json" \
  --output .reports/evidence "$evidence_reference"
python scripts/release.py finalize .reports/release-candidate.json .reports/evidence \
  .reports/evidence-manifest.json .reports/release.json
echo 'Release metadata promoted; no Kubernetes deployment and no mutable tag promotion'
