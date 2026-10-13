#!/usr/bin/env bash
set -euo pipefail
python scripts/bundle.py verify out --commit "$GITHUB_SHA" > .reports/qualified-build.json
[[ "$(python -c 'import json; print(json.load(open("out/build.json"))["digest"])')" == "$IMAGE_DIGEST" ]]
reference="$ACR_LOGIN_SERVER/secure-api@$IMAGE_DIGEST"
az acr login --name "$ACR_NAME" --expose-token --query accessToken -o tsv \
  | .tools/bin/oras login "$ACR_LOGIN_SERVER" --username 00000000-0000-0000-0000-000000000000 \
      --password-stdin --registry-config "$DOCKER_CONFIG/config.json"
az keyvault certificate show --vault-name "$SIGNING_VAULT" --name "$CERTIFICATE_NAME" \
  -o json > .reports/certificate-public.json
python - <<'PY'
import json, os
c = json.load(open('.reports/certificate-public.json'))
assert c['kid'] == os.environ['KEY_ID']
assert c['policy']['keyProperties']['exportable'] is False
assert c['policy']['keyProperties']['keyType'] == 'RSA-HSM'
assert c['attributes']['enabled'] is True
PY
# Plugin installed from an already verified locked archive; no private key download.
mkdir -p "$XDG_CONFIG_HOME/notation/plugins/azure-kv"
cp .tools/bin/notation-azure-kv "$XDG_CONFIG_HOME/notation/plugins/azure-kv/notation-azure-kv"
.tools/bin/notation plugin ls
.tools/bin/notation policy import security/notation/trustpolicy.json
.tools/bin/notation cert add --type ca --store production security/notation/certificates/root.pem
.tools/bin/notation sign --signature-format cose --plugin azure-kv --id "$KEY_ID" \
  --plugin-config credential_type=azurecli --plugin-config "ca_certs=$CA_BUNDLE" "$reference"
bash scripts/verify-image.sh "$reference"
# Bind BuildKit provenance, SBOMs and qualification to the exact validated source/digest.
pushd out >/dev/null
../.tools/bin/oras attach --registry-config "$DOCKER_CONFIG/config.json" \
  --artifact-type application/vnd.secure-api.evidence.v1+json --export-manifest evidence-manifest.json \
  "$reference" build.json:application/json provenance.buildkit.json:application/json \
  sbom.cdx.json:application/vnd.cyclonedx+json sbom.spdx.json:application/spdx+json \
  qualification.json:application/json
evidence_digest="sha256:$(sha256sum evidence-manifest.json | cut -d' ' -f1)"
popd >/dev/null
evidence_reference="$ACR_LOGIN_SERVER/secure-api@$evidence_digest"
.tools/bin/notation sign --signature-format cose --plugin azure-kv --id "$KEY_ID" \
  --plugin-config credential_type=azurecli --plugin-config "ca_certs=$CA_BUNDLE" "$evidence_reference"
.tools/bin/notation verify "$evidence_reference" > .reports/notation-evidence.txt
echo "evidence_digest=$evidence_digest" >> "$GITHUB_OUTPUT"
echo "reference=$reference" >> "$GITHUB_OUTPUT"
