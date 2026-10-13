#!/usr/bin/env bash
set -euo pipefail
python scripts/bundle.py verify out --commit "$GITHUB_SHA" > .reports/qualified-build.json
digest="$(python -c 'import json; print(json.load(open("out/build.json"))["digest"])')"
az acr login --name "$ACR_NAME" --expose-token --query accessToken -o tsv \
  | .tools/bin/oras login "$ACR_LOGIN_SERVER" --username 00000000-0000-0000-0000-000000000000 \
      --password-stdin --registry-config "$DOCKER_CONFIG/config.json"
.tools/bin/oras cp --from-oci-layout out/image-layout:ci \
  --to-registry-config "$DOCKER_CONFIG/config.json" "$ACR_LOGIN_SERVER/secure-api:sha-$GITHUB_SHA"
actual="$(.tools/bin/oras resolve --registry-config "$DOCKER_CONFIG/config.json" "$ACR_LOGIN_SERVER/secure-api:sha-$GITHUB_SHA")"
[[ "$actual" == "$digest" ]]
echo "digest=$digest" >> "$GITHUB_OUTPUT"
echo "reference=$ACR_LOGIN_SERVER/secure-api@$digest" >> "$GITHUB_OUTPUT"
