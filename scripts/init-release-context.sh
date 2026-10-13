#!/usr/bin/env bash
set -euo pipefail
for directory in secure-api-registry secure-api-azure secure-api-notation; do
  mkdir -p "$RUNNER_TEMP/$directory"
  chmod 700 "$RUNNER_TEMP/$directory"
done
{
  echo "DOCKER_CONFIG=$RUNNER_TEMP/secure-api-registry"
  echo "AZURE_CONFIG_DIR=$RUNNER_TEMP/secure-api-azure"
  echo "XDG_CONFIG_HOME=$RUNNER_TEMP/secure-api-notation"
} >> "$GITHUB_ENV"
mkdir -p .reports
