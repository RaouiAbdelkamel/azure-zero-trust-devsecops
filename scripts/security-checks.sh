#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .reports
export PATH="$PWD/.tools/bin:$PATH"
# Scan all source/configuration including Terraform; no credentials or PR code on Azure runners.
gitleaks dir . --config security/gitleaks/.gitleaks.toml --redact --no-banner \
  --report-format json --report-path .reports/gitleaks-files.json
if [[ -d .git ]]; then
  gitleaks git . --config security/gitleaks/.gitleaks.toml --redact --no-banner \
    --log-opts="--all" --report-format json --report-path .reports/gitleaks-history.json
else
  echo 'BLOCK: Git history unavailable in CI' >&2
  exit 1
fi
python -m ruff check app/src app/tests app/scripts --output-format json > .reports/ruff.json
python -m ruff format --check app/src app/tests app/scripts
python -m bandit -r app/src app/scripts/resolve_base_image.py \
  app/scripts/scan_image_layers.py app/scripts/smoke_local.py -c app/pyproject.toml \
  -f json -o .reports/bandit.json
python -m pip_audit -r app/requirements.lock --require-hashes --disable-pip \
  --format json --output .reports/audit-runtime.json
python -m pip_audit -r app/requirements-dev.lock --require-hashes --disable-pip \
  --format json --output .reports/audit-dev.json
python -m pip check
trivy fs --config security/trivy/trivy.yaml --scanners vuln,misconfig,secret \
  --format json --output .reports/trivy-fs.json .
python scripts/policy.py trivy .reports/trivy-fs.json
