#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python scripts/policy.py workflows
python scripts/policy.py dependencies
.tools/bin/actionlint
python -m ruff check scripts security/tests
python -m ruff format --check scripts security/tests
for script in scripts/*.sh; do bash -n "$script"; done
python -m pytest security/tests -q --no-cov
