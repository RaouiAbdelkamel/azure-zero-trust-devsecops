#!/usr/bin/env bash
set -euo pipefail
reference="${1:?immutable reference required}"
[[ "$reference" =~ ^[a-z0-9]+\.azurecr\.io/secure-api@sha256:[0-9a-f]{64}$ ]] || exit 1
expected="${reference##*@}"
actual="$(.tools/bin/oras resolve "$reference")"
[[ "$actual" == "$expected" ]]
.tools/bin/notation verify "$reference" > .reports/notation-verify.txt
echo 'Notation strict trust and immutable digest verified'
