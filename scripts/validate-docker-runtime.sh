#!/usr/bin/env bash
set -euo pipefail
image="${1:?image required}"
config_digest="${2:?expected config digest required}"
[[ "$config_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 1
[[ "$(docker image inspect --format '{{.Id}}' "$image")" == "$config_digest" ]]
[[ "$(docker image inspect --format '{{.Config.User}}' "$image")" == '10001:10001' ]]
docker info --format '{{json .SecurityOptions}}' | grep -q 'name=seccomp.*profile=builtin'
name="secure-api-ci-${GITHUB_RUN_ID:-local}-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" --read-only --cap-drop ALL \
  --security-opt no-new-privileges=true --user 10001:10001 \
  --pids-limit 128 --memory 512m --cpus 1 -e APP_ENV=test \
  -p 127.0.0.1::8080 "$image" >/dev/null
docker exec -i "$name" python - <<'PY'
import importlib.util, os, pathlib, shutil, ssl
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
assert os.getuid() == 10001 and os.getgid() == 10001 and 0 not in os.getgroups()
assert not any(shutil.which(name) for name in ('gcc', 'cc', 'g++', 'make'))
assert all(importlib.util.find_spec(name) is None for name in ('pytest', 'bandit', 'pip'))
assert not list(pathlib.Path('/app').rglob('.env*'))
fields = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert int(fields['CapEff'].strip(), 16) == 0
assert fields['NoNewPrivs'].strip() == '1' and fields['Seccomp'].strip() == '2'
# Exercise native musl crypto wheels and CA availability in the actual runtime.
# Ephemeral in-memory test key/token; never printed or saved as credentials.
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
token = jwt.encode({'aud': 'runtime-fixture', 'iss': 'runtime-fixture'}, key, algorithm='RS256')
assert jwt.decode(token, key.public_key(), algorithms=['RS256'], audience='runtime-fixture', issuer='runtime-fixture')['aud'] == 'runtime-fixture'
try:
    jwt.decode(token, key.public_key(), algorithms=['RS256'], audience='rejected-fixture', issuer='runtime-fixture')
except jwt.InvalidAudienceError:
    pass
else:
    raise AssertionError('Native JWT audience validation bypass')
assert pathlib.Path(ssl.get_default_verify_paths().cafile).is_file()
try:
    pathlib.Path('/app/write-probe').write_text('probe')
except OSError:
    pass
else:
    raise AssertionError('Writable application root')
PY
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$name")" == true ]]
port="$(docker port "$name" 8080/tcp | head -n1 | cut -d: -f2)"
healthy=false
for attempt in $(seq 1 30); do
  if curl --silent --fail "http://127.0.0.1:$port/health/live" | grep -q alive \
      && curl --silent --fail "http://127.0.0.1:$port/health/ready" | grep -q ready; then
    healthy=true
    break
  fi
  sleep 1
done
[[ "$healthy" == true ]]
docker stop --time 30 "$name" >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$name")" == 0 ]]
echo 'Container restricted runtime qualified'
