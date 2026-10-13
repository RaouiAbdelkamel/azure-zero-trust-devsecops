#!/usr/bin/env bash
set -euo pipefail
python scripts/policy.py azure
python - <<'PY'
import ipaddress, json, socket, ssl
c = json.load(open('security/azure-config.json'))
for hostname in (c['registry'], c['signing_vault'] + '.vault.azure.net'):
    addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    if not addresses or not all(ipaddress.ip_address(value).is_private for value in addresses):
        raise SystemExit('BLOCK: private DNS required')
    with socket.create_connection((hostname, 443), timeout=5) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname=hostname):
            pass
print('Private DNS and verified TLS connectivity available; OIDC/RBAC still require real operations')
PY
# Read-only ARM check: requires the narrow registry-configuration-reader role documented in setup.
az acr show --name "$ACR_NAME" --query '{public:publicNetworkAccess,admin:adminUserEnabled,mode:roleAssignmentMode}' \
  -o json > .reports/acr-readiness.json
python - <<'PY'
import json
d = json.load(open('.reports/acr-readiness.json'))
assert d['public'] == 'Disabled' and d['admin'] is False
assert d['mode'] == 'LegacyRegistryPermissions'
PY
