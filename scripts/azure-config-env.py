"""Export strictly validated public configuration; never export secret material."""

import os

from policy import ROOT, azure_config, read_json, require

c = read_json(ROOT / "security/azure-config.json")
azure_config(c)
values = {
    "ACR_NAME": c["registry"].split(".")[0],
    "ACR_LOGIN_SERVER": c["registry"],
    "CERTIFICATE_NAME": c["certificate_name"],
    "SIGNING_VAULT": c["signing_vault"],
    "KEY_ID": c["key_id"],
    "CA_BUNDLE": c["ca_bundle"],
    "AZURE_SELECTED_CLIENT_ID": c[os.environ["CI_ROLE"] + "_client_id"],
    "AZURE_TARGET_TENANT_ID": c["tenant_id"],
    "AZURE_TARGET_SUBSCRIPTION_ID": c["subscription_id"],
}
with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
    for name, value in values.items():
        require("\n" not in value and "\r" not in value, "Unsafe configuration value")
        output.write(f"{name}={value}\n")
