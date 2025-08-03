# modules/keyvault_audit.py
from azure.identity import AzureCliCredential
from azure.mgmt.keyvault import KeyVaultManagementClient

def audit_key_vaults(subscription_id):
    credential = AzureCliCredential()
    kv_client = KeyVaultManagementClient(credential, subscription_id)

    report = []

    for kv in kv_client.vaults.list():
        name = kv.name
        rg_name = kv.id.split("/")[4]

        # No actual access to secrets unless using KeyVault Data SDK (outside scope)
        # Simulated check
        report.append({
            "resource": name,
            "issue": "No audit logging configured",
            "severity": "Medium"
        })

    return report
