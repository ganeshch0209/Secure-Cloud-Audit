# modules/storage_audit.py
from azure.mgmt.storage import StorageManagementClient
from azure.identity import AzureCliCredential

def audit_storage_accounts(subscription_id):
    credential = AzureCliCredential()
    client = StorageManagementClient(credential, subscription_id)

    report = []

    for account in client.storage_accounts.list():
        name = account.name
        rg_name = account.id.split("/")[4]

        properties = client.storage_accounts.get_properties(rg_name, name)

        # Check for HTTPS
        if not properties.enable_https_traffic_only:
            report.append({
                "resource": name,
                "issue": "HTTPS not enforced",
                "severity": "High"
            })

        # Check for public access
        blob_props = client.blob_services.get_service_properties(rg_name, name, 'default')
        if blob_props and blob_props.is_public_access_allowed:
            report.append({
                "resource": name,
                "issue": "Blob storage public access enabled",
                "severity": "Medium"
            })

        # Encryption check
        if not properties.encryption.services.blob.enabled:
            report.append({
                "resource": name,
                "issue": "Blob encryption disabled",
                "severity": "High"
            })

    return report
