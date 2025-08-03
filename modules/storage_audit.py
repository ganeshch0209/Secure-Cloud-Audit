# modules/storage_audit.py

"""
Scans all Azure Storage Accounts in a subscription for:
1. Missing HTTPS enforcement
2. Public blob access enabled
3. Encryption not enabled for blob service
"""

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

        # HTTPS enforcement check
        if not getattr(properties, "enable_https_traffic_only", True):
            report.append({
                "Resource Type": "Storage",
                "Name": name,
                "Issue Found": "HTTPS not enforced",
                "Severity": "High"
            })

        # Public access check
        blob_props = client.blob_services.get_service_properties(rg_name, name, 'default')
        if getattr(blob_props, "is_public_access_allowed", False):
            report.append({
                "Resource Type": "Storage",
                "Name": name,
                "Issue Found": "Blob storage public access enabled",
                "Severity": "Medium"
            })

        # Blob encryption check
        blob_encryption = getattr(properties.encryption.services, "blob", None)
        if blob_encryption and not getattr(blob_encryption, "enabled", True):
            report.append({
                "Resource Type": "Storage",
                "Name": name,
                "Issue Found": "Blob encryption disabled",
                "Severity": "High"
            })

    return report
