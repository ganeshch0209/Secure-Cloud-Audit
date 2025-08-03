# modules/identity_audit.py
from msgraph.core import GraphClient
from azure.identity import InteractiveBrowserCredential

def audit_identity():
    credential = InteractiveBrowserCredential()
    client = GraphClient(credential=credential)

    report = []

    # Get users
    users = client.get("/users?$select=displayName,userPrincipalName,accountEnabled")

    for user in users.json().get('value', []):
        username = user['userPrincipalName']

        # Placeholder: Assume MFA is disabled
        mfa_enabled = False

        if not mfa_enabled:
            report.append({
                "Resource Type": "User",
                "Name": username,
                "Issue Found": "MFA not enabled",
                "Severity": "High"
            })

        # Simulate check for inactivity (in real audit, use sign-in logs or `signInActivity`)
        report.append({
            "Resource Type": "User",
            "Name": username,
            "Issue Found": "Inactive for 90+ days",
            "Severity": "Medium"
        })

    return report
