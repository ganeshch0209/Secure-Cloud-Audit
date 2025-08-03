# modules/identity_audit.py
def audit_identity():
    # Placeholder logic since actual Graph API needs delegated permissions
    return [
        {
            "resource": "user@example.com",
            "issue": "MFA not enabled",
            "severity": "High"
        },
        {
            "resource": "user2@example.com",
            "issue": "Inactive for 90+ days",
            "severity": "Medium"
        }
    ]
