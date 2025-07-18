# 🔐 SecureCloudAudit – Azure Security Misconfiguration Scanner

**SecureCloudAudit** is a Python-based auditing tool designed to scan an Azure subscription for common security misconfigurations. It's inspired by Microsoft Defender for Cloud, but built from scratch to demonstrate practical cloud security skills, automation, and compliance monitoring.

---

## 🎯 Features

✅ Scans Azure resources for common misconfigurations  
✅ Generates detailed CSV compliance reports  
✅ Built with Azure SDK for Python and Azure CLI  
✅ Modular architecture – easy to extend  
✅ Optional dashboarding with Streamlit or Power BI  
✅ Stretch features: Auto-remediation & Email alerts

---

## 🔍 Current Audit Checks (MVP)

| Category | Check | Severity |
|----------|-------|----------|
| NSG | Port 22/3389 open to 0.0.0.0/0 | High |
| VM | Public IP with open NSG | High |
| Storage | Public access, no HTTPS, no encryption | Medium/High |
| Identity | Users without MFA, inactive users | High |
| Key Vault | Expiring secrets, audit logs disabled | Medium |

---

## 🧠 Tech Stack

| Layer | Tool |
|-------|------|
| Language | Python 3.x |
| Cloud | Microsoft Azure |
| APIs | Azure SDK for Python, Azure CLI, Azure REST |
| Data | SQLite / CSV Reports |
| Optional UI | Streamlit, Power BI |
| Optional Alerts | Azure Logic Apps, SendGrid |

---

## 📁 Project Structure

```
SecureCloudAudit/
├── main.py
├── config.json
├── modules/
│   ├── nsg_scanner.py
│   ├── vm_checker.py
│   ├── storage_audit.py
│   ├── identity_audit.py
│   └── keyvault_audit.py
├── reports/
│   └── report_YYYY_MM_DD.csv
├── README.md
└── requirements.txt
```

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/SecureCloudAudit.git
cd SecureCloudAudit
```

### 2. Set up Python environment
```bash
python -m venv venv
source venv/bin/activate  # For Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Authenticate with Azure
```bash
az login
```

---

## 📤 Sample Report Output (CSV)

| Resource Type | Name          | Issue Found                 | Severity |
|---------------|---------------|-----------------------------|----------|
| NSG           | nsg-open-all  | Port 22 open to all         | High     |
| VM            | vm-dev-test   | Public IP with open RDP     | High     |
| Storage       | mystorage01   | Public access enabled       | Medium   |
| User          | ganesh-admin  | MFA not enabled             | High     |

---

## 🧩 Future Enhancements

- ✅ Power BI / Streamlit dashboards  
- ✅ Email alerts via SendGrid  
- ✅ Auto-remediation via Logic Apps / Functions  
- ✅ CI/CD with GitHub Actions  

---

## 📚 Resources

- [Azure SDK for Python](https://learn.microsoft.com/en-us/azure/developer/python/azure-sdk-overview)  
- [Azure CLI Reference](https://learn.microsoft.com/en-us/cli/azure/)  
- [Azure Security Best Practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/)  
- [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)

---

## 📌 About the Author

👨‍💻 This project was created as part of my portfolio while preparing for a Master’s in Cybersecurity. It aligns with the Azure SC-200 and AZ-500 certifications and demonstrates real-world cloud security auditing.

---

## 🛡️ License

MIT License. Use and contribute freely.
