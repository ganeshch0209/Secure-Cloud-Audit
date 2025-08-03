import json
import os
from datetime import datetime
from modules import nsg_scanner, vm_checker, storage_audit, identity_audit, keyvault_audit

def load_config():
    with open('config.json') as f:
        return json.load(f)

def main():
    config = load_config()
    print("✅ Configuration loaded.")

    # Create report directory if not exists
    os.makedirs(config["report_path"], exist_ok=True)
    timestamp = datetime.now().strftime("%Y_%m_%d_%H%M")

    # NSG scan
    nsg_findings = nsg_scanner.scan_nsgs(config)
    nsg_file = os.path.join(config["report_path"], f"nsg_report_{timestamp}.csv")
    nsg_scanner.export_to_csv(nsg_findings, nsg_file)
    print(f"✅ NSG scan complete. Report saved to {nsg_file}")

    # VM scan
    vm_findings = vm_checker.scan_vms(config)
    vm_file = os.path.join(config["report_path"], f"vm_report_{timestamp}.csv")
    vm_checker.export_to_csv(vm_findings, vm_file)
    print(f"✅ VM scan complete. Report saved to {vm_file}")

    # Storage scan
    storage_findings = storage_audit.scan_storage_accounts(config)
    storage_file = os.path.join(config["report_path"], f"storage_report_{timestamp}.csv")
    storage_audit.export_to_csv(storage_findings, storage_file)
    print(f"✅ Storage scan complete. Report saved to {storage_file}")

    # Identity scan
    identity_findings = identity_audit.scan_identities(config)
    identity_file = os.path.join(config["report_path"], f"identity_report_{timestamp}.csv")
    identity_audit.export_to_csv(identity_findings, identity_file)
    print(f"✅ Identity scan complete. Report saved to {identity_file}")

    # Key Vault scan
    kv_findings = keyvault_audit.scan_key_vaults(config)
    kv_file = os.path.join(config["report_path"], f"keyvault_report_{timestamp}.csv")
    keyvault_audit.export_to_csv(kv_findings, kv_file)
    print(f"✅ Key Vault scan complete. Report saved to {kv_file}")

if __name__ == "__main__":
    main()
