import csv
from azure.mgmt.network import NetworkManagementClient
from azure.identity import AzureCliCredential

"""
This module scans Azure NSGs for inbound rules that expose critical ports (e.g., 22, 3389) to the public internet.
"""

def scan_nsgs(config):
    findings = []

    credential = AzureCliCredential()
    network_client = NetworkManagementClient(credential, config["subscription_id"])

    for nsg in network_client.network_security_groups.list_all():
        if not nsg.security_rules:
            continue

        for rule in nsg.security_rules:
            if rule.access == "Allow" and rule.direction == "Inbound":
                if rule.source_address_prefix in ["*", "0.0.0.0/0"] and rule.destination_port_range:
                    try:
                        port = int(rule.destination_port_range)
                    except ValueError:
                        continue  # skip non-integer ranges like '*', '443-500'

                    if port in config["nsg_critical_ports"]:
                        findings.append({
                            "Resource Type": "NSG",
                            "Name": nsg.name,
                            "Issue Found": f"Port {port} open to {rule.source_address_prefix}",
                            "Severity": "High"
                        })

    return findings

def export_to_csv(data, filename):
    if not data:
        print("✅ No NSG misconfigurations found.")
        return

    keys = data[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)
