# modules/vm_checker.py

"""
This module checks if any Azure VM has both:
1. A public IP address
2. An NSG allowing inbound access to critical ports (22, 3389)

Such a combination poses a high security risk.
"""

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.identity import AzureCliCredential

def check_vm_public_ip_and_nsg(subscription_id):
    credential = AzureCliCredential()
    compute_client = ComputeManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)

    report = []

    for vm in compute_client.virtual_machines.list_all():
        vm_name = vm.name
        rg_name = vm.id.split('/')[4]

        for nic_ref in vm.network_profile.network_interfaces:
            nic_id = nic_ref.id
            nic_name = nic_id.split('/')[-1]
            nic = network_client.network_interfaces.get(rg_name, nic_name)

            for ipconfig in nic.ip_configurations:
                if ipconfig.public_ip_address:
                    public_ip = ipconfig.public_ip_address.id.split('/')[-1]
                    public_ip_obj = network_client.public_ip_addresses.get(rg_name, public_ip)

                    if nic.network_security_group:
                        nsg_name = nic.network_security_group.id.split('/')[-1]
                        nsg_rules = network_client.security_rules.list(rg_name, nsg_name)

                        for rule in nsg_rules:
                            if rule.access == 'Allow' and rule.direction == 'Inbound':
                                try:
                                    port = int(rule.destination_port_range)
                                    if port in [22, 3389]:
                                        report.append({
                                            "Resource Type": "VM",
                                            "Name": vm_name,
                                            "Issue Found": f"Public IP + open NSG rule ({rule.name}) on port {port}",
                                            "Severity": "High"
                                        })
                                except (ValueError, TypeError):
                                    continue

    return report
