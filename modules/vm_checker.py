 # modules/vm_checker.py
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
        nic_id = vm.network_profile.network_interfaces[0].id
        nic_name = nic_id.split('/')[-1]
        rg_name = vm.id.split('/')[4]

        nic = network_client.network_interfaces.get(rg_name, nic_name)
        for ipconfig in nic.ip_configurations:
            if ipconfig.public_ip_address:
                public_ip = ipconfig.public_ip_address.id.split('/')[-1]
                public_ip_obj = network_client.public_ip_addresses.get(rg_name, public_ip)

                nsg = nic.network_security_group
                if nsg:
                    nsg_name = nsg.id.split('/')[-1]
                    nsg_rules = network_client.security_rules.list(rg_name, nsg_name)
                    for rule in nsg_rules:
                        if rule.access == 'Allow' and rule.direction == 'Inbound':
                            if '22' in rule.destination_port_range or '3389' in rule.destination_port_range:
                                report.append({
                                    "resource": vm_name,
                                    "issue": f"Public IP + open NSG rule: {rule.name}",
                                    "severity": "High"
                                })
    return report
