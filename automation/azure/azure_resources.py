import logging
import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.core.exceptions import AzureError
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient

# .env
load_dotenv()

resource_group_name = "w-energy-02"
location = "East US"
vm_name = "w-energy-vm"
storage_account_name = "wenergystorage02"
network_name = "w-energy-vnet"
subnet_name = "w-energy-subnet"
sql_server_name = "w-energy-assesment-02-v01"
ip_name = "w-energy-public-ip"
sql_db_name = "w_energy_db"
network_interface = "w-energy-interface"
sql_private_endpoint_name = "sql-private-endpoint"
sql_private_dns_zone_name = "w-energy-assesment-02-v01.database.windows.net"

admin_username = os.environ.get("ADMIN_USERNAME")
admin_password = os.environ.get("ADMIN_PASSWORD")

# Logging
logging.basicConfig(filename=".logs", level=logging.INFO)
logger = logging.getLogger(__name__)

# Credentials and clients
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")

credentials = ClientSecretCredential(tenant_id, client_id, client_secret)

resource_client = ResourceManagementClient(credentials, subscription_id)
compute_client = ComputeManagementClient(credentials, subscription_id)
network_client = NetworkManagementClient(credentials, subscription_id)
sql_client = SqlManagementClient(credentials, subscription_id)
storage_client = StorageManagementClient(credentials, subscription_id)

def create_resource_group():
    if resource_client.resource_groups.check_existence(resource_group_name):
        logger.info("Resource group already exists.")
        return
    logger.info("Creating resource group...")
    resource_group_params = {"location": location}
    resource_client.resource_groups.create_or_update(resource_group_name, resource_group_params)

def create_virtual_network():
    try:
        network_client.virtual_networks.get(resource_group_name, network_name)
        logger.info("Virtual network already exists.")
        return
    except AzureError:
        pass
    logger.info("Creating virtual network...")
    vnet_params = {
        "location": location,
        "address_space": {"address_prefixes": ["10.0.0.0/16"]}
    }
    network_client.virtual_networks.begin_create_or_update(resource_group_name, network_name, vnet_params).result()

    subnet_params = {
        "address_prefix": "10.0.10.0/24",
        "private_endpoint_network_policies": "Disabled"
    }
    network_client.subnets.begin_create_or_update(resource_group_name, network_name, subnet_name, subnet_params).result()

def create_public_ip():
    try:
        network_client.public_ip_addresses.get(resource_group_name, ip_name)
        logger.info("Public IP already exists.")
        return
    except AzureError:
        pass
    logger.info("Creating public IP...")
    ip_params = {
        "location": location,
        "public_ip_allocation_method": "Dynamic"
    }
    network_client.public_ip_addresses.begin_create_or_update(resource_group_name, ip_name, ip_params).result()

def create_network_interface():
    try:
        network_client.network_interfaces.get(resource_group_name, network_interface)
        logger.info("Network interface already exists.")
        return
    except AzureError:
        pass
    logger.info("Creating network interface...")
    subnet_info = network_client.subnets.get(resource_group_name, network_name, subnet_name)
    public_ip_info = network_client.public_ip_addresses.get(resource_group_name, ip_name)
    
    nic_params = {
        "location": location,
        "ip_configurations": [{
            "name": "ipConfig1",
            "subnet": {"id": subnet_info.id},
            "public_ip_address": {"id": public_ip_info.id}
        }]
    }
    network_client.network_interfaces.begin_create_or_update(resource_group_name, network_interface, nic_params).result()

def create_vm():
    try:
        compute_client.virtual_machines.get(resource_group_name, vm_name)
        logger.info("Virtual machine already exists.")
        return
    except AzureError:
        pass
    logger.info("Creating virtual machine...")
    nic_info = network_client.network_interfaces.get(resource_group_name, network_interface)
    
    vm_parameters = {
        "location": location,
        "hardware_profile": {
            "vm_size": "Standard_B1s"
        },
        "storage_profile": {
            "image_reference": {
                "publisher": "Canonical",
                "offer": "UbuntuServer",
                "sku": "18.04-LTS",
                "version": "latest"
            }
        },
        "os_profile": {
            "computer_name": vm_name,
            "admin_username": admin_username,
            "admin_password": admin_password
        },
        "network_profile": {
            "network_interfaces": [{"id": nic_info.id}]
        }
    }
    compute_client.virtual_machines.begin_create_or_update(resource_group_name, vm_name, vm_parameters).result()

def create_storage_account():
    try:
        storage_client.storage_accounts.get_properties(resource_group_name, storage_account_name)
        logger.info("Storage account already exists.")
        return
    except AzureError:
        pass
    logger.info("Creating storage account...")
    storage_account_parameters = {
        "sku": {"name": "Standard_LRS"},
        "kind": "StorageV2",
        "location": location
    }
    storage_client.storage_accounts.begin_create(resource_group_name, storage_account_name, storage_account_parameters).result()


def create_sql_server():
    try:
        sql_client.servers.get(resource_group_name, sql_server_name)
        logger.info("SQL Server already exists.")
        return
    except AzureError:
        pass
    logger.info("Creating SQL server...")
    sql_server_parameters = {
        "location": location,
        "administrator_login": "sqladmin",
        "administrator_login_password": admin_password
    }
    sql_client.servers.begin_create_or_update(resource_group_name, sql_server_name, sql_server_parameters).result()

def create_sql_database():
    try:
        sql_client.databases.get(resource_group_name, sql_server_name, sql_db_name)
        logger.info("SQL Database already exists.")
        return
    except AzureError:
        pass
    logger.info("Creating SQL database...")
    sql_db_parameters = {
        "location": location,
        "sku": {"name": "Basic"}
    }
    sql_client.databases.begin_create_or_update(resource_group_name, sql_server_name, sql_db_name, sql_db_parameters).result()

def create_private_dns_zone():
    try:
        logger.info("Creating private DNS zone...")
        try:
            existing_zone = network_client.private_dns_zones.get(resource_group_name, sql_private_dns_zone_name)
            logger.info(f"Private DNS zone {sql_private_dns_zone_name} already exists.")
        except AzureError as e:
            if 'ResourceNotFound' in e.message:
                dns_zone_params = {
                    "location": "global"
                }
                network_client.private_dns_zones.create_or_update(resource_group_name, sql_private_dns_zone_name, dns_zone_params)
                logger.info(f"Private DNS zone {sql_private_dns_zone_name} created.")
            else:
                logger.error(f"Error checking private DNS zone: {e.message}")
                raise
    except AzureError as e:
        logger.error(f"AzureError while creating private DNS zone: {e.message}")

def link_private_dns_zone():
    try:
        logger.info("Linking private DNS zone to virtual network...")
        link_name = f"{sql_private_dns_zone_name}-link"
        try:
            existing_link = network_client.private_dns_zone_virtual_network_links.get(resource_group_name, sql_private_dns_zone_name, link_name)
            logger.info(f"Link {link_name} already exists.")
        except AzureError as e:
            if 'ResourceNotFound' in e.message:
                link_params = {
                    "location": "global",
                    "virtual_network": {
                        "id": network_client.virtual_networks.get(resource_group_name, network_name).id
                    }
                }
                network_client.private_dns_zone_virtual_network_links.create_or_update(
                    resource_group_name,
                    sql_private_dns_zone_name,
                    link_name,
                    link_params
                )
                logger.info(f"Link {link_name} created.")
            else:
                logger.error(f"Error checking link: {e.message}")
                raise
    except AzureError as e:
        logger.error(f"AzureError while linking private DNS zone to virtual network: {e.message}")

def create_private_endpoint():
    try:
        logger.info("Creating private endpoint for SQL Database...")
        try:
            existing_endpoint = network_client.private_endpoints.get(resource_group_name, sql_private_endpoint_name)
            logger.info(f"Private endpoint {sql_private_endpoint_name} already exists.")
        except AzureError as e:
            if 'ResourceNotFound' in e.message:
                subnet_info = network_client.subnets.get(resource_group_name, network_name, subnet_name)
                private_endpoint_parameters = {
                    "location": location,
                    "subnet": {"id": subnet_info.id},
                    "private_link_service_connections": [{
                        "name": sql_private_endpoint_name,
                        "private_link_service_id": sql_client.servers.get(resource_group_name, sql_server_name).id,
                        "group_ids": ["sqlServer"],
                        "private_link_service_connection_state": {
                            "status": "Approved",
                            "description": "Auto-approved"
                        }
                    }]
                }
                network_client.private_endpoints.begin_create_or_update(resource_group_name, sql_private_endpoint_name, private_endpoint_parameters).result()
                logger.info(f"Private endpoint {sql_private_endpoint_name} created.")
            else:
                logger.error(f"Error checking private endpoint: {e.message}")
                raise
    except AzureError as e:
        logger.error(f"AzureError while creating private endpoint for SQL Database: {e.message}")

def configure_sql_firewall():
    try:
        logger.info("Configuring SQL server firewall...")
        private_endpoint = network_client.private_endpoints.get(resource_group_name, sql_private_endpoint_name)
        private_ip = private_endpoint.network_interfaces[0].ip_configurations[0].private_ip_address
        firewall_rule_name = "AllowPrivateEndpoint"
        firewall_rule_parameters = {
            "start_ip_address": private_ip,
            "end_ip_address": private_ip
        }
        try:
            sql_client.firewall_rules.get(resource_group_name, sql_server_name, firewall_rule_name)
            logger.info(f"Firewall rule {firewall_rule_name} already exists.")
        except AzureError as e:
            if 'ResourceNotFound' in e.message:
                sql_client.firewall_rules.create_or_update(resource_group_name, sql_server_name, firewall_rule_name, firewall_rule_parameters)
                logger.info(f"Firewall rule {firewall_rule_name} created.")
            else:
                logger.error(f"Error checking firewall rule: {e.message}")
                raise
    except AzureError as e:
        logger.error(f"AzureError while configuring SQL server firewall: {e.message}")


def start_vm():
    logger.info("Starting virtual machine...")
    compute_client.virtual_machines.begin_start(resource_group_name, vm_name).result()

def stop_vm():
    logger.info("Stopping virtual machine...")
    compute_client.virtual_machines.begin_deallocate(resource_group_name, vm_name).result()

def delete_vm():
    logger.info("Deleting virtual machine...")
    compute_client.virtual_machines.begin_delete(resource_group_name, vm_name).result()

def delete_resource_group():
    logger.info("Deleting resource group...")
    resource_client.resource_groups.begin_delete(resource_group_name).result()

def create_all_resources():
    create_resource_group()
    create_virtual_network()
    create_public_ip()
    create_network_interface()
    create_vm()
    create_storage_account()
    create_sql_server()
    create_sql_database()
    create_private_endpoint()
    start_vm()
    logging.info("All created")

def delete_all_resources():
    delete_vm()
    delete_resource_group()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Azure Resource Management Script")
    parser.add_argument("--create-all", action="store_true", help="Create all resources")
    parser.add_argument("--delete-all", action="store_true", help="Delete all resources")
    parser.add_argument("--create-vm", action="store_true", help="Create virtual machine")
    parser.add_argument("--start-vm", action="store_true", help="Start virtual machine")
    parser.add_argument("--stop-vm", action="store_true", help="Stop virtual machine")
    parser.add_argument("--delete-vm", action="store_true", help="Delete virtual machine")

    args = parser.parse_args()

    try:
        if args.create_all:
            create_all_resources()
        if args.delete_all:
            delete_all_resources()
        if args.create_vm:
            create_vm()
        if args.start_vm:
            start_vm()
        if args.stop_vm:
            stop_vm()
        if args.delete_vm:
            delete_vm()
    except AzureError as e:
        logger.error(f"Azure operation failed: {e}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
