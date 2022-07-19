from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
AZURE_CLIENT_MANAGER = {
    "cluster": ContainerServiceClient,
    "instance": ComputeManagementClient,
    "network": NetworkManagementClient,
    "storage": StorageManagementClient,
    "sql": SqlManagementClient,
    "monitor": MonitorManagementClient,
    "resource_group": ResourceManagementClient,
    "key_vault": KeyVaultManagementClient,
    "postgresql": PostgreSQLManagementClient
}
