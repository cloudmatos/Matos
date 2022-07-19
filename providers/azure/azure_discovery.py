from select import select
from .azure_connection import Azure
from datetime import date, timedelta
import re


class AzureDiscovery(Azure):
    """
    """

    def __init__(self,
                 **kwargs) -> None:
        try:
            super().__init__(**kwargs)
        except Exception as ex:
            raise Exception(ex)

    def get_clusters(self):
        client = self.client('cluster')
        resources = [item.as_dict() for item in client.managed_clusters.list()]
        resources = [
            {
                "type": 'cluster',
                'name': resource['name'],
                "location": resource['location']
            } for resource in resources]
        return resources

    def get_instances(self):
        client = self.client('instance')
        resources = [item.as_dict()
                     for item in client.virtual_machines.list_all()]
        resources = [{"type": 'instance', 'name': resource['name']}
                     for resource in resources]
        return resources

    def get_networks(self):
        client = self.client('network')
        resources = [item.as_dict()
                     for item in client.virtual_networks.list_all()]
        resources = [{"type": 'network', 'name': resource['name']}
                     for resource in resources]
        return resources

    def get_storages(self):
        client = self.client('storage')
        resources = [item.as_dict() for item in client.storage_accounts.list()]
        resources = [{"type": 'storage', 'name': resource['name']}
                     for resource in resources]
        return resources

    def get_sqls(self):
        client = self.client('sql')
        resources = [item.as_dict() for item in client.servers.list()]
        resources = [{"type": 'sql', 'name': resource['name']}
                     for resource in resources]
        return resources

    def get_activity(self):
        client = self.client('resource_group')
        resources = [i.as_dict() for i in client.resource_groups.list()]
        resources = [{"type": 'monitor', 'name': resource['name']}
                     for resource in resources]
        return resources

    def get_key_vault(self):
        client = self.client('key_vault')
        resources = [i.as_dict() for i in client.vaults.list()]
        resources = [{"type": 'key_vault', 'name': resource['name'], "resource_name":re.search('resourceGroups/(.*?)/', str(resource['id'])).group(1)}
                     for resource in resources]
        return resources

    def get_postgresql_server(self):
        client = self.client('postgresql')
        resources = [i.as_dict() for i in client.servers.list()]
        resources = [{"type": "postgresql", "name": resource['name'], "resource_name":re.search(
            'resourceGroups/(.*?)/', str(resource['id'])).group(1)} for resource in resources]
        return resources

    def find_resources(self, **kwargs):
        """
        """
        resources = []
        resources.extend(self.get_clusters())
        resources.extend(self.get_instances())
        resources.extend(self.get_networks())
        resources.extend(self.get_storages())
        resources.extend(self.get_sqls())
        resources.extend(self.get_activity())
        resources.extend(self.get_key_vault())
        resources.extend(self.get_postgresql_server())
        # print(resources, "==== azure resources")
        return resources
