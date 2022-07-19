from providers.discovery import Discovery
from providers.resources import Resource
from utils.reformer import reform_resources


class ResourceService:
    # provider = 'gcp'

    def __init__(self, provider):
        self.provider = provider

    def get_resource(self, remove_instance=True):
        pretty_resources = {}
        try:
            resource_list = Discovery(self.provider).find_resources(
            ) if self.provider != 'gcp' else []
            resource_obj = Resource(self.provider)
            resources = resource_obj.get_resource_inventory(
                resource_list=resource_list)
        except Exception as ex:
            raise Exception(ex)
        for type in resources.keys():
            resource = resources.get(type, {})
            if self.provider == 'gcp':
                pretty_resources = {**pretty_resources, **
                                    (reform_resources(self.provider, resource))}
                # print("*** pretty resources ***", pretty_resources)
            else:
                if type not in pretty_resources:
                    pretty_resources[type] = []
                for item in resource:
                    reformatted_resource = reform_resources(
                        self.provider, item)
                    pretty_resources[type].extend(
                        [reformatted_resource[type]] if type in reformatted_resource else [])

        cluster_node_name_list = []
        if remove_instance:
            for cluster in pretty_resources.get('cluster', []):
                cluster_node_name_list.extend(
                    [node['self']['name' if self.provider == 'gcp' else 'instance_id'] for node in cluster.get('node', [])])
            if 'instance' in pretty_resources:
                pretty_resources['instance'] = [rsc for rsc in pretty_resources['instance'] if
                                                rsc['self'].get('display_name', '') not in cluster_node_name_list]

        return pretty_resources, cluster_node_name_list
