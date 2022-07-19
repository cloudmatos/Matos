from multiprocessing import managers
from .config import PROVIDERS, PROVIDER_RESOURCE_MANAGER
from .gcp.gcp_config import RESOURCE_TYPE_REQUESTS
import threading


# TODO: Logging needs to be initialise and apply.


class Resource:
    def __init__(self,
                 provider: str,
                 ):
        if provider not in PROVIDERS:
            raise Exception(f"Provider {provider} is not supported.")
        self.provider = provider
        self._manager = None
        self.resources = {}

    @property
    def manager(self):
        if not self._manager:
            _manager = PROVIDER_RESOURCE_MANAGER.get(self.provider)
            if _manager:
                try:
                    self._manager = _manager()
                except Exception as ex:
                    raise Exception(ex)
                # if self.provider == "gcp":
                # else:
                #     self._manager = _manager()
        return self._manager

    def get_resource_inventory(
            self,
            resource_list
    ):
        """
        """
        def fetch_resource_details(rsc):
            type = rsc.get('type')
            detail = self.manager.get_assets_inventory(rsc)
            self.resources[type] = [detail] if type not in self.resources else [
                *self.resources[type], detail]

        if self.manager:
            # resources = {}
            if self.provider == 'gcp':
                try:
                    for resource_type in RESOURCE_TYPE_REQUESTS.keys():
                        self.resources[resource_type] = self.manager.get_assets_inventory(
                            {"type": resource_type})
                except Exception as ex:
                    raise Exception(ex)
            else:
                threads = []
                for resource in resource_list:
                    thread = threading.Thread(
                        target=fetch_resource_details, args=(resource,))
                    thread.start()
                    threads.append(thread)
                for t in threads:
                    t.join()

            return self.resources
