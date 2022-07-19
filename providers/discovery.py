from .config import DISCOVERY_MANAGER


class Discovery:

    def __init__(self,
                 provider: str,
                 **kwargs,
                 ) -> None:
        """
        """
        self.provider = provider
        self.kwargs = kwargs

        if provider not in DISCOVERY_MANAGER:
            raise NotImplementedError("Provider not implemented yet")

        self.manager = DISCOVERY_MANAGER[provider](
            **kwargs,
        )

    def find_resources(self, **kwargs):
        """
        """
        return self.manager.find_resources(**kwargs)
