# -*- coding: utf-8 -*-
import json
import os

import boto3
import structlog

from azure.identity import ClientSecretCredential
from .azure_config import AZURE_CLIENT_MANAGER

logger = structlog.get_logger(__file__)


class Azure:
    def __init__(self,
                 **kwargs) -> None:

        svc_account_filename = "azure_account.json"
        azure_svc_account_path = os.getenv(
            "AZURE_SVC_ACCOUNT_PATH", "credentials")
        self._azure_svc_account_file = os.path.join(
            azure_svc_account_path, svc_account_filename)
        # TODO: Change to local credential file
        # print(self._azure_svc_account_file)
        try:
            azure_credentials = json.load(open(self._azure_svc_account_file))
        except:
            AZURE_CRED_EXCEPTION = "Not found account service json for Azure - credentials/azure_account.json"
            raise Exception(AZURE_CRED_EXCEPTION)
        log = logger.bind()
        if not azure_credentials:
            AZURE_CRED_EXCEPTION = "No credentials found."
            log.exception(AZURE_CRED_EXCEPTION)
            raise Exception(AZURE_CRED_EXCEPTION)
        self.tenant_id = azure_credentials.get("tenantId", "")
        self.client_id = azure_credentials.get("clientId", "")
        self.client_secret = azure_credentials.get("clientSecret", "")
        self.subscription_id = azure_credentials.get("subscription_id", "")

        self._credential = None

    def client(self, service_name: str):
        """"""
        ClientClass = AZURE_CLIENT_MANAGER.get(service_name, None)
        return ClientClass(self.credential, self.subscription_id) if ClientClass else None

    @property
    def credential(self):
        if not self._credential:
            self._credential = ClientSecretCredential(
                client_id=self.client_id,
                client_secret=self.client_secret,
                tenant_id=self.tenant_id)
        return self._credential

    def scrub(self, x):
        org = x.as_dict()
        backup = vars(x)
        for k in backup:
            if backup[k] is None:
                backup[k] = 'None'
            elif k in org.keys():
                backup[k] = org[k]
        return backup
