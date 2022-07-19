import os
import re
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
import requests


class TestPostgreSQL(TestCase):
    def __init__(self):
        # fp = open(os.getcwd() + "/test/data/test_azure_postgresql.json", "r")
        fp = open(
            "C:/Users/LENOVO/Downloads/docs/matos/matosphere/matosphere/test/data/test_azure_postgresql.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    # Ensure that geo-redundant backups are enabled for your Azure PostgreSQL database servers.
    def test_geo_redundant_backups(self):
        """check if geo-redundant backups are enabled or not
        """
        test = [match for match in self.resources['postgreSQL']
                if match['self'][0]['servers']['storage_profile']['geo_redundant_backup'] == 'Enabled']
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="geo-redundant backups are not enabled for one of your Azure PostgreSQL database servers")

    # Ensure that in-transit encryption is enabled for your Azure PostgreSQL database servers.
    def test_in_transit_encryption(self):
        """check if in-transit encryption is enabled or not
        """
        test = [match for match in self.resources['postgreSQL']
                if match['self'][0]['servers']['ssl_enforcement'] == 'Enabled']
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="in-transit encryption is not enabled for one of your Azure PostgreSQL database servers")

    # Ensure that storage auto-growth is enabled for your Microsoft Azure PostgreSQL database servers.
    def test_storage_auto_growth(self):
        """check if storage auto-growth is enabled or not
        """
        test = [match for match in self.resources['postgreSQL']
                if match['self'][0]['servers']['storage_profile']['storage_autogrow'] == 'Enabled']
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="storage auto-growth is not enabled for one of your Microsoft Azure PostgreSQL database servers")

    # Ensure that PostgreSQL database servers are using the latest major version of PostgreSQL database.
    def test_database_server_latest_version(self):
        """check if PostgreSQL database serrver is using latest version
        """
        latest_version = requests.get(
            'https://docs.microsoft.com/en-us/azure/postgresql/single-server/concepts-supported-versions').text
        version = re.search('<h2 id=".*?>(.*?)<', str(latest_version), re.S)
        if version:
            version = version.group(1)
        version = version.split(' ')[-1]
        test = [match for match in self.resources['postgreSQL']
                if match['self'][0]['servers']['version'] == version]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="One of the PostgreSQL database servers are not using the latest major version of PostgreSQL database")

    # Ensure that an Azure Active Directory (AAD) admin is configured for PostgreSQL authentication.
    def test_AAD_is_configured(self):
        """check if Azure Activer Directory admin is configured or not
        """
        test = [match for match in self.resources['postgreSQL']
                if len(match['self'][0]['administrators']) >= 1]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="One of the Azure Active Directory (AAD) admin is not configured for PostgreSQL authentication")

    # Ensure that PostgreSQL database servers have a sufficient log retention period configured.
    def test_log_retention_period(self):
        """check if PostgreSQL database servers have a sufficient log retention period configured
        """
        test = [filter(lambda item: item['name'] == 'log_retention_days',
                       match['self'][0]['Logs']) for match in self.resources['postgreSQL']]
        test = [i for i in test if int(list(i)[0]['value']) > 3]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="one of the PostgreSQL database servers not have a sufficient log retention period configured")

    # Ensure that "connection_throttling" parameter is set to "ON" within your Azure PostgreSQL server settings.
    def test_connection_throttling(self):
        """check if "connection_throttling" parameter is set to "ON" within your Azure PostgreSQL server settings
        """
        test = [list(filter(lambda item: item['name'] == 'connection_throttling',
                            match['self'][0]['Logs'])) for match in self.resources['postgreSQL']]

        test = [i for i in test if list(i)[0]['value'] == "on"]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="one of the 'connection_throttling' parameter is not set to 'ON' within your Azure PostgreSQL server settings")

    # Enable "log_checkpoints" parameter for your Microsoft Azure PostgreSQL database servers.
    def test_log_checkpoint(self):
        """check if "log_checkpoints" parameter is enable for your Microsoft Azure PostgreSQL database servers
        """
        test = [list(filter(lambda item: item['name'] == 'log_checkpoints',
                            match['self'][0]['Logs'])) for match in self.resources['postgreSQL']]

        test = [i for i in test if list(i)[0]['value'] == "on"]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="one of the 'log_checkpoints' parameter is not enable for your Microsoft Azure PostgreSQL database servers")

    # Enable "log_connections" parameter for your Microsoft Azure PostgreSQL database servers.
    def test_log_connections(self):
        """check if "log_connections" parameter is enable for your Microsoft Azure PostgreSQL database servers
        """
        test = [list(filter(lambda item: item['name'] == 'log_connections',
                            match['self'][0]['Logs'])) for match in self.resources['postgreSQL']]

        test = [i for i in test if list(i)[0]['value'] == "on"]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="one of the 'log_connections' parameter is not enable for your Microsoft Azure PostgreSQL database servers")

    # Enable "log_disconnections" parameter for your Microsoft Azure PostgreSQL database servers.
    def test_log_disconnection(self):
        """check if "log_disconnections" parameter is enable for your Microsoft Azure PostgreSQL database servers
        """
        test = [list(filter(lambda item: item['name'] == 'log_disconnections',
                            match['self'][0]['Logs'])) for match in self.resources['postgreSQL']]

        test = [i for i in test if list(i)[0]['value'] == "ON"]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="one of the 'log_disconnections' parameter is not enable for your Microsoft Azure PostgreSQL database servers")

    # Enable "log_duration" parameter on your Microsoft Azure PostgreSQL database servers.
    def test_log_duration(self):
        """check if "log_duration" parameter is enable for your Microsoft Azure PostgreSQL database servers
        """
        test = [list(filter(lambda item: item['name'] == 'log_duration',
                            match['self'][0]['Logs'])) for match in self.resources['postgreSQL']]

        test = [i for i in test if list(i)[0]['value'] == "ON"]
        flag = len(test) == len(self.resources.get('postgreSQL', []))
        self.assertEqual(
            True, flag, msg="one of the 'log_duration' parameter is not enable for your Microsoft Azure PostgreSQL database servers")
