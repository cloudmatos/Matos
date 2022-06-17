import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSConfigService(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_config_should_be_enabled(self):
        """
        [PCI.Config.1] AWS Config should be enabled

        """
        test = [match.value for match in parse('config_service[*].self.source_data.recording').find(self.resources)]
        flag = True in test
        self.assertEqual(True, flag, msg="Recording of resource configuration is not enabled")
