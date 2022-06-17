import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSSageMaker(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_notebook_instance_should_not_have_direct_internet_access(self):
        """
        [PCI.CloudTrail.1] CloudTrail logs should be encrypted at rest using AWS KMS keys

        """
        test = [match.value for match in parse('sagemaker[*].self.source_data.DirectInternetAccess').find(self.resources)]
        flag = 'Disabled' not in test
        self.assertEqual(True, flag, msg="One of the sagemaker notebook instance have direct internet access")