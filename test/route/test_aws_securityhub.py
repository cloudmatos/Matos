from importlib.metadata import distributions
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt


class TestAWSSecurityHub(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_securityhub_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_seurity_hub_enabled(self):
        """
       AWS Security Hub should be enabled for an AWS Account
        """
        hub = [match.value for match in parse('securityhub[*]').find(self.resources)]
        flag = len(hub) < 1
        self.assertEqual(False, flag, msg="security hub isn't enable")