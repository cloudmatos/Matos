import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse

class TestCloudSql(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
    
    def test_network_default_or_not(self):
        """
        Check if network is default or not
        """
        test = [match.value for match in parse('network[*].self[*].is_default').find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in [False, 'false']
        self.assertEqual(True, flag, msg="Default VPC is used")
