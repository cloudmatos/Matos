import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestCloudSql(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_kms_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_kms_rotation(self):
        """
        test Ensure rotation for customer created CMKs is enabled
        """
        test = [match.value for match in parse('kms[*].self.source_data.KeyRotationEnabled').find(self.resources) if match.value in ['false', False]]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few kms keys without enable key rotation.")





