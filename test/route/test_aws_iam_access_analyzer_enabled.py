import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMAccessAnalyzerEnabled(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.iam_key_active = "Active"

    def test_iam_access_analyzer_exists(self):
        """
        Check if Access Analyzer exists in IAM access analyzer
        """
        access_analyzer_criteria = 'analyzer[*].self.source_data'
        access_analyzers = [match.value for match in parse(access_analyzer_criteria).find(self.resources)]
        analyzer_exists = len(access_analyzers)>0
        self.assertEqual(True, analyzer_exists, msg="Access Analyzer does not exists")



    