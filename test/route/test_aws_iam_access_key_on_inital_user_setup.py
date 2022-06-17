import os
from datetime import datetime
import time
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMAccessKeyOnInitialUserSetup(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.diff_threshold = 10

    def test_if_access_key_is_created_successfully(self):
        """
        Check if access key is created successfully
        """
        iams_criteria = 'serviceAccount[*].self.source_data'
        iams = [match.value for match in parse(iams_criteria)\
            .find(self.resources)]
        key_created_initially = False
        for iam in iams:
            access_keys = iam.get("AccessKeys",[])
            if len(access_keys) == 0:
                continue
            user_created_at = iam['CreateDate']
            user_created_at = datetime.strptime(user_created_at.replace(' GMT','Z'),"%a, %d %b %Y %H:%M:%S%z")
            for key in access_keys:
                key_created_at = key["CreateDate"]
                key_created_at = datetime.strptime(key_created_at.replace(' GMT','Z'),"%a, %d %b %Y %H:%M:%S%z")
                diff = datetime.timestamp(key_created_at) - datetime.timestamp(user_created_at)
                if diff<self.diff_threshold:
                    key_created_initially = True
        self.assertEqual(False, key_created_initially, msg=f"Access key is created initially")