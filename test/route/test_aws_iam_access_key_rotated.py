import os
from datetime import datetime
import time
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMAccessKeyRotated(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.days_threshold = 90

    def test_if_access_key_is_not_rotated_from_90_days(self):
        """
        Check if access key is not rotated from 90 days
        """
        key_criteria = 'serviceAccount[*].self.source_data.AccessKeys[*]'
        keys = [match.value for match in parse(key_criteria)\
            .find(self.resources)]
        disable_user = False
        for key in keys:
            if key["Status"]!="Active":
                continue
            created_at = key["CreateDate"]
            dt = datetime.strptime(created_at.replace(' GMT','Z'),"%a, %d %b %Y %H:%M:%S%z")
            diff = time.time() - datetime.timestamp(dt)
            days = diff/(60*60*24)
            if days>=self.days_threshold:
                disable_user = True
        self.assertEqual(False, disable_user, msg=f"Some of the user key\
                is not rotated from last {self.days_threshold} days")



    