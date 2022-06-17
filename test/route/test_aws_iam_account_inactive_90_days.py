import os
from datetime import datetime
import time
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMAccountInactive90Days(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.days_threshold = 90

    def test_if_password_is_not_used_from_90_days(self):
        """
        Check if user password is not used from 90 days
        """
        iams_criteria = 'serviceAccount[*].self.source_data'
        iams = [match.value for match in parse(iams_criteria)\
            .find(self.resources)]
        disable_user = False
        for iam in iams:
            if not iam["PasswordEnable"]:
                continue
            last_used = iam.get("PasswordLastUsed")
            if last_used is None:
                last_used = iam.get("CreateDate")
            dt = datetime.strptime(last_used.replace(' GMT','Z'),"%a, %d %b %Y %H:%M:%S%z")
            diff = time.time() - datetime.timestamp(dt)
            days = diff/(60*60*24)
            if days>=self.days_threshold:
                disable_user = True
        self.assertEqual(False, disable_user, msg=f"some of the user password\
                is not used from last {self.days_threshold} days")

    def test_if_access_key_is_not_used_from_90_days(self):
        """
        Check if access key is not used from 90 days
        """
        keys_criteria = 'serviceAccount[*].self.source_data.AccessKeys[*]'
        keys = [match.value for match in parse(keys_criteria)\
            .find(self.resources)]
        disable_user = False
        for key in keys:
            if key["Status"]!="Active":
                continue
            last_used = key.get("AccessKeyLastUsed")
            if last_used is None:
                last_used = key.get("CreateDate")
            dt = datetime.strptime(last_used.replace(' GMT','Z'),"%a, %d %b %Y %H:%M:%S%z")
            diff = time.time() - datetime.timestamp(dt)
            days = diff/(60*60*24)
            if days>=self.days_threshold:
                disable_user = True
        self.assertEqual(False, disable_user, msg=f"Some of the user key\
                is not used from last {self.days_threshold} days")



    