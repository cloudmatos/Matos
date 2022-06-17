import os
from datetime import datetime
import time
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMTwoAccessKeys(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.days_threshold = 90

    def test_if_iam_user_has_two_access_keys(self):
        """
        Check if an IAM user is having two access keys
        """
        iams_criteria = 'serviceAccount[*].self.source_data'
        iams = [match.value for match in parse(iams_criteria)\
            .find(self.resources)]
        have_two_active_keys = False
        for iam in iams:
            keys = [key for key in iam.get("AccessKeys",[]) if key['Status']=='Active']
            if len(keys)==2:
                have_two_active_keys = True
        self.assertEqual(False, have_two_active_keys, msg=f"Some of the user is having \
            two access keys")