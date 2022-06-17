import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMAvoidRootAccountUse(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.iam_key_active = "Active"

    def test_iam_root_account_key_is_inactive(self):
        """
        Check if keys in IAM root account is inactive
        """
        iams_criteria = 'serviceAccount[*].self.source_data'
        iams = [match.value for match in parse(iams_criteria).find(self.resources)]
        disable_key = False
        for iam in iams:
            is_admin = False
            for tag in iam.get("Tags",[]):
                if tag["Key"]=="Admins" and tag["Value"]=="All access":
                    is_admin = True
            if is_admin:
                for key in iam.get("AccessKeys",[]):
                    if key['Status']==self.iam_key_active:
                        disable_key = True
        self.assertEqual(False, disable_key, msg="Key of root account is Active")



    