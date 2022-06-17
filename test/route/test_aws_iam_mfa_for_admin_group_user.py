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
        self.account_id = "144908232300"
        self.mfa_policy_name = f"mfa_enable_access_group_{self.account_id}"

    def test_mfa_enabled_for_admin_group_user(self):
        """
        Check if keys in IAM root account is inactive
        """
        iams_criteria = 'serviceAccount[*].self.source_data'
        iams = [match.value for match in parse(iams_criteria).find(self.resources)]
        enable_mfa = False
        for iam in iams:
            group_names = [group["GroupName"] for group in iam.get("GroupList",[])]
            if self.mfa_policy_name in group_names:
                continue
            for group in iam.get("GroupList",[]):
                for policy in group.get("AttachedPolicies",[]):
                    if policy["PolicyName"]=="AdministratorAccess" and  len(iam.get("MFADevices",[]))==0:
                        enable_mfa = True
        self.assertEqual(False, enable_mfa, msg="MFA for some of the admin group accounts is not enabled")



    