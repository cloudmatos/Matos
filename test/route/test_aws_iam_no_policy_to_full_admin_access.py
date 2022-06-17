import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMNoPolicyToFullAdminAccess(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.support_policy_arn = 'arn:aws:iam::aws:policy/AWSSupportAccess'

    def test_if_policy_to_allow_full_admin_access(self):
        """
        Check if there is a policy other than AWS managed AdministorAccess policy 
        that gives full admin access.
        """
        policy_criteria = 'Policy[*].self.source_data'
        policies = [match.value for match in parse(policy_criteria)\
            .find(self.resources)]
        admin_access_given = False
        for policy in policies:
            if policy['Arn']=='arn:aws:iam::aws:policy/AdministratorAccess':
                continue
            for statement in policy.get("Statement",[]):
                if statement.get("Action",'')=="*" and statement.get("Resource",'')=='*':
                    admin_access_given = True
        self.assertEqual(False, admin_access_given, msg=f"There is a policy that \
            gives full admin access")



    