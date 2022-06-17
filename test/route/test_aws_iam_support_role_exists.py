import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSIAMSupportRoleExists(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.support_policy_arn = 'arn:aws:iam::aws:policy/AWSSupportAccess'

    def test_if_iam_support_role_exists(self):
        """
        Check if IAM support role exists
        """
        policy_criteria = 'policy[*].self.source_data'
        policies = [match.value for match in parse(policy_criteria)\
            .find(self.resources)]
        support_policy = [policy for policy in policies if policy.get('Arn')\
            ==self.support_policy_arn ][0]
        role_attached = len(support_policy['PolicyRoles'])!=0
        self.assertEqual(True, role_attached, msg=f"No role is attached to support policy.")



    