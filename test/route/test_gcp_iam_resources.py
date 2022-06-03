import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
import datetime

class TestIAM(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_gcp_iam_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_iam_with_admin_permissions(self):
        """
        Check service accounts has admin permissions or not
        """
        test = [match.value for match in
                parse('project[*].self.iam_policy.bindings[*]').find(self.resources) if 'Admin' in match.value.get('role', '') and [sa for sa in match.value.get('members', []) if 'serviceAccount' in sa ]]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few service accounts having admin permission assinged.")

    def test_user_having_service_account_user_at_project_level(self):
        """
        Check users has service account user permission at project level
        """
        test = [match.value for match in parse('project[*].self.iam_policy.bindings[*].role').find(self.resources) if 'roles/iam.serviceAccountUser' in match.value]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few users having service account user permission assinged at project level.")

    def test_check_user_with_project_adminstrative_roles(self):
        """
        Check service account has project wise roles assigned or not
        """
        test = [match.value for match in parse('project[*].self.iam_policy.bindings[*].role').find(self.resources) if match.value in ['roles/editor', 'roles/owner']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few identity having administrative permission at project level.")

    def test_check_gmail_account_is_being_used(self):
        """
        Check either gmail account is being used or not
        """
        test = [match.value for match in parse('project[*].self.iam_policy.bindings[*].members[*]').find(self.resources) if 'gmail.com' in match.value]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few roles assigned to gmail accounts.")