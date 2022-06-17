from operator import truediv
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
import re  

class TestCluster(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_iam_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_iam_policy_attached_to_user(self):
        """
        Ensure IAM policies are attached only to groups or roles
        """
        test = [match.value for match in parse('serviceAccount[*].self').find(self.resources) if match.value.get('PasswordEnable') in ['true', True] and len(match.value.get('AttachedManagedPolicies'))]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few users having policy attached directly.")
        
    #Use Case: IAM.21 IAM customer managed policies that you create should not allow wildcard actions for services
    def test_user_has_custom_policy_wildcard_permissions(self):
        """
        Check user has customer manage policy attached which support wildcard permission
        """
        test = [match.value for match in parse('serviceAccount[*].self.AttachedManagedPolicies[*]').find(self.resources) 
                    if len([policy_version.value for policy_version in parse('PolicyVersion.Document.Statement[*]').find(match.value) if policy_version.value.get('Resource') == '*' and  policy_version.value.get('Effect') == 'Allow' and len([i for i in policy_version.value.get('Action', []) if ':*' in i or i == '*'])])
                ]

        flag = len(test) > 0 
        self.assertEqual(False, flag, msg="There are few policies with wildcard permissions assigned to the users")

    #Use Case: IAM.21 IAM customer managed policies that you create should not allow wildcard actions for services
    def test_group_has_custom_policy_wildcard_permissions(self):
        """
        Check user has customer manage policy attached which support wildcard permission
        """
        fp1 = open(os.getcwd() + "/test/data/test_aws_user_groups_resources.json", "r")
        content1 = fp1.read()
        fp1.close()
        self.resources1 = loads(content1)

        test1 = [match.value for match in parse('user_groups[*].self.source_data.AttachedPolicies[*]').find(self.resources1) 
                    if len([policy_version.value for policy_version in parse('PolicyVersion.Document.Statement[*]').find(match.value) if policy_version.value.get('Resource') == '*' and  policy_version.value.get('Effect') == 'Allow' and len([i for i in policy_version.value.get('Action', []) if ':*' in i or i == '*'])])
                ]
        flag = len(test1) > 0
        self.assertEqual(False, flag, msg="There are few policies with wildcard permissions assigned to the groups")


    # Use Case: 1.5 [check15] Ensure IAM password policy requires at least one uppercase letter - iam [Medium]
    def test_password_policy_upper_case_character(self):
        """
        Check password policy has upper case character enable or not
        """
        test = [match.value for match in parse('iam_setting.self.source_data.PasswordPolicy.RequireUppercaseCharacters').find(self.resources) if match.value in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="password policy without uppercase character required.")

    # Use Case: 1.6 [check16] Ensure IAM password policy require at least one lowercase letter - iam [Medium]
    def test_password_policy_lower_case_character(self):
        """
        Check password policy has lower case character enable or not
        """
        test = [match.value for match in parse('iam_setting.self.source_data.PasswordPolicy.RequireLowercaseCharacters').find(self.resources) if match.value in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="password policy without lower case character required.")

    # Use Case: 1.7 [check17] Ensure IAM password policy require at least one symbol - iam [Medium]
    def test_password_policy_symbol_character(self):
        """
        Check password policy has symbol character enable or not
        """
        test = [match.value for match in parse('iam_setting.self.source_data.PasswordPolicy.RequireSymbols').find(self.resources) if match.value in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="password policy without symbol character required.")

    # Use Case: 1.8 [check18] Ensure IAM password policy require at least one number - iam [Medium]
    def test_password_policy_numeric_character(self):
        """
        Check password policy has numeric character enable or not
        """
        test = [match.value for match in parse('iam_setting.self.source_data.PasswordPolicy.RequireNumbers').find(self.resources) if match.value in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="password policy without numeric character required.")

    # Use Case: 1.9 [check19] Ensure IAM password policy requires minimum length of 14 or greater - iam [Medium]
    def test_password_policy_length(self):
        """
        Check password policy has minimum 14 character length
        """
        test = [match.value for match in parse('iam_setting.self.source_data.PasswordPolicy.MinimumPasswordLength').find(self.resources) if match.value < 14]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="Password policy has less then 14 character required.")

