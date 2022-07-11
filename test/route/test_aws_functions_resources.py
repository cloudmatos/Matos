from operator import truediv
import os
from unittest import TestCase
from json import loads, dumps
import json
from jsonpath_ng import parse
import re  

class TestFunctions(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_functions_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
    
    #use Case: 7.98 [extra798] Check if Lambda functions have resource-based policy set as Public - lambda [Critical]
    def test_functions_public_access(self):
        """
        Check if function can access by anyone
        """
        test = [match.value  for match in parse('[*].Statement.[*]').find([json.loads(match.value) for match in parse('functions[*].self.source_data.AttachedPolicies.Policy').find(self.resources)]) if match.value.get('Effect') == 'Allow' and match.value.get('Principal') == '*' and match.value.get('Condition', {}).get('StringEquals', {}).get('lambda:FunctionUrlAuthType', {}) == 'NONE']
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few functions which are publicly accessible by everyone.")

    #use Case: 7.145 [extra7145] Check if Lambda functions have policies which allow access to any AWS account - lambda [Critical]
    def test_functions_access_to_any_aws_account(self):
        """
        Access of lamda functions by any aws accounts
        """
        test = [match.value  for match in parse('[*].Statement.[*]').find([json.loads(match.value) for match in parse('functions[*].self.source_data.AttachedPolicies.Policy').find(self.resources)]) if match.value.get('Effect') == 'Allow' and match.value.get('Principal') == '*' and not match.value.get('Condition')]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few functions which are accessible by any aws accounts.")

    #[Lambda.4] Lambda functions should have a dead-letter queue configured (Retired)
    def test_functions_test_dead_letter_configured(self):
        """
        check dead ltter configured for lambda
        """
        test = [match.value  for match in parse('functions[*].self.source_data.FunctionDetails.Configuration').find(self.resources) if not match.value.get('DeadLetterConfig')]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few functions without dead letter configured.")

    
    #[Lambda.5] VPC Lambda functions should operate in more than one Availability Zone
    def test_functions_multiple_az_configured(self):
        """
        check functions has az configured
        """
        test = [match.value  for match in parse('functions[*].self.source_data.VpcConfig.SubnetIds').find(self.resources) if len(match.value) < 2]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few functions without high availbility configured.")

    #Lambda functions should be in a VPC
    def test_functions_vpc_configured(self):
        """
        check functions has connected with VPC
        """
        test = [match.value  for match in parse('functions[*].self.source_data').find(self.resources) if not match.value.get('VpcConfig')]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few functions without connected with any vpc.")
    
