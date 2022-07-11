import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSEC2IsSSMManaged(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)


    def test_instance_profile_associated_with_role(self):
        """
        Check if instance profile is associated with a role, need to pass this role value into 
        ansible script var - instance_role_name if test case passes.
        """
        test = [match.value for match in parse('instance[*].self.source_data.IamInstanceProfile.Roles[0]').find(self.resources)]
        flag = len(test) == len(self.resources.get("instance"))
        self.assertEqual(True, flag, msg="Instance profile is not associated with a role")

    def test_instance_is_ssm_managed(self):
        """
        Check if assume role policy document associated with the instance role is having permission for the EC2 service.
        """
        criteria = 'instance[*].self[*].source_data.SSM[*].InstanceId'
        ssm_managed_instances = [match.value for match in parse(criteria).find(self.resources)]
        all_instances_are_ssm_managed = len(set(ssm_managed_instances)) == len(self.resources['instance'])
        self.assertEqual(True, all_instances_are_ssm_managed, 
        msg="Some of the ec2 instance is not ssm managed")        
  
