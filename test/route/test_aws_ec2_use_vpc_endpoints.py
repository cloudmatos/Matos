import os
import re
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSEC2UseVPCEndpoint(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.service_regex = "com.amazonaws\.(.+).ec2"

    def test_endpoint_created_for_ec2_vpc(self):
        """
        Check if EC2 instance is assigned an instance profile or not.
        Note: To assign a role to the EC2 instance an instance profile is assigned.
        """
        ec2_vpc_criteria = 'instance[*].self.source_data.NetworkInterfaces[*].VpcId'
        ec2_vpcs = [match.value for match in parse(ec2_vpc_criteria).find(self.resources)]
        vpcs_endpoints = [match.value for match in parse('network[*].self.VpcEndpoints[*]').find(self.resources)]
        ec2_endpoints = []
        for endpoint in vpcs_endpoints:
            service_name = endpoint.get("ServiceName")
            if service_name is not None and re.search(self.service_regex,\
                service_name) is None:
                ec2_endpoints.append(endpoint)

        endpoint_exits = True
        for vpc in ec2_vpcs:
            if vpc not in ec2_endpoints:
                endpoint_exits = False
        self.assertEqual(True, endpoint_exits, msg="Endpoint does not exist for some VPC")

    def test_instance_profile_associated_with_role(self):
        """
        Check if instance profile is associated with a role
        """
        test = [match.value for match in parse('instance[*].self[*].IamInstanceProfile.Roles[0]').find(self.resources)]
        flag = len(test) == len(self.resources.get("instance"))
        self.assertEqual(True, flag, msg="Instance profile is not associated with a role")

    def test_trust_principal_is_ec2(self):
        """
        Check if assume role policy document associated with the instance role is having permission for the EC2 service.
        """
        criteria = 'instance[*].self[*].IamInstanceProfile.Roles[*].AssumeRolePolicyDocument.Statement[*].Principal.Service'
        test = [match.value for match in parse(criteria).find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in ['ec2.amazonaws.com']
        self.assertEqual(True, flag, msg="Principal in assume role policy document is not ec2 service")        
  
