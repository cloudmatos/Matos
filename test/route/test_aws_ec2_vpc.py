import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse

class TestAWSNetworkAcl(TestCase):
    def setUp(self):
        print(os.getcwd() )
        fp = open(os.getcwd() + "/test/data/test_aws_ec2_vpc.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_vpc_network_acl_unused(self):
        """
        Checks if there are unused network access control lists (network ACLs)
        """
        test = [match.value['NetworkAclId'] for match in parse('network[*].self.source_data.network_acl[*]').find(self.resources) if match.value.get('IsDefault') == False and len(match.value.get('Associations')) == 0]
        flag = len(set(test)) == 1
        self.assertEqual(True, flag, msg="VPC has some unused network ACLs")
