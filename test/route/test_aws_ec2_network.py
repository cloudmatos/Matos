import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse

class TestAWSNetwork(TestCase):
    def setUp(self):
        print(os.getcwd() )
        fp = open(os.getcwd() + "/test/data/test_aws_ec2_network.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_network_unused(self):
        """
        Checks if there are unused network interfaces
        """
        test = [match.value['NetworkInterfaceId'] for match in parse('network[*].self.source_data.network_interfaces[*]').find(self.resources) if match.value.get('Status') == 'available']
        flag = len(set(test)) == 1
        self.assertEqual(True, flag, msg="Network interfaces has some unused network")
