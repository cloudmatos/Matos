import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSDefaultSgRestrictions(TestCase):
    
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.default_sg_name = 'default'


    def test_ingress_access(self):
        """
        No ingress rule should exists in default security group
        """
        sg_criteria = 'network[*].self.source_data.security_group[*]'
        security_groups = [match.value for match in parse(sg_criteria).find(self.resources)]
        default_groups = [sg for sg in security_groups if 
        sg["GroupName"]==self.default_sg_name ]
        ingress_criteria = '[*].IpPermissions[*]'
        ingress_rules = security_groups = [match.value for match in parse(ingress_criteria)\
            .find(default_groups)]
        no_ingress = len(ingress_rules) == 0
        self.assertEqual(True, no_ingress, msg="No ingress rule should exists for \
            a default security group")

    def test_egress_access(self):
        """
        No egress rule should exists in default security group
        """
        sg_criteria = 'network[*].self.source_data.security_group[*]'
        security_groups = [match.value for match in parse(sg_criteria).find(self.resources)]
        default_groups = [sg for sg in security_groups if 
        sg["GroupName"] == self.default_sg_name ]
        egress_criteria = '[*].IpPermissionsEgress[*]'
        egress_rules = security_groups = [match.value for match in parse(egress_criteria)\
            .find(default_groups)]
        no_egress = len(egress_rules) == 0
        self.assertEqual(True, no_egress, msg="No egress rule should exists for \
            a default security group")

    