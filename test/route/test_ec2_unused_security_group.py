import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt


class TestUnusedSecurityGroup(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
      
    def test_unused_security_group(self):
        """
        Check if a security group is being used.
        """
        
        all_sgs_criteria = 'network[*].self.source_data.security_group[*]'
        all_sgs = [match.value for match in parse(all_sgs_criteria)\
            .find(self.resources)]
        groups_to_consider = []
        for sg in all_sgs:
            if sg["GroupName"]=="default":
                continue
            should_include = True
            tags = sg.get("Tags",[])
            for tag in tags:
                if tag["Key"]=='matos_is_dependent' and tag["Value"]=="True":
                    should_include = False
            if should_include:
                groups_to_consider.append(sg)            
        all_sgs_criteria = '[*].GroupId'
        all_sgs = [match.value for match in parse(all_sgs_criteria)\
            .find(groups_to_consider)]
        instance_sgs_criteria = 'instance[*].self.source_data.SecurityGroups[*].GroupId'
        instance_sgs = [match.value for match in parse(instance_sgs_criteria)\
            .find(self.resources)]
        all_are_used = len(set(all_sgs)) <= len(set(instance_sgs))
        self.assertEqual(True, all_are_used, msg="Found unsed security groups")

    