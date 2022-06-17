import os
import re
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSVPCFlowLogEnabled(TestCase):
    
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.vpc_id_regex = 'vpc-(.+)'


    def test_flow_log_in_all_vpc(self):
        """
        Test flow log exits in all VPC
        """
        flow_log_criteria = 'network[*].self.source_data.flow_logs[*]'
        vpc_resources = []
        flow_logs = [match.value for match in parse(flow_log_criteria).\
            find(self.resources)]
        for log in flow_logs:
            resource_id = log.get("ResourceId")
            x = re.search(self.vpc_id_regex,resource_id)
            if x is not None:
                vpc_resources.append(resource_id)
        flow_log_exists =  len(self.resources["network"])==len(set(vpc_resources
        ))
        self.assertEqual(True, flow_log_exists, msg="Flow log is not enabled \
            for one or more VPC")

    