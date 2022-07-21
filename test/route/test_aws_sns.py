import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestAWSSNS(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_sns_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_sns_topic_policy_set_as_public(self):
        """
        MS- I520 7.31 [extra731] Check if SNS topics have policy set as Public - sns [Critical]

        """
        logging = [match.value for match in parse('sns[*].self.source_data.TopicAttributes.Policy').find(self.resources) if len([i for i in loads(match.value).get('Statement') if (i.get('Principal')=='*' or i.get('Principal',{}).get('AWS')=='*') and not i.get('Condition')])]
        flag = len(logging)
        self.assertEqual(False, flag, msg="In one of the SNS topic policy is public")
    
    