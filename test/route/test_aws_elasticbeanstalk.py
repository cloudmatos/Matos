import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse

class TestEasticBeanstalk(TestCase):
    def setUp(self):
        print(os.getcwd() )
        fp = open(os.getcwd() + "/test/data/test_aws_elasticbeanstalk.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_elasticbeanstalk_managed_platform(self):
        """
        Check if Elastic Beanstalk managed platform updates is enabled
        """

        test = [match.value['Value'] for match in parse('apphosting[*]..OptionSettings[*]').find(self.resources) if match.value.get('OptionName') == 'ManagedActionsEnabled']
        flag = len(set(test)) == 1 and set(test).pop() in [True, 'true']
        self.assertEqual(True, flag, msg="Elastic Beanstalk managed platform updates is not enabled")

    def test_elasticbeanstalk_enhanced_health_reporting(self):
        """
        Check if Elastic Beanstalk environments enhanced health reporting is enabled (i.e. enhanced and not basic)
        """

        test = [match.value['Value'] for match in parse('apphosting[*]..OptionSettings[*]').find(self.resources) if match.value.get('OptionName') == 'SystemType']
        flag = len(set(test)) == 1 and set(test).pop() in ['enhanced']
        self.assertEqual(True, flag, msg="Elastic Beanstalk environments enhanced health reporting is not enabled")
