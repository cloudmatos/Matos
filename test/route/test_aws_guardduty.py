import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSGuardDuty(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_guardduty_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_guardduty_should_be_enabled(self):
        """
        [PCI.GuardDuty.1] GuardDuty should be enabled

        """
        guardduties = [match.value for match in parse('guardduty[*]').find(self.resources)]
        flag =len(guardduties)>0
        self.assertEqual(True, flag, msg="Guarduty is not enabled")
    
    def test_high_severity_guardduty_findings(self):
        """
        MS- I529 7.139 [extra7139] There are High severity GuardDuty findings - guardduty [High]

        """
        severe_findings = [match.value for match in parse('guardduty[*].self.source_data..high_severity_findings[*]').find(self.resources)]
        flag = len(severe_findings)
        self.assertEqual(False, flag, msg="There are high severity findings in guardduty")
