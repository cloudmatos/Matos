import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSCloudTrail(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_cloudtrail_log_should_be_encrypted_at_rest(self):
        """
        [PCI.CloudTrail.1] CloudTrail logs should be encrypted at rest using AWS KMS keys

        """
        test = [match.value for match in parse('log_monitor[*].self.source_data.KmsKeyId').find(self.resources)]
        flag = len(test)==len(self.resources.get('log_monitor',[]))
        self.assertEqual(True, flag, msg="One of the cloudtrail log is not encrpyted with KMS key")


    def test_cloudtrail_should_be_enabled(self):
        """
        [PCI.CloudTrail.2] CloudTrail should be enabled

        """
        test = [match.value for match in parse('log_monitor[*].self.source_data.event_selectors[*].IncludeManagementEvents').find(self.resources)]
        flag = True in test
        self.assertEqual(True, flag, msg="No trail has management events enabled")
    
    def test_cloudtrail_log_file_validation_should_be_enabled(self):
        """
        [PCI.CloudTrail.3] CloudTrail log file validation should be enabled

        """
        test = [match.value for match in parse('log_monitor[*].self.source_data.LogFileValidationEnabled').find(self.resources)]
        flag = False not in test
        self.assertEqual(True, flag, msg="In one of the trail log file validation is not enabled")

    def test_cloudtrail_should_be_integrated_with_cloudwatch(self):
        """
        [PCI.CloudTrail.4] CloudTrail trails should be integrated with CloudWatch Logs

        """
        test = [match.value for match in parse('log_monitor[*].self.source_data.CloudWatchLogsLogGroupArn').find(self.resources)]
        flag = len(test)==len(self.resources.get('log_monitor',[]))
        self.assertEqual(True, flag, msg="In one of the trail log group is not associated")

    