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

    def test_s3_bucket_access_logging_is_enabled(self):
        """
        2.6 [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket - s3 [Medium]

        """
        criteria = 'log_monitor[*].self.source_data.S3BucketLogging.TargetBucket'
        test = [match.value for match in parse(criteria).find(self.resources)]
        flag = len(test)==len(self.resources.get('log_monitor',[]))
        self.assertEqual(True, flag, msg="In one of the trail s3 bucket logging is not enabled")
    
    def test_s3_have_object_level_logging_enabled_in_cloudtrail(self):
        """
        7.25 [extra725] Check if S3 buckets have Object-level logging enabled in CloudTrail - s3 [Medium]

        """
        all_s3_arn =  "arn:aws:s3"
        all_s3_object = "AWS::S3::Object"
        data_resource_criteria = 'log_monitor[*].self.source_data.event_selectors[*].DataResources[*]'
        data_resource = [match.value for match in parse(data_resource_criteria).find(self.resources)]
        s3_data_resources = [item  for item in data_resource if item.get('Type')==all_s3_object and all_s3_arn in item.get('Values')]
        flag = len(s3_data_resources)>0
        self.assertEqual(True, flag, msg="S3 object level logging is not enabled for all the buckets")
    
    def test_atleast_one_multiregion_trail_should_be_present(self):
        """
        At least one multi-region AWS CloudTrail should be present in an account

        """
        criteria = 'log_monitor[*].self.source_data.IsMultiRegionTrail'
        test = [match.value for match in parse(criteria).find(self.resources)]
        flag = True in test
        self.assertEqual(True, flag, msg="Atleast one trail should be multi region")

    def test_s3_bucket_cloudtrail_logs_to_is_not_publicly_accessible(self):
        """
        2.3 [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible 
        - cloudtrail [Critical]

        """
        public_acl_uris = ["http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]
        is_public = False
        def check_access_policy(log_monitor):
            is_public = False
            if 'S3BucketAccessPoints' not in log_monitor:
                is_public = True
            for access_point in log_monitor.get('S3BucketAccessPoints'):
                public_block = access_point['PublicAccessBlockConfiguration']
                policy = access_point['Policy']
                if (public_block is None or not public_block.get('RestrictPublicBuckets')) and (policy is not None and loads(policy).get('Statement') is not None):
                    for statement in loads(policy).get('Statement'):
                        condition = statement.get("Condition")
                        if statement.get('Effect')=='Allow' and statement.get('Principal')=='*' \
                            and (condition is None or condition.get('StringLike') is not None):
                            is_public = True
            return is_public

        if not self.resources["s3control"][0]['self']['source_data']['RestrictPublicBuckets']:
            for log_monitor in self.resources.get("log_monitor",[]):
                log_monitor = log_monitor['self']['source_data']
                if 'Statement' in log_monitor['S3BucketPolicy'] and \
                    not log_monitor["S3PublicAccessBlock"]["RestrictPublicBuckets"]:
                    for statement in log_monitor['S3BucketPolicy']['Statement']:
                        principal = statement.get("Principal")
                        effect = statement.get("Effect")
                        condition = statement.get("Condition")
                        if effect=='Allow' and principal=='*' and (condition is None or condition.get('StringLike') is not None):
                            is_public = True
                        if effect=='Allow' and principal is not None and principal=={'AWS':'*'} and \
                            condition is not None and condition.get("StringEquals") is not None and \
                                condition.get("StringEquals").get('s3:DataAccessPointAccount') is not None:
                            if check_access_policy(log_monitor):
                                is_public=True
                            
        if not self.resources["s3control"][0]['self']['source_data']['IgnorePublicAcls']:
            for log_monitor in self.resources.get("log_monitor",[]):
                log_monitor = log_monitor['self']['source_data']
                if 'Grants' in log_monitor['S3BucketACL'] and \
                    not log_monitor["S3PublicAccessBlock"]["IgnorePublicAcls"]:
                    for grants in log_monitor['S3BucketACL']['Grants']:
                        if grants["Grantee"].get("Type")=='Group' and \
                            grants["Grantee"].get("URI") in public_acl_uris:
                            is_public = True
        self.assertEqual(False, is_public, msg="Atleast one of the cloudtrail s3 bucket \
            is publicly accessible")

    