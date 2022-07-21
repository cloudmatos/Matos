from importlib.metadata import distributions
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt
from datetime import datetime
import time

class TestAWSCodeBuild(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_codebuild_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_codebuild_verify_buildspec_enabled(self):
        """
       7.175 [extra7175] CodeBuild Project with an user controlled buildspec - codebuild [High]

        """
        response = [match.value for match in parse('codebuild[*].self.source_data.source').find(self.resources) if not match.value.get('buildspec') or not '.yml' in match.value.get('buildspec') or match.value.get('buildspec') in ['commands']]
        flag = len(response) > 0
        self.assertEqual(False, flag, msg="few of the codebuilds configurations user specify buildspec not defined.")
    
    def test_codebuild_verify_source_oauth_enabled(self):
        """
       [PCI.CodeBuild.1] CodeBuild GitHub or Bitbucket source repository URLs should use OAuth
        """
        response = [match.value for match in parse('codebuild[*].self.source_data.sourceCredentialsInfos[*]').find(self.resources) if match.value.get('serverType') in ['BITBUCKET', 'GITHUB'] and match.value.get('authType') != 'OAUTH']
        flag = len(response) > 0
        self.assertEqual(False, flag, msg="either github or bitbucket authentication hasn't configured with oauth.")
    
    def test_codebuild_verify_logging_enabled(self):
        """
        [CodeBuild.4] CodeBuild project environments should have a logging configuration
        """
        response = [match.value for match in parse('codebuild[*].self.source_data.logsConfig').find(self.resources) if not match.value.get('cloudWatchLogs') or match.value.get('cloudWatchLogs').get('status') != 'ENABLED']
        flag = len(response) > 0
        self.assertEqual(False, flag, msg="one of the codebuild projects hasn't configured with cloudwatch enabled.")
    
    def test_codebuild_verify_privileged_mode_enabled(self):
        """
        [CodeBuild.5] CodeBuild project environments should not have privileged mode enabled
        """
        response = [match.value for match in parse('codebuild[*].self.source_data.environment').find(self.resources) if not match.value.get('privilegedMode') or match.value.get('privilegedMode') in ['false', False]]
        flag = len(response) > 0
        self.assertEqual(False, flag, msg="one of the codebuild projects hasn't configured with privileged mode enabled.")
    
    def test_codebuild_verify_artifact_encryption_enabled(self):
        """
        codebuild-project-artifact-encryption-enabled
        """
        response = [match.value for match in parse('codebuild[*].self.source_data.artifacts').find(self.resources) if match.value.get('encryptionDisabled') in ['true', True]]
        flag = len(response) > 0
        self.assertEqual(False, flag, msg="one of the codebuild projects hasn't configured with artifact encryption enabled.")
    
    def test_codebuild_verify_s3_logs_encryption_enabled(self):
        """
        codebuild-project-s3-logs-encryption-enabled
        """
        response = [match.value for match in parse('codebuild[*].self.source_data.logs.s3Logs').find(self.resources) if match.value.get('encryptionDisabled') in ['true', True]]
        flag = len(response) > 0
        self.assertEqual(False, flag, msg="one of the codebuild projects hasn't configured with s3logs encryption enabled.")
    
    def test_codebuild_verify_last_build_days(self):
        """
        7.174 [extra7174] CodeBuild Project last invoked greater than 90 days - codebuild [High]
        """
        response = [match.value for match in parse('codebuild[*].self.source_data.lastBuildDetails').find(self.resources) if match.value.get('endTime')  and  (time.time() - datetime.timestamp(datetime.strptime(match.value.get('endTime').replace(' GMT','Z'),"%a, %d %b %Y %H:%M:%S%z")))/(60*60*24) > 90]
        flag = len(response) > 0
        self.assertEqual(False, flag, msg="one of the codebuild projects hasn't configured with s3logs encryption enabled.")
    