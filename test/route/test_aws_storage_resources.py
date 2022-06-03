import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
import json

class TestCloudStorage(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_lifecycle(self):
        """
        Check is any lifecycle policy is configured 
        """
        test = [match.value for match in parse('storage[*].self[*].lifecycle').find(self.resources)]
        flag = len(test) >= 1 and len(set(test.pop())) >= 1
        self.assertEqual(True, flag, msg="Lifecycle policy is not configured")

    def test_policy_status(self):
        """
        Check if any bucket is private or not
        """
        test = [match.value for match in parse('storage[*].self[*].policy_status.isPublic').find(self.resources)]
        flag = (len(set(test)) >= 1 and set(test).pop() in [False, 'false']) or (len(set(test)) == 0)
        self.assertEqual(True, flag, msg="Bucket is public!!")

    def test_intelligent_tiering(self):
        """
        Check if intelligent tiering is configured 
        """
        test = [match.value for match in
                parse('storage[*].self[*].intelligent_tiering_configuration').find(self.resources)]
        flag = len(test) >= 1 and len(set(test.pop())) >= 1
        self.assertEqual(True, flag, msg="Intelligent Tiering is not configured")

    def test_tagsExists(self):
        """
        Check if tag exists
        """
        test = [match.value for match in parse('storage[*].self[*].tagging').find(self.resources)]
        flag = len(test) >= 1
        self.assertEqual(True, flag, msg="Tags do not exists")

    def test_versioningEnabled(self):
        """
        Check if versioning is enabled
        """
        test = [match.value for match in parse('storage[*].self[*].versioning.Status').find(self.resources)]
        print(test)
        flag = (len(set(test)) >= 1 and set(test).pop() in ['Enabled'])
        self.assertEqual(True, flag, msg="Versioning is not enabled")
    
    # Use Case: S3.9 S3 bucket server access logging should be enabled
    def test_server_access_logs(self):
        """
        Check access logs enable or not for bucket
        """
        test = [match.value for match in parse('storage[*].self.source_data.logging').find(self.resources) if not match.value]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few buckets without logging enabled")
    
    #use case: PCI.S3.3 S3 buckets should have cross-region replication enabled
    def test_cross_region_replication(self):
        """
        Check storage has cross region replication enabled.
        """
        test = [match.value for match in parse('storage[*].self.source_data.replicationConfiguration').find(self.resources) if not match.value]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few buckets without replication enabled")
    
    #use case: PCI.S3.4 S3 buckets should have server-side encryption enabled
    def test_server_side_encryption(self):
        """
        Check storage bucket has server side encryption enabled
        """
        test = [match.value for match in parse('storage[*].self.source_data.encryption').find(self.resources) if not match.value.get('ServerSideEncryptionConfiguration')]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few buckets server side encryption enabled enabled")
    
    #Use case: PCI.S3.5 S3 buckets should require requests to use Secure Socket Layer
    def test_allow_ssl_connection(self):
        """
        Check storage bucket ssl only policy attached or not
        """
        final_data = [json.loads(match.value) if type(match.value) == str else match.value  for match in parse('storage[*].self.source_data.policy').find(self.resources)]
        test = [match.value  for match in parse('[*]').find(final_data) if  len([ssl for ssl in parse('Statement[*].Sid').find(match.value) if ssl.value == 'AllowSSLRequestsOnly']) < 1]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few buckets without ssl only policy attached")
    

    #Use case: S3.11 S3 buckets should have event notifications enabled
    def test_configure_event_notification(self):
        """
        Check storage bucket has notifications enabled
        """
        test = [match.value  for match in parse('storage[*].self.source_data.notification').find(self.resources) if len(match.value) < 1]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few buckets without notifications configured.")
    
