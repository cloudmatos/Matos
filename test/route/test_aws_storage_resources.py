import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


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
        flag = (len(set(test)) >=1 and set(test).pop() in [False, 'false']) or (len(set(test)) == 0)  
        self.assertEqual(True, flag, msg="Bucket is public!!")

    def test_intelligent_tiering(self):
        """
        Check if intelligent tiering is configured 
        """
        test = [match.value for match in parse('storage[*].self[*].intelligent_tiering_configuration').find(self.resources)]
        flag = len(test) >= 1 and len(set(test.pop())) >= 1
        self.assertEqual(True, flag, msg="Intelligent Tiering is not configured")

    def test_tagsExists(self):
        """
        Check if tag exists
        """
        test = [match.value for match in parse('storage[*].self[*].tagging').find(self.resources)]
        flag = len(test) >=1
        self.assertEqual(True, flag, msg="Tags do not exists")
    
    def test_versioningEnabled(self):
        """
        Check if versioning is enabled
        """
        test = [match.value for match in parse('storage[*].self[*].versioning.Status').find(self.resources)]
        print(test)
        flag = (len(set(test)) >=1 and set(test).pop() in ['Enabled'])
        self.assertEqual(True, flag, msg="Versioning is not enabled")
