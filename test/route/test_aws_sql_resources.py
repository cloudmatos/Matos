import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse

class TestCloudSql(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
    
    def test_IAMDatabaseAuthentication(self):
        """
        Check if database is IAM authenticated 
        """
        test = [match.value for match in parse('sql[*].self[*].IAMDatabaseAuthenticationEnabled').find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in [True, 'true']
        self.assertEqual(True, flag, msg="Database authentication via IAM is not enabled")

    def test_DeletionProtection(self):
        """
        Check if DeletionProtection is enabled 
        """
        test = [match.value for match in parse('sql[*].self[*].DeletionProtection').find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in [True, 'true']
        self.assertEqual(True, flag, msg="Deletion Protection is not enabled")

    def test_MultiAZ(self):
        """
        Check if MultiAZ is enabled 
        """
        test = [match.value for match in parse('sql[*].self[*].MultiAZ').find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in [True, 'true']
        self.assertEqual(True, flag, msg="Multiple availability is not enabled")

    def test_PerformanceInsights(self):
        """
        Check if Performance Insights are enabled
        """
        test = [match.value for match in parse('sql[*].self[*].PerformanceInsightsEnabled').find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in [True, 'true']
        self.assertEqual(True, flag, msg="Performance Insights are not enabled")

    def test_PubliclyAccessible(self):
        """
        Check if publicly accessible 
        """
        test = [match.value for match in parse('sql[*].self[*].PubliclyAccessible').find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in [False, 'false']
        self.assertEqual(True, flag, msg="Database is publicly accessible")
    
    def test_StorageEncrypted(self):
        """
        Check if storage is encrypted
        """
        test = [match.value for match in parse('sql[*].self[*].StorageEncrypted').find(self.resources)]
        flag = len(set(test)) == 1 and set(test).pop() in [True, 'true']
        self.assertEqual(True, flag, msg=" Storage Encryption is not enabled")
