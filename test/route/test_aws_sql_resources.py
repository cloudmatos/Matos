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

    def test_MinerUpgrade(self):
        """
        Check if rds has miner version upgrade enabled or not
        """
        test = [match.value for match in parse('sql[*].self.AutoMinorVersionUpgrade').find(self.resources) if match.value in [False, 'false']]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few rds server without enabled miner version upgrade enabled.")

    def test_copyTagsToSnapshot(self):
        """
        Check if copy tags to snapshot is enabled or not
        """
        test = [match.value for match in parse('sql[*].self').find(self.resources) if not match.value.get('CopyTagsToSnapshot') or match.value.get('CopyTagsToSnapshot', '') in [False, 'false']]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few rds server without Copy Tags To Snapshot enabled.")

    def test_default_db_port(self):
        """
        Check rds has default port enabled or not
        """
        test = [match.value for match in parse('sql[*].self.Endpoint.Port').find(self.resources) if match.value in [3306, 5432, 1521, 1433]]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few rds instances with default port enabled")

    def test_enhance_monitoring(self):
        """
        Check rds has enabled enhance monitoring or not
        """
        test = [match.value for match in parse('sql[*].self').find(self.resources) if match.value.get('MonitoringInterval') in [0, '0'] or  match.value.get('MonitoringRoleArn', True)]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few rds instances without enable enhance monitoring enabled.")

    def test_master_username(self):
        """
        Check master username in rds
        """
        test = [match.value for match in parse('sql[*].self.MasterUsername').find(self.resources) if match.value == 'admin']
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few rds instances with default master rds username")

    def test_cloud_logging_enabled(self):
        """
        Check logging is enabled or not
        """
        test = [match.value for match in parse('sql[*].self').find(self.resources) if match.value.get('EnabledCloudwatchLogsExports', True)]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few rds instances without enable logging.")

    # Use case: RDS.14 Amazon Aurora clusters should have backtracking enabled
    def test_aurora_back_tracking(self):
        """
        Check back tracking is enabled for aurora db
        """
        test = [match.value for match in parse('sql[*].self.source_data').find(self.resources) if match.value.get('StorageType', True) == 'aurora' and not (match.value.get('DBCluster').get('BacktrackWindow', False) or match.value.get('DBCluster').get('BacktrackWindow', 0) > 0)]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few aurora rds instances without back tracking enabled.")




