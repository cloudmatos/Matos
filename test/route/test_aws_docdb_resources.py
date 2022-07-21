import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestDocDB(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_docdb_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    #Use Case: Amazon DocumentDB cluster deletion protection enabled
    def test_docdb_deletion_protection(self):
        """
        Amazon DocumentDB cluster deletion protection enabled
        """
        test = [match.value for match in parse('docdb[*].self.source_data.DeletionProtection').find(self.resources) if match.value in ['false', False]]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb clusters without deletion protection enabled.")
    
    #Use Case: Amazon DocumentDB cluster multi az enabled
    def test_docdb_multi_az_validation(self):
        """
        Amazon DocumentDB cluster multi az enabled
        """
        test = [match.value for match in parse('docdb[*].self.source_data.MultiAZ').find(self.resources) if match.value in ['false', False]]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb clusters without enable multi az cluster.")
    
    #Use Case: Amazon DocumentDB instance audit logging enabled
    def test_docdb_audit_logging_validation(self):
        """
        Amazon DocumentDB instance audit logging enabled
        """
        test = [match.value for match in parse('docdb[*].self.source_data').find(self.resources) if not match.value.get('EnabledCloudwatchLogsExports') or 'audit' not in match.value.get('EnabledCloudwatchLogsExports') ]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb instances without enable audit logging.")
    
    #Use Case: Amazon DocumentDB instance encryption enabled
    def test_docdb_encypted_validation(self):
        """
        Amazon DocumentDB instance encryption enabled
        """
        test = [match.value for match in parse('docdb[*].self.source_data.StorageEncrypted').find(self.resources) if not match.value in ['false', False]]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb instances without encrypted enabled.")
    
    #Use Case: Amazon DocumentDB parameter group audit logging enabled
    def test_docdb_parameter_logging_validation(self):
        """
        Amazon DocumentDB parameter group audit logging enabled
        """
        test = [match.value for match in parse('docdb[*].self.source_data.Parameters[*]').find(self.resources) if match.value.get('ParameterName') == 'audit_logs' and match.value.get('ParameterValue') == 'disabled' ]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb clusters without enabled parameters audit logs")
    
    #Use Case: Amazon DocumentDB parameter group enforce tls connections
    def test_docdb_parameter_tls_validation(self):
        """
        Amazon DocumentDB parameter group enforce tls connections
        """
        test = [match.value for match in parse('docdb[*].self.source_data.Parameters[*]').find(self.resources) if match.value.get('ParameterName') == 'tls' and match.value.get('ParameterValue') == 'disabled' ]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb clusters without enable parameters tls connection")

    #Use Case: Amazon DocumentDB snapshot encryption enabled
    def test_docdb_snapshot_ecryption_validation(self):
        """
        Amazon DocumentDB snapshot encryption enabled
        """
        test = [match.value for match in parse('docdb[*].self.source_data.DBClusterSnapshots[*]').find(self.resources) if match.value.get('StorageEncrypted') in ['false', False] ]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb clusters without enable snapshot encryption")

    
    #Use Case: Amazon DocumentDB snapshot not publicly accesible
    def test_docdb_snapshot_publicly_accessible_validation(self):
        """
        Amazon DocumentDB snapshot not publicly accesible
        """
        test = [match.value for match in parse('docdb[*].self.source_data.DBClusterSnapshots[*].DBClusterSnapshotAttributes[*]').find(self.resources) if match.value.get('AttributeName') == 'restore' and 'all' in match.value.get('AttributeValues') ]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="There are few docdb snapshots, shared with public.")

    