import os
from unittest import TestCase
from json import loads, dumps
from click import BadParameter
from jsonpath_ng import parse

class TestAWSElasticFileSystem(TestCase):
    def setUp(self):
        print(os.getcwd() )
        fp = open(os.getcwd() + "/test/data/test_aws_efs.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_efs_backup_policy(self):
        """
        Checks if Amazon EFS volumes has backup enabled
        """

        test = [match.value['FileSystemId'] for match in parse('filesystem[*].self.source_data').find(self.resources) if (match.value.get('BackupPolicy') == {} or match.value.get('BackupPolicy')["Status"] == "DISABLED" )]
        flag = len(set(test)) == 0
        self.assertEqual(True, flag, msg="Some Amazon EFS volumes don't have backup enabled")

    def test_efs_encrypted(self):
        """
        Checks if Amazon EFS is encrypted
        """

        test = [match.value['FileSystemId'] for match in parse('filesystem[*].self.source_data').find(self.resources) if match.value.get('Encrypted') == False]
        flag = len(set(test)) == 0
        self.assertEqual(True, flag, msg="Some EFS is not configured to encrypt file data at rest")
