import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestEbsSnapshotEncrypted(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
      
    def test_ebs_snapshot_encrypted(self):
        """
        Check if all the ebs snapshots are encrypted.
        """
        snapshots_to_encrypt = []
        for snapshot in self.resources['snapshot']:
            source_data = snapshot['self']['source_data']
            if source_data['Encrypted']==True:
                continue
            append = False
            if "Tags" not in source_data:
                append = True
            else:
                append = True
                for tag in source_data.get("Tags",[]):
                    if tag['Key']=='metos_source' and tag['Value']=='True':
                        append=False
                        break
            if append:
                snapshots_to_encrypt.append(snapshot)
        all_encrypted = len(snapshots_to_encrypt) == 0
        self.assertEqual(True, all_encrypted, msg="EBS snapshot is not encrypted")

    