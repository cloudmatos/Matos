import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt


class TestEbsVolumeEncrypted(TestCase):

    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
      
    def test_ebs_volume_encrypted(self):
        """
        Check if ebs volumes attached to the ec2 instance are encrypted.
        """
        attached_volumes = [volume for volume in self.resources['disk'] if len(volume['self']['source_data']['Attachments'])>0]
        criteria = '[*].self.source_data.Encrypted'
        encryptions = [match.value for match in parse(criteria).find(attached_volumes)]
        all_encrypted = False not in encryptions
        self.assertEqual(True, all_encrypted, msg="EBS volume is not encrypted")

    