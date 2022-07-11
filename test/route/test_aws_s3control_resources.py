import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
import json

class TestS3ControlResource(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_s3control.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_s3_account_level_public_access_block(self):
        """
        7.186 [extra7186] Check S3 Account Level Public Access Block - s3 [High] 
        """
        test = [match.value for match in parse('s3control[*].self.source_data').find(self.resources) if not match.value['IgnorePublicAcls'] or not match.value['RestrictPublicBuckets']]
        flag = len(test)
        self.assertEqual(False, flag, msg="S3 account level public access is not restricted")