from importlib.metadata import distributions
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt
import json

class TestAWSSQS(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_sqs_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_sqs_queue_encrypted_at_rest(self):
        """
       Amazon SQS queues encryption at rest enabled
        """
        data = [match.value for match in parse('sqs[*].self.source_data').find(self.resources) if match.value.get('SqsManagedSseEnabled') in ['false', False] and not match.value('KmsMasterKeyId')]
        flag = len(data)
        self.assertEqual(False, flag, msg="There are few sqs queues, without server side encrypted enabled")
    
    def test_sqs_queue_publicly_accessible(self):
        """
       Amazon SQS queues not publicly accessible
        """
        data = [match.value for match in parse('sqs[*].self.source_data.Policy').find(self.resources) if len([policy for policy in parse('Statement[*]').find(json.loads(match.value)) if policy.value.get('Effect') == 'Allow' and policy.value.get('Principal') == '*'])]
        flag = len(data) > 0
        self.assertEqual(False, flag, msg="There are few sqs queues, without disbled public access.")
    
    def test_sqs_queue_encrypted_with_CMEK(self):
        """
       Ensure SQS queues are encrypted with KMS CMKs to gain full control over data encryption and decryption.
        """
        data = [match.value for match in parse('sqs[*].self.source_data').find(self.resources) if match.value.get('SqsManagedSseEnabled') in ['true', True] and not match.value('KmsMasterKeyId')]
        flag = len(data) > 0
        self.assertEqual(False, flag, msg="There are few sqs queues, without encrypted the data using CMEK.")
    