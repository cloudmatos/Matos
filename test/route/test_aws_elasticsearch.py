import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSElasticSearch(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_elasticsearch_domain_should_be_in_vpc(self):
        """
        [PCI.ES.1] Elasticsearch domains should be in a VPC

        """
        test = [match.value for match in parse('elasticsearch[*].self.source_data.Endpoint').find(self.resources)]
        flag = len(test)>0
        self.assertEqual(False, flag, msg="One of the es domain is publicly accessible")


    def test_elasticsearch_domain_should_have_encryption_at_rest_enabled(self):
        """
        [PCI.ES.2] Elasticsearch domains should have encryption at rest enabled

        """
        test = [match.value for match in parse('elasticsearch[*].self.source_data.EncryptionAtRestOptions.Enabled').find(self.resources)]
        flag = False in test
        self.assertEqual(False, flag, msg="Encryption at rest is not enabled for some of the es domains")
    
    