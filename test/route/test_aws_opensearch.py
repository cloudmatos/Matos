import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSOpenSearch(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_opensearch_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        
    #use Case: OpenSearch domains should have encryption at rest enabled
    def test_opensearch_encrypted_at_rest(self):
        """
        [Redshift.1] OpenSearch domains should have encryption at rest enabled
        """
        test = [match.value for match in parse('opensearch[*].self.source_data.DomainStatus.EncryptionAtRestOptions.Enabled').find(self.resources) if match.value in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few opensearch domains without encryption at rest enabled.")

    #use Case: openSearch domains should encrypt data sent between nodes
    def test_opensearch_encrypted_between_node(self):
        """
        [Redshift.1] openSearch domains should encrypt data sent between nodes
        """
        test = [match.value for match in parse('opensearch[*].self.source_data.DomainStatus.NodeToNodeEncryptionOptions.Enabled').find(self.resources) if match.value in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few opensearch domains without encryption between node enabled.")

    #use Case: Connections to OpenSearch domains should be encrypted using TLS 1.2
    def test_opensearch_tls_encryption_check(self):
        """
        Connections to OpenSearch domains should be encrypted using TLS 1.2
        """
        test = [match.value for match in parse('opensearch[*].self.source_data.DomainStatus.DomainEndpointOptions.TLSSecurityPolicy').find(self.resources) if match.value not in ['Policy-Min-TLS-1-2-2019-07']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few opensearch domains without TLS 1.2 encryption enabled.")

    #use Case: OpenSearch domains should have at least three data nodes
    def test_opensearch_total_node_check(self):
        """
        OpenSearch domains should have at least three data nodes
        """
        test = [match.value for match in parse('opensearch[*].self.source_data.DomainStatus.ClusterConfig.InstanceCount').find(self.resources) if match.value < 3]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few opensearch domains having less then 3 nodes.")

    #use Case: OpenSearch should be in a VPC
    def test_opensearch_vpc_check(self):
        """
        OpenSearch should be in a VPC
        """
        test = [match.value for match in parse('opensearch[*].self.source_data.DomainStatus').find(self.resources) if not match.value.get('VPCOptions') or not match.value.get('VPCOptions').get('VPCId')]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few opensearch domains without includes in VPC")

    #use Case: OpenSearch domain error logging to CloudWatch Logs should be enabled
    def test_opensearch_error_logs_enable(self):
        """
        OpenSearch domain error logging to CloudWatch Logs should be enabled
        """
        test = [match.value for match in parse('opensearch[*].self.source_data.DomainStatus').find(self.resources) if not match.value.get('LogPublishingOptions') or not match.value.get('LogPublishingOptions').get('ES_APPLICATION_LOGS') or match.value.get('LogPublishingOptions').get('ES_APPLICATION_LOGS').get('Enabled') in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few opensearch domains without enable error logs")

    #use Case:  OpenSearch domains should have audit logging enabled
    def test_opensearch_audit_logs_enable(self):
        """
         OpenSearch domains should have audit logging enabled
        """
        test = [match.value for match in parse('opensearch[*].self.source_data.DomainStatus').find(self.resources) if not match.value.get('LogPublishingOptions') or not match.value.get('LogPublishingOptions').get('AUDIT_LOGS') or match.value.get('LogPublishingOptions').get('AUDIT_LOGS').get('Enabled') in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few opensearch domains without enable audit logs")

