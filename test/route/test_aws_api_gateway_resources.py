from importlib.metadata import distributions
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt
from datetime import datetime
import time

class TestAWSAPIGateway(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_apigateway_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_rest_api_logging(self):
        """
        [APIGateway.1] API Gateway REST API logging should be enabled
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]').find(self.resources) if not match.value.get('accessLogSettings') or not match.value.get('accessLogSettings').get('destinationArn')]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest apigateway without configured logging")

    def test_web_socket_api_logging(self):
        """
        [APIGateway.1] API Gateway SOCKET API logging should be enabled
        """
        logging = [match.value for match in parse('apigateway[*].self.source_data.stages[*]').find(self.resources) if not match.value.get('accessLogSettings') or not match.value.get('accessLogSettings').get('destinationArn')]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few web socket apigateway without configured logging")

    def test_rest_api_ssl_certificate_verification(self):
        """
        API Gateway REST API stages should be configured to use SSL certificates for backend authentication

        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]').find(self.resources) if not match.value.get('clientCertificateId') ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api stages without ssl certificate configured")

    def test_rest_api_xray_tracing_verification(self):
        """
        API Gateway REST API stages should have AWS X-Ray tracing enabled
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]').find(self.resources) if not match.value.get('tracingEnabled') ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api stages without AWS X-Ray tracing configured")

    def test_rest_api_web_acl_verification(self):
        """
        API Gateway REST API should be associated with an AWS WAF web ACL
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]').find(self.resources) if not match.value.get('webAclArn') ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api stages without web acl configured")

    def test_rest_api_cache_data_encryption_verification(self):
        """
        API Gateway REST API cache data should be encrypted at rest

        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]..cacheDataEncrypted').find(self.resources) if not match.value ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api stages without cache encrypted at rest configured")

    def test_rest_api_public_endpoint_verification(self):
        """
        Check if API Gateway REST API endpoint is public or private

        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.endpointConfiguration').find(self.resources) if not match.value.get('types') or 'PRIVATE' not in match.value.get('types') ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api without without configured private endpoint")

    def test_rest_api_response_cache_enabled_verification(self):
        """
        Ensure that REST APIs created with Amazon API Gateway have response caching enabled.
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]').find(self.resources) if not match.value.get('cacheClusterEnabled')]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api without without configured response cache enabled.")

    def test_rest_api_cloud_watch_verification(self):
        """
        Ensure detailed CloudWatch metrics are enabled for Amazon API Gateway APIs stages.
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]..metricsEnabled').find(self.resources) if not match.value ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api stages without cloud watch configured")

    def test_rest_api_content_encoding_verification(self):
        """
        Ensure APIs created with Amazon API Gateway have Content Encoding feature enabled.
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data').find(self.resources) if not match.value.get('minimumCompressionSize') ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api stages without content encoding configured")

    def test_rest_api_certificate_rotate_periodically_verification(self):
        """
        Ensure that SSL certificates associated with API Gateway REST APIs are rotated periodically
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.stages[*]').find(self.resources) if match.value.get('CertificateExpirationDate') and  (datetime.timestamp(datetime.strptime(match.value.get('CertificateExpirationDate').replace(' GMT','Z'),"%a, %d %b %Y %H:%M:%S%z")) - time.time())/(60*60*24) < 30]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api stages certificates rotation due in next 30 days")
    
    def test_rest_api_custom_authorizer_verification(self):
        """
        Check if API Gateway REST API has configured authorizers - apigateway
        """
        logging = [match.value for match in parse('rest_api[*].self.source_data.resources[*].resourceMethods..authorizationType').find(self.resources) if match.value == 'NONE' ]
        flag = len(logging)
        self.assertEqual(False, flag, msg="there are few rest api methods without configured authorizations")
    
    