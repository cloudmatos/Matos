import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestElasticLoadBalancer(TestCase):
    def setUp(self):
        print(os.getcwd())
        fp = open(os.getcwd() + "/test/data/test_aws_elb_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_elb_https_tls_termination(self):
        """
        Check if HTTPS or TLS termination is enabled
        """

        test = [match.value for match in parse('lb[*]..Attributes').find(self.resources) if
                match.value.get('routing.http.x_amzn_tls_version_and_cipher_suite.enabled') in ['true', True]]
        flag = len(set(test)) == 1
        self.assertEqual(True, flag,
                         msg="Classic Load Balancer listeners should be configured with HTTPS or TLS termination")

    def test_elb_deletion_protection(self):
        """
        Check if deletion protection option is enabled
        """

        test = [match.value for match in parse('lb[*]..Attributes').find(self.resources) if
                match.value.get('deletion_protection.enabled') in ['true', True]]
        flag = len(set(test)) == 1
        self.assertEqual(True, flag,
                         msg="Application Load Balancer deletion protection should be enabled")

    def test_elb_drop_http_headers(self):
        """
        Check if drop http header option is enabled
        """

        test = [match.value for match in parse('lb[*]..Attributes').find(self.resources) if
                match.value.get('routing.http.drop_invalid_header_fields.enabled') in ['true', True]]
        flag = len(set(test)) == 1
        self.assertEqual(True, flag,
                         msg="Application load balancer should be configured to drop http headers")

    def test_elb_access_log(self):
        """
        Check if access log option is enabled
        """

        test = [match.value for match in parse('lb[*]..Attributes').find(self.resources) if
                match.value.get('access_logs.s3.enabled') in ['true', True]]
        flag = len(set(test)) == 1
        self.assertEqual(True, flag,
                         msg="Application and Classic Load Balancers logging should be enabled")

    def test_elb_cross_zone(self):
        """
        Check if cross zone option is enabled
        """

        test = [match.value for match in parse('lb[*]..Attributes').find(self.resources) if
                match.value.get('load_balancing.cross_zone.enabled', True) in ['true', True]]
        flag = len(set(test)) == 1
        self.assertEqual(True, flag,
                         msg="Classic Load Balancers should have cross-zone load balancing enabled")

