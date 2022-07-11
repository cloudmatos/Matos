from importlib.metadata import distributions
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt


class TestAWSCloudFront(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_cloudfront_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_cloudfront_distribution_should_have_logging_enabled(self):
        """
        MS- I576 [CloudFront.5] CloudFront distributions should have logging enabled

        """
        logging = [match.value for match in parse('cloudfront[*].self.source_data.DistributionConfig.Logging.Enabled').find(self.resources) if match.value in [False,'False','false']]
        flag = len(logging)
        self.assertEqual(False, flag, msg="In one of the cloudfront distribution logging is not enabled")
    
    def test_cloudfront_distribution_should_have_encryption_in_transit(self):
        """
        MS- I574 [CloudFront.3] CloudFront distributions should require 
        encryption in transit
        """
        not_encrypted = [match.value for match in parse('cloudfront[*].self.source_data.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy').find(self.resources) if match.value == 'allow-all']
        flag = len(not_encrypted)
        self.assertEqual(False, flag, msg="In one of the cloudfront distribution encryption in transit is not enabled")
    
    def test_cloudfront_distribution_should_have_default_root_object(self):
        """
        MS- I572 [CloudFront.1] CloudFront distributions should have a 
        default root object configured
        """
        root_objects = [match.value for match in parse('cloudfront[*].self.source_data.DistributionConfig.DefaultRootObject').find(self.resources) if match.value==""]
        flag = len(root_objects)
        self.assertEqual(False, flag, msg="In one of the cloudfront distribution encryption in transit is not enabled")
    
    def test_cloudfront_distribution_should_have_origin_access_identity_enabled(self):
        """
        [CloudFront.2] CloudFront distributions should have origin access identity enabled
        """
        root_objects = [match.value for match in parse('cloudfront[*].self.source_data.DistributionConfig.Origins.Items[*].S3OriginConfig.OriginAccessIdentity').find(self.resources) if match.value!=""]
        flag = len(root_objects)==len(self.resources['cloudfront'])
        self.assertEqual(True, flag, msg="In one of the cloudfront distribution origin access identity is not enabled")
    
    def test_cloudfront_distribution_should_have_origin_failover_configured(self):
        """
        [CloudFront.4] CloudFront distributions should have origin failover configured
        """
        root_objects = [match.value for match in parse('cloudfront[*].self.source_data.DistributionConfig.OriginGroups.Quantity').find(self.resources) if match.value>0]
        flag = len(root_objects)==len(self.resources['cloudfront'])
        self.assertEqual(True, flag, msg="In one of the cloudfront distribution origin failover is not enabled")
    
    def test_cloudfront_distribution_should_be_integrated_with_waf(self):
        """
        [CloudFront.6] CloudFront distributions should have AWS WAF enabled
        """
        web_acl_ids = [match.value for match in parse('cloudfront[*].self.source_data.DistributionConfig.WebACLId').find(self.resources) if match.value!=""]
        flag = len(web_acl_ids)==len(self.resources['cloudfront'])
        self.assertEqual(True, flag, msg="In one of the cloudfront distribution origin WAF is not enabled")
    
    def test_cloudfront_distribution_should_encrypt_traffic_to_custom_origins(self):
        """
        [CloudFront.9] CloudFront distributions should encrypt traffic to custom origins
        """
        encrypted = True
        dist_configs = [match.value for match in parse('cloudfront[*].self.source_data.DistributionConfig').find(self.resources) if match.value!=""]
        for config in dist_configs:
            for item in config['Origins'].get('Items',[]):
                if item.get('CustomOriginConfig',{}).get('OriginProtocolPolicy')=='http-only':
                    encrypted = False
                elif  item.get('CustomOriginConfig',{}).get('OriginProtocolPolicy')=='match-viewer':
                    if config.get('DefaultCacheBehavior',{}).get('ViewerProtocolPolicy') == 'allow-all':
                        encrypted = False
        
        self.assertEqual(True, encrypted, msg="In one of the cloudfront distribution traffic to custom origins is not encrypted")

    def test_cloudfront_distribution_should_use_custom_ssl_tls_certificates(self):
        """
        [CloudFront.7] CloudFront distributions should use custom SSL/TLS certificates
        Reference - https://aws.amazon.com/premiumsupport/knowledge-center/install-ssl-cloudfront/
        """
        flag = True
        distributions = [match.value for match in parse('cloudfront[*].self.source_data').find(self.resources)]
        for distribution in distributions:
            if distribution.get('ViewerCertificate',{}).get('CloudFrontDefaultCertificate',True) and distribution.get('Aliases').get('Quantity')!=0:
                flag = False
        
        self.assertEqual(True, flag, msg="In one of the cloudfront distribution custom cert is not used for custom domains")
    
    def test_cloudfront_distribution_should_use_sni_to_serve_https_requests(self):
        """
        [CloudFront.8] CloudFront distributions should use SNI to serve HTTPS requests.
        Reference - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-https-dedicated-ip-or-sni.html
        """
        flag = True
        distributions = [match.value for match in parse('cloudfront[*].self.source_data').find(self.resources)]
        for distribution in distributions:
            if not distribution.get('ViewerCertificate',{}).get('CloudFrontDefaultCertificate',True) and distribution.get('ViewerCertificate',{}).get('SSLSupportMethod')!='sni-only':
                flag = False
        self.assertEqual(True, flag, msg="In one of the cloudfront distribution where custom cert is used but sni support is not enabled")