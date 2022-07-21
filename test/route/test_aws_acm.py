from importlib.metadata import distributions
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt
from datetime import datetime

class TestAWSACM(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_acm_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_acm_certificate_have_transparency_logging_enabled(self):
        """
        7.24 [extra724] Check if ACM certificates have Certificate Transparency logging enabled - acm [Medium]

        """
        logging = [match.value for match in parse('acm[*].self.source_data').find(self.resources) if match.value.get('Type')!='IMPORTED' and match.value.get('Options').get('CertificateTransparencyLoggingPreference') !='ENABLED']
        flag = len(logging)
        self.assertEqual(False, flag, msg="ACM certificate transparency logging is not enabled.")
    
    def test_acm_certificates_are_about_to_expire_in_7_days(self):
        """
        7.30 [extra730] Check if ACM Certificates are about to expire in 7 days or less - acm [High]

        """
        
        about_to_expire = [match.value for match in parse('acm[*].self.source_data').find(self.resources) if  match.value.get('Type')!='IMPORTED' and (datetime.strptime(match.value.get("NotAfter"),"%a, %d %b %Y %H:%M:%S %Z")-datetime.utcnow()).days<=7]
        flag = len(about_to_expire)
        self.assertEqual(False, flag, msg="ACM certificate are about to expire in less than 7 days")
    
    def test_import_or_acm_certificates_are_about_to_expire_in_certain_days(self):
        """
        [ACM.1] Imported and ACM-issued certificates should be renewed after a specified time period

        """
        certain_days = 7
        about_to_expire = [match.value for match in parse('acm[*].self.source_data').find(self.resources) if (datetime.strptime(match.value.get("NotAfter"),"%a, %d %b %Y %H:%M:%S %Z")-datetime.utcnow()).days<=certain_days]
        flag = len(about_to_expire)
        self.assertEqual(False, flag, msg=f"ACM certificate are about to expire in less than {certain_days} days")
    
    def test_acm_wildcard_certificates_are_not_in_use(self):
        """
        Ensure that wildcard certificates issued by Amazon Certificate Manager (ACM) or imported to ACM are not in use.

        """
        wild_card_certs = [match.value for match in parse('acm[*].self.source_data').find(self.resources) if '*' in match.value.get('DomainName') and match.value.get('Status')=='ISSUED']
        flag = len(wild_card_certs)
        self.assertEqual(False, flag, msg=f"There are some wildcard certificates in use")
    
    def test_acm_certificates_are_in_use_or_not(self):
        """
        acm-certificates-in-use

        """
        not_in_use_certs = [match.value for match in parse('acm[*].self.source_data.InUseBy').find(self.resources) if len(match.value)==0 ]
        flag = len(not_in_use_certs)
        self.assertEqual(False, flag, msg=f"There are some certificates not in use")
    
    def test_acm_certificates_monitored_for_revocation(self):
        """
        acm-certificates-monitored-for-revocation

        """
        not_monitored_certs = [match.value for match in parse('acm[*].self.source_data').find(self.resources) if  match.value.get('CertificateAuthority') and not match.value.get('CertificateAuthority').get('RevocationConfiguration',{}).get('CrlConfiguration',{}).get('Enabled') and not match.value.get('CertificateAuthority').get('RevocationConfiguration',{}).get('OcspConfiguration',{}).get('Enabled') ]
        flag = len(not_monitored_certs)
        self.assertEqual(False, flag, msg=f"There are some ACM certificates those are not monitored")
    
    def test_acm_certificates_renewed_successfully(self):
        """
        acm-certificates-renewed-successfully

        """
        expired_certs = [match.value for match in parse('acm[*].self.source_data.Status').find(self.resources) if  match.value=='EXPIRED' ]
        flag = len(expired_certs)
        self.assertEqual(False, flag, msg=f"There are some expired certificates")
    
    def test_elb_acm_certificate_required(self):
        """
        ec2-elb-acm-certificate-required
        """

        test = [match.value for match in parse('lb[*]..ListenerDescriptions[*].Listener').find(self.resources) if match.value.get('SSLCertificateId') and ':acm:' not in match.value.get('SSLCertificateId')]
        flag = len(test)
        self.assertEqual(False, flag,
                         msg="In classic Load Balancers ACM certificate is not configured")
    
    def test_elbv2_acm_certificate_required(self):
        """
        ec2-elbv2-acm-certificate-required
        """

        test = [match.value for match in parse('lb[*].self.source_data').find(self.resources) if  match.value['Type']=='application' and len([certificate['CertificateArn'] for  listener in match.value.get('Listeners',[]) for certificate in listener.get('Certificates',{}) if ':acm:' not in certificate.get('CertificateArn')])]
        flag = len(test)
        self.assertEqual(False, flag,
                         msg="Application Load Balancers ACM certificate is not configured")
    
   