import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSRedShift(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_redshift_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
    #use Case: Amazon Redshift clusters should prohibit public access
    # def test_redshift_public_access(self):
    #     """
    #     [Redshift.1] Amazon Redshift clusters should prohibit public access
    #     """
    #     test = [match.value for match in parse('redshift[*].self.source_data.PubliclyAccessible').find(self.resources) if match.value in [False, 'false']]
    #     flag = len(test) > 0
    #     self.assertEqual(False, flag, msg="there are few redshift clusters are publicly accessible.")

    # #Use Case: Amazon Redshift clusters should not use the default Admin username
    # def test_redshift_check_default_username(self):
    #     """
    #     Amazon Redshift clusters should not use the default Admin username
    #     """
    #     test = [match.value for match in parse('redshift[*].self.source_data.MasterUsername').find(self.resources) if match.value == 'awsuser']
    #     flag = len(test) > 0
    #     self.assertEqual(False, flag, msg="there are few redshift clusters, having default aws username.")


    # #Use Case: Amazon Redshift clusters should use enhanced VPC routing
    # def test_redshift_check_enhance_vpc_routing(self):
    #     """
    #     Amazon Redshift clusters should use enhanced VPC routing
    #     """
    #     test = [match.value for match in parse('redshift[*].self.source_data.EnhancedVpcRouting').find(self.resources) if match.value in [False, 'false']]
    #     flag = len(test) > 0
    #     self.assertEqual(False, flag, msg="there are few redshift clusters, without enhance vpc routing enabled.")

    # #Use Case: Amazon Redshift should have automatic upgrades to major versions enabled
    # def test_redshift_check_automatic_upgrade(self):
    #     """
    #     Amazon Redshift should have automatic upgrades to major versions enabled
    #     """
    #     test = [match.value for match in parse('redshift[*].self.source_data.AllowVersionUpgrade').find(self.resources) if match.value in [False, 'false']]
    #     flag = len(test) > 0
    #     self.assertEqual(False, flag, msg="there are few redshift clusters, without automatic upgrade enabled.")

    # #Use Case: Amazon Redshift clusters should have automatic snapshots enabled
    # def test_redshift_check_automatic_snapshot(self):
    #     """
    #     Amazon Redshift clusters should have automatic snapshots enabled
    #     """
    #     test = [match.value for match in parse('redshift[*].self.source_data.AutomatedSnapshotRetentionPeriod').find(self.resources) if match.value in ['0', 0]]
    #     flag = len(test) > 0
    #     self.assertEqual(False, flag, msg="there are few redshift clusters, without automatic snapshot enabled.")

    # #Use Case: Connections to Amazon Redshift clusters should be encrypted in transit
    # def test_redshift_check_ssl_enable(self):
    #     """
    #     Connections to Amazon Redshift clusters should be encrypted in transit
    #     """
    #     test = [match.value for match in parse('redshift[*].self.source_data.ParameterGroups[*]').find(self.resources) if match.value.get('ParameterName') == 'require_ssl' and match.value.get('ParameterValue') in [False, 'false']]
    #     flag = len(test) > 0
    #     self.assertEqual(False, flag, msg="there are few redshift clusters, without ssl enabled at transit.")

    # #Use Case: Amazon Redshift clusters should have user activity logging enabled
    # def test_redshift_check_user_activities(self):
    #     """
    #     Amazon Redshift clusters should have user activity logging enabled
    #     """
    #     test = [match.value for match in parse('redshift[*].self.source_data.ParameterGroups[*]').find(self.resources) if match.value.get('ParameterName') == 'enable_user_activity_logging' and match.value.get('ParameterValue') in [False, 'false']]
    #     flag = len(test) > 0
    #     self.assertEqual(False, flag, msg="there are few redshift clusters, without user activities.")
    
    #Use Case: Amazon Redshift clusters should have audit logging enabled
    def test_redshift_audit_logging(self):
        """
        Amazon Redshift clusters should have audit logging enabled
        """
        test = [match.value for match in parse('redshift[*].self.source_data.LoggingEnabled').find(self.resources) if match.value in [False, 'false']]
        flag = len(test) > 0
        self.assertEqual(False, flag, msg="there are few redshift clusters, without audit logging enabled")
    
    



