from importlib.metadata import distributions
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse
from rsa import encrypt


class TestAWSGlue(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_glue_resource.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    # def test_glue_job_have_s3_encryption_enabled(self):
    #     """
    #     7.114 [extra7114] Check if Glue job have S3 encryption enabled. - glue

    #     """
    #     logging = [match.value for match in parse('glue[*].Jobs[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('S3Encryption')[0]['S3EncryptionMode']=='DISABLED']
    #     flag = len(logging)
    #     self.assertEqual(False, flag, msg="In one of the glue job s3 encryption is not enabled")
    
    # def test_glue_dev_endpoint_have_s3_encryption_enabled(self):
    #     """
    #     7.114 [extra7114] Check if Glue development endpoints have S3 encryption enabled. - glue

    #     """
    #     logging = [match.value for match in parse('glue[*].DevEndpoints[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('S3Encryption')[0]['S3EncryptionMode']=='DISABLED']
    #     flag = len(logging)
    #     self.assertEqual(False, flag, msg="In one of the glue dev endpoint s3 encryption is not enabled")

    # def test_glue_encryption_at_rest_is_enabled_for_cloudwatch_logs(self):
    #     """
    #     Ensure that at-rest encryption is enabled when writing Amazon Glue logs to CloudWatch Logs

    #     """
    #     dev_endpoint_logging = [match.value for match in parse('glue[*].DevEndpoints[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('CloudWatchEncryption')['CloudWatchEncryptionMode']=='DISABLED']
    #     jobs_logging = [match.value for match in parse('glue[*].Jobs[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('CloudWatchEncryption')['CloudWatchEncryptionMode']=='DISABLED']
    #     flag = len(dev_endpoint_logging) or len(jobs_logging)
    #     self.assertEqual(False, flag, msg="In one of the glue security configuration encryption at rest is not enabled for logs to cloudwatch")
    
    # def test_glue_data_catalogs_enforce_data_at_rest_encryption_using_cmk_kms(self):
    #     """
    #     Ensure that Amazon Glue Data Catalogs enforce data-at-rest encryption using KMS CMKs.
    #     """
    #     settings = [match.value for match in parse('glue[*].DataCatalogueEncryptionSettings.self.source_data').find(self.resources) if match.value.get('EncryptionAtRest').get('CatalogEncryptionMode') != 'SSE-KMS' or match.value.get('KeyDetails').get('KeyManager')!='CUSTOMER']
    #     flag = len(settings)
    #     self.assertEqual(False, flag, msg="Data catalogue encryption at rest is not using CMK KMS")
    
    # def test_glue_data_catalogs_object_and_connection_password_are_encrypted(self):
    #     """
    #     Ensure that Amazon Glue Data Catalog objects and connection passwords are encrypted
    #     """
    #     settings = [match.value for match in parse('glue[*].DataCatalogueEncryptionSettings.self.source_data').find(self.resources) if not match.value.get('ConnectionPasswordEncryption').get('ReturnConnectionPasswordEncrypted')]
    #     flag = len(settings)
    #     self.assertEqual(False, flag, msg="Data catalogue objects and password are not encrpyted")

    # def test_encryption_at_rest_is_enabled_for_glue_job_bookmarks(self):
    #     """
    #     Ensure that encryption at rest is enabled for Amazon Glue job bookmarks.
    #     #     """
    #     jobs_bookmarks = [match.value for match in parse('glue[*].Jobs[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('JobBookmarksEncryption')['JobBookmarksEncryptionMode']=='DISABLED']
    #     flag = len(jobs_bookmarks)
    #     self.assertEqual(False, flag, msg="encryption at rest is not enabled for Amazon Glue job bookmarks")

    # def test_glue_encryption_at_rest_is_enabled_for_crawlers_logs(self):
    #     """
    #     glue-crawlers-cloudwatch-logs-encryption-enabled

    #     """
    #     crawlers_logging = [match.value for match in parse('glue[*].Crawlers[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('CloudWatchEncryption')['CloudWatchEncryptionMode']=='DISABLED']
    #     flag = len(crawlers_logging)
    #     self.assertEqual(False, flag, msg="In one of the Crawler encryption at rest is not enabled for logs to cloudwatch")

    # def test_glue_data_catalogs_fine_grained_access_controls_with_resource_policy_enforced(self):
    #     """
    #     glue-data-catalogs-fine-grained-access-controls-with-resource-policy-enforced

    #     """
    #     catalogue_resource_policies = [match.value for match in parse('glue[*].DataCatalogueResourcePolicy[*].self.source_data').find(self.resources) ]
    #     fine_grained_access = True
    #     for policy in catalogue_resource_policies:
    #         policy_in_json = loads(policy['PolicyInJson'])
    #         print(f"policy in json {policy_in_json}")
    #         for statement in policy_in_json['Statement']:
    #             if (statement.get('Principal')=='*' or statement.get('Principal',{}).get('AWS')=='*') and not statement.get('Condition'):
    #                 fine_grained_access = False
    #     self.assertEqual(True, fine_grained_access, msg="In data catalogue resource policy fine grained access is not provided")

    # def test_glue_data_catalogs_metadata_encryption_is_not_enabled(self):
    #     """
    #     glue-data-catalogs-metadata-encryption-enabled.
    #     """
    #     settings = [match.value for match in parse('glue[*].DataCatalogueEncryptionSettings.self.source_data').find(self.resources) if match.value.get('EncryptionAtRest').get('CatalogEncryptionMode') == 'DISABLED']
    #     flag = len(settings)
    #     self.assertEqual(False, flag, msg="Data catalogue metadata encryption is not enabled")
    
    
    # def test_glue_database_connections_ssl_enabled(self):
    #     """
    #     glue-database-connections-ssl-enabled.
    #     """
    #     settings = [match.value for match in parse('glue[*].Connections[*].self.source_data.ConnectionProperties').find(self.resources) if  match.value.get('JDBC_ENFORCE_SSL',False) in [False,"false"]]
    #     flag = len(settings)
    #     self.assertEqual(False, flag, msg="In database connection SSL is not enabled")
    
    
    # def test_glue_development_endpoints_encryption_at_rest_is_enabled_for_cloudwatch_logs(self):
    #     """
    #     glue-development-endpoints-cloudwatch-logs-encryption-enabled

    #     """
    #     dev_endpoint_logging = [match.value for match in parse('glue[*].DevEndpoints[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('CloudWatchEncryption')['CloudWatchEncryptionMode']=='DISABLED']
    #     flag = len(dev_endpoint_logging)
    #     self.assertEqual(False, flag, msg="In one of the dev endpoints encryption at rest is not enabled for logs to cloudwatch")
    
    # def test_encryption_at_rest_is_enabled_for_glue_devendpoints_bookmarks(self):
    #     """
    #     Ensure that encryption at rest is enabled for development endpoints Glue job bookmarks.
    #     #     """
    #     dev_endpoint_bookmarks = [match.value for match in parse('glue[*].DevEndpoints[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('JobBookmarksEncryption')['JobBookmarksEncryptionMode']=='DISABLED']
    #     flag = len(dev_endpoint_bookmarks)
    #     self.assertEqual(False, flag, msg="encryption at rest is not enabled for Amazon Glue job bookmarks")

    # def test_glue_encryption_at_rest_is_enabled_for_etl_jobs_cloudwatch_logs(self):
    #     """
    #     glue-etl-jobs-cloudwatch-logs-encryption-enabled
    #     """
    #     jobs_logging = [match.value for match in parse('glue[*].Jobs[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('CloudWatchEncryption')['CloudWatchEncryptionMode']=='DISABLED']
    #     flag = len(jobs_logging)
    #     self.assertEqual(False, flag, msg="In one of the glue etl job cloudwatch log encryption at rest is not enabled for logs to cloudwatch")

    def test_encryption_at_rest_is_enabled_for_glue_etl_jobs_bookmarks(self):
        """
        glue-etl-jobs-job-bookmark-encryption-enabled    
        """
        dev_endpoint_bookmarks = [match.value for match in parse('glue[*].Jobs[*].self.source_data').find(self.resources) if match.value.get('SecurityConfigurationDetails') is not None and match.value.get('SecurityConfigurationDetails').get('EncryptionConfiguration').get('JobBookmarksEncryption')['JobBookmarksEncryptionMode']=='DISABLED']
        flag = len(dev_endpoint_bookmarks)
        self.assertEqual(False, flag, msg="encryption at rest is not enabled for Amazon Glue job bookmarks")