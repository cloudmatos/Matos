import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestCloudSql(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_kms_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_kms_rotation(self):
        """
        test Ensure rotation for customer created CMKs is enabled
        """
        test = [match.value for match in parse('kms[*].self.source_data.KeyRotationEnabled').find(self.resources) if match.value in ['false', False]]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few kms keys without enable key rotation.")

    def test_customer_managed_policy_should_not_allow_decryption_reencryption_on_all_keys(self):
        """
        [KMS.1] IAM customer managed policies should not allow decryption and re-encryption 
        actions on all KMS keys
        """
        flag = False
        statements = [match.value for match in parse('policy[*].self.source_data.Document.Statement[*]').find(self.resources)]
        for statement in statements:
            if statement['Effect']=='Allow' and statement['Resource']=='*' and statement.get('Condition') is None and ('kms:*' in statement['Action'] or 'kms:Decrypt' in statement['Action'] or  'kms:ReEncryptFrom' in statement['Action']):
                flag = True
        self.assertEqual(False, flag, msg="There are CM policies those allow decryption and reencryption \
            permissions to all keys.")

    def test_attached_inline_policy_should_not_allow_decryption_reencryption_on_all_keys(self):
        """
        [KMS.2] IAM principals should not have IAM inline policies that allow decryption 
        and re-encryption actions on all KMS keys
        """
        flag = False
        statements = [match.value for match in parse('serviceAccount[*].self.source_data.AttachedManagedPolicies[*]..Document.Statement[*]').find(self.resources)]
        for statement in statements:
            if statement['Effect']=='Allow' and statement['Resource']=='*' and statement.get('Condition') is None and ('kms:*' in statement['Action'] or 'kms:Decrypt' in statement['Action'] or  'kms:ReEncryptFrom' in statement['Action']):
                flag = True
        self.assertEqual(False, flag, msg="There are CM policies those allow decryption and reencryption \
            permissions to all keys.")

    def test_kms_keys_should_not_be_unintentionally_deleted(self):
        """
        [KMS.3] AWS KMS keys should not be unintentionally deleted
        """
        flag = False
        key_states = [match.value for match in parse('kms[*].self.source_data.KeyState').find(self.resources) if match.value=='PendingDeletion']
        flag = len(key_states)
        self.assertEqual(False, flag, msg="Some of the key is pending for deletion")

    def test_metric_filter_alarm_exists_for_disabling_or_scheduled_deletion(self):
        """
        3.7 [check37] Ensure a log metric filter and alarm exist for disabling or 
        scheduled deletion of customer created KMS CMKs
        """
        criteria = 'log_monitor[*].self.source_data.CloudWatchLogGroup.metricFilters[*]'
        metric_filters = [match.value for match in parse(criteria).find(self.resources)]
        filter_pattern = ["$.eventSource=kms*","$.eventSource=kms.amazonaws.com","$.eventName=DisableKey","$.eventName=ScheduleKeyDeletion"]
        alarms = []  
        for m in metric_filters:
            if m['filterName']!='user01-test-filter':
                continue
            if self.checkFilter(m['filterPattern'], filter_pattern, condition='and') and \
                len(m.get('metricTransformations',[]))>0:
                transformations = m.get('metricTransformations')
                for t in transformations:
                   [alarms.append(alarm) for alarm in t.get('metricAlarms',[])]
        alarms = [alarm for alarm in alarms if alarm.get("ActionsEnabled",False) is True]
        flag = len(alarms)>0
        self.assertEqual(True, flag, msg="No alarm for kms metric filter exists")    

    def checkFilter(self, filters, custom_patterns, condition='and'):
        replace_value = filters.replace('"','').replace("'", '').replace(' ', '')
        output = [filter for filter in custom_patterns if filter in replace_value]
        return len(output) > 2 if condition == 'and' else len(output) > 0


    def test_kms_keys_should_not_be_exposed(self):
        """
        7.36 [extra736] Check exposed KMS keys - kms [Critical]
        """
        flag = False
        statements = [match.value for match in parse('kms[*].self.source_data.KeyPolicies[*].Statement[*]').find(self.resources)]
        
        for statement in statements:
            if statement['Effect']=='Allow' and \
                (statement['Principal']=='*' or statement['Principal']=={"AWS":"*"}) \
                    and statement.get('Condition') is None:
                flag = True
        self.assertEqual(False, flag, msg="Some of the key is publicly exposed")

    def test_kms_keys_should_not_be_unintentionally_deleted(self):
        """
        7.126 [extra7126] Check if there are CMK KMS keys not used - kms [Medium]
        """
        flag = False
        key_states = [match.value for match in parse('kms[*].self.source_data').find(self.resources) if match.value.get('KeyState')=='Disabled' and match.value.get('KeyManager')=='CUSTOMER']
        flag = len(key_states)
        self.assertEqual(False, flag, msg="Some of the key is pending for deletion")

    def test_customer_managed_policy_should_not_allow_decryption_on_kms_keys(self):
        """
        KMS key decryption should be restricted in IAM customer managed policy
        """
        flag = False
        statements = [match.value for match in parse('policy[*].self.source_data.Document.Statement[*]').find(self.resources)]
        for statement in statements:
            if statement['Effect']=='Allow' and statement['Resource']=='*' and statement.get('Condition') is None and ('kms:*' in statement['Action'] or 'kms:Decrypt' in statement['Action']):
                flag = True
        self.assertEqual(False, flag, msg="There are CM policies those allow decryption and reencryption \
            permissions to all keys.")

    def test_attached_inline_policy_should_not_allow_decryption_on_kms_keys(self):
        """
        KMS key decryption should be restricted in IAM inline policy
        """
        flag = False
        statements = [match.value for match in parse('serviceAccount[*].self.source_data.AttachedManagedPolicies[*]..Document.Statement[*]').find(self.resources)]
        for statement in statements:
            if statement['Effect']=='Allow' and  statement['Resource']=='*' and statement.get('Condition') is None and ('kms:*' in statement['Action'] or 'kms:Decrypt' in statement['Action']):
                flag = True
        self.assertEqual(False, flag, msg="There are CM policies those allow decryption \
            permissions to all keys.")



