import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestAWSSSM(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_ssm.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_instance_is_patch_compliant(self):
        """
        [extra7127] Check if EC2 instances managed by Systems Manager are compliant with patching requirements - ssm [High]
        """
        compliant_instances = [match.value for match in parse('instance[*].self.source_data.ssm_patch_compliance[*]').find(self.resources) if  match.value['Status']=='COMPLIANT']
        flag = len(compliant_instances) == len(self.resources.get("instance"))
        self.assertEqual(True, flag, msg="Some of the instances are not Patch compliant")
    
    def test_ssm_document_is_public(self):
        """
        extra7140] Check if there are SSM Documents set as public - ssm
        
        """
        account_ids = [match.value for match in parse('ssm[*].self.source_data.shared_permissions.AccountIds[*]').find(self.resources)]
        flag = len(account_ids)
        self.assertEqual(False, flag, msg="Some of the SSM documents are public")

    def test_instance_is_association_compliant(self):
        """
        [extra7127] Check if EC2 instances managed by Systems Manager are compliant with association requirements - ssm [High]
        Reference - PCI.SSM.2
        """
        compliant_instances = [match.value for match in parse('instance[*].self.source_data.ssm_association_compliance[*]').find(self.resources) if match.value['Status']=='COMPLIANT']
        flag = len(compliant_instances) == len(self.resources.get("instance"))
        self.assertEqual(True, flag, msg="Some of the instances are not Patch compliant")

    def test_instance_ssm_agent_is_updated(self):
        """
        Check if EC2 instance has latest Linux SSM agent installed
        Reference - https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-state-cli.html
        
        """
        update_ssm_agent_associations = [match.value for match in parse('instance[*].self.source_data.SSM[*]').find(self.resources) if match.value['Name']=='AWS-UpdateSSMAgent' and match.value['Status']=='Success']
        flag = len(update_ssm_agent_associations)
        self.assertEqual(True, flag, msg="Auto update of ssm agent is not configured for some of the instances")