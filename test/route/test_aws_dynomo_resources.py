import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestCloudSql(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_dynomodb_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    #Use Case: DynamoDB.1 DynamoDB tables should automatically scale capacity with demand
    def test_automatic_scalling(self):
        """
        Check if dynomodb tables configured to be autoscaled or not
        """
        test = [match.value for match in parse('no_sql[*].self.source_data.TableCapacity').find(self.resources) if match.value.get('ReadCapacityUnits', '').get('AutoScalingStatus') not in ['true', True] or match.value.get('WriteCapacityUnits', '').get('AutoScalingStatus') not in ['true', True]]
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few dynomodb tables without enable autoscaling for read or write.")
    
    #Use Case: DynamoDB.2 DynamoDB tables should have point-in-time recovery enabled
    def test_point_in_time_recovery(self):
        """
        Check if dynomodb tables has configured point in time recovery
        """
        test = [match.value for match in parse('no_sql[*].self.source_data.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus').find(self.resources) if match.value == 'DISABLED']
        flag = len(test)
        self.assertEqual(False, flag, msg="There are few dynomodb tables without enable point in time recovery.")
    