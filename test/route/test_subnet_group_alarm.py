import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestSubnetGroupAlarm(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.sg_filter_pattern = ["$.eventName=AuthorizeSecurityGroupIngress","$.eventName=AuthorizeSecurityGroupEgress","$.eventName=RevokeSecurityGroupIngress","$.eventName=RevokeSecurityGroupEgress","$.eventName=CreateSecurityGroup","$.eventName=DeleteSecurityGroup"]

    def test_trail_exists(self):
        """
        Check if trail exists in cloudwatch.
        """
        criteria = 'cloudtrail[*].self[*]'
        trails = [match.value for match in parse(criteria).find(self.resources)]
        flag = len(trails) > 0
        self.assertEqual(True, flag, msg="No trail exists in cloud trail")

    def test_trail_is_associated_with_log_group(self):
        """
        Check if atleast one trail is associated with a log group
        """
        criteria = 'cloudtrail[*].self.source_data.CloudWatchLogsLogGroupArn'
        log_group_arns = [match.value for match in parse(criteria).find(self.resources)]
        flag = len(log_group_arns) > 0
        self.assertEqual(True, flag, msg="No trail is associated with log group")

    def test_log_group_is_having_metric_filters(self):
        """
        Check if alteast one log group is having metric filter.
        """
        criteria = 'cloudtrail[*].self.source_data.CloudWatchLogGroup.metricFilters[*]'
        metric_filters = [match.value for match in parse(criteria).find(self.resources)]
        flag = len(metric_filters) > 0
        self.assertEqual(True, flag, msg="No metric fitler is created over any log group") 

    def test_metric_filter_for_security_group(self):
        """
        Check if there is filter for security group changes in metric filter.
        """
        criteria = 'cloudtrail[*].self.source_data.CloudWatchLogGroup.metricFilters[*].\
            filterPattern'
        metric_filters = [match.value for match in parse(criteria).find(self.resources)]
        sg_filter_exits = False
        for m in metric_filters:
            if self.checkFilter(m['filterPattern'], self.sg_filter_pattern, condition='and'):
                sg_filter_exits = True
        self.assertEqual(True, sg_filter_exits, msg="No metric filter for vpc security group")

    def test_alarm_for_security_group_metric_filter(self):
        """
        Check if there is an alarm over metric filter for security group changes.
        """
        criteria = 'cloudtrail[*].self.source_data.CloudWatchLogGroup.metricFilters[*]'
        metric_filters = [match.value for match in parse(criteria).find(self.resources)]
        sg_alarms = []  
        for m in metric_filters:
            if self.checkFilter(m['filterPattern'], self.sg_filter_pattern, condition='and') and \
                len(m.get('metricTransformations',[]))>0:
                transformations = m.get('metricTransformations')
                for t in transformations:
                    sg_alarms.append(*t.get('metricAlarms',[]))
        flag = len(sg_alarms)>0
        self.assertEqual(True, flag, msg="No alarm for vpc security group metric filter")
        
    def test_alarm_for_security_group_has_action_enabled(self):
        """
        Check if alarm for security group changes has action enabled.
        """
        criteria = 'cloudtrail[*].self.source_data.CloudWatchLogGroup.metricFilters[*]'
        metric_filters = [match.value for match in parse(criteria).find(self.resources)]
        sg_alarms = []  
        for m in metric_filters:
            if self.checkFilter(m['filterPattern'], self.sg_filter_pattern, condition='and') and \
                len(m.get('metricTransformations',[]))>0:
                transformations = m.get('metricTransformations')
                for t in transformations:
                    sg_alarms.append(*t.get('metricAlarms',[]))
        sg_alarms = [alarm for alarm in sg_alarms if alarm.get("ActionsEnabled",False) is True]
        flag = len(sg_alarms)>0
        self.assertEqual(True, flag, msg="No alarm for vpc security group metric filter")    

    def checkFilter(self, filters, custom_patterns, condition='and'):
        # print(filters)
        replace_value = filters.replace('"','').replace("'", '').replace(' ', '')
        output = [filter for filter in custom_patterns if filter in replace_value]
        return len(output) == len(custom_patterns) if condition == 'and' else len(output) > 0
