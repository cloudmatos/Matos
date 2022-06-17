import os
from unittest import TestCase
from json import loads
from jsonpath_ng import parse


class TestSecurityGroupPublicIngress(TestCase):
    
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        self.ports_to_ignore = [80,443]

        self.public_ipv4_cidr = '0.0.0.0/0'
        self.public_ipv6_cidr = '::/0'


    def test_ingress_public_access_over_authorized_ports(self):
        """
        Check if ingress public access is not allowed over ports other than 
        80 and 443
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        ports_to_ignore_set = set(self.ports_to_ignore)
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges',[])
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                ip_range_set.remove(80)
                ip_range_set.remove(443)
                if len(ip_range_set)==0:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allow access to the \
            ports other than the authorized ports")

    def test_ingress_public_access_not_allowed_for_unauthorized_ports(self):
        """
        Check if ingress public access is not allowed over ports other than 
        80 and 443
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        ports_to_ignore_set = set(self.ports_to_ignore)
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                ip_range_set.remove(80)
                ip_range_set.remove(443)
                if len(ip_range_set)==0:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the unauthorized ports")
    
    def test_ingress_public_access_not_allowed_for_port_22(self):
        """
        Check if ingress public access is not allowed over port 22
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 22 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 22")

    def test_ingress_public_access_not_allowed_for_port_3306(self):
        """
        Check if ingress public access is not allowed over port 3306
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 3306 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 3306")


    def test_ingress_public_access_not_allowed_for_port_3389(self):
        """
        Check if ingress public access is not allowed over port 3389
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 3389 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 3389")
    
    def test_ingress_public_access_not_allowed_for_port_5432(self):
        """
        Check if ingress public access is not allowed over port 5432
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 5432 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 5432")

    def test_ingress_public_access_not_allowed_for_port_1521_2483(self):
        """
        Check if ingress public access is not allowed over ports 1521, 2483
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 1521 not in ip_range_set and 2483 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 1521, 2483")

    def test_ingress_public_access_not_allowed_for_port_6379(self):
        """
        Check if ingress public access is not allowed over ports 6379
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 6379 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 6379")

    def test_ingress_public_access_not_allowed_for_port_27017_27018(self):
        """
        Check if ingress public access is not allowed over ports 27017, 27018
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ipv6_ranges = permission.get('Ipv6Ranges')
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 27017 not in ip_range_set and 27018 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr]:
                    is_secure = False
            for ipv6_range in ipv6_ranges:
                cidr_ipv6 = ipv6_range.get('CidrIpv6')
                if cidr_ipv6 in [self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 27017, 27108")

    def test_ingress_public_access_not_allowed_for_port_7199_9160_8888(self):
        """
        Check if ingress public access is not allowed over ports 7199, 9160, 8888
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 7199 not in ip_range_set and 9160 not in ip_range_set \
                    and 8888 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 7199, 9160, 8888")

    def test_ingress_public_access_not_allowed_for_port_11211(self):
        """
        Check if ingress public access is not allowed over ports 11211
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 11211 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 11211")

    def test_ingress_public_access_not_allowed_for_port_20_21(self):
        """
        Check if ingress public access is not allowed over ports 20, 21
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 20 not in ip_range_set and 21 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 20, 21")

    def test_ingress_public_access_not_allowed_for_port_9092(self):
        """
        Check if ingress public access is not allowed over ports 9092
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 9092 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 9092")

    def test_ingress_public_access_not_allowed_for_port_23(self):
        """
        Check if ingress public access is not allowed over ports 23
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 23 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 23")

    def test_ingress_public_access_not_allowed_for_port_1433_1434(self):
        """
        Check if ingress public access is not allowed over ports 1433, 1434
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 1433 not in ip_range_set and 1434 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 1433, 1434")

    def test_ingress_public_access_over_any_port(self):
        """
        Check if ingress public access is not allowed over any port
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allow access to a \
            port")

    def test_ingress_public_access_not_allowed_for_kibana_port(self):
        """
        Check if ingress public access is not allowed over ports 5601
        """
        criteria = 'network[*].self.source_data.security_group[*].IpPermissions[*]'
        ip_permissions = [match.value for match in parse(criteria).find(self.resources)]
        is_secure = True
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges')
            ip_v6_ranges = permission.get('Ipv6Ranges',[])
            if from_port is None or ip_ranges is None:
                continue
            if from_port!=-1:
                from_port = int(from_port)
                to_port = int(to_port)
                ip_range_set = range(from_port,to_port+1)
                if 5601 not in ip_range_set:
                    continue
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
            for ip_range in ip_v6_ranges:
                cidr_ip = ip_range.get('CidrIpv6')
                if cidr_ip in [self.public_ipv4_cidr,self.public_ipv6_cidr]:
                    is_secure = False
        self.assertEqual(True, is_secure, msg="Ingress rule allows access to \
            the port 5601")
    
