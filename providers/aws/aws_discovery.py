from .connection import AWS
import threading


class AWSDiscovery(AWS):
    """
    """

    def __init__(self,
                 **kwargs) -> None:
        try:
            super().__init__(**kwargs)
            self.eks = self.client('eks')
            self.ec2 = self.client('ec2')
            self.s3 = self.client('s3')
            self.firewall = self.client('network-firewall')
            self.network = self.client('networkmanager')
            self.rds = self.client('rds')
            self.iam = self.client('iam')
            self.cloudtrail = self.client('cloudtrail')
            self.kms = self.client('kms')
            self.dynamodb = self.client('dynamodb')
            self.apphosting = self.client('elasticbeanstalk')
            self.filesystem = self.client('efs')
            self.elbv2 = self.client('elbv2')
            self.elb = self.client('elb')
            self.analyzer = self.client('accessanalyzer')
            self.sagemaker = self.client('sagemaker')
            self.resources = [{"type": 'iam'}]
            self.user_groups = self.client('iam')
            self.config_service = self.client('config')
            self.func = {
                'cluster': self.get_clusters,
                'instance': self.get_instances,
                'cloudtrail': self.get_cloudtrails,
                'storage': self.get_buckets,
                'snapshot': self.get_snapshot,
                'network': self.get_networks,
                'kms': self.get_kms,
                'disk': self.get_disk,
                'serviceAccount': self.get_iam,
                'sql': self.get_database,
                'no_sql': self.get_dynamo_db,
                'lb': self.get_elb(),
                'eip': self.get_eip,
                'filesystem': self.get_efs,
                'apphosting': self.get_apphosting,
                'analyzer': self.get_analyzer,
                'policy': self.get_policy,
                'user_groups': self.get_user_groups,
                'sagemaker':self.get_sagemaker_instances,
                'config_service':self.get_config_service
            }
        except Exception as ex:
            raise Exception(ex)

    def get_user_groups(self):
        response = self.user_groups.list_groups()
        Policies = self.user_groups.list_policies(Scope='Local').get('Policies')
        Policies = [policy.get('Arn') for policy in Policies]
        users = [{**item, "UserPoliciesArn": Policies, "type": "user_groups"} for item in response.get('Groups', [])]
        self.resources.extend(users)

    def get_instances(self):
        """
        """

        resources = self.ec2.describe_instances()
        reservations = resources['Reservations']

        instances = []

        for reservation in reservations:
            for instance in reservation.get('Instances', []):
                instances.append({
                    'type': 'instance',
                    'instance_id': instance['InstanceId'],
                    'name': instance['InstanceId'],
                    'location': instance['Placement']['AvailabilityZone']
                })
        self.resources.extend(instances)

    def get_clusters(self):
        """
        """

        clusters = self.eks.list_clusters()
        clusters = clusters['clusters']

        cluster_resources = []

        for cluster in clusters:
            location = ""

            cluster_details = self.eks.describe_cluster(name=cluster)
            cluster_details = cluster_details['cluster']

            try:
                location = cluster_details['endpoint'].replace('.eks.amazonaws.com', '').split('.')[-1]
            except Exception as ex:
                # In some cases location is not available. e.g. when the status is in "CREATING"
                pass
            
            cluster_resources.append({
                'name': cluster_details['name'],
                'type': 'cluster',
                'location': location
            })
        self.resources.extend(cluster_resources)

    def get_buckets(self):
        """
        """

        buckets = self.s3.list_buckets()
        owner = buckets['Owner']

        bucket_resources = []
        for bucket in buckets['Buckets']:
            detail = {
                'name': bucket.get('Name', ""),
                'type': 'storage',
                'creationDate': bucket.get('CreationDate', ''),
                'owner': {
                    'displayName': owner.get('DisplayName', ''),
                    'id': owner.get('ID', "")
                },
            }
            bucket_resources.append(detail)

        self.resources.extend(bucket_resources)

    def get_networks(self):
        def fetch_network(network_list=None, continueToken: str = None):
            request = {}
            if continueToken:
                request['NextToken'] = continueToken
            response = self.ec2.describe_vpcs(**request)
            continueToken = response.get('NextToken', None)
            current_networks = [] if not network_list else network_list
            current_networks.extend(response.get('Vpcs', []))

            return current_networks, continueToken

        try:
            networks, nextToken = fetch_network()

            while nextToken:
                networks, nextToken = fetch_network(networks, nextToken)
        except Exception as ex:
            print("network fetch error: ", ex)
            return []
        network_resources = []
        for network in networks:
            detail = {
                'id': network.get('VpcId', ""),
                'type': 'network',
                'dhcp_options_id': network.get("DhcpOptionsId", ""),
                'owner_id': network.get("OwnerId", ""),
                'state': network.get("State", ""),
                'description': network.get("Description", ""),
                'tags': network.get("Tags", []),
                'is_default': network.get("isDefault", False),
                "cidr_block_association_set": network.get("CidrBlockAssociationSet", []),
                "ipv6_cidr_block_association_set": network.get("Ipv6CidrBlockAssociationSet", []),
                "instance_tenancy": network.get("InstanceTenancy", []),
            }
            network_resources.append(detail)
        self.resources.extend(network_resources)

    def get_firewalls(self):
        def fetch_firewalls(firewall_list=None, continueToken: str = None):
            request = {}
            if continueToken:
                request['NextToken'] = continueToken
            response = self.firewall.list_firewalls(**request)
            continueToken = response.get('NextToken', None)
            current_firewalls = [] if not firewall_list else firewall_list
            current_firewalls.extend(response.get('Firewalls', []))

            return current_firewalls, continueToken

        try:
            firewalls, nextToken = fetch_firewalls()

            while nextToken:
                firewalls = fetch_firewalls(firewalls, nextToken)
        except Exception as ex:
            print("firewall: ", ex)
            return []
        firewall_resources = []
        for firewall in firewalls:
            detail = {
                'name': firewall.get('FirewallName', ""),
                'type': 'firewall',
                'arn': firewall.get("FirewallArn")
            }
            firewall_resources.append(detail)

        self.resources.extend(firewall_resources)

    def get_cloudtrails(self):
        def fetch_cloudtrails(cloudtrail_list=None, continueToken: str = None):
            request = {}
            if continueToken:
                request['NextToken'] = continueToken
            response = self.cloudtrail.list_trails(**request)
            continueToken = response.get('NextToken', None)
            current_cloudtrails = [] if not cloudtrail_list else cloudtrail_list
            current_cloudtrails.extend(response.get('Trails', []))

            return current_cloudtrails, continueToken

        try:
            cloudtrails, nextToken = fetch_cloudtrails()

            while nextToken:
                cloudtrails = fetch_cloudtrails(cloudtrails, nextToken)
        except Exception as ex:
            print("cloudtrail: ", ex)
            return []
        cloudtrail_resources = []
        for cloudtrail in cloudtrails:
            detail = {
                'name': cloudtrail.get('Name', ""),
                'arn': cloudtrail.get('TrailARN'),
                'region': cloudtrail.get("HomeRegion"),
                'type': 'log_monitor'
            }
            cloudtrail_resources.append(detail)

        self.resources.extend(cloudtrail_resources)

    def get_database(self):
        response = self.rds.describe_db_instances()
        databases = [{**item, "type": "sql"} for item in response.get('DBInstances', [])]
        self.resources.extend(databases)

    def get_iam(self):
        response = self.iam.list_users()
        users = [{**item, "type": "serviceAccount"} for item in response.get('Users', [])]
        self.resources.extend(users)

    def get_kms(self):
        response = self.kms.list_keys()
        keys = [{**item, "type": "kms"} for item in response.get('Keys', [])]
        self.resources.extend(keys)

    def get_policy(self):
        response = self.iam.list_policies(Scope="Local")
        policies = [{**item, "type": "policy", "Scope": "Local"} for item in response.get('Policies', [])]

        aws_support_policy = self.iam.get_policy(PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess").get('Policy')
        policies.append({
            **aws_support_policy,
            "type": "policy",
            "Scope": "AWS"
        })
        self.resources.extend(policies)

    def get_dynamo_db(self):
        response = self.dynamodb.list_tables()
        dynamodbs = [{"name": item, "type": "no_sql"} for item in response.get('TableNames', [])]
        print(dynamodbs, "==== dynamodb")
        self.resources.extend(dynamodbs)

    def get_snapshot(self):
        user = self.iam.list_users().get('Users', [])[0]
        owner_id = user.get('Arn').split(':')[-2]
        response = self.ec2.describe_snapshots(Filters=[
            {
                'Name': 'owner-id',
                'Values': [
                    owner_id,
                ]
            },
        ], )
        snapshots = [{**item, "type": "snapshot"} for item in response.get('Snapshots', [])]
        self.resources.extend(snapshots)

    def get_disk(self):
        response = self.ec2.describe_volumes()
        volumes = [{**item, "type": "disk"} for item in response.get('Volumes', [])]
        self.resources.extend(volumes)

    def get_eip(self):
        response = self.ec2.describe_addresses()
        eip = [{**item, "type": "eip"} for item in response.get('Addresses', [])]
        self.resources.extend(eip)

    def get_apphosting(self):
        resources = self.apphosting.describe_environments()
        environments = resources["Environments"]

        environment_resources = []

        for environment in environments:
            environment_resources.append({
                'type': 'apphosting',
                **environment,
            })
        self.resources.extend(environment_resources)

    def get_efs(self):
        resources = self.filesystem.describe_file_systems()
        files = resources["FileSystems"]

        filesystem_resources = []
        for file in files:
            filesystem_resources.append({
                'type': 'filesystem',
                **file,
            })
        self.resources.extend(filesystem_resources)

    def get_elb(self):
        resources = self.elb.describe_load_balancers()
        elb = [{"type": "lb", **lb, "Type": "classic"} for lb in resources.get("LoadBalancerDescriptions", [])]

        resources = self.elbv2.describe_load_balancers()
        elbv2 = [{"type": "lb", **lb} for lb in resources.get("LoadBalancers", [])]

        self.resources.extend(elb + elbv2)

    def get_analyzer(self):
        resources = self.analyzer.list_analyzers().get('analyzers')
        resources = [{**resource, "type": 'analyzer'} for resource in resources]
        resources = resources if resources else [{"type": 'analyzer', 'empty': True}]
        self.resources.extend(resources)
    
    def get_sagemaker_instances(self):
        resources = self.sagemaker.list_notebook_instances().get('NotebookInstances')
        resources = [{**resource, "type": 'sagemaker'} for resource in resources]
        resources = resources if resources else [{"type": 'sagemaker', 'empty': True}]
        self.resources.extend(resources)
    
    def get_config_service(self):
        resources = self.config_service.describe_configuration_recorder_status().get('ConfigurationRecordersStatus')
        resources = [{**resource, "type": 'config_service'} for resource in resources]
        resources = resources if resources else [{"type": 'config_service', 'empty': True}]
        self.resources.extend(resources)

    def find_resources(self, **kwargs):
        """
        """
        threads = []
        print(self.func.keys())
        for rsc_type in self.func.keys():
            thread = threading.Thread(target=self.func.get(rsc_type))
            thread.start()
            threads.append(thread)

        for t in threads:
            t.join()

        return self.resources
