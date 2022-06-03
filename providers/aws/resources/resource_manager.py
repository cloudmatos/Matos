# -*- coding: utf-8 -*-
from structlog import get_logger

from providers.aws.connection import AWS
from providers.aws.aws_config import INSTANCE_TYPE_CONFIG
from datetime import datetime, timedelta
import time
from kubernetes import client as kclient
from datetime import datetime, timedelta
from awscli.customizations.eks.get_token import STSClientFactory, TokenGenerator, TOKEN_EXPIRATION_MINS
import json
import base64

logger = get_logger(__file__)


class AWSResourceManager:
    def __init__(self,
                 **kwargs,
                 ) -> None:
        print("AWS Resource Manage __init__ Method")

    def get_assets_inventory(
            self, resource, **kwargs
    ):
        RESOURCE_TYPES = {
            "eks": Cluster,
            "cluster": Cluster,
            "ec2": Instance,
            "instance": Instance,
            "storage": Storage,
            "network": Network,
            "sql": SQL,
            "serviceAccount": ServiceAccount,
            "log_monitor": CloudTrail,
            "kms": KMS,
            "policy": Policy,
            "no_sql": DynamoDB,
            "disk": Disk,
            "snapshot": Snapshot,
            "eip": EIP,
            "apphosting": ElasticBeanstalk,
            "lb": LoadBalancing,
            "iam": IAM,
            "analyzer": Analyzer,
            "filesystem": ElasticFileSystem,
        }

        log = logger.new()
        # print(resource['type'], "==== resource type")

        # try:
        Resource = RESOURCE_TYPES.get(resource['type'])
        if not Resource:
            log.info("Requested resource_type is not supported.")
            return
        # try:
        cloud_resource = Resource(
            resource,
        )

        resource_details = cloud_resource.get_resource_inventory()
        # except Exception as ex:
        #     print(ex, "===== cloud_resource.get_resource_inventory()")
        #     raise Exception(ex)

        if resource_details:
            resource.update(details=resource_details)
        # except Exception as ex:
        #     log.error("Error while fetching resource details.",
        #               error_message=str(ex))

        return resource


class Cluster(AWS):

    def __init__(self,
                 resource,
                 **kwargs,
                 ) -> None:
        try:
            super(Cluster, self).__init__()
            self.conn = self.client("eks")
            self.cluster_names = [resource['name']]
        except Exception as ex:
            raise Exception(ex)

    def get_cluster_client(self,
                           cluster_name,
                           cluster_host,
                           ):
        """
        """

        work_session = self.session._session
        client_factory = STSClientFactory(work_session)

        def get_expiration_time():
            token_expiration = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINS)
            return token_expiration.strftime('%Y-%m-%dT%H:%M:%SZ')

        def get_token(cluster_name: str, role_arn: str = None) -> dict:
            sts_client = client_factory.get_sts_client(role_arn=role_arn)
            token = TokenGenerator(sts_client).get_token(cluster_name)
            return {
                "kind": "ExecCredential",
                "apiVersion": "client.authentication.k8s.io/v1alpha1",
                "spec": {},
                "status": {
                    "expirationTimestamp": get_expiration_time(),
                    "token": token
                }
            }

        token = get_token(cluster_name)['status']['token']
        conf = kclient.Configuration()

        conf.host = cluster_host + ':443'
        conf.verify_ssl = False
        conf.api_key = {'authorization': "Bearer " + token}
        k8s_client = kclient.ApiClient(conf)
        k8s_client_v1 = kclient.CoreV1Api(k8s_client)

        return k8s_client_v1

    def get_resource_inventory(self):
        """
        Fetches cluster details.

        Args:
        cluster_name: name of the eks instance.

        return: dictionary object.
        """
        cluster_details = self.get_cluster_details()
        return cluster_details

    def get_object_count(self,
                         object_types,
                         time_period=100 * 60,
                         filters={},
                         ):
        """
        """

        logs = self.client('logs')

        then = (datetime.utcnow() - timedelta(seconds=time_period)).timestamp()
        now = datetime.utcnow().timestamp()

        log_groups = [
            '/aws/containerinsights/wpcon/performance',
            '/aws/containerinsights/wpcon/host',
            '/aws/containerinsights/wpcon/application',
            '/aws/containerinsights/wpcon/dataplane',
        ]

        map1 = {
            'pod': 'kubernetes.pod_name',
            'namespace': 'kubernetes.namespace_name',
            'container': 'kubernetes.container_name',
            'service': 'kubernetes.service_name',
        }

        map2 = {
            'pod': 'PodName',
            'namespace': 'Namespace',
            'node': 'NodeName',
            'cluster': 'ClusterName'
        }

        object_names = [(map2.get(o) or map1.get(o) or o)
                        for o in object_types]

        fields = ', '.join(object_names)
        field_query = f"fields {fields}"
        count_query = ", ".join([f"count_distinct({o})" for o in object_names])

        if filters:
            filter_queries = [f'filter({map2.get(x) or map1.get(x) or x}="{y}")'
                              for x, y in filters.items()]
            filter_string = ' | '.join(filter_queries)
            query = f'{field_query} | {filter_string} | {count_query}'
        else:
            query = f'{field_query} | {count_query}'

        query_response = logs.start_query(
            startTime=int(then),
            endTime=int(now),
            queryString=query,
            logGroupNames=log_groups)

        while True:
            query_result = logs.get_query_results(
                queryId=query_response['queryId'])
            if query_result['status'] == 'Running':
                time.sleep(1)
                continue

            break

        rev = {x: y for y, x in map1.items()}
        rev.update({x: y for y, x in map2.items()})

        retdict = {}

        for res in query_result['results'][0]:
            o = res['field'][15:][:-1]
            o = rev.get(o) or o
            v = int(res['value'])
            retdict[o] = v

        return retdict

    def add_cluster_objects_from_k8s(self,
                                     cluster_details,
                                     ):
        """
        """

        name = cluster_details['name']
        endpoint = cluster_details['endpoint']
        k8s_client = self.get_cluster_client(name, endpoint)

        function_map = {
            'pod': k8s_client.list_pod_for_all_namespaces,
            'namespace': k8s_client.list_namespace,
            'node': k8s_client.list_node,
            'service': k8s_client.list_service_for_all_namespaces,
        }

        object_map = {}

        def append_objects(object_type, objects, cluster_name):
            for object in objects.items:
                object_list = object_map.get(object_type, [])
                object_name = object.metadata.name
                object_namespace = getattr(object.metadata, 'namespace', None)
                object_uid = getattr(object.metadata, 'uid', None)
                object_self_link = getattr(object.metadata, 'self_link', None)
                object_node_name = getattr(object.spec, "node_name", None)
                if object_type == 'pod':
                    object_container = [{'name': c.name, 'image_pull_policy': c.image_pull_policy} for c in
                                        object.spec.containers]
                else:
                    object_container = None

                object_details = {
                    'name': object_name,
                    'cluster_name': cluster_name
                }

                if object_namespace:
                    object_details.update(namespace=object_namespace)

                if object_self_link:
                    object_details.update(self_link=object_self_link)

                if object_self_link:
                    object_details.update(uid=object_uid)

                if object_node_name:
                    object_details.update(node=object_node_name)

                if object_container:
                    object_details.update(container=object_container)

                if object_type == 'node':
                    try:
                        instance_id = object.spec.provider_id.split('/')[-1]
                        object_details.update(instance_id=instance_id)
                    except:
                        pass

                object_list.append(object_details)
                object_map[object_type] = object_list

        for object_type, function in function_map.items():
            try:
                objects = function()
                append_objects(object_type, objects, name)

            except Exception as ex:
                print(ex, "=======", object_type, "=======")
                pass

        cluster_details.update(object_map)

    def add_cluster_objects_from_cloudwatch(self,
                                            cluster_details,
                                            ):
        """
        """

        name = cluster_details['name']

        object_list = ['pod', 'namespace', 'node', 'container', 'service']

        object_count = self.get_object_count(
            object_list, filters={'cluster': name})

        for object, count in object_count.items():
            cluster_details[f"{object}_count"] = count

        return cluster_details

    def get_cluster_details(self, fetch_objects=True):

        def add_objects(cluster_details):
            try:
                self.add_cluster_objects_from_k8s(cluster_details)
            except:
                try:
                    self.add_cluster_objects_from_cloudwatch(cluster_details)
                except:
                    pass

        if self.cluster_names and len(self.cluster_names) == 1:
            name = self.cluster_names[0]
            cluster_details = self.conn.describe_cluster(name=name)
            cluster_details = cluster_details.get("cluster")
            if cluster_details and fetch_objects:
                add_objects(cluster_details)
            return cluster_details

        clusters = self.conn.list_clusters()
        clusters_details = []

        for name in clusters.get('clusters', []):

            if self.cluster_names and name not in self.cluster_names:
                continue

            data = self.conn.describe_cluster(name=name)
            cluster = data.get('cluster')

            if cluster and fetch_objects:
                add_objects(cluster)

            clusters_details.append(cluster)

        return clusters_details


class Instance(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(Instance, self).__init__()
            self.conn = self.client("ec2")
            self.iam = self.client("iam")
            self.ssm = self.client('ssm')
            self.instance_ids = resource.get('instance_id') or resource.get('name')
            self._iam_instance_profiles = None

            if self.instance_ids:
                self.instance_ids = [self.instance_ids]
        except Exception as ex:
            raise Exception(ex)

    @property
    def iam_instance_profiles(self):
        if not self._iam_instance_profiles:
            self._iam_instance_profiles = self.iam.list_instance_profiles().get('InstanceProfiles')

        return self._iam_instance_profiles

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        instances_details = self.get_describe_instances()
        instances_details = self.get_instance_details(instances_details)
        return instances_details

    def get_describe_instances(self):
        if self.instance_ids:
            instance_details = self.conn.describe_instances(
                InstanceIds=self.instance_ids
            )
        else:
            instance_details = self.conn.describe_instances()

        return instance_details

    def get_instance_details(self, instances_details):
        reservations = instances_details.get("Reservations")
        if reservations and isinstance(reservations, list):
            instances = [
                instance.get("Instances")[0]
                for instance in reservations
                if instance.get("Instances")
            ]
            for instance_details in instances:
                self.update_volume_details(instance_details)
                instance_type = instance_details.get("InstanceType")
                instance_config = INSTANCE_TYPE_CONFIG.get(instance_type)
                instance_details["InstanceMemory"] = {
                    "total": instance_config["memory"] if instance_config else 0,
                    "unit": "GB",
                }
                iam_instance_profile_id = instance_details.get('IamInstanceProfile', {}).get('Id')
                if iam_instance_profile_id:
                    iam_instance_profile_details = self.get_iam_instance_profile(iam_instance_profile_id)
                    instance_details['IamInstanceProfile'] = iam_instance_profile_details

                ssm_info = self.get_ssm_info(instance_details.get('InstanceId'))
                if ssm_info:
                    instance_details['SSM'] = ssm_info

                if self.instance_ids and \
                        instance_details.get("InstanceId") in self.instance_ids:
                    return instance_details
            return instances

    def get_ssm_info(self, instance_id):
        result = []
        try:
            result = self.ssm.describe_instance_information(
                InstanceInformationFilterList=[
                    {
                        'key': 'InstanceIds',
                        'valueSet': [
                            instance_id
                        ]
                    }
                ]
            ).get('InstanceInformationList', [])
        except Exception as ex:
            print(ex, "===== fetch instance information for SSM")

        return result[0] if result else None

    def update_volume_details(self, instance_details):
        """
        Update instance details with additional volumes data.
        """
        volume_ids = [
            vol["Ebs"]["VolumeId"] for vol in instance_details["BlockDeviceMappings"]
        ]
        volumes = self.conn.describe_volumes(VolumeIds=volume_ids)
        volumes = volumes.get("Volumes")
        total_size = 0
        volumes_data = []
        if volumes:
            for vol in volumes:
                volumes_data.append(vol)
                total_size += vol.get("Size")
            if volumes_data:
                instance_details["BlockDeviceMappings"] = {
                    "DiskSize": {"total": total_size, "unit": "GB"},
                    "Volumes": volumes_data,
                }

    def get_iam_instance_profile(self, profile_id):
        try:
            profiles = [profile for profile in self.iam_instance_profiles if
                        profile.get('InstanceProfileId') == profile_id]
        except Exception as ex:
            print(ex, "====== iam instance profile fetch error")
            return {}
        return profiles[0]


class Storage(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(Storage, self).__init__()
            self.conn = self.client("s3")
            self.bucket = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        self.bucket = {
            **self.bucket,
            "type": "bucket",
            "policy": self.get_bucket_policy_list(),
            "metric_configuration": self.get_bucket_metrics_configuration_list(),
            "inventory_configuration": self.get_bucket_inventory_configuration_list(),
            "intelligent_tiering_configuration": self.get_bucket_intelligent_tiering_configurations_list(),
            "acl": self.get_bucket_acl(),
            "policy_status": self.get_bucket_policy_status(),
            # "object": self.get_object_list(),
            "lifecycle": self.get_bucket_lifecycle(),
            "encryption": self.get_bucket_encryption(),
            "versioning": self.get_bucket_versioning(),
            "tagging": self.get_bucket_tagging(),
            "location": self.get_bucket_location(),
            "logging": self.get_bucket_logging(),
            "public_access_block": self.get_bucket_public_access_block(),
            "ownership": self.get_bucket_ownership(),
            "notification": self.get_bucket_notification_configuration(),
            "replicationConfiguration": self.get_bucket_replication()
        }
        return self.bucket

    def get_bucket_replication(self):
        try:
            replication = self.conn.get_bucket_replication(Bucket=self.bucket.get('name')).get(
                'ReplicationConfiguration')
        except Exception as ex:
            print(ex, "======= fetch bucket replication")
            replication = None
        return replication

    def get_bucket_notification_configuration(self):
        resp = self.conn.get_bucket_notification_configuration(Bucket=self.bucket.get('name'))
        print(self.bucket.get('name'), "=====bucket name")
        del resp['ResponseMetadata']

        return resp

    def get_bucket_policy_list(self):
        bucket_name = self.bucket['name']
        try:
            policies = self.conn.get_bucket_policy(Bucket=bucket_name)
            policy = policies['Policy']
        except Exception as ex:
            print(bucket_name, " policy error: ", ex)
            policy = {}

        return policy

    def get_bucket_ownership(self):
        bucket_name = self.bucket['name']
        try:
            ownership = self.conn.get_bucket_ownership_controls(Bucket=bucket_name)
            rules = ownership['OwnershipControls']['Rules']
        except Exception as ex:
            print(bucket_name, "Ownership controls error: ", ex)
            rules = []

        return rules

    def get_bucket_public_access_block(self):
        bucket_name = self.bucket['name']
        try:
            resp = self.conn.get_public_access_block(Bucket=bucket_name)
            publicAccessBlock = resp.get('PublicAccessBlockConfiguration', {})
        except Exception as ex:
            print(bucket_name, " public access block error: ", ex)
            publicAccessBlock = {}

        return publicAccessBlock

    def get_bucket_location(self):
        bucket_name = self.bucket['name']
        try:
            resp = self.conn.get_bucket_location(Bucket=bucket_name)
            location = resp['LocationConstraint']
        except Exception as ex:
            print(bucket_name, " location getting error: ", ex)
            location = ''

        return location

    def fetch_metric_config(self,
                            metrics=None,
                            continuationToken: str = None):
        request = {
            "Bucket": self.bucket['name'],
            # "ExpectedBucketOwner": self.bucket['owner']['id']
        }
        if continuationToken:
            request['ContinuationToken'] = continuationToken
        response = self.conn.list_bucket_metrics_configurations(**request)
        nextContinuationToken = response.get('NextContinuationToken', None)
        current_metrics = [] if not metrics else metrics
        current_metrics.extend(response.get('MetricsConfigurationList', []))

        return current_metrics, nextContinuationToken

    def get_bucket_metrics_configuration_list(self):
        try:
            metrics, nextContinuationToken = self.fetch_metric_config()

            while nextContinuationToken:
                metrics, nextContinuationToken = self.fetch_metric_config(metrics, nextContinuationToken)

        except Exception as ex:
            print(self.bucket['name'], " metric configuration: ", ex)
            return []

        return metrics

    def fetch_inventory_config(self,
                               metrics=None,
                               continuationToken: str = None):
        request = {
            "Bucket": self.bucket['name'],
            # "ExpectedBucketOwner": self.bucket['owner']['id']
        }
        if continuationToken:
            request['ContinuationToken'] = continuationToken
        response = self.conn.list_bucket_inventory_configurations(**request)
        nextContinuationToken = response.get('NextContinuationToken', None)
        current_inventories = [] if not metrics else metrics
        current_inventories.extend(response.get('InventoryConfigurationList', []))

        return current_inventories, nextContinuationToken

    def get_bucket_inventory_configuration_list(self):
        try:
            inventories, nextContinuationToken = self.fetch_inventory_config()

            while nextContinuationToken:
                inventories, nextContinuationToken = self.fetch_inventory_config(inventories, nextContinuationToken)

        except Exception as ex:
            print(self.bucket['name'], " inventory configuration: ", ex)
            return []

        return inventories

    def fetch_intelligent_tiering_config(self,
                                         tierings=None,
                                         continuationToken: str = None):
        request = {
            "Bucket": self.bucket['name'],
            # "ExpectedBucketOwner": self.bucket['owner']['id']
        }
        if continuationToken:
            request['ContinuationToken'] = continuationToken
        response = self.conn.list_bucket_inventory_configurations(**request)
        nextContinuationToken = response.get('NextContinuationToken', None)
        current_tierings = [] if not tierings else tierings
        current_tierings.extend(response.get('IntelligentTieringConfigurationList', []))

        return current_tierings, nextContinuationToken

    def get_bucket_intelligent_tiering_configurations_list(self):
        try:
            tiering, nextContinuationToken = self.fetch_intelligent_tiering_config()

            while nextContinuationToken:
                tiering, nextContinuationToken = self.fetch_intelligent_tiering_config(tiering, nextContinuationToken)

        except Exception as ex:
            print(self.bucket['name'], " intelligent tiering configuration: ", ex)
            return []

        return tiering

    def get_bucket_acl(self):
        try:
            response = self.conn.get_bucket_acl(Bucket=self.bucket['name'])
            del response['ResponseMetadata']
        except Exception as ex:
            print(self.bucket['name'], " bucket ACL: ", ex)
            response = {}
        return response

    def get_bucket_encryption(self):
        try:
            response = self.conn.get_bucket_encryption(Bucket=self.bucket['name'])
            del response['ResponseMetadata']
        except Exception as ex:
            print(self.bucket['name'], " bucket encryption: ", ex)
            response = {}
        return response

    def get_bucket_versioning(self):
        try:
            response = self.conn.get_bucket_versioning(Bucket=self.bucket['name'])
            del response['ResponseMetadata']
        except Exception as ex:
            print(self.bucket['name'], " bucket versioning: ", ex)
            response = {}
        return response

    def get_bucket_tagging(self):
        try:
            response = self.conn.get_bucket_tagging(Bucket=self.bucket['name'])
            del response['ResponseMetadata']
        except Exception as ex:
            print(self.bucket['name'], " bucket tagging: ", ex)
            response = {}
        return response

    def get_bucket_policy_status(self):
        try:
            response = self.conn.get_bucket_policy_status(Bucket=self.bucket['name'])
            del response['ResponseMetadata']
        except Exception as ex:
            print(self.bucket['name'], " policy status: ", ex)
            response = {}
        return response

    def get_object_acl(self, key):
        try:
            response = self.conn.get_object_acl(Bucket=self.bucket['name'], Key=key)
        except Exception as ex:
            print(self.bucket['name'], " object acl: ", ex)
            response = {}
        return response

    def get_object_list(self):
        try:
            response = self.conn.list_objects(Bucket=self.bucket['name'])
        except Exception as ex:
            print(self.bucket['name'], " object list: ", ex)
            response = {}
        object_list = response.get('Contents', [])
        objects = []
        for object in object_list:
            object_acl = self.get_object_acl(object['Key'])
            del object_acl['ResponseMetadata']
            objects.append({
                **object,
                "Acl": object_acl
            })
        return objects

    def get_bucket_lifecycle(self):
        try:
            response = self.conn.get_bucket_lifecycle(Bucket=self.bucket['name'])
        except Exception as ex:
            print(self.bucket['name'], " bucket lifecycle: ", ex)
            response = {}
        return response

    def get_bucket_logging(self):
        try:
            response = self.conn.get_bucket_logging(Bucket=self.bucket['name'])
        except Exception as ex:
            print(self.bucket['name'], " bucket logging: ", ex)
            response = {}
        return response.get('LoggingEnabled')


class Network(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(Network, self).__init__()
            self.conn = self.client("ec2")
            self.network = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        subnets = self.get_subnet()
        network_acl = self.get_network_acl()

        self.network = {
            **self.network,
            "subnets": subnets,
            "network_acl": network_acl,
            "security_group": self.get_security_group(),
            "flow_logs": self.get_flow_logs(),
            "instance_sg": self.get_instance_sg_list(),
            "endpoints": self.get_vpc_endpoints(),
            "network_interfaces": self.get_network_interface()
        }
        return self.network

    def get_network_interface(self):
        try:
            interfaces = self.conn.describe_network_interfaces(Filters=[{
                "Name": 'vpc-id',
                "Values": [self.network.get('id')]
            }]).get('NetworkInterfaces')
        except Exception as ex:
            interfaces = []
            print(ex, "====== fetch network interface")
        interfaces = [{
            "NetworkInterfaceId": interface.get('NetworkInterfaceId'),
            "Status": interface.get('Status'),
            "OwnerId": interface.get('OwnerId'),
            "RequesterId": interface.get('RequesterId'),
        } for interface in interfaces]

        return interfaces

    def get_vpc_endpoints(self):
        def fetch_vpc_endpoints(endpoints=None, continueToken: str = None):
            request = {
                "Filters": [
                    {
                        "Name": "vpc-id",
                        "Values": [self.network.get('id')]
                    }
                ]
            }
            if continueToken:
                request['NextToken'] = continueToken
            response = self.conn.describe_vpc_endpoints(**request)
            continueToken = response.get('NextToken', None)
            current_endpoint = [] if not endpoints else endpoints
            current_endpoint.extend(response.get('VpcEndpoints', []))

            return current_endpoint, continueToken

        try:
            endpoint_list, nextToken = fetch_vpc_endpoints()

            while nextToken:
                endpoint_list, nextToken = fetch_vpc_endpoints(endpoint_list, nextToken)
        except Exception as ex:
            print("network Endpoints fetch error: ", ex)
            return []

        return endpoint_list

    def get_instance_sg_list(self):
        instances = self.conn.describe_instances()
        instance_sg_list = [sg.get('GroupId') for reserve in instances.get('Reservations', []) for instance in
                            reserve.get('Instances', []) for sg in instance.get('SecurityGroups', [])]

        return instance_sg_list

    def get_subnet(self):
        def fetch_subnet(subnetwork_list=None, continueToken: str = None):
            request = {
                "Filters": [
                    {
                        "Name": "vpc-id",
                        "Values": [self.network['id']]
                    }
                ]
            }
            if continueToken:
                request['NextToken'] = continueToken
            response = self.conn.describe_subnets(**request)
            continueToken = response.get('NextToken', None)
            current_subnets = [] if not subnetwork_list else subnetwork_list
            current_subnets.extend(response.get('Subnets', []))

            return current_subnets, continueToken

        try:
            subnets, nextToken = fetch_subnet()

            while nextToken:
                subnets, nextToken = fetch_subnet(subnets, nextToken)
        except Exception as ex:
            print("subnet fetch error: ", ex)
            return []

        return subnets

    def get_network_acl(self):
        def fetch_network_acl(acl_list=None, continueToken: str = None):
            request = {
                "Filters": [
                    {
                        "Name": "vpc-id",
                        "Values": [self.network['id']]
                    }
                ]
            }
            if continueToken:
                request['NextToken'] = continueToken
            response = self.conn.describe_network_acls(**request)
            continueToken = response.get('NextToken', None)
            current_acls = [] if not acl_list else acl_list
            current_acls.extend(response.get('NetworkAcls', []))

            return current_acls, continueToken

        try:
            acls, nextToken = fetch_network_acl()

            while nextToken:
                acls, nextToken = fetch_network_acl(acls, nextToken)
        except Exception as ex:
            print("network acl fetch error: ", ex)
            return []

        return acls

    def get_security_group(self):
        def fetch_security_group(sg_list=None, continueToken: str = None):
            request = {
                "Filters": [
                    {
                        "Name": "vpc-id",
                        "Values": [self.network['id']]
                    }
                ]
            }
            if continueToken:
                request['NextToken'] = continueToken
            response = self.conn.describe_security_groups(**request)
            continueToken = response.get('NextToken', None)
            current_sg = [] if not sg_list else sg_list
            current_sg.extend(response.get('SecurityGroups', []))

            return current_sg, continueToken

        try:
            sg_data, nextToken = fetch_security_group()

            while nextToken:
                sg_data, nextToken = fetch_security_group(sg_data, nextToken)
        except Exception as ex:
            print("network SG fetch error: ", ex)
            return []

        return sg_data

    def get_flow_logs(self):
        def fetch_flow_logs(flow_log_list=None, continueToken: str = None):
            request = {
                "Filters": [
                    {
                        "Name": "resource-id",
                        "Values": [self.network['id']]
                    }
                ]
            }
            if continueToken:
                request['NextToken'] = continueToken
            response = self.conn.describe_flow_logs(**request)
            continueToken = response.get('NextToken', None)
            current_flow_logs = [] if not flow_log_list else flow_log_list
            current_flow_logs.extend(response.get('FlowLogs', []))

            return current_flow_logs, continueToken

        try:
            flow_logs, nextToken = fetch_flow_logs()

            while nextToken:
                flow_logs, nextToken = fetch_flow_logs(flow_logs, nextToken)
        except Exception as ex:
            print("network Flow log fetch error: ", ex)
            return []

        return flow_logs


class SQL(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(SQL, self).__init__()
            self.conn = self.client("rds")
            self.database = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """

        self.database = {
            **self.database,
            "DBSnapshots": self.get_db_snapshots(instance_id=self.database.get('DBInstanceIdentifier')),
            "DBCluster": None
        }

        if self.database.get('DBClusterIdentifier'):
            db_cluster = self.get_db_cluster(self.database.get('DBClusterIdentifier'))
            if db_cluster:
                self.database['DBCluster'] = db_cluster

        return self.database

    def get_db_snapshots(self, instance_id):
        response = self.conn.describe_db_snapshots(DBInstanceIdentifier=instance_id)
        return response.get('DBSnapshots')

    def get_db_cluster(self, cluster_id):
        def get_db_cluster_snapshot(c_id):
            resp = self.conn.describe_db_cluster_snapshots(DBClusterIdentifier=c_id)
            return resp.get('DBClusterSnapshots')

        filters = [
            {
                "Name": "db-cluster-id",
                "Values": [cluster_id]
            }
        ]
        response = self.conn.describe_db_clusters(Filters=filters)

        clusters = response.get('DBClusters', [])

        clusters = [{
            **cluster,
            "Snapshots": get_db_cluster_snapshot(c_id=cluster.get('DBClusterIdentifier'))
        } for cluster in clusters]

        return clusters[0] if clusters else None


class ServiceAccount(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(ServiceAccount, self).__init__()
            self.conn = self.client("iam")
            self.user = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        resp = self.conn.generate_credential_report()
        pwd_enable_content = self.get_credential_report(self.user['UserName'])
        pwd_enable = pwd_enable_content[0] if pwd_enable_content else None

        users = self.conn.get_account_authorization_details().get('UserDetailList')
        users = [user for user in users if user.get('UserName') == self.user['UserName']]
        user = users[-1]
        custom_policy_list = self.conn.list_policies(Scope='Local').get('Policies')
        policy_details = []
        for policy in user.get('AttachedManagedPolicies', []):
            scope = 'Local' if [p for p in custom_policy_list if p.get('Arn') == policy.get('PolicyArn')] else 'AWS'
            policy_detail = self.conn.get_policy(PolicyArn=policy.get('PolicyArn')).get('Policy')
            policy_version = self.conn.get_policy_version(PolicyArn=policy.get('PolicyArn'),
                                                          VersionId=policy_detail.get('DefaultVersionId')).get(
                'PolicyVersion')
            policy_details.append({**policy_detail, "PolicyVersion": policy_version, "Scope": scope})

        access_keys = self.get_access_keys(self.user.get('UserName'))
        user_data = {
            **user,
            "PasswordEnable": pwd_enable,
            "AttachedManagedPolicies": policy_details,
            "GroupList": self.get_group_list(user.get('UserName')),
            "MFADevices": self.get_mfa_devices(user.get('UserName')),
            "PasswordLastUsed": self.get_password_last_used(user.get('UserName'))
        }

        if access_keys:
            user_data['AccessKeys'] = access_keys

        return user_data

    def get_access_keys(self, user_name):
        access_keys = None
        try:
            access_keys = self.conn.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
            access_keys = [{
                **key,
                "AccessKeyLastUsed": self.conn.get_access_key_last_used(AccessKeyId=key.get('AccessKeyId')).get(
                    'AccessKeyLastUsed', {}).get('LastUsedDate')
            } for key in access_keys]
        except Exception as ex:
            print(ex, "===== fetch list access key error")

        return access_keys

    def get_credential_report(self, user_name):
        content = []
        try:
            response = self.conn.get_credential_report()
            origin_content = response.get('Content', '')
            content = [False if user.split(',')[3] in ['false'] else True if user.split(',')[3] in ['true'] else
            user.split(',')[3] for user in origin_content.decode('UTF-8').split('\n') if
                       user.split(',')[0] == user_name]
        except Exception as ex:
            print(ex, "===== credential report")

        return content

    def get_group_list(self, user_name):
        try:
            groups = self.conn.list_groups_for_user(UserName=user_name).get('Groups')
        except:
            groups = []
        group_list = []
        for group in groups:
            try:
                group_policies = self.conn.list_attached_group_policies(GroupName=group.get('GroupName')).get(
                    'AttachedPolicies')
            except:
                group_policies = []
            group_list.append({
                **group,
                "AttachedPolicies": group_policies
            })

        return group_list

    def get_mfa_devices(self, user_name):
        try:
            mfa_devices = self.conn.list_mfa_devices(UserName=user_name).get('MFADevices', [])
        except:
            mfa_devices = []

        return mfa_devices

    def get_password_last_used(self, user_name):
        return self.conn.get_user(UserName=user_name).get('User').get('PasswordLastUsed')


class KMS(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(KMS, self).__init__()
            self.conn = self.client("kms")
            self.kms = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        key_detail = self.conn.describe_key(KeyId=self.kms.get('KeyId')).get('KeyMetadata')
        key_policy_names = self.conn.list_key_policies(KeyId=self.kms.get('KeyId')).get('PolicyNames')
        key_policies = [
            json.loads(self.conn.get_key_policy(KeyId=self.kms.get('KeyId'), PolicyName=p_name).get('Policy')) for
            p_name in key_policy_names]
        rotation_status = self.conn.get_key_rotation_status(KeyId=self.kms.get('KeyId')).get('KeyRotationEnabled')

        self.kms = {
            **key_detail,
            "KeyPolicies": key_policies,
            "KeyRotationEnabled": rotation_status
        }
        return self.kms


class CloudTrail(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(CloudTrail, self).__init__()
            self.conn = self.client("cloudtrail")
            self.logs = self.client('logs')
            self.watch = self.client('cloudwatch')
            self.trail = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        response = self.conn.get_trail(Name=self.trail['name'])
        trail_data = {
            "type": "cloudtrail",
            **response.get('Trail', {})
        }
        log_group_arn = trail_data.get('CloudWatchLogsLogGroupArn')
        if log_group_arn:
            log_group = self.get_log_group(log_group_arn)
            log_group_name = log_group.get('logGroupName')
            if log_group_name:
                metric_filters = self.get_metric_filters(log_group_name)
                metric_filters = [{
                    **metric,
                    "metricTransformations": [{
                        **data,
                        "metricAlarms": self.get_alarms_for_metric(data.get('metricName'), data.get('metricNamespace'))
                    } for data in metric.get('metricTransformations', [])]
                } for metric in metric_filters]
                log_group['metricFilters'] = metric_filters
            trail_data['CloudWatchLogGroup'] = log_group

        return trail_data

    def get_log_group(self, arn):
        def fetch_log_group(log_list=None, continueToken=None):
            request = {}
            if continueToken:
                request['nextToken'] = continueToken
            response = self.logs.describe_log_groups(**request)
            continueToken = response.get('NextToken', None)
            current_logs = [] if not log_list else log_list
            current_logs.extend(response.get('logGroups', []))

            return current_logs, continueToken

        try:
            logs, nextToken = fetch_log_group()

            while nextToken:
                logs = fetch_cloudtrails(logs, nextToken)
        except Exception as ex:
            print("cloudwatchlogs log group: ", ex)
            return {}
        logs = [log for log in logs if log.get('arn') == arn]
        return logs[0] if logs else {}

    def get_metric_filters(self, logGroupName):
        def fetch_metric_filters(metric_filter_list=None, continueToken=None, name=None):
            request = {}
            if continueToken:
                request['nextToken'] = continueToken
                request['logGroupName'] = name
            response = self.logs.describe_metric_filters(**request)
            continueToken = response.get('NextToken', None)
            current_metric_filters = [] if not metric_filter_list else metric_filter_list
            current_metric_filters.extend(response.get('metricFilters', []))

            return current_metric_filters, continueToken

        try:
            metric_filters, nextToken = fetch_metric_filters(name=logGroupName)

            while nextToken:
                metric_filters = fetch_cloudtrails(metric_filters, nextToken, logGroupName)
        except Exception as ex:
            print("cloudwatchlogs log group metric filter: ", ex)
            return {}

        return metric_filters

    def get_alarms_for_metric(self, filterName, filterNamespace):
        response = self.watch.describe_alarms_for_metric(MetricName=filterName, Namespace=filterNamespace)
        return response.get('MetricAlarms')


class Policy(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(Policy, self).__init__()
            self.conn = self.client("iam")
            self.policy = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        policy = {
            **self.policy,
            "Document": self.conn.get_policy_version(PolicyArn=self.policy.get('Arn'),
                                                     VersionId=self.policy.get('DefaultVersionId')).get(
                'PolicyVersion').get('Document')
        }

        return policy


class Snapshot(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(Snapshot, self).__init__()
            self.conn = self.client("ec2")
            self.snapshot = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        snapshot = {
            **self.snapshot,
        }
        print(snapshot, "==== snapshot")

        return snapshot


class EIP(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(EIP, self).__init__()
            self.conn = self.client("ec2")
            self.eip = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        eip = {
            **self.eip,
        }
        print(eip, "==== eip")

        return eip


class Disk(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(Disk, self).__init__()
            self.conn = self.client("ec2")
            self.disk = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        disk = {
            **self.disk,
        }

        return disk


class DynamoDB(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(DynamoDB, self).__init__()
            self.conn = self.client("dynamodb")
            self.ddb = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        dynamo_db = {
            **self.conn.describe_table(TableName=self.ddb.get('name')).get('Table', {}),
            "TableAutoScalingDescription": self.get_table_replica_auto_scaling(),
            "ContinuousBackupsDescription": self.get_continuous_backups(),
            "type": 'no_sql'
        }

        return dynamo_db

    def get_table_replica_auto_scaling(self):
        try:
            resp = self.conn.describe_table_replica_auto_scaling(TableName=self.ddb.get('name'))
        except Exception as ex:
            print(ex, "==== no sql auto scaling")
            resp = {}
        return resp.get('TableAutoScalingDescription')

    def get_continuous_backups(self):
        try:
            resp = self.conn.describe_continuous_backups(TableName=self.ddb.get('name'))
        except Exception as ex:
            print(ex, "===== no sql continuous backups")
            resp = {}
        return resp.get('ContinuousBackupsDescription')


class ElasticBeanstalk(AWS):
    def __init__(self,
                 resource,
                 **kwargs,
                 ) -> None:
        try:
            super(ElasticBeanstalk, self).__init__()
            self.conn = self.client("elasticbeanstalk")
            self.environment = resource
            self.environment_details = {}
        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        """

        settings = self.conn.describe_configuration_settings(
            ApplicationName=self.environment['ApplicationName'],
            EnvironmentName=self.environment['EnvironmentName'],
        )

        ConfigurationSettings = settings["ConfigurationSettings"]

        requied_options = ["ManagedActionsEnabled", "SystemType"]

        for ConfigurationSetting in ConfigurationSettings:
            OptionSettings = ConfigurationSetting["OptionSettings"]
            required_OptionSettings = []

            for OptionSetting in OptionSettings:
                if OptionSetting["OptionName"] in requied_options:
                    required_OptionSettings.append(OptionSetting)

            ConfigurationSetting["OptionSettings"] = required_OptionSettings

        self.environment_details = {
            **self.environment,
            "ConfigurationSettings": settings["ConfigurationSettings"],
        }
        return self.environment_details


class LoadBalancing(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(LoadBalancing, self).__init__()
            self.conn = self.client("elbv2")
            self.elbv1 = self.client("elb")
            self.elb = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        if self.elb.get('Type') in ['classic']:
            elb = {
                **self.elb,
                "Attributes": self.get_elbv1_attributes(self.elb.get('LoadBalancerName'))
            }
        else:
            elb = {
                **self.elb,
                "Attributes": self.get_attributes(),
                "Listeners": self.get_listeners(),
                "TargetGroups": self.get_target_groups()
            }

        return elb

    def get_attributes(self):
        resp = self.conn.describe_load_balancer_attributes(LoadBalancerArn=self.elb.get('LoadBalancerArn'))

        attributes = resp.get('Attributes', [])
        attr_data = {}
        for attr in attributes:
            attr_data[attr.get('Key')] = attr.get('Value')
        return attr_data

    def get_listeners(self):
        resources = []
        try:
            resp = self.conn.describe_listeners(LoadBalancerArn=self.elb.get('LoadBalancerArn'))
            listeners = resp.get('Listeners', [])
            for listener in listeners:
                try:
                    rules = self.conn.describe_rules(ListenerArn=listener.get('ListenerArn')).get('Rules', [])
                except Exception as ex:
                    rules = []

                try:
                    sslPolicies = self.conn.describe_ssl_policies(Names=[listener.get('SslPolicy')]).get('SslPolicies',
                                                                                                         [])
                    sslPolicy = sslPolicies[0] if sslPolicies else {"Name": listener.get('SslPolicy')}
                except:
                    sslPolicy = {"Name": listener.get('SslPolicy')}

                resources.append({
                    **listener,
                    "SslPolicy": sslPolicy,
                    "Rules": rules
                })
        except Exception as ex:
            print(ex, "=== fetch elb listener issue")

        return resources

    def get_target_groups(self):
        resources = []
        try:
            target_groups = self.conn.describe_target_groups(LoadBalancerArn=self.elb.get('LoadBalancerArn')).get(
                'TargetGroups', [])
            for target in target_groups:
                arn = target.get('TargetGroupArn')
                # target group attrs
                tg_attrs = self.conn.describe_target_group_attributes(TargetGroupArn=arn).get('Attributes')
                attr = {}
                for att in tg_attrs:
                    attr[att.get('Key')] = att.get('Value')
                # target health
                target_health = self.conn.describe_target_health(TargetGroupArn=arn).get('TargetHealthDescriptions', [])
                resources.append({
                    **target,
                    "Attributes": attr,
                    "TargetHealthDescriptions": target_health
                })
        except Exception as ex:
            print(ex, "===== target group fetch error")

        return resources

    def get_elbv1_attributes(self, name):
        attr = {}
        try:
            attr = self.elbv1.describe_load_balancer_attributes(LoadBalancerName=name).get('LoadBalancerAttributes')
        except Exception as ex:
            print(ex, "=== fetch elb v1 attributes")

        return attr


class IAM(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(IAM, self).__init__()
            self.conn = self.client("iam")

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        pwd_policy = None
        try:
            pwd_policy = self.conn.get_account_password_policy().get('PasswordPolicy')
        except Exception as ex:
            print(ex, "==== password policy fetch error")
        user_data = {
            "type": "iam",
        }
        if pwd_policy:
            user_data['PasswordPolicy'] = pwd_policy
        return user_data


class Analyzer(AWS):
    def __init__(self,
                 resource: dict,
                 **kwargs,
                 ) -> None:
        """
        """
        try:
            super(Analyzer, self).__init__()
            self.conn = self.client("accessanalyzer")
            self.analyzer = resource

        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        Fetches instance details.

        Args:
        instance_id (str): Ec2 instance id.
        return: dictionary object.
        """
        analyzer = {**self.analyzer}
        return analyzer


class ElasticFileSystem(AWS):
    def __init__(self,
                 resource,
                 **kwargs,
                 ) -> None:
        try:
            super(ElasticFileSystem, self).__init__()
            self.conn = self.client("efs")
            self.filesystem = resource
            self.filesystem_details = {}
        except Exception as ex:
            raise Exception(ex)

    def get_resource_inventory(self):
        """
        """

        print("get_resource_inventory")
        backup_policy = {}

        try:
            response = self.conn.describe_backup_policy(FileSystemId=self.filesystem['FileSystemId'])
            backup_policy = response['BackupPolicy']
        except Exception as ex:
            # PolicyNotFound
            pass

        self.filesystem_details = {
            **self.filesystem,
            "BackupPolicy": backup_policy,
        }
        return self.filesystem_details
