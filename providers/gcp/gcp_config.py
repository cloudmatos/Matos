# -*- coding: utf-8 -*-
from google.cloud import monitoring_v3


METRIC_FILTERS = {
    "node.ephemeral_storage_used_bytes": {
        "metric.type": "kubernetes.io/node/ephemeral_storage/used_bytes",
        "resource.type": "k8s_node",
    },
    "node.ephemeral_storage_total_bytes": {
        "metric.type": "kubernetes.io/node/ephemeral_storage/total_bytes",
        "resource.type": "k8s_node",
    },
    "node.ephemeral_storage_free_inodes": {
        "metric.type": "kubernetes.io/node/ephemeral_storage/inodes_free",
        "resource.type": "k8s_node",
    },
    "node.ephemeral_storage_total_inodes": {
        "metric.type": "kubernetes.io/node/ephemeral_storage/inodes_total",
        "resource.type": "k8s_node",
    },
    # # Node PID
    "node.pid_used": {
        "metric.type": "kubernetes.io/node/pid_used",
        "resource.type": "k8s_node",
    },
    "node.pid_limit": {
        "metric.type": "kubernetes.io/node/pid_limit",
        "resource.type": "k8s_node",
    },
    # # Node CPU
    "node.cpu_usage": {
        "metric.type": "kubernetes.io/node/cpu/core_usage_time",
        "resource.type": "k8s_node",
    },
    "node.total_cores": {
        "metric.type": "kubernetes.io/node/cpu/total_cores",
        "resource.type": "k8s_node",
    },
    "node.allocatable_cores": {
        "metric.type": "kubernetes.io/node/cpu/allocatable_cores",
        "resource.type": "k8s_node",
    },
    "node.memory_usage": {
        "metric.type": "kubernetes.io/node/memory/used_bytes",
        "resource.type": "k8s_node",
        "metric.label.memory_type": "non-evictable",
    },
    "node.total_memory": {
        "metric.type": "kubernetes.io/node/memory/total_bytes",
        "resource.type": "k8s_node",
    },
    "node.allocatable_memory": {
        "metric.type": "kubernetes.io/node/memory/allocatable_bytes",
        "resource.type": "k8s_node",
    },
    # Instances
    "instance.memory_utilization": {
        "metric.type": "compute.googleapis.com/instance/memory/balloon/ram_used",
        "resource.type": "gce_instance",
    },
    "instance.total_memory": {
        "metric.type": "compute.googleapis.com/instance/memory/balloon/ram_size",
        "resource.type": "gce_instance",
    },
    "instance.cpu_utilization": {
        "metric.type": "compute.googleapis.com/instance/cpu/utilization",
        "resource.type": "gce_instance",
    },
    "instance.network_receivedBytes": {
        "metric.type": "compute.googleapis.com/instance/network/received_bytes_count",
        "resource.type": "gce_instance",
    },
    "instance.network_sendBytes": {
        "metric.type": "compute.googleapis.com/instance/network/sent_bytes_count",
        "resource.type": "gce_instance",
    },
    "instance.disk_readBytes": {
        "metric.type": "compute.googleapis.com/instance/disk/read_bytes_count",
        "resource.type": "gce_instance",
    },
}

METRIC_KINDS = METRIC_FILTERS.keys()

MACHINE_TYPES = {
    "c2-standard-4": {"memory": 16, "cpu": 4},
    "c2-standard-8": {"memory": 32, "cpu": 8},
    "c2-standard-16": {"memory": 64, "cpu": 16},
    "c2-standard-30": {"memory": 120, "cpu": 20},
    "c2-standard-60": {"memory": 240, "cpu": 60},
    "e2-micro": {"memory": 1, "cpu": 2},
    "e2-small": {"memory": 2, "cpu": 2},
    "e2-medium": {"memory": 4, "cpu": 2},
    "e2-standard-2": {"memory": 8, "cpu": 2},
    "e2-standard-4": {"memory": 16, "cpu": 4},
    "e2-standard-8": {"memory": 32, "cpu": 8},
    "e2-standard-16": {"memory": 64, "cpu": 16},
    "e2-highmem-2": {"memory": 16, "cpu": 2},
    "e2-highmem-4": {"memory": 32, "cpu": 4},
    "e2-highmem-8": {"memory": 64, "cpu": 8},
    "e2-highmem-16": {"memory": 128, "cpu": 16},
    "e2-highcpu-2": {"memory": 2, "cpu": 2},
    "e2-highcpu-4": {"memory": 4, "cpu": 4},
    "e2-highcpu-8": {"memory": 8, "cpu": 8},
    "e2-highcpu-16": {"memory": 16, "cpu": 16},
}

VALUE_TYPES = [
    "VALUE_TYPE_UNSPECIFIED",
    "bool",
    "int64",
    "double",
    "string",
    "distribution",
]


K8S_TYP = (
    "k8s_container",
    "k8s_node",
)
RESOURCE_FACTOR = 1
RESOURCE_TYPE_FACTOR = {
    "k8s_container": 10 ** 3,
    "k8s_node": 10 ** 3,
    "gce_instance": 1.0,
}

FILTERS_ARGS = {
    "k8s_container": [
        "metric_type",
        "resource_type",
        "resource_name",
        "location",
    ],  # resource_name=cluster_name
    "k8s_node": [
        "metric_type",
        "resource_type",
        "resource_name",
        "location",
        "node_value",
    ],  # resource_name=cluster_name, node_value=node_name
    "gce_instance": [
        "metric_type",
        "resource_type",
        "node_value",
        "zone",
    ],  # node_value=instance_id
}

# With the following resource_name would be name of the resource in cloud with respect to its associated type.
FILTERS_MAP = {
    "k8s_container": 'metric.type = "{}" resource.type = "{}" \
        resource.label."cluster_name"="{}" resource.label."location"="{}"',
    "k8s_node": 'metric.type = "{}" resource.type = "{}" \
        resource.label."cluster_name"="{}" \
        resource.label."location"="{}" resource.label."node_name"="{}"',
    "gce_instance": 'metric.type = "{}" resource.type = "{}" \
        resource.label."instance_id"="{}" \resource.label."zone"="{}"',
}

OBSERV_RESOURCE_MAPPER = {
    "cluster": "",
    "vm": "",
}

# RESOURCE_TYPE_REQUESTS = {
#     "cluster": "container.googleapis.com/Cluster",
#     "pod": "k8s.io/Pod",
#     "service": "k8s.io/Service",
#     "namespace": "k8s.io/Namespace",
#     "node": "k8s.io/Node",
#     "instance": "compute.googleapis.com/Instance",
# }

ASSET_TYPES = {
    "k8s.io/Pod": "pods",
    "k8s.io/Service": "services",
    "k8s.io/Node": "nodes",
    "apps.k8s.io/Deployment": "deployments",
    "container.googleapis.com/Cluster": "cluster",
    "compute.googleapis.com/Instance": "instance",
    "compute.googleapis.com/Network": "network",
    "compute.googleapis.com/Subnetwork": "subnetworks",
    "compute.googleapis.com/Route": "routes",
    "compute.googleapis.com/Firewall": "firewalls",
    "storage.googleapis.com/Bucket": "storages",
    "iam.googleapis.com/Role": "role",
    "iam.googleapis.com/ServiceAccount": "serviceAccount",
    # "iam.googleapis.com/ServiceAccountKey": "serviceAccount",
    "iam.googleapis.com/ServiceAccountKey": "serviceAccountKey",
    "sqladmin.googleapis.com/Instance": "sql",
    'cloudresourcemanager.googleapis.com/Project': 'iam',
    'compute.googleapis.com/Disk': 'disk',
    'compute.googleapis.com/Snapshot': 'snapshot',
}

RESOURCE_TYPE_REQUESTS = {
    "cluster": [
        "container.googleapis.com/Cluster",
        "k8s.io/Pod",
        "k8s.io/Service",
        "k8s.io/Node",
        "apps.k8s.io/Deployment",
    ],
    "instance": ["compute.googleapis.com/Instance"],
    "network": [
        "compute.googleapis.com/Network",
        "compute.googleapis.com/Subnetwork",
        "compute.googleapis.com/Route",
        "compute.googleapis.com/Firewall"
    ],
    "storage": [
        "storage.googleapis.com/Bucket"
    ],
    "serviceAccount": [
        "iam.googleapis.com/ServiceAccount",
        "iam.googleapis.com/ServiceAccountKey"
    ],
    'sql': [
        "sqladmin.googleapis.com/Instance",
    ],
    'iam': [
        'cloudresourcemanager.googleapis.com/Project'
    ],
    'disk': [
        'compute.googleapis.com/Disk'
    ],
    'snapshot': [
        'compute.googleapis.com/Snapshot'
    ],
    'log_monitor': [],
    'kms': [],
    'policy': [],
    'no_sql': [],
    "eip": [],
    'apphosting': [],
    'lb': [],
    'analyzer': [],
    "filesystem": [],
    "user_groups": [],
    "functions": [],
    "redshift": [],
    "opensearch": [],
    "apigateway": [],
    "rest_api": [],
    "sqs": [],
    "docdb": [],
    "logs_metrics": [],
    "codebuild": [],
    "securityhub": []
}

POD_STATUS = ['Running']
IAM_TYPE = ['serviceAccount', 'storage', 'iam']

PLURAL_RESOURCE_TYPE_LIST = [
    'cluster', 'instance', 'network', 'sql', 'serviceAccount', 'storage', 'iam'
]


class GCPConfig:
    """
    contains all the GCP related configuration used for monitoring
    """

    aggregation_map = {
        # (metric_type, value_type) : default aggregator and reducer
        # both aggregator and reducer are statistical methods used to
        # align time series values, but not all aggregators work on all metrics,
        # aggregator type is bound by the type of metric and metric values.
        ("GAUGE", "INT64"): (
            monitoring_v3.Aggregation.Aligner.ALIGN_MEAN,
            monitoring_v3.Aggregation.Reducer.REDUCE_MEAN,
        ),
        ("GAUGE", "DOUBLE"): (
            monitoring_v3.Aggregation.Aligner.ALIGN_MEAN,
            monitoring_v3.Aggregation.Reducer.REDUCE_MEAN,
        ),
        ("DELTA", "INT64"): (
            monitoring_v3.Aggregation.Aligner.ALIGN_MEAN,
            monitoring_v3.Aggregation.Reducer.REDUCE_MEAN,
        ),
        ("DELTA", "DOUBLE"): (
            monitoring_v3.Aggregation.Aligner.ALIGN_MEAN,
            monitoring_v3.Aggregation.Reducer.REDUCE_MEAN,
        ),
        ("DELTA", "DISTRIBUTION"): (None, None),
        ("CUMULATIVE", "INT64"): (None, None),
        ("CUMULATIVE", "DOUBLE"): (None, None),
    }

    metric_type_map = {
        # GCP Enum for metricKind
        1: "GAUGE",
        2: "DELTA",
        3: "CUMULATIVE",
    }

    value_type_map = {
        # GCP Enum for valueType
        1: "BOOL",
        2: "INT64",
        3: "DOUBLE",
        4: "STRING",
        5: "DISTRIBUTION",
    }

    filter_name_map = {
        # filter names in our system are made generic
        # like cluster=some, node=something
        # but these filters are called something else in GCP
        # which is mapped here.
        "cluster": "resource.labels.cluster_name",
        "node": "resource.labels.node_name",
        "project": "resource.labels.project_id",
        "location": "resource.labels.location",
        "zone": "resource.labels.zone",
        "container": "resource.labels.container_name",
        "namespace": "resource.labels.namespace_name",
        "pod": "resource.labels.pod_name",
        "instance": "metric.labels.instance_name",
        "instance_id": "resource.labels.instance_id",
    }
