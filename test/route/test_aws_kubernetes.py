import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestCluster(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_aws_kubernetes.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_networkpolicy(self):
        """
        Test for Network policy
        """
        test = [match.value for match in parse('self..ds_name').find(self.resources)]
        ds_name = set(test.pop())
        if ('calico-node' in ds_name):
            flaglist = True
        else:
            flaglist = False
        flag = len(ds_name) >= 1 and flaglist
        self.assertEqual(True, flag, msg="Network policy is not enabled")

    def test_metricsserver(self):
        """
        Test for Metric Server
        """
        test = [match.value for match in parse('self..deployname').find(self.resources)]
        deploy_name = set(test.pop())
        if ('metrics-server' in deploy_name):
            flaglist = True
        else:
            flaglist = False
        flag = len(deploy_name) >= 1 and flaglist
        self.assertEqual(True, flag, msg="Metric server is not installed")

    def test_kubernetes_dashboard(self):
        """
        Test for Kubernetes dashboard
        """
        test = [match.value for match in parse('self..deployname').find(self.resources)]
        deploy_name = set(test.pop())
        if ('kubernetes-dashboard' in deploy_name):
            flaglist = True
        else:
            flaglist = False
        flag = len(deploy_name) >= 1 and flaglist
        self.assertEqual(False, flag, msg="Kubernetes dashboard is installed")

    def test_image_pull_policy(self):
        """
        Test for image pull policy
        """
        test = [match.value for match in parse('self..deployment[*].image_pull_policy').find(self.resources)]
        image_pull_policy = [each for each in test if each != 'IfNotPresent']
        flag = len(image_pull_policy) > 0
        self.assertEqual(False, flag, msg="image pull policy is not set to 'IfNotPresent'")

    def test_run_as_non_root(self):
        """
        Test for whether security context is set to use non-root user
        """
        test = [match.value for match in parse('self..deployment[*].run_as_non_root').find(self.resources)]
        run_as_non_root = [each for each in test if each != 'true']
        flag = len(run_as_non_root) > 0
        self.assertEqual(False, flag, msg="run_as_non_root is not set to 'true'")

    def test_cpu_request(self):
        """
        Test for whether CPU requests are set, This test case is not finished yet, needs some work
        """
        test_requests = [match.value for match in parse('self..deployment[*].resource_requests').find(self.resources)]
        test_cpu = [match.value for match in parse('self..deployment[*].resource_requests.cpu').find(self.resources)]
        flag = len(test_requests) == len(test_cpu)
        self.assertEqual(True, flag, msg="CPU requests are not set")

    def test_cpu_limit(self):
        """
        Test for whether CPU limits are set, This test case is not finished yet, needs some work
        """

        test_requests = [match.value for match in parse('self..deployment[*].resource_limits').find(self.resources)]
        test_cpu = [match.value for match in parse('self..deployment[*].resource_requests.cpu').find(self.resources)]
        flag = len(test_requests) == len(test_cpu)
        self.assertEqual(True, flag, msg="CPU requests are not set")

    def test_memory_request(self):
        """
        Test for whether memory requests are set, This test case is not finished yet, needs some work
        """

        test_requests = [match.value for match in parse('self..deployment[*].resource_requests').find(self.resources)]
        test_cpu = [match.value for match in parse('self..deployment[*].resource_requests.memory').find(self.resources)]
        flag = len(test_requests) == len(test_cpu)
        self.assertEqual(True, flag, msg="CPU requests are not set")

    def test_memory_limit(self):
        """
        Test for whether memory limits are set, This test case is not finished yet, needs some work
        """

        test_requests = [match.value for match in parse('self..deployment[*].resource_limits').find(self.resources)]
        test_cpu = [match.value for match in parse('self..deployment[*].resource_requests.memory').find(self.resources)]
        flag = len(test_requests) == len(test_cpu)
        self.assertEqual(True, flag, msg="CPU requests are not set")
    
    def test_memory_limit(self):
        """
        Test for whether memory limits are set, This test case is not finished yet, needs some work
        """

        test_requests = [match.value for match in parse('self..deployment[*].resource_limits').find(self.resources)]
        test_cpu = [match.value for match in parse('self..deployment[*].resource_requests.memory').find(self.resources)]
        flag = len(test_requests) == len(test_cpu)
        self.assertEqual(True, flag, msg="CPU requests are not set")
    
    def test_eks_control_plane_logging_enabled(self):
        """
        7.94 [extra794] Ensure EKS Control Plane Audit Logging is enabled for all log types - eks [Medium]
        """
        
        test_requests = [match.value for match in parse('cluster[*].self.logging.clusterLogging[*].enabled').find(self.resources) if match.value is False]
        flag = len(test_requests)
        self.assertEqual(False, flag, msg="In one of the cluster control plane logging is not enabled")

    def test_eks_private_endpoint_enabled(self):
        """
        7.95 [extra795] Ensure EKS Clusters are created with Private Endpoint Enabled and Public Access Disabled - eks [High]
        """
        
        test_requests = [match.value for match in parse('cluster[*].self.source_data.resourcesVpcConfig').find(self.resources) if match.value['endpointPrivateAccess'] is False or match.value['endpointPublicAccess'] is True]
        flag = len(test_requests)
        self.assertEqual(False, flag, msg="In one of the cluster private access is not enabled or public access is not disabled")
    
    
    def test_eks_restrict_access_to_control_plane_endpoint(self):
        """
        7.96 [extra796] Restrict Access to the EKS Control Plane Endpoint - eks [High]
        """
        
        test_requests = [match.value for match in parse('cluster[*].self.source_data.resourcesVpcConfig').find(self.resources) if match.value['endpointPrivateAccess'] is False or match.value['endpointPublicAccess'] is True or '0.0.0.0/0' in match.value['publicAccessCidrs']]
        flag = len(test_requests)
        self.assertEqual(False, flag, msg="In one of the cluster private access is not enabled or public access is not disabled")
    
    def test_eks_secrets_are_encrypted(self):
        """
        7.97 [extra797] Ensure Kubernetes Secrets are encrypted using Customer Master Keys (CMKs) - eks [Medium]
        """
       
        test_requests = [match.value for match in parse('cluster[*].self.source_data.encryptionConfig[*].provider.keyArn').find(self.resources)]
        flag = len(test_requests)
        self.assertEqual(True, flag, msg="In one of the cluster secrets are not encrypted")