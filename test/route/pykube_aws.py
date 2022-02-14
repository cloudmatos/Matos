# Configs can be set in Configuration class directly or using helper utility
from kubernetes import client, config
import os
import json
from jsonpath_ng import parse
from itertools import groupby
import pdb

kube_config = os.getcwd() + "/credentials/kube_config_aws"
config.load_kube_config(kube_config)


def get_result():
    """
    """
    res = {}
    resjson = {}
    res["ds_name"] = get_ds()
    res["deployments"] = get_deployments()
    res["psp_name"] = get_podsecuritypolicy()
    #resjson = selfish(json.dumps(res))
    resjson["self"] = res
    print(json.dumps(resjson,indent=2))

def get_ds():
    """
    Get list of DaemonSets 
    """ 
    v1 = client.AppsV1Api()
    ret = v1.list_daemon_set_for_all_namespaces(watch=False)
    list_ds = []
    for i in ret.items:
        item = "%s" % (i.metadata.name)
        list_ds.append(item)
    return list_ds

def get_deployments():
    """
    Get list of deployments
    """
    v1 = client.AppsV1Api()
    ret = v1.list_deployment_for_all_namespaces(watch=False)
    list_deploy = []
    for i in ret.items:
        deploydata = create_metadata_deployment(i)
        list_deploy.append(deploydata)
        
    return list_deploy    
   
def selfish(data):
        return {
        "deployment": data
    }


def create_metadata_deployment(deploy_data):
    '''
    To be extended to support multi container pods
    '''
    pdb.set_trace()
    data = selfish({
                "deployname": deploy_data.metadata.name,
                "replicas": deploy_data.spec.replicas,
                "liveness_probe": deploy_data.spec.template.spec.containers[0].liveness_probe._exec,
                "resource_requests": deploy_data.spec.template.spec.containers[0].resources.requests,
                "resource_limits": deploy_data.spec.template.spec.containers[0].resources.limits,
                #"readiness_probe": deploy_data.spec.template.spec.containers[0].readiness_probe._exec.command[0],
                "run_as_non_root": deploy_data.spec.template.spec.security_context.run_as_non_root,
                "image_pull_policy": deploy_data.spec.template.spec.containers[0].image_pull_policy
            })
  
    return data
    


def get_podsecuritypolicy():
    """
    Get list of pod network policy
    """
    v1 = client.PolicyV1beta1Api()
    ret = v1.list_pod_security_policy(watch=False)
    list_policy = []
    for i in ret.items:
        item = "%s" % (i.metadata.name)
        list_policy.append(item)
        psp_details = v1.read_pod_security_policy(item, pretty=True)
    return list_policy 

def get_pod():
    """
    Get list of pods
    """
    v1 = client.CoreV1Api()
    ret = v1.list_pod_for_all_namespaces(watch=False)
    list_pod = []
    for i in ret.items:
        item = "%s" % (i.metadata.name)
        list_pod.append(item)
    return list_pod    

def from_dict(data, *paths, raise_error=False):
    """
    """

    last_value = data
    
    for current_path in paths:
        
        if isinstance(last_value, (list, tuple)):
            
            if not isinstance(current_path, int):
                if raise_error:
                    raise KeyError(f"{current_path} should be a integer,"
                                   " target value is a sequence")
                else:
                    return
            
            last_value = last_value[current_path]
            
            continue
        elif isinstance(last_value, dict):
            
            if current_path not in last_value:
                if raise_error:
                    raise KeyError(f"{current_path} is not present in target")
                else:
                    return
            
            last_value = last_value[current_path]
            continue

        if raise_error:
            raise KeyError(f"{type(last_value)} is not "
                           f"accessible with key {current_path}")
        else:
            
            return
    
    return last_value

def add_child(child_mapper,
              source_key,
              target_key,
              source_data,
              target_data
              ):
    """
    """

    if source_key not in source_data:
        return

    try:
        data = source_data[source_key]

        if not data:
            return

        if isinstance(data, (list, tuple, set)):
            mapped = [child_mapper(s) for s in data if from_dict(s, "cluster_name") == target_data['self']['name']]
        else:
            mapped = child_mapper(data) if from_dict(data, "cluster_name") == target_data['self']['name'] else None

        target_data.update({target_key: mapped})
    except:
        return


get_result()
