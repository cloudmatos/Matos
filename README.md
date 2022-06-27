<img src="images/matos-logo.png" width="200" height="200">

![GitHub release (latest by date)](https://img.shields.io/github/v/release/matos/matos)
![GitHub Downloads](https://img.shields.io/github/downloads/matos/matos/total?logo=github&logoColor=white)
[![Go Report Card](https://goreportcard.com/badge/github.com/matos/matos)](https://goreportcard.com/report/github.com/matos/matos)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3588/badge)](https://bestpractices.coreinfrastructure.org/projects/3588)

# Introduction

Matos is a cloud resource anomaly detection application. It helps detect anomalies; configuration and policy drifts. It interacts with native cloud services api's or third party tools to deduce current status and metadata of underlying resources and represents current security and compliance posture, one use case at a time. Inherently supports Amazon Web Services and Google Cloud Platform services. Resource support and use cases will be extended as a part of planned road map.

# Features and Supported Services

- Support Amazon Web Services (AWS), Google Cloud Platform (GCP) and Microsoft Azure cloud service providers.
- Discover cloud infrastructure resources (e.g. Cloud Storage, SQL, Compute Instance, Cluster K8s & Networking) and services of the provided account or organization (AWS) / project (GCP) / subscription (Azure).
- Observe and analyze the cloud infrastructure resource in real-time to identify issues and pro-actively resolve them for improved performance.

# Roadmap

- Extend the support to additional cloud service providers (CSP).
- Extend the support to additional cloud infrastructure resources and services.
- Identify and recommend remediation based on detected anomalies and drifts.
- Identify and recommend remediation based on compliance requirements and best practices for security and governance.
- Get health information and compare it against set/defined thresholds.
- Detect anomalies and drifts in cloud infrastructure setup and policies.

# Audience 

- This project is intended to serve a diverse audience who build, maintain and manage cloud infrastructure.

    - Site Reliability Engineering (SRE)
    - DevSecOps
    - Cloud Security Architects and Developers

# Prerequisites 

* Amazon Web Services: Access to AWS account with credential having (programmatic access - access key ID and secret access key) having read-access permission.
* Microsoft Azure: Access to Azure subscription with app registered having read-access permission.
* Google Cloud: Access to Google projects with a service account having read-access permission.

# Quick Start  

Clone the Matos repository into a directory

    git clone https://github.com/cloudmatos/Matos.git

Change directory

    cd Matos

Create a virtual environment

    python3 -m venv ./.venv 

Activate the virtual environment

    source ./.venv/bin/activate

Upgrade pip (optional)

    python3 -m pip install --upgrade pip

Install packages using requirements.txt

    python3 -m pip install -r requirements.txt

Set `FLASK_APP` environment variable to specify the application

    export FLASK_APP=matos.py

Run the application

    python3 -m flask run

<img width="2032" alt="matos-starter-kit" src="https://user-images.githubusercontent.com/30431135/169472274-64203af9-dc20-42e3-87bf-d4d3f8b7851c.png">

https://user-images.githubusercontent.com/30431135/169459671-cae99636-2e54-4134-814c-f432f2eee3af.mov


# Contents

Directory|Description
-|-
[api](api) | API model, routes and schema definitions module
[credentials](credentials)| Cloud account credential json files for authentication and authorization
[docs](docs) | Matos project documents
[images](images) | Matos project image assets
[providers](providers) | Cloud Service Provider discovery, observability module
[services](services) | Cloud Infrastructure resource service module
[test](test) | Matos project test cases and data 
[utils](utils) | Utility library module

# Testing	

Matos supports the `unittest` & `pytest` unit testing frameworks to create and execute automated unit test cases. Unit test cases are created in Matos to identify and check the state of the cloud infrastructure resources. 

Before creating the unit test cases, the input required for the test cases must be collected. Test data are saved in the `Matos/test/data/` folder.
The API response of the cloud service provider is processed to meet the Matos requirement and saved in JSON format. The test data describes the current state of the cloud infrastructure resources.
These could be resource metadata or additional information describing the resource configuration and state.

Test cases are located in the folder `Matos/test/route/`, and the test case file name begins with `test_`. The python class represents the test suite and the python function represents the test case.  Depending on the test need, many functions can be added to cover all test scenarios.

## Naming convention

Replace the content in the curly bracket with the actual value. Examples are shown below.

**Test data file:**

    test_{cloud-provider}_{cloud-infrastructure}.json
e.g. test_gcp_cloud_storage_resources.json


**Test case file:**

    test_{cloud-provider}_{cloud-infrastructure}.py
e.g. test_gcp_cloud_storage_resources.py

**Class:**

    Test{cloud-infrastructure}
e.g. TestCloudStorage

**Function:**

    test_{use-case}
e.g. test_public_access


## Unit test example

```python
import os
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestCloudStorage(TestCase):
    def setUp(self):
        fp = open(os.getcwd() + "/test/data/test_gcp_cloud_storage_resources.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)

    def test_public_access(self):
        """
        Check bucket is publicly accessible or not
        """
        test = [match.value for match in parse('storage[*].self.iam_policy.bindings[*].members[*]').find(self.resources)
                if match.value == 'allUsers']
        flag = len(test) > 0
        self.assertEqual(True, flag, msg="There are few buckets which are publicly accessible.")
```

## Command to excute unit test

Using unit testing framework `unittest`

    python3 -m unittest

Using unit test framework `pytest`

    python3 -m pytest

# Documentation & Support

- [Quickstart](./docs/QUICKSTART.md)
- [Community](./docs/COMMUNITY.md)
- [Code of Conduct](./docs/CODE_OF_CONDUCT.md)
- [Maintainers](./docs/MAINTAINERS.md)
  - [CodeOwners](./docs/CODEOWNERS.md)
  - [Contribution Guidelines](./docs/CONTRIBUTION_GUIDELINES.md)
  - [Security](./docs/SECURITY.md)
- [License](./docs/LICENSE.md)

# Disclaimer

Matos does not save, publish or share with anyone any identifiable confidential information.

# Support

Cloudmatos builds and maintains Matos to make deep observability and policy checks simple and accessible.
Start with our Documentation for quick start and tests.
If you need direct support you can contact us at [community@cloudmatos.com](mailto:community@cloudmatos.com).
