# Remediation - AWS VPC Default Security Group Restricts All Traffic
This policy validates that the default Security Group for a given AWS VPC restricts all inbound and outbound traffic.
The principle of least privilege dictates that all traffic should be blocked unless explicitly needed, and it's recommended to create security groups for all categorizations of inbound/outbound traffic flows. Ensuring the default security group blocks all traffic enables this behavior by forcing all new EC2 instances to be moved off the default security group if they require internet access.

> Remediation Tool   - [Ansible](https://www.ansible.com/)

> Remediation Script - [playbook.yml](playbook.yml)

## Remediation Requirements
The below requirements are needed to execute remediation script

> pip packages
- python >= 3.6
- boto3 >= 1.15.0
- botocore >= 1.18.0

## Remediation Parameters

| Parameter | Comments |
| ------ | ------ |
| aws_access_key | AWS Access key |
| aws_secret_key | AWS Secret key |
| security_groups | List of default security groups |


## Remediation Execution
Following command need to execute
```sh
ansible-playbook playbook.yml --extra-vars '{
  "aws_access_key": "xxxx",
  "aws_secret_key": "xxxx",
  "security_groups": [
      {
        "id": "sg-0daf8300bb0f99668",
        "name": "default",
        "description": "default VPC security group"
      }
    ]
}'
```