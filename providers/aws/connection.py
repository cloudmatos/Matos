# -*- coding: utf-8 -*-
import json
import os

import boto3
import structlog

logger = structlog.get_logger(__file__)


def __sts_connection():
    aws_svc_account_path = os.getenv("AWS_SVC_ACCOUNT_PATH", "credentials")
    aws_role_json_path = os.path.join(aws_svc_account_path, "aws_role_account.json")
    # aws_role_json_path = os.path.join(os.getcwd(), "credentials/aws_role_account.json")
    with open(aws_role_json_path, "r") as file_obj:
        data = json.load(file_obj)
        arn = data.get("ARN")
        role_session_name = data.get("ROLE_SESSION_NAME")
        if role_session_name and arn:
            sts_connection = boto3.client("sts")
            return sts_connection.assume_role(
                RoleArn=arn, RoleSessionName=role_session_name
            )


def parse_credentials(STS_FLAG):
    """
    Currently access to AWS is done through simply passing ACCESS and SECRET keys.

    But going forward, it needs to be setup through service credentials token.

    Args:
    STS_FLAG bool: Optional flag if need to get the access using openId connect.
    """
    if STS_FLAG:
        sts_connection = __sts_connection()
        if sts_connection:
            return {
                "ACCESS_KEY_ID": sts_connection["Credentials"]["AccessKeyId"],
                "SECRET_ACCESS_KEY": sts_connection["Credentials"]["SecretAccessKey"],
                "SESSION_TOKEN": sts_connection["Credentials"]["SessionToken"],
            }
    else:
        with open("aws_role_account.json", "r") as file_obj:
            data = json.load(file_obj)
            return {
                "ACCESS_KEY_ID": data.get("ACCESS_KEY_ID"),
                "SECRET_ACCESS_KEY": data.get("SECRET_ACCESS_KEY"),
                "DEFAULT_REGION": data.get("DEFAULT_REGION"),
            }


class AWS:

    active_sessions = {}

    def __init__(self,
                 **kwargs) -> None:

        svc_account_filename = "aws_role_account.json"
        aws_svc_account_path = os.getenv("AWS_SVC_ACCOUNT_PATH", "credentials")
        self._aws_svc_account_file = os.path.join(aws_svc_account_path, svc_account_filename)
        # TODO: Change to local credential file
        try:
            aws_credentials = json.load(open(self._aws_svc_account_file))
        except:
            AWS_CRED_EXCEPTION = "Not found account service json for AWS - credentials/aws_role_account.json"
            raise Exception(AWS_CRED_EXCEPTION)
        log = logger.bind()
        if not aws_credentials:
            AWS_CRED_EXCEPTION = "No credentials found."
            log.exception(AWS_CRED_EXCEPTION)
            raise Exception(AWS_CRED_EXCEPTION)
        self.access_key = aws_credentials.get("ACCESS_KEY_ID")
        self.secret_access_key = aws_credentials.get("SECRET_ACCESS_KEY")
        self.session_token = aws_credentials.get("SESSION_TOKEN", "")
        self.region = aws_credentials.get("DEFAULT_REGION", "us-west-2")

        self._session = None

    def __get_access_kwargs(self):
        kwargs = {
            "aws_access_key_id": self.access_key,
            "aws_secret_access_key": self.secret_access_key,
        }
        if self.session_token:
            kwargs.update({"aws_session_token": self.session_token})

        if self.region:
            kwargs.update({"region_name": self.region})

        return kwargs

    @property
    def session(self):
        """"""
        if not self._session:
            self._session = boto3.Session(**self.__get_access_kwargs())
        return self._session

    def resource(self, service_name: str):
        """"""
        return self.session.resource(service_name)

    def client(self, service_name: str,region_name=None):
        """"""
        if region_name is not None:
            return self.session.client(service_name,region_name=region_name)
        return self.session.client(service_name)
