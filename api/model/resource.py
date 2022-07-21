class ResourceModel:
    def __init__(self, resource):
        self.cluster = resource.get('cluster')
        self.instance = resource.get('instance')
        self.network = resource.get('network')
        self.storage = resource.get('storage')
        self.serviceAccount = resource.get('serviceAccount')
        self.sql = resource.get('sql')
        self.iam = resource.get('iam')
        self.disk = resource.get('disk')
        self.snapshot = resource.get('snapshot')
        self.log_monitor = resource.get('log_monitor')
        self.kms = resource.get('kms')
        self.policy = resource.get('policy')
        self.no_sql = resource.get('no_sql')
        self.eip = resource.get('eip')
        self.apphosting = resource.get('apphosting')
        self.lb = resource.get('lb')
        self.analyzer = resource.get('analyzer')
        self.filesystem = resource.get('filesystem')
        self.user_groups = resource.get('user_groups')
        self.functions = resource.get('functions')
        self.sagemaker = resource.get('sagemaker')
        self.config_service = resource.get('config_service')
        self.elasticsearch = resource.get('elasticsearch')
        self.guardduty = resource.get('guardduty')
        self.redshift = resource.get('redshift')
        self.s3control = resource.get('s3control')
        self.dax = resource.get('dax')
        self.opensearch = resource.get('opensearch')
        self.cloudfront = resource.get('cloudfront')
        self.apigateway = resource.get('apigateway')
        self.rest_api = resource.get('rest_api')
        self.sqs = resource.get('sqs')
        self.ssm = resource.get('ssm')
        self.sns = resource.get('sns')
        self.docdb = resource.get('docdb')
        self.logs_metrics = resource.get('logs_metrics')
        self.codebuild = resource.get('codebuild')
        self.glue = resource.get('glue')
        self.acm = resource.get('acm')
        self.securityhub = resource.get('securityhub')
        
