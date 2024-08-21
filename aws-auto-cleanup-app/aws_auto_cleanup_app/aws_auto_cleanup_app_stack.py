from aws_cdk import Stack
import aws_cdk as cdk
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_events as events
import aws_cdk.aws_glue as glue
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as aws_lambda
import aws_cdk.aws_logs as logs
import aws_cdk.aws_s3 as s3
from constructs import Construct

"""
  The AWS CloudFormation template for this Serverless application
"""
class AwsAutoCleanupAppStack(Stack):
  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # Resources
    allowlistTable = dynamodb.CfnTable(self, 'AllowlistTable',
          table_name = 'auto-cleanup-app-prod-allowlist',
          attribute_definitions = [
            {
              'attributeName': 'resource_id',
              'attributeType': 'S',
            },
          ],
          key_schema = [
            {
              'attributeName': 'resource_id',
              'keyType': 'HASH',
            },
          ],
          time_to_live_specification = {
            'attributeName': 'expiration',
            'enabled': True,
          },
          billing_mode = 'PAY_PER_REQUEST',
          point_in_time_recovery_specification = {
            'pointInTimeRecoveryEnabled': True,
          },
        )

    athenaResultsBucket = s3.CfnBucket(self, 'AthenaResultsBucket',
          bucket_name = f"""auto-cleanup-app-prod-athena-results-{self.account}""",
          access_control = 'Private',
          bucket_encryption = {
            'serverSideEncryptionConfiguration': [
              {
                'serverSideEncryptionByDefault': {
                  'sseAlgorithm': 'AES256',
                },
              },
            ],
          },
          lifecycle_configuration = {
            'rules': [
              {
                'id': 'DeleteAfter7Days',
                'status': 'Enabled',
                'expirationInDays': 7,
              },
            ],
          },
        )
    athenaResultsBucket.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    autoCleanupDatabase = glue.CfnDatabase(self, 'AutoCleanupDatabase',
          database_input = {
            'name': 'auto-cleanup-app-prod',
          },
          catalog_id = self.account,
        )

    autoCleanupLogGroup = logs.CfnLogGroup(self, 'AutoCleanupLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-app-prod',
        )

    executionLogBucket = s3.CfnBucket(self, 'ExecutionLogBucket',
          bucket_name = f"""auto-cleanup-app-prod-execution-log-{self.account}""",
          access_control = 'Private',
          bucket_encryption = {
            'serverSideEncryptionConfiguration': [
              {
                'serverSideEncryptionByDefault': {
                  'sseAlgorithm': 'AES256',
                },
              },
            ],
          },
        )
    executionLogBucket.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    iamRoleLambdaExecution = iam.CfnRole(self, 'IamRoleLambdaExecution',
          assume_role_policy_document = {
            'Version': '2012-10-17',
            'Statement': [
              {
                'Effect': 'Allow',
                'Principal': {
                  'Service': [
                    'lambda.amazonaws.com',
                  ],
                },
                'Action': [
                  'sts:AssumeRole',
                ],
              },
            ],
          },
          policies = [
            {
              'policyName': '-'.join([
                'auto-cleanup-app',
                'prod',
                'lambda',
              ]),
              'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'logs:CreateLogStream',
                      'logs:CreateLogGroup',
                      'logs:TagResource',
                    ],
                    'Resource': [
                      f"""arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/aws/lambda/auto-cleanup-app-prod*:*""",
                    ],
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'logs:PutLogEvents',
                    ],
                    'Resource': [
                      f"""arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/aws/lambda/auto-cleanup-app-prod*:*:*""",
                    ],
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      '*',
                    ],
                    'Resource': '*',
                    'Condition': {
                      'ForAnyValue:StringEquals': {
                        'aws:CalledVia': [
                          'cloudformation.amazonaws.com',
                        ],
                      },
                    },
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'airflow:DeleteEnvironment',
                      'airflow:GetEnvironment',
                      'airflow:ListEnvironments',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'amplify:DeleteApp',
                      'amplify:ListApps',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'cloudformation:DeleteStack',
                      'cloudformation:DescribeStacks',
                      'cloudformation:DescribeStackResources',
                      'cloudformation:ListStackResources',
                      'cloudformation:ListStacks',
                      'cloudformation:UpdateTerminationProtection',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'codecommit:GetRepository',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'dynamodb:BatchWriteItem',
                      'dynamodb:DeleteItem',
                      'dynamodb:DeleteTable',
                      'dynamodb:DescribeTable',
                      'dynamodb:GetItem',
                      'dynamodb:ListTables',
                      'dynamodb:PutItem',
                      'dynamodb:Scan',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'ec2:DeleteNatGateway',
                      'ec2:DeleteSecurityGroup',
                      'ec2:DeleteSnapshot',
                      'ec2:DeleteVolume',
                      'ec2:DeregisterImage',
                      'ec2:DescribeAddresses',
                      'ec2:DescribeImages',
                      'ec2:DescribeInstanceAttribute',
                      'ec2:DescribeInstances',
                      'ec2:DescribeNatGateways',
                      'ec2:DescribeSecurityGroups',
                      'ec2:DescribeSnapshots',
                      'ec2:DescribeVolumes',
                      'ec2:ModifyInstanceAttribute',
                      'ec2:ReleaseAddress',
                      'ec2:StopInstances',
                      'ec2:TerminateInstances',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'ecr:BatchDeleteImage',
                      'ecr:DeleteRepository',
                      'ecr:DescribeImages',
                      'ecr:DescribeRepositories',
                      'ecr:ListImages',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'ecs:DeleteCluster',
                      'ecs:DeleteService',
                      'ecs:DescribeClusters',
                      'ecs:DescribeServices',
                      'ecs:ListClusters',
                      'ecs:ListServices',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'eks:DeleteCluster',
                      'eks:DeleteFargateProfile',
                      'eks:DeleteNodegroup',
                      'eks:DescribeCluster',
                      'eks:DescribeFargateProfile',
                      'eks:DescribeNodegroup',
                      'eks:ListClusters',
                      'eks:ListFargateProfiles',
                      'eks:ListNodegroups',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'elasticbeanstalk:DeleteApplication',
                      'elasticbeanstalk:DescribeApplications',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'elasticache:DeleteCacheCluster',
                      'elasticache:DeleteReplicationGroup',
                      'elasticache:DescribeCacheClusters',
                      'elasticache:DescribeReplicationGroups',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'elasticfilesystem:DeleteFileSystem',
                      'elasticfilesystem:DeleteMountTarget',
                      'elasticfilesystem:DescribeFileSystems',
                      'elasticfilesystem:DescribeMountTargets',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'elasticloadbalancing:DeleteLoadBalancer',
                      'elasticloadbalancing:DescribeLoadBalancers',
                      'elasticloadbalancing:ModifyLoadBalancerAttributes',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'elasticmapreduce:ListClusters',
                      'elasticmapreduce:TerminateJobFlows',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'es:DeleteElasticsearchDomain',
                      'es:DescribeElasticsearchDomainConfig',
                      'es:ListDomainNames',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'glue:DeleteCrawler',
                      'glue:DeleteDatabase',
                      'glue:DeleteDevEndPoint',
                      'glue:GetCrawlers',
                      'glue:GetDatabases',
                      'glue:GetDevEndpoints',
                      'glue:GetTable',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'iam:DeleteAccessKey',
                      'iam:DeleteInstanceProfile',
                      'iam:DeleteLoginProfile',
                      'iam:DeletePolicy',
                      'iam:DeletePolicyVersion',
                      'iam:DeleteRole',
                      'iam:DeleteRolePolicy',
                      'iam:DeleteUser',
                      'iam:DeleteUserPolicy',
                      'iam:DetachGroupPolicy',
                      'iam:DetachRolePolicy',
                      'iam:DetachUserPolicy',
                      'iam:GenerateServiceLastAccessedDetails',
                      'iam:GetAccessKeyLastUsed',
                      'iam:GetServiceLastAccessedDetails',
                      'iam:ListAccessKeys',
                      'iam:ListAttachedRolePolicies',
                      'iam:ListEntitiesForPolicy',
                      'iam:ListGroupsForUser',
                      'iam:ListInstanceProfilesForRole',
                      'iam:ListPolicies',
                      'iam:ListPolicyVersions',
                      'iam:ListRolePolicies',
                      'iam:ListRoles',
                      'iam:ListUserPolicies',
                      'iam:ListUsers',
                      'iam:RemoveRoleFromInstanceProfile',
                      'iam:RemoveUserFromGroup',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'kafka:DeleteCluster',
                      'kafka:ListClustersV2',
                      'ec2:DeleteVpcEndpoints',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'kinesis:DeleteStream',
                      'kinesis:DescribeStream',
                      'kinesis:ListStreams',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'kms:DescribeKey',
                      'kms:ListKeys',
                      'kms:ScheduleKeyDeletion',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'lambda:DeleteFunction',
                      'lambda:ListFunctions',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'logs:DeleteLogGroup',
                      'logs:DescribeLogGroups',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'redshift:DeleteCluster',
                      'redshift:DeleteClusterSnapshot',
                      'redshift:DescribeClusterSnapshots',
                      'redshift:DescribeClusters',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'rds:DeleteDBCluster',
                      'rds:DeleteDBClusterSnapshot',
                      'rds:DeleteDBInstance',
                      'rds:DeleteDBSnapshot',
                      'rds:DescribeDBClusters',
                      'rds:DescribeDBClusterSnapshots',
                      'rds:DescribeDBInstances',
                      'rds:DescribeDBSnapshots',
                      'rds:ModifyDBCluster',
                      'rds:ModifyDBInstance',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      's3:Delete*',
                      's3:Get*',
                      's3:List*',
                      's3:Put*',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'sagemaker:DeleteApp',
                      'sagemaker:DeleteEndpoint',
                      'sagemaker:DeleteNotebookInstance',
                      'sagemaker:ListApps',
                      'sagemaker:ListEndpoints',
                      'sagemaker:ListNotebookInstances',
                      'sagemaker:StopNotebookInstance',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'sts:GetCallerIdentity',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'transfer:DeleteServer',
                      'transfer:ListServers',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'xray:PutTraceSegments',
                      'xray:PutTelemetryRecords',
                    ],
                    'Resource': [
                      '*',
                    ],
                  },
                ],
              },
            },
          ],
          path = '/',
          role_name = '-'.join([
            'auto-cleanup-app',
            'prod',
            self.region,
            'lambdaRole',
          ]),
        )

    serverlessDeploymentBucket = s3.CfnBucket(self, 'ServerlessDeploymentBucket',
          bucket_encryption = {
            'serverSideEncryptionConfiguration': [
              {
                'serverSideEncryptionByDefault': {
                  'sseAlgorithm': 'AES256',
                },
              },
            ],
          },
        )

    settingsTable = dynamodb.CfnTable(self, 'SettingsTable',
          table_name = 'auto-cleanup-app-prod-settings',
          attribute_definitions = [
            {
              'attributeName': 'key',
              'attributeType': 'S',
            },
          ],
          key_schema = [
            {
              'attributeName': 'key',
              'keyType': 'HASH',
            },
          ],
          billing_mode = 'PAY_PER_REQUEST',
          point_in_time_recovery_specification = {
            'pointInTimeRecoveryEnabled': True,
          },
        )

    executionLogTable = glue.CfnTable(self, 'ExecutionLogTable',
          catalog_id = self.account,
          database_name = autoCleanupDatabase.ref,
          table_input = {
            'name': 'execution_log',
            'storageDescriptor': {
              'columns': [
                {
                  'name': 'platform',
                  'type': 'string',
                },
                {
                  'name': 'region',
                  'type': 'string',
                },
                {
                  'name': 'service',
                  'type': 'string',
                },
                {
                  'name': 'resource',
                  'type': 'string',
                },
                {
                  'name': 'resource_id',
                  'type': 'string',
                },
                {
                  'name': 'action',
                  'type': 'string',
                },
                {
                  'name': 'timestamp',
                  'type': 'timestamp',
                },
                {
                  'name': 'dry_run_flag',
                  'type': 'boolean',
                },
                {
                  'name': 'execution_id',
                  'type': 'string',
                },
              ],
              'compressed': False,
              'location': ''.join([
                's3://',
                executionLogBucket.ref,
                '/',
              ]),
              'inputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
              'outputFormat': 'org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat',
              'serdeInfo': {
                'serializationLibrary': 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
                'parameters': {
                  'field.delim': ',',
                },
              },
            },
            'parameters': {
              'delimiter': ',',
              'classification': 'csv',
              'skip.header.line.count': 1,
              'has_encrypted_data': True,
            },
          },
        )

    pythonRequirementsLambdaLayer = aws_lambda.CfnLayerVersion(self, 'PythonRequirementsLambdaLayer',
          content = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-app/prod/1724203000349-2024-08-21T01:16:40.349Z/pythonRequirements.zip',
          },
          layer_name = 'auto-cleanup-app-prod-requirements',
          description = 'Python requirements generated by serverless-python-requirements.',
          compatible_runtimes = [
            'python3.9',
          ],
        )

    serverlessDeploymentBucketPolicy = s3.CfnBucketPolicy(self, 'ServerlessDeploymentBucketPolicy',
          bucket = serverlessDeploymentBucket.ref,
          policy_document = {
            'Statement': [
              {
                'Action': 's3:*',
                'Effect': 'Deny',
                'Principal': '*',
                'Resource': [
                  ''.join([
                    'arn:',
                    self.partition,
                    ':s3:::',
                    serverlessDeploymentBucket.ref,
                    '/*',
                  ]),
                  ''.join([
                    'arn:',
                    self.partition,
                    ':s3:::',
                    serverlessDeploymentBucket.ref,
                  ]),
                ],
                'Condition': {
                  'Bool': {
                    'aws:SecureTransport': False,
                  },
                },
              },
            ],
          },
        )

    autoCleanupLambdaFunction = aws_lambda.CfnFunction(self, 'AutoCleanupLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-app/prod/1724203000349-2024-08-21T01:16:40.349Z/AutoCleanup.zip',
          },
          handler = 'src/main.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-app-prod',
          memory_size = 512,
          timeout = 900,
          description = 'Removes unused AWS resources based on time of creation',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'EXECUTION_LOG_BUCKET': executionLogBucket.ref,
              'SETTINGS_TABLE': settingsTable.ref,
              'ALLOWLIST_TABLE': allowlistTable.ref,
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
          layers = [
            pythonRequirementsLambdaLayer.ref,
          ],
        )
    autoCleanupLambdaFunction.add_dependency(autoCleanupLogGroup)

    autoCleanupEventsRuleSchedule1 = events.CfnRule(self, 'AutoCleanupEventsRuleSchedule1',
          schedule_expression = 'rate(3 days)',
          state = 'ENABLED',
          targets = [
            {
              'arn': autoCleanupLambdaFunction.attr_arn,
              'id': 'AutoCleanupSchedule',
            },
          ],
        )

    autoCleanupLambdaEvConf = aws_lambda.CfnEventInvokeConfig(self, 'AutoCleanupLambdaEvConf',
          function_name = autoCleanupLambdaFunction.ref,
          destination_config = {
          },
          qualifier = '$LATEST',
          maximum_retry_attempts = 0,
        )

    autoCleanupLambdaVersionp8VbiaCgdLIcfTj9xdhXlhuyW0yIbVcKiyIpb9am4 = aws_lambda.CfnVersion(self, 'AutoCleanupLambdaVersionp8VBIACgdLIcfTJ9xdhXlhuyW0YIbVcKIYIpb9am4',
          function_name = autoCleanupLambdaFunction.ref,
          code_sha256 = 'rswQ+OsWq1ImPI7fvF7ZsADHHHCUAgXefYa4prCmTW8=',
          description = 'Removes unused AWS resources based on time of creation',
        )
    autoCleanupLambdaVersionp8VbiaCgdLIcfTj9xdhXlhuyW0yIbVcKiyIpb9am4.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    autoCleanupLambdaPermissionEventsRuleSchedule1 = aws_lambda.CfnPermission(self, 'AutoCleanupLambdaPermissionEventsRuleSchedule1',
          function_name = autoCleanupLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'events.amazonaws.com',
          source_arn = autoCleanupEventsRuleSchedule1.attr_arn,
        )

    # Outputs
    self.serverless_deployment_bucket_name = serverlessDeploymentBucket.ref
    cdk.CfnOutput(self, 'CfnOutputServerlessDeploymentBucketName', 
      key = 'ServerlessDeploymentBucketName',
      export_name = 'sls-auto-cleanup-app-prod-ServerlessDeploymentBucketName',
      value = str(self.serverless_deployment_bucket_name),
    )

    """
      Current Lambda layer version
    """
    self.python_requirements_lambda_layer_qualified_arn = pythonRequirementsLambdaLayer.ref
    cdk.CfnOutput(self, 'CfnOutputPythonRequirementsLambdaLayerQualifiedArn', 
      key = 'PythonRequirementsLambdaLayerQualifiedArn',
      description = 'Current Lambda layer version',
      export_name = 'sls-auto-cleanup-app-prod-PythonRequirementsLambdaLayerQualifiedArn',
      value = str(self.python_requirements_lambda_layer_qualified_arn),
    )

    """
      Current Lambda layer hash
    """
    self.python_requirements_lambda_layer_hash = '0c2cd8e289c0c8ed46947cb4f68da7d2976df3ed'
    cdk.CfnOutput(self, 'CfnOutputPythonRequirementsLambdaLayerHash', 
      key = 'PythonRequirementsLambdaLayerHash',
      description = 'Current Lambda layer hash',
      export_name = 'sls-auto-cleanup-app-prod-PythonRequirementsLambdaLayerHash',
      value = str(self.python_requirements_lambda_layer_hash),
    )

    """
      Current Lambda layer S3Key
    """
    self.python_requirements_lambda_layer_s3_key = 'serverless/auto-cleanup-app/prod/1724203000349-2024-08-21T01:16:40.349Z/pythonRequirements.zip'
    cdk.CfnOutput(self, 'CfnOutputPythonRequirementsLambdaLayerS3Key', 
      key = 'PythonRequirementsLambdaLayerS3Key',
      description = 'Current Lambda layer S3Key',
      export_name = 'sls-auto-cleanup-app-prod-PythonRequirementsLambdaLayerS3Key',
      value = str(self.python_requirements_lambda_layer_s3_key),
    )

    """
      Current Lambda function version
    """
    self.auto_cleanup_lambda_function_qualified_arn = autoCleanupLambdaVersionp8VbiaCgdLIcfTj9xdhXlhuyW0yIbVcKiyIpb9am4.ref
    cdk.CfnOutput(self, 'CfnOutputAutoCleanupLambdaFunctionQualifiedArn', 
      key = 'AutoCleanupLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-app-prod-AutoCleanupLambdaFunctionQualifiedArn',
      value = str(self.auto_cleanup_lambda_function_qualified_arn),
    )

    self.execution_log_bucket_name = executionLogBucket.ref
    cdk.CfnOutput(self, 'CfnOutputExecutionLogBucketName', 
      key = 'ExecutionLogBucketName',
      value = str(self.execution_log_bucket_name),
    )

    self.settings_table_name = settingsTable.ref
    cdk.CfnOutput(self, 'CfnOutputSettingsTableName', 
      key = 'SettingsTableName',
      value = str(self.settings_table_name),
    )

    self.allowlist_table_name = allowlistTable.ref
    cdk.CfnOutput(self, 'CfnOutputAllowlistTableName', 
      key = 'AllowlistTableName',
      value = str(self.allowlist_table_name),
    )



