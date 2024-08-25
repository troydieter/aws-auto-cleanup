import os
import subprocess

from aws_cdk import (
    aws_lambda as _lambda,
    Stack,
    Duration,
    core
)
from aws_cdk.aws_dynamodb import Table, Attribute, AttributeType, BillingMode
from aws_cdk.aws_events import Rule, Schedule
from aws_cdk.aws_glue import CfnDatabase, CfnTable
from aws_cdk.aws_iam import Role, ServicePrincipal, ManagedPolicy, PolicyDocument, PolicyStatement
from aws_cdk.aws_s3 import Bucket, BucketEncryption, LifecycleRule
from aws_cdk.aws_logs import LogGroup
from constructs import Construct


class AwsAutoCleanupAppStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        ac_lambda_role = Role(self, 'IamRoleLambdaExecution',
                              assume_role_policy_document={
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
                              policies=[
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
                              path='/',
                              role_name='-'.join([
                                  'auto-cleanup-app',
                                  'prod',
                                  self.region,
                                  'lambdaRole',
                              ]),
                              )

        ac_function = _lambda.Function(self, "ac_function",
                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                       handler="./aws_auto_cleanup_app/src/main.lambda_handler",
                                       code=_lambda.Code.from_asset("./aws_auto_cleanup_app/src/"),
                                       memory_size=512,
                                       timeout=Duration.seconds(900),
                                       retry_attempts=0,
                                       description="Removes unused AWS resources based on time of creation",
                                       layers=[self.create_dependencies_layer(self.stack_name, "ac_cleanup")],
                                       role=ac_lambda_role
                                       )

        # DynamoDB Allowlist Table
        allowlist_table = Table(
            self, 'AllowlistTable',
            table_name='auto-cleanup-app-prod-allowlist',
            partition_key=Attribute(
                name='resource_id',
                type=AttributeType.STRING
            ),
            billing_mode=BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute='expiration',
            point_in_time_recovery=True
        )

        # S3 Bucket for Athena Results
        athena_results_bucket = Bucket(
            self, 'AthenaResultsBucket',
            bucket_name=f"auto-cleanup-app-prod-athena-results-{self.account}",
            encryption=BucketEncryption.S3_MANAGED,
            lifecycle_rules=[
                LifecycleRule(
                    id='DeleteAfter7Days',
                    enabled=True,
                    expiration=core.Duration.days(7)
                )
            ],
            removal_policy=core.RemovalPolicy.RETAIN
        )

        # Glue Database
        auto_cleanup_database = CfnDatabase(
            self, 'AutoCleanupDatabase',
            database_name='auto-cleanup-app-prod'
        )

        # CloudWatch Log Group
        auto_cleanup_log_group = LogGroup(
            self, 'AutoCleanupLogGroup',
            log_group_name='/aws/lambda/auto-cleanup-app-prod',
            removal_policy=core.RemovalPolicy.RETAIN
        )

        # S3 Bucket for Execution Logs
        execution_log_bucket = Bucket(
            self, 'ExecutionLogBucket',
            bucket_name=f"auto-cleanup-app-prod-execution-log-{self.account}",
            encryption=BucketEncryption.S3_MANAGED,
            removal_policy=core.RemovalPolicy.RETAIN
        )

        # S3 Bucket for Serverless Deployment
        serverless_deployment_bucket = Bucket(
            self, 'ServerlessDeploymentBucket',
            encryption=BucketEncryption.S3_MANAGED
        )

        # DynamoDB Settings Table
        settings_table = Table(
            self, 'SettingsTable',
            table_name='auto-cleanup-app-prod-settings',
            partition_key=Attribute(
                name='key',
                type=AttributeType.STRING
            ),
            billing_mode=BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True
        )

        # Glue Table for Execution Logs
        execution_log_table = CfnTable(
            self, 'ExecutionLogTable',
            catalog_id=self.account,
            database_name=auto_cleanup_database.database_name,
            table_input=CfnTable.TableInputProperty(
                name='execution_log',
                storage_descriptor=CfnTable.StorageDescriptorProperty(
                    columns=[
                        CfnTable.ColumnProperty(name='platform', type='string'),
                        CfnTable.ColumnProperty(name='region', type='string'),
                        CfnTable.ColumnProperty(name='service', type='string'),
                        CfnTable.ColumnProperty(name='resource', type='string'),
                        CfnTable.ColumnProperty(name='resource_id', type='string'),
                        CfnTable.ColumnProperty(name='action', type='string'),
                        CfnTable.ColumnProperty(name='timestamp', type='timestamp'),
                        CfnTable.ColumnProperty(name='dry_run_flag', type='boolean'),
                        CfnTable.ColumnProperty(name='execution_id', type='string')
                    ],
                    location=f"s3://{execution_log_bucket.bucket_name}/",
                    input_format='org.apache.hadoop.mapred.TextInputFormat',
                    output_format='org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat',
                    serde_info=CfnTable.SerdeInfoProperty(
                        serialization_library='org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
                        parameters={'field.delim': ','}
                    )
                ),
                parameters={
                    'classification': 'csv',
                    'skip.header.line.count': '1',
                    'has_encrypted_data': 'true'
                }
            )
        )

        # EventBridge Rule for AutoCleanup Schedule
        auto_cleanup_events_rule_schedule1 = Rule(
            self, 'AutoCleanupEventsRuleSchedule1',
            schedule=Schedule.rate(core.Duration.days(3)),
            targets=[]
        )

    def create_dependencies_layer(self, project_name, function_name: str) -> _lambda.LayerVersion:
        requirements_file = "./aws_auto_cleanup_app/src/requirements.txt"
        output_dir = f"./aws_auto_cleanup_app/.build/app"

        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)

        if not os.environ.get("SKIP_PIP"):
            try:
                subprocess.check_call(
                    ["python", "-m", "pip", "install", "-r", requirements_file, "-t", f"{output_dir}/python"],
                    shell=True  # Allows the command to be executed in the Windows shell
                )
            except subprocess.CalledProcessError as e:
                print(f"Failed to install dependencies: {e}")
                raise

        layer_id = "ac-dependencies"
        layer_code = _lambda.Code.from_asset(output_dir)

        ac_layer = _lambda.LayerVersion(
            self,
            layer_id,
            code=layer_code,
        )

        return ac_layer
