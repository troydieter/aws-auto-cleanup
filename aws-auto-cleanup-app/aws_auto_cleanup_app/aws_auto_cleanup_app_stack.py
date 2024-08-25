import os
import subprocess
from sys import path

from aws_cdk import (
    aws_lambda as lambda_,
    Stack,
    Duration
)
import aws_cdk as core
from aws_cdk.aws_dynamodb import Table, Attribute, AttributeType, BillingMode
from aws_cdk.aws_events import Rule, Schedule
from aws_cdk.aws_glue import CfnTable, CfnDatabase
from aws_cdk.aws_iam import Role, ServicePrincipal, Policy, PolicyStatement, Effect, PolicyDocument
from aws_cdk.aws_logs import LogGroup
from aws_cdk.aws_s3 import Bucket, BucketEncryption, LifecycleRule
from aws_cdk.aws_events_targets import LambdaFunction
from constructs import Construct
DIRNAME = os.path.dirname(__file__)

class AwsAutoCleanupAppStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        ac_lambda_role = Role(
            self, 'IamRoleLambdaExecution',
            assumed_by=ServicePrincipal("lambda.amazonaws.com"),
            role_name=f"auto-cleanup-app-prod-{self.region}-lambdaRole",
            path='/'
        )

        policy_document = PolicyDocument(
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "logs:CreateLogStream",
                        "logs:CreateLogGroup",
                        "logs:TagResource",
                    ],
                    resources=[
                        f"arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/aws/lambda/auto-cleanup-app-prod*:*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["logs:PutLogEvents"],
                    resources=[
                        f"arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/aws/lambda/auto-cleanup-app-prod*:*:*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["*"],
                    resources=["*"],
                    conditions={
                        "ForAnyValue:StringEquals": {
                            "aws:CalledVia": ["cloudformation.amazonaws.com"]
                        }
                    }
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "airflow:DeleteEnvironment",
                        "airflow:GetEnvironment",
                        "airflow:ListEnvironments",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "amplify:DeleteApp",
                        "amplify:ListApps",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "cloudformation:DeleteStack",
                        "cloudformation:DescribeStacks",
                        "cloudformation:DescribeStackResources",
                        "cloudformation:ListStackResources",
                        "cloudformation:ListStacks",
                        "cloudformation:UpdateTerminationProtection",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["codecommit:GetRepository"],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "dynamodb:BatchWriteItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:DeleteTable",
                        "dynamodb:DescribeTable",
                        "dynamodb:GetItem",
                        "dynamodb:ListTables",
                        "dynamodb:PutItem",
                        "dynamodb:Scan",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "ec2:DeleteNatGateway",
                        "ec2:DeleteSecurityGroup",
                        "ec2:DeleteSnapshot",
                        "ec2:DeleteVolume",
                        "ec2:DeregisterImage",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeImages",
                        "ec2:DescribeInstanceAttribute",
                        "ec2:DescribeInstances",
                        "ec2:DescribeNatGateways",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSnapshots",
                        "ec2:DescribeVolumes",
                        "ec2:ModifyInstanceAttribute",
                        "ec2:ReleaseAddress",
                        "ec2:StopInstances",
                        "ec2:TerminateInstances",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "ecr:BatchDeleteImage",
                        "ecr:DeleteRepository",
                        "ecr:DescribeImages",
                        "ecr:DescribeRepositories",
                        "ecr:ListImages",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "ecs:DeleteCluster",
                        "ecs:DeleteService",
                        "ecs:DescribeClusters",
                        "ecs:DescribeServices",
                        "ecs:ListClusters",
                        "ecs:ListServices",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "eks:DeleteCluster",
                        "eks:DeleteFargateProfile",
                        "eks:DeleteNodegroup",
                        "eks:DescribeCluster",
                        "eks:DescribeFargateProfile",
                        "eks:DescribeNodegroup",
                        "eks:ListClusters",
                        "eks:ListFargateProfiles",
                        "eks:ListNodegroups",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "elasticbeanstalk:DeleteApplication",
                        "elasticbeanstalk:DescribeApplications",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "elasticache:DeleteCacheCluster",
                        "elasticache:DeleteReplicationGroup",
                        "elasticache:DescribeCacheClusters",
                        "elasticache:DescribeReplicationGroups",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "elasticfilesystem:DeleteFileSystem",
                        "elasticfilesystem:DeleteMountTarget",
                        "elasticfilesystem:DescribeFileSystems",
                        "elasticfilesystem:DescribeMountTargets",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "elasticloadbalancing:DeleteLoadBalancer",
                        "elasticloadbalancing:DescribeLoadBalancers",
                        "elasticloadbalancing:ModifyLoadBalancerAttributes",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "elasticmapreduce:ListClusters",
                        "elasticmapreduce:TerminateJobFlows",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "es:DeleteElasticsearchDomain",
                        "es:DescribeElasticsearchDomainConfig",
                        "es:ListDomainNames",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "glue:DeleteCrawler",
                        "glue:DeleteDatabase",
                        "glue:DeleteDevEndPoint",
                        "glue:GetCrawlers",
                        "glue:GetDatabases",
                        "glue:GetDevEndpoints",
                        "glue:GetTable",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "iam:DeleteAccessKey",
                        "iam:DeleteInstanceProfile",
                        "iam:DeleteLoginProfile",
                        "iam:DeletePolicy",
                        "iam:DeletePolicyVersion",
                        "iam:DeleteRole",
                        "iam:DeleteRolePolicy",
                        "iam:DeleteUser",
                        "iam:DeleteUserPolicy",
                        "iam:DetachGroupPolicy",
                        "iam:DetachRolePolicy",
                        "iam:DetachUserPolicy",
                        "iam:GenerateServiceLastAccessedDetails",
                        "iam:GetAccessKeyLastUsed",
                        "iam:GetServiceLastAccessedDetails",
                        "iam:ListAccessKeys",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListEntitiesForPolicy",
                        "iam:ListGroupsForUser",
                        "iam:ListInstanceProfilesForRole",
                        "iam:ListPolicies",
                        "iam:ListPolicyVersions",
                        "iam:ListRolePolicies",
                        "iam:ListRoles",
                        "iam:ListUserPolicies",
                        "iam:ListUsers",
                        "iam:RemoveRoleFromInstanceProfile",
                        "iam:RemoveUserFromGroup",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "kafka:DeleteCluster",
                        "kafka:ListClustersV2",
                        "ec2:DeleteVpcEndpoints",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "kinesis:DeleteStream",
                        "kinesis:DescribeStream",
                        "kinesis:ListStreams",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "kms:DescribeKey",
                        "kms:ListKeys",
                        "kms:ScheduleKeyDeletion",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "lambda:DeleteFunction",
                        "lambda:ListFunctions",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "logs:DeleteLogGroup",
                        "logs:DescribeLogGroups",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "redshift:DeleteCluster",
                        "redshift:DeleteClusterSnapshot",
                        "redshift:DescribeClusterSnapshots",
                        "redshift:DescribeClusters",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "rds:DeleteDBCluster",
                        "rds:DeleteDBClusterSnapshot",
                        "rds:DeleteDBInstance",
                        "rds:DeleteDBSnapshot",
                        "rds:DescribeDBClusters",
                        "rds:DescribeDBClusterSnapshots",
                        "rds:DescribeDBInstances",
                        "rds:DescribeDBSnapshots",
                        "rds:ModifyDBCluster",
                        "rds:ModifyDBInstance",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "s3:Delete*",
                        "s3:Get*",
                        "s3:List*",
                        "s3:Put*",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "sagemaker:DeleteApp",
                        "sagemaker:DeleteEndpoint",
                        "sagemaker:DeleteNotebookInstance",
                        "sagemaker:ListApps",
                        "sagemaker:ListEndpoints",
                        "sagemaker:ListNotebookInstances",
                        "sagemaker:StopNotebookInstance",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["sts:GetCallerIdentity"],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "transfer:DeleteServer",
                        "transfer:ListServers",
                    ],
                    resources=["*"]
                ),
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        "xray:PutTraceSegments",
                        "xray:PutTelemetryRecords",
                    ],
                    resources=["*"]
                ),
            ]
        )

        ac_lambda_role.attach_inline_policy(
            Policy(
                self, 'AutoCleanupAppProdLambdaPolicy',
                document=policy_document
            )
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
            point_in_time_recovery=True,
            removal_policy=core.RemovalPolicy.DESTROY
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
            removal_policy=core.RemovalPolicy.DESTROY
        )

        # Glue Database
        auto_cleanup_database = CfnDatabase(
            self, 'AutoCleanupDatabase',
            database_name='auto-cleanup-app-prod',
            catalog_id=self.account,
            database_input=CfnDatabase.DatabaseInputProperty(
                name='auto-cleanup-app-prod',
                description='Database for Auto Cleanup App'
            )
        )

        # CloudWatch Log Group
        auto_cleanup_log_group = LogGroup(
            self, 'AutoCleanupLogGroup',
            log_group_name='/aws/lambda/auto-cleanup-app-prod',
            removal_policy=core.RemovalPolicy.DESTROY
        )

        # S3 Bucket for Execution Logs
        execution_log_bucket = Bucket(
            self, 'ExecutionLogBucket',
            bucket_name=f"auto-cleanup-app-prod-execution-log-{self.account}",
            encryption=BucketEncryption.S3_MANAGED,
            removal_policy=core.RemovalPolicy.DESTROY
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
            point_in_time_recovery=True,
            removal_policy=core.RemovalPolicy.DESTROY
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
        )

        ac_function = lambda_.Function(self, "ac_function",
                                       runtime=lambda_.Runtime.PYTHON_3_9,
                                       handler="main.lambda_handler",
                                       code=lambda_.Code.from_asset(os.path.join(DIRNAME, "src")),
                                       memory_size=512,
                                       timeout=Duration.seconds(900),
                                       retry_attempts=0,
                                       description="Removes unused AWS resources based on time of creation",
                                       layers=[self.create_dependencies_layer(self.stack_name, "ac_cleanup")],
                                       role=ac_lambda_role,
                                       environment={
                                           "LOG_LEVEL": "INFO",
                                           "EXECUTION_LOG_BUCKET": execution_log_bucket.bucket_name,
                                           "SETTINGS_TABLE": settings_table.table_name,
                                           "ALLOWLIST_TABLE": allowlist_table.table_name
                                       }
                                       )

        # Target the function
        auto_cleanup_events_rule_schedule1.add_target(LambdaFunction(ac_function))

    def create_dependencies_layer(self, project_name, function_name: str) -> lambda_.LayerVersion:
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
        layer_code = lambda_.Code.from_asset(output_dir)

        ac_layer = lambda_.LayerVersion(
            self,
            layer_id,
            code=layer_code,
        )

        return ac_layer
