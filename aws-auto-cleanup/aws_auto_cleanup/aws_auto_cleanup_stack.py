import os
from constructs import Construct
from aws_cdk import (
    App, Stack, Tags, RemovalPolicy, Duration, CfnOutput
)
from aws_cdk.aws_dynamodb import (
    Table,
    Attribute,
    AttributeType,
    BillingMode
)
from aws_cdk.aws_s3 import (
    Bucket, BucketEncryption, LifecycleRule
)
from aws_cdk.aws_lambda import (
    Function, Runtime, Code, LayerVersion
)
from aws_cdk.aws_iam import (
    Role, ServicePrincipal, PolicyDocument, PolicyStatement, Effect
)
from aws_cdk.aws_events import Rule, Schedule
from aws_cdk.aws_events_targets import LambdaFunction
from aws_cdk.aws_s3 import (
    Bucket, BucketEncryption, LifecycleRule
)
from aws_cdk.aws_glue import (
    CfnDatabase, CfnTable
)
from aws_cdk.aws_apigateway import (
    MethodLoggingLevel
)

DIRNAME = os.path.dirname(__file__)


class AwsAutoCleanupStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, stage, context, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        project = context["project"]
        Tags.of(self).add("project", project)
        log_level = "INFO"

        # Define DynamoDB tables
        settings_table = Table(
            self, "SettingsTable",
            table_name=f"auto-cleanup-app-{stage}-settings",
            partition_key=Attribute(name="key", type=AttributeType.STRING),
            billing_mode=BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
        )

        allowlist_table = Table(
            self, "AllowlistTable",
            table_name=f"auto-cleanup-app-{stage}-allowlist",
            partition_key=Attribute(name="resource_id", type=AttributeType.STRING),
            billing_mode=BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            time_to_live_attribute="expiration",
        )

        # Define S3 buckets
        execution_log_bucket = Bucket(
            self, "ExecutionLogBucket",
            bucket_name=f"auto-cleanup-app-{stage}-execution-log-{self.account}",
            encryption=BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,
        )

        athena_results_bucket = Bucket(
            self, "AthenaResultsBucket",
            bucket_name=f"auto-cleanup-app-{stage}-athena-results-{self.account}",
            encryption=BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,
            lifecycle_rules=[
                LifecycleRule(expiration=Duration.days(7))
            ],
        )

        # Define IAM role
        role = Role(
            self, "AutoCleanupRole",
            assumed_by=ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "AllowActions": PolicyDocument(statements=[
                    PolicyStatement(
                        effect=Effect.ALLOW,
                        actions=["*"],
                        resources=["*"],
                        conditions={"ForAnyValue:StringEquals": {"aws:CalledVia": ["cloudformation.amazonaws.com"]}}
                    ),
                    PolicyStatement(
                        effect=Effect.ALLOW,
                        actions=[
                            "airflow:DeleteEnvironment", "airflow:GetEnvironment", "airflow:ListEnvironments",
                            "amplify:DeleteApp", "amplify:ListApps",
                            "cloudformation:DeleteStack", "cloudformation:DescribeStacks",
                            "cloudformation:DescribeStackResources",
                            "cloudformation:ListStackResources", "cloudformation:ListStacks",
                            "cloudformation:UpdateTerminationProtection",
                            "codecommit:GetRepository",
                            "dynamodb:BatchWriteItem", "dynamodb:DeleteItem", "dynamodb:DeleteTable",
                            "dynamodb:DescribeTable",
                            "dynamodb:GetItem", "dynamodb:ListTables", "dynamodb:PutItem", "dynamodb:Scan",
                            "ec2:DeleteNatGateway", "ec2:DeleteSecurityGroup", "ec2:DeleteSnapshot", "ec2:DeleteVolume",
                            "ec2:DeregisterImage", "ec2:DescribeAddresses", "ec2:DescribeImages",
                            "ec2:DescribeInstanceAttribute",
                            "ec2:DescribeInstances", "ec2:DescribeNatGateways", "ec2:DescribeSecurityGroups",
                            "ec2:DescribeSnapshots",
                            "ec2:DescribeVolumes", "ec2:ModifyInstanceAttribute", "ec2:ReleaseAddress",
                            "ec2:StopInstances", "ec2:TerminateInstances",
                            "ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:DescribeImages",
                            "ecr:DescribeRepositories", "ecr:ListImages",
                            "ecs:DeleteCluster", "ecs:DeleteService", "ecs:DescribeClusters", "ecs:DescribeServices",
                            "ecs:ListClusters", "ecs:ListServices",
                            "eks:DeleteCluster", "eks:DeleteFargateProfile", "eks:DeleteNodegroup",
                            "eks:DescribeCluster", "eks:DescribeFargateProfile",
                            "eks:DescribeNodegroup", "eks:ListClusters", "eks:ListFargateProfiles",
                            "eks:ListNodegroups",
                            "elasticbeanstalk:DeleteApplication", "elasticbeanstalk:DescribeApplications",
                            "elasticache:DeleteCacheCluster", "elasticache:DeleteReplicationGroup",
                            "elasticache:DescribeCacheClusters", "elasticache:DescribeReplicationGroups",
                            "elasticfilesystem:DeleteFileSystem", "elasticfilesystem:DeleteMountTarget",
                            "elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeMountTargets",
                            "elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:DescribeLoadBalancers",
                            "elasticloadbalancing:ModifyLoadBalancerAttributes",
                            "elasticmapreduce:ListClusters", "elasticmapreduce:TerminateJobFlows",
                            "es:DeleteElasticsearchDomain", "es:DescribeElasticsearchDomainConfig",
                            "es:ListDomainNames",
                            "glue:DeleteCrawler", "glue:DeleteDatabase", "glue:DeleteDevEndPoint", "glue:GetCrawlers",
                            "glue:GetDatabases", "glue:GetDevEndpoints", "glue:GetTable",
                            "iam:DeleteAccessKey", "iam:DeleteInstanceProfile", "iam:DeleteLoginProfile",
                            "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:DeleteRole",
                            "iam:DeleteRolePolicy", "iam:DeleteUser", "iam:DeleteUserPolicy", "iam:DetachGroupPolicy",
                            "iam:DetachRolePolicy", "iam:DetachUserPolicy",
                            "iam:GenerateServiceLastAccessedDetails", "iam:GetAccessKeyLastUsed",
                            "iam:GetServiceLastAccessedDetails", "iam:ListAccessKeys",
                            "iam:ListAttachedRolePolicies", "iam:ListEntitiesForPolicy", "iam:ListGroupsForUser",
                            "iam:ListInstanceProfilesForRole", "iam:ListPolicies",
                            "iam:ListPolicyVersions", "iam:ListRolePolicies", "iam:ListRoles", "iam:ListUserPolicies",
                            "iam:ListUsers", "iam:RemoveRoleFromInstanceProfile",
                            "iam:RemoveUserFromGroup",
                            "kafka:DeleteCluster", "kafka:ListClustersV2", "ec2:DeleteVpcEndpoints",
                            "kinesis:DeleteStream", "kinesis:DescribeStream", "kinesis:ListStreams",
                            "kms:DescribeKey", "kms:ListKeys", "kms:ScheduleKeyDeletion",
                            "lambda:DeleteFunction", "lambda:ListFunctions",
                            "logs:DeleteLogGroup", "logs:DescribeLogGroups",
                            "redshift:DeleteCluster", "redshift:DeleteClusterSnapshot",
                            "redshift:DescribeClusterSnapshots", "redshift:DescribeClusters",
                            "rds:DeleteDBCluster", "rds:DeleteDBClusterSnapshot", "rds:DeleteDBInstance",
                            "rds:DeleteDBSnapshot", "rds:DescribeDBClusters", "rds:DescribeDBClusterSnapshots",
                            "rds:DescribeDBInstances", "rds:DescribeDBSnapshots", "rds:ModifyDBCluster",
                            "rds:ModifyDBInstance",
                            "s3:Delete*", "s3:Get*", "s3:List*", "s3:Put*",
                            "sagemaker:DeleteApp", "sagemaker:DeleteEndpoint", "sagemaker:DeleteNotebookInstance",
                            "sagemaker:ListApps",
                            "sagemaker:ListEndpoints", "sagemaker:ListNotebookInstances",
                            "sagemaker:StopNotebookInstance",
                            "sts:GetCallerIdentity",
                            "transfer:DeleteServer", "transfer:ListServers"
                        ],
                        resources=["*"]
                    )
                ])
            }
        )

        # Define Lambda function
        auto_cleanup_function = Function(
            self, "AutoCleanupFunction",
            function_name=f"auto-cleanup-app-{stage}",
            description="Removes unused AWS resources based on time of creation",
            runtime=Runtime.PYTHON_3_9,
            handler="src.main.lambda_handler",
            code=Code.from_asset(os.path.join(DIRNAME, "src")),
            memory_size=512,
            timeout=Duration.minutes(15),
            retry_attempts=0,
            role=role,
            environment={
                "LOG_LEVEL": "INFO",  # Change to "DEBUG" for development
                "EXECUTION_LOG_BUCKET": execution_log_bucket.bucket_name,
                "SETTINGS_TABLE": settings_table.table_name,
                "ALLOWLIST_TABLE": allowlist_table.table_name
            }
        )

        # Schedule the Lambda function
        rule = Rule(
            self, "ScheduleRule",
            schedule=Schedule.rate(Duration.days(3))
        )
        rule.add_target(LambdaFunction(auto_cleanup_function))

        # Glue database and table
        glue_db = CfnDatabase(
            self, "AutoCleanupDatabase",
            catalog_id=self.account,
            database_input={"name": f"auto-cleanup-db-{stage}"}
        )

        glue_table = CfnTable(
            self, "AutoCleanupTable",
            catalog_id=self.account,
            database_name=glue_db.ref,
            table_input={
                "name": f"auto-cleanup-table-{stage}",
                "tableType": "EXTERNAL_TABLE",
                "parameters": {"classification": "parquet"},
                "storageDescriptor": {
                    "columns": [
                        {"name": "resource_id", "type": "string"},
                        {"name": "resource_type", "type": "string"},
                        {"name": "creation_time", "type": "timestamp"},
                        {"name": "last_access_time", "type": "timestamp"},
                    ],
                    "location": f"s3://{athena_results_bucket.bucket_name}/",
                    "inputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
                    "outputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
                    "serdeInfo": {"serializationLibrary": "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"}
                }
            }
        )

        # IAM Role for Lambda
        lambda_role = Role(self, "LambdaRole",
                           assumed_by=ServicePrincipal("lambda.amazonaws.com"),
                           inline_policies={
                               "AllowDynamoDB": PolicyDocument(statements=[
                                   PolicyStatement(
                                       effect=Effect.ALLOW,
                                       actions=[
                                           "dynamodb:DeleteItem",
                                           "dynamodb:GetItem",
                                           "dynamodb:PutItem",
                                           "dynamodb:Scan"
                                       ],
                                       resources=["*"]
                                   )
                               ]),
                               "AllowS3": PolicyDocument(statements=[
                                   PolicyStatement(
                                       effect=Effect.ALLOW,
                                       actions=[
                                           "s3:Get*",
                                           "s3:List*"
                                       ],
                                       resources=["*"]
                                   )
                               ])
                           }
                           )

        # Lambda Layers
        python_requirements_layer = LayerVersion(self, "PythonRequirementsLayer",
                                                 code=Code.from_asset("path/to/layer.zip"),
                                                 compatible_runtimes=[Runtime.PYTHON_3_9]
                                                 )

        # API Gateway
        api = RestApi(self, "AutoCleanupApi",
                      rest_api_name="Auto Cleanup API",
                      description="API for auto-cleanup service",
                      deploy_options={
                          "tracing_enabled": True,
                          "data_trace_enabled": True,
                          "metrics_enabled": True,
                          "logging_level": MethodLoggingLevel.INFO,
                          "cache_cluster_enabled": True,
                          "cache_cluster_size": "0.5"
                      }
                      )

        # Define the Lambdas and API Gateway Endpoints
        functions = [
            {
                "name": "AllowlistCreate",
                "handler": "src/allowlist/create.lambda_handler",
                "memory_size": 128,
                "timeout": 30,
                "description": "Create allowlist entry",
                "path": "/allowlist/entry",
                "method": "POST"
            },
            {
                "name": "AllowlistRead",
                "handler": "src/allowlist/read.lambda_handler",
                "memory_size": 512,
                "timeout": 30,
                "description": "Read allowlist",
                "path": "/allowlist",
                "method": "GET"
            },
            {
                "name": "AllowlistUpdate",
                "handler": "src/allowlist/update.lambda_handler",
                "memory_size": 128,
                "timeout": 30,
                "description": "Update allowlist entry",
                "path": "/allowlist/entry",
                "method": "PUT"
            },
            {
                "name": "AllowlistDelete",
                "handler": "src/allowlist/delete.lambda_handler",
                "memory_size": 128,
                "timeout": 30,
                "description": "Delete allowlist entry",
                "path": "/allowlist/entry",
                "method": "DELETE"
            },
            {
                "name": "ServiceRead",
                "handler": "src/service/read.lambda_handler",
                "memory_size": 512,
                "timeout": 30,
                "description": "Returns AWS services supported by Auto Cleanup",
                "path": "/settings/service",
                "method": "GET"
            },
            {
                "name": "ExecutionLogList",
                "handler": "src/execution_log/list.lambda_handler",
                "memory_size": 512,
                "timeout": 30,
                "description": "Returns execution logs",
                "path": "/execution",
                "method": "GET"
            },
            {
                "name": "ExecutionLogRead",
                "handler": "src/execution_log/read.lambda_handler",
                "memory_size": 2048,
                "timeout": 30,
                "description": "Returns execution logs",
                "path": "/execution/{key}",
                "method": "GET"
            }
        ]

        for function in functions:
            lambda_function = _lambda.Function(self, function["name"],
                                               runtime=_lambda.Runtime.PYTHON_3_9,
                                               code=_lambda.Code.from_asset(os.path.join(DIRNAME, "src"),
                                                                            handler=function["handler"],
                                                                            memory_size=function["memory_size"],
                                                                            timeout=core.Duration.seconds(
                                                                                function["timeout"]),
                                                                            description=function["description"],
                                                                            environment={
                                                                                "LOG_LEVEL": log_level,
                                                                                # Add other environment variables here as needed
                                                                            },
                                                                            role=lambda_role,
                                                                            layers=[python_requirements_layer]
                                                                            ))

            # API Gateway integration
            lambda_integration = LambdaIntegration(lambda_function)
            resource = api.root.resource_for_path(function["path"])
            resource.add_method(function["method"], lambda_integration, api_key_required=True)

        # Outputs
        CfnOutput(self, "SettingsTableName", value=settings_table.table_name)
        CfnOutput(self, "AllowlistTableName", value=allowlist_table.table_name)
        CfnOutput(self, "ExecutionLogBucketName", value=execution_log_bucket.bucket_name)
        CfnOutput(self, "AthenaResultsBucketName", value=athena_results_bucket.bucket_name)
