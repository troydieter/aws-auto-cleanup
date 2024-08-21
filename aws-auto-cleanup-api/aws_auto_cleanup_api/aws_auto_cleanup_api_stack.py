from aws_cdk import Stack
import aws_cdk as cdk
import aws_cdk.aws_apigateway as apigateway
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as aws_lambda
import aws_cdk.aws_logs as logs
import aws_cdk.aws_s3 as s3
from constructs import Construct

"""
  The AWS CloudFormation template for this Serverless application
"""
class AwsAutoCleanupApiStack(Stack):
  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # Resources
    allowlistCreateLogGroup = logs.CfnLogGroup(self, 'AllowlistCreateLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-api-prod-allowlist-create',
        )

    allowlistDeleteLogGroup = logs.CfnLogGroup(self, 'AllowlistDeleteLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-api-prod-allowlist-delete',
        )

    allowlistReadLogGroup = logs.CfnLogGroup(self, 'AllowlistReadLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-api-prod-allowlist-read',
        )

    allowlistUpdateLogGroup = logs.CfnLogGroup(self, 'AllowlistUpdateLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-api-prod-allowlist-update',
        )

    apiGatewayRestApi = apigateway.CfnRestApi(self, 'ApiGatewayRestApi',
          name = 'prod-auto-cleanup-api',
          endpoint_configuration = {
            'types': [
              'EDGE',
            ],
          },
          policy = '',
          minimum_compression_size = 0,
        )

    executionLogListLogGroup = logs.CfnLogGroup(self, 'ExecutionLogListLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-api-prod-execution-log-list',
        )

    executionLogReadLogGroup = logs.CfnLogGroup(self, 'ExecutionLogReadLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-api-prod-execution-log-read',
        )

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
                'auto-cleanup-api',
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
                      f"""arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/aws/lambda/auto-cleanup-api-prod*:*""",
                    ],
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'logs:PutLogEvents',
                    ],
                    'Resource': [
                      f"""arn:{self.partition}:logs:{self.region}:{self.account}:log-group:/aws/lambda/auto-cleanup-api-prod*:*:*""",
                    ],
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      'dynamodb:DeleteItem',
                      'dynamodb:GetItem',
                      'dynamodb:PutItem',
                      'dynamodb:Scan',
                    ],
                    'Resource': '*',
                  },
                  {
                    'Effect': 'Allow',
                    'Action': [
                      's3:Get*',
                      's3:List*',
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
            'auto-cleanup-api',
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

    serviceReadLogGroup = logs.CfnLogGroup(self, 'ServiceReadLogGroup',
          log_group_name = '/aws/lambda/auto-cleanup-api-prod-service-read',
        )

    allowlistDeleteLambdaFunction = aws_lambda.CfnFunction(self, 'AllowlistDeleteLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203631219-2024-08-21T01:27:11.219Z/AllowlistDelete.zip',
          },
          handler = 'src/allowlist/delete.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-api-prod-allowlist-delete',
          memory_size = 128,
          timeout = 30,
          description = 'Delete allowlist entry',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'ALLOWLIST_TABLE': 'auto-cleanup-app-prod-allowlist',
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
        )
    allowlistDeleteLambdaFunction.add_dependency(allowlistDeleteLogGroup)

    allowlistReadLambdaFunction = aws_lambda.CfnFunction(self, 'AllowlistReadLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203631219-2024-08-21T01:27:11.219Z/AllowlistRead.zip',
          },
          handler = 'src/allowlist/read.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-api-prod-allowlist-read',
          memory_size = 512,
          timeout = 30,
          description = 'Read allowlist',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'ALLOWLIST_TABLE': 'auto-cleanup-app-prod-allowlist',
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
        )
    allowlistReadLambdaFunction.add_dependency(allowlistReadLogGroup)

    apiGatewayResourceAllowlist = apigateway.CfnResource(self, 'ApiGatewayResourceAllowlist',
          parent_id = apiGatewayRestApi.attr_root_resource_id,
          path_part = 'allowlist',
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayResourceExecution = apigateway.CfnResource(self, 'ApiGatewayResourceExecution',
          parent_id = apiGatewayRestApi.attr_root_resource_id,
          path_part = 'execution',
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayResourceSettings = apigateway.CfnResource(self, 'ApiGatewayResourceSettings',
          parent_id = apiGatewayRestApi.attr_root_resource_id,
          path_part = 'settings',
          rest_api_id = apiGatewayRestApi.ref,
        )

    executionLogListLambdaFunction = aws_lambda.CfnFunction(self, 'ExecutionLogListLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203631219-2024-08-21T01:27:11.219Z/ExecutionLogList.zip',
          },
          handler = 'src/execution_log/list.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-api-prod-execution-log-list',
          memory_size = 512,
          timeout = 30,
          description = 'Returns execution logs',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'EXECUTION_LOG_BUCKET': 'auto-cleanup-app-prod-execution-log-550767824695',
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
        )
    executionLogListLambdaFunction.add_dependency(executionLogListLogGroup)

    executionLogReadLambdaFunction = aws_lambda.CfnFunction(self, 'ExecutionLogReadLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203631219-2024-08-21T01:27:11.219Z/ExecutionLogRead.zip',
          },
          handler = 'src/execution_log/read.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-api-prod-execution-log-read',
          memory_size = 2048,
          timeout = 30,
          description = 'Returns execution logs',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'EXECUTION_LOG_BUCKET': 'auto-cleanup-app-prod-execution-log-550767824695',
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
        )
    executionLogReadLambdaFunction.add_dependency(executionLogReadLogGroup)

    pythonRequirementsLambdaLayer = aws_lambda.CfnLayerVersion(self, 'PythonRequirementsLambdaLayer',
          content = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203520580-2024-08-21T01:25:20.580Z/pythonRequirements.zip',
          },
          layer_name = 'auto-cleanup-api-prod-requirements',
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

    allowlistCreateLambdaFunction = aws_lambda.CfnFunction(self, 'AllowlistCreateLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203631219-2024-08-21T01:27:11.219Z/AllowlistCreate.zip',
          },
          handler = 'src/allowlist/create.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-api-prod-allowlist-create',
          memory_size = 128,
          timeout = 30,
          description = 'Create allowlist entry',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'SETTINGS_TABLE': 'auto-cleanup-app-prod-settings',
              'ALLOWLIST_TABLE': 'auto-cleanup-app-prod-allowlist',
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
          layers = [
            pythonRequirementsLambdaLayer.ref,
          ],
        )
    allowlistCreateLambdaFunction.add_dependency(allowlistCreateLogGroup)

    allowlistDeleteLambdaPermissionApiGateway = aws_lambda.CfnPermission(self, 'AllowlistDeleteLambdaPermissionApiGateway',
          function_name = allowlistDeleteLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'apigateway.amazonaws.com',
          source_arn = ''.join([
            'arn:',
            self.partition,
            ':execute-api:',
            self.region,
            ':',
            self.account,
            ':',
            apiGatewayRestApi.ref,
            '/*/*',
          ]),
        )

    allowlistDeleteLambdaVersionqxFZimqVhCwPcXxKqBcpQw82PnWrtpIOwGJqnB8Kos = aws_lambda.CfnVersion(self, 'AllowlistDeleteLambdaVersionqxFZimqVHCwPcXxKqBCPQw82PNWrtpIOwGJqnB8Kos',
          function_name = allowlistDeleteLambdaFunction.ref,
          code_sha256 = '1Gg6Rl1XFVsbRADRYisg/J4SwEbPeN+dMNCzJQ6J7pM=',
          description = 'Delete allowlist entry',
        )
    allowlistDeleteLambdaVersionqxFZimqVhCwPcXxKqBcpQw82PnWrtpIOwGJqnB8Kos.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    allowlistReadLambdaPermissionApiGateway = aws_lambda.CfnPermission(self, 'AllowlistReadLambdaPermissionApiGateway',
          function_name = allowlistReadLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'apigateway.amazonaws.com',
          source_arn = ''.join([
            'arn:',
            self.partition,
            ':execute-api:',
            self.region,
            ':',
            self.account,
            ':',
            apiGatewayRestApi.ref,
            '/*/*',
          ]),
        )

    allowlistReadLambdaVersioniIkLkvxiCxm5ce7WoxsbbKbSmCmuioCjphJ1hyWw = aws_lambda.CfnVersion(self, 'AllowlistReadLambdaVersioniIKLkvxiCXM5CE7WoxsbbKbSmCmuioCjphJ1hyWw',
          function_name = allowlistReadLambdaFunction.ref,
          code_sha256 = '3/ZVpcrY/4kJNzfD17TO2yXZlZ4iH1p8+6t3QIUl4yw=',
          description = 'Read allowlist',
        )
    allowlistReadLambdaVersioniIkLkvxiCxm5ce7WoxsbbKbSmCmuioCjphJ1hyWw.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    allowlistUpdateLambdaFunction = aws_lambda.CfnFunction(self, 'AllowlistUpdateLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203631219-2024-08-21T01:27:11.219Z/AllowlistUpdate.zip',
          },
          handler = 'src/allowlist/update.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-api-prod-allowlist-update',
          memory_size = 128,
          timeout = 30,
          description = 'Update allowlist entry',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'SETTINGS_TABLE': 'auto-cleanup-app-prod-settings',
              'ALLOWLIST_TABLE': 'auto-cleanup-app-prod-allowlist',
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
          layers = [
            pythonRequirementsLambdaLayer.ref,
          ],
        )
    allowlistUpdateLambdaFunction.add_dependency(allowlistUpdateLogGroup)

    apiGatewayMethodAllowlistOptions = apigateway.CfnMethod(self, 'ApiGatewayMethodAllowlistOptions',
          authorization_type = 'NONE',
          http_method = 'OPTIONS',
          method_responses = [
            {
              'statusCode': '200',
              'responseParameters': {
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True,
                'method.response.header.Access-Control-Allow-Methods': True,
              },
              'responseModels': {
              },
            },
          ],
          request_parameters = {
          },
          integration = {
            'type': 'MOCK',
            'requestTemplates': {
              'application/json': '{statusCode:200}',
            },
            'contentHandling': 'CONVERT_TO_TEXT',
            'integrationResponses': [
              {
                'statusCode': '200',
                'responseParameters': {
                  'method.response.header.Access-Control-Allow-Origin': '\'*\'',
                  'method.response.header.Access-Control-Allow-Headers': '\'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id\'',
                  'method.response.header.Access-Control-Allow-Methods': '\'OPTIONS,GET\'',
                },
                'responseTemplates': {
                  'application/json': '',
                },
              },
            ],
          },
          resource_id = apiGatewayResourceAllowlist.ref,
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayMethodExecutionOptions = apigateway.CfnMethod(self, 'ApiGatewayMethodExecutionOptions',
          authorization_type = 'NONE',
          http_method = 'OPTIONS',
          method_responses = [
            {
              'statusCode': '200',
              'responseParameters': {
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True,
                'method.response.header.Access-Control-Allow-Methods': True,
              },
              'responseModels': {
              },
            },
          ],
          request_parameters = {
          },
          integration = {
            'type': 'MOCK',
            'requestTemplates': {
              'application/json': '{statusCode:200}',
            },
            'contentHandling': 'CONVERT_TO_TEXT',
            'integrationResponses': [
              {
                'statusCode': '200',
                'responseParameters': {
                  'method.response.header.Access-Control-Allow-Origin': '\'*\'',
                  'method.response.header.Access-Control-Allow-Headers': '\'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id\'',
                  'method.response.header.Access-Control-Allow-Methods': '\'OPTIONS,GET\'',
                },
                'responseTemplates': {
                  'application/json': '',
                },
              },
            ],
          },
          resource_id = apiGatewayResourceExecution.ref,
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayResourceAllowlistEntry = apigateway.CfnResource(self, 'ApiGatewayResourceAllowlistEntry',
          parent_id = apiGatewayResourceAllowlist.ref,
          path_part = 'entry',
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayResourceExecutionKeyVar = apigateway.CfnResource(self, 'ApiGatewayResourceExecutionKeyVar',
          parent_id = apiGatewayResourceExecution.ref,
          path_part = '{key}',
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayResourceSettingsService = apigateway.CfnResource(self, 'ApiGatewayResourceSettingsService',
          parent_id = apiGatewayResourceSettings.ref,
          path_part = 'service',
          rest_api_id = apiGatewayRestApi.ref,
        )

    executionLogListLambdaPermissionApiGateway = aws_lambda.CfnPermission(self, 'ExecutionLogListLambdaPermissionApiGateway',
          function_name = executionLogListLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'apigateway.amazonaws.com',
          source_arn = ''.join([
            'arn:',
            self.partition,
            ':execute-api:',
            self.region,
            ':',
            self.account,
            ':',
            apiGatewayRestApi.ref,
            '/*/*',
          ]),
        )

    executionLogListLambdaVersionDm1f0OyFvzDstsKtrrEmauzAukEvWdiXDv19YtU = aws_lambda.CfnVersion(self, 'ExecutionLogListLambdaVersionDm1f0OyFvzDstsKtrrEMAUZAukEvWdiXDv19YtU',
          function_name = executionLogListLambdaFunction.ref,
          code_sha256 = 'x5t0iR+DQmCW0ylgw85DYc3nfTMOKg6qklC/LYw6yRA=',
          description = 'Returns execution logs',
        )
    executionLogListLambdaVersionDm1f0OyFvzDstsKtrrEmauzAukEvWdiXDv19YtU.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    executionLogReadLambdaPermissionApiGateway = aws_lambda.CfnPermission(self, 'ExecutionLogReadLambdaPermissionApiGateway',
          function_name = executionLogReadLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'apigateway.amazonaws.com',
          source_arn = ''.join([
            'arn:',
            self.partition,
            ':execute-api:',
            self.region,
            ':',
            self.account,
            ':',
            apiGatewayRestApi.ref,
            '/*/*',
          ]),
        )

    executionLogReadLambdaVersion7HsnSlUb64Db58zb1Yzny7ZmrJaMqg29ySzgq = aws_lambda.CfnVersion(self, 'ExecutionLogReadLambdaVersion7HsnSlUb64DB58zb1YZNY7ZmrJaMQG29ySZGQ',
          function_name = executionLogReadLambdaFunction.ref,
          code_sha256 = 'bfAKQcYN1pTIsLJM9HFQvtPxpmXtv8F/hcy5pySTT1E=',
          description = 'Returns execution logs',
        )
    executionLogReadLambdaVersion7HsnSlUb64Db58zb1Yzny7ZmrJaMqg29ySzgq.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    serviceReadLambdaFunction = aws_lambda.CfnFunction(self, 'ServiceReadLambdaFunction',
          code = {
            's3Bucket': serverlessDeploymentBucket.ref,
            's3Key': 'serverless/auto-cleanup-api/prod/1724203631219-2024-08-21T01:27:11.219Z/ServiceRead.zip',
          },
          handler = 'src/service/read.lambda_handler',
          runtime = 'python3.9',
          function_name = 'auto-cleanup-api-prod-service-read',
          memory_size = 512,
          timeout = 30,
          description = 'Returns AWS services supported by Auto Cleanup',
          tracing_config = {
            'mode': 'Active',
          },
          environment = {
            'variables': {
              'LOG_LEVEL': 'INFO',
              'SETTINGS_TABLE': 'auto-cleanup-app-prod-settings',
            },
          },
          role = iamRoleLambdaExecution.attr_arn,
          layers = [
            pythonRequirementsLambdaLayer.ref,
          ],
        )
    serviceReadLambdaFunction.add_dependency(serviceReadLogGroup)

    allowlistCreateLambdaPermissionApiGateway = aws_lambda.CfnPermission(self, 'AllowlistCreateLambdaPermissionApiGateway',
          function_name = allowlistCreateLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'apigateway.amazonaws.com',
          source_arn = ''.join([
            'arn:',
            self.partition,
            ':execute-api:',
            self.region,
            ':',
            self.account,
            ':',
            apiGatewayRestApi.ref,
            '/*/*',
          ]),
        )

    allowlistCreateLambdaVersionOiGvRisA6vlZcwsDkJbuHvboBpdfu6Syw2jKPfM5dH8 = aws_lambda.CfnVersion(self, 'AllowlistCreateLambdaVersionOiGvRisA6vlZcwsDkJBUHvboBpdfu6SYW2jKPfM5dH8',
          function_name = allowlistCreateLambdaFunction.ref,
          code_sha256 = 'FCsndUFcujtqTcSzHXYqp8uxEbKfq9HukWxsq7sdPxs=',
          description = 'Create allowlist entry',
        )
    allowlistCreateLambdaVersionOiGvRisA6vlZcwsDkJbuHvboBpdfu6Syw2jKPfM5dH8.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    allowlistUpdateLambdaPermissionApiGateway = aws_lambda.CfnPermission(self, 'AllowlistUpdateLambdaPermissionApiGateway',
          function_name = allowlistUpdateLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'apigateway.amazonaws.com',
          source_arn = ''.join([
            'arn:',
            self.partition,
            ':execute-api:',
            self.region,
            ':',
            self.account,
            ':',
            apiGatewayRestApi.ref,
            '/*/*',
          ]),
        )

    allowlistUpdateLambdaVersionjVNghuqLm4pfDdyyJbTa7pXyxiHhrl8bYrMfMb3ekXs = aws_lambda.CfnVersion(self, 'AllowlistUpdateLambdaVersionjVNghuqLm4pfDdyyJbTA7PXyxiHhrl8bYrMfMb3ekXs',
          function_name = allowlistUpdateLambdaFunction.ref,
          code_sha256 = 'SbN0qnQjZFZYH5frvnOZBC2BnG+anYVTcGqzdlaExFI=',
          description = 'Update allowlist entry',
        )
    allowlistUpdateLambdaVersionjVNghuqLm4pfDdyyJbTa7pXyxiHhrl8bYrMfMb3ekXs.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    apiGatewayMethodAllowlistEntryDelete = apigateway.CfnMethod(self, 'ApiGatewayMethodAllowlistEntryDelete',
          http_method = 'DELETE',
          request_parameters = {
          },
          resource_id = apiGatewayResourceAllowlistEntry.ref,
          rest_api_id = apiGatewayRestApi.ref,
          api_key_required = True,
          authorization_type = 'NONE',
          integration = {
            'integrationHttpMethod': 'POST',
            'type': 'AWS_PROXY',
            'uri': ''.join([
              'arn:',
              self.partition,
              ':apigateway:',
              self.region,
              ':lambda:path/2015-03-31/functions/',
              allowlistDeleteLambdaFunction.attr_arn,
              '/invocations',
            ]),
          },
          method_responses = [
          ],
        )
    apiGatewayMethodAllowlistEntryDelete.add_dependency(allowlistDeleteLambdaPermissionApiGateway)

    apiGatewayMethodAllowlistEntryOptions = apigateway.CfnMethod(self, 'ApiGatewayMethodAllowlistEntryOptions',
          authorization_type = 'NONE',
          http_method = 'OPTIONS',
          method_responses = [
            {
              'statusCode': '200',
              'responseParameters': {
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True,
                'method.response.header.Access-Control-Allow-Methods': True,
              },
              'responseModels': {
              },
            },
          ],
          request_parameters = {
          },
          integration = {
            'type': 'MOCK',
            'requestTemplates': {
              'application/json': '{statusCode:200}',
            },
            'contentHandling': 'CONVERT_TO_TEXT',
            'integrationResponses': [
              {
                'statusCode': '200',
                'responseParameters': {
                  'method.response.header.Access-Control-Allow-Origin': '\'*\'',
                  'method.response.header.Access-Control-Allow-Headers': '\'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id\'',
                  'method.response.header.Access-Control-Allow-Methods': '\'OPTIONS,DELETE,PUT,POST\'',
                },
                'responseTemplates': {
                  'application/json': '',
                },
              },
            ],
          },
          resource_id = apiGatewayResourceAllowlistEntry.ref,
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayMethodAllowlistGet = apigateway.CfnMethod(self, 'ApiGatewayMethodAllowlistGet',
          http_method = 'GET',
          request_parameters = {
          },
          resource_id = apiGatewayResourceAllowlist.ref,
          rest_api_id = apiGatewayRestApi.ref,
          api_key_required = True,
          authorization_type = 'NONE',
          integration = {
            'integrationHttpMethod': 'POST',
            'type': 'AWS_PROXY',
            'uri': ''.join([
              'arn:',
              self.partition,
              ':apigateway:',
              self.region,
              ':lambda:path/2015-03-31/functions/',
              allowlistReadLambdaFunction.attr_arn,
              '/invocations',
            ]),
          },
          method_responses = [
          ],
        )
    apiGatewayMethodAllowlistGet.add_dependency(allowlistReadLambdaPermissionApiGateway)

    apiGatewayMethodExecutionGet = apigateway.CfnMethod(self, 'ApiGatewayMethodExecutionGet',
          http_method = 'GET',
          request_parameters = {
          },
          resource_id = apiGatewayResourceExecution.ref,
          rest_api_id = apiGatewayRestApi.ref,
          api_key_required = True,
          authorization_type = 'NONE',
          integration = {
            'integrationHttpMethod': 'POST',
            'type': 'AWS_PROXY',
            'uri': ''.join([
              'arn:',
              self.partition,
              ':apigateway:',
              self.region,
              ':lambda:path/2015-03-31/functions/',
              executionLogListLambdaFunction.attr_arn,
              '/invocations',
            ]),
          },
          method_responses = [
          ],
        )
    apiGatewayMethodExecutionGet.add_dependency(executionLogListLambdaPermissionApiGateway)

    apiGatewayMethodExecutionKeyVarGet = apigateway.CfnMethod(self, 'ApiGatewayMethodExecutionKeyVarGet',
          http_method = 'GET',
          request_parameters = {
          },
          resource_id = apiGatewayResourceExecutionKeyVar.ref,
          rest_api_id = apiGatewayRestApi.ref,
          api_key_required = True,
          authorization_type = 'NONE',
          integration = {
            'integrationHttpMethod': 'POST',
            'type': 'AWS_PROXY',
            'uri': ''.join([
              'arn:',
              self.partition,
              ':apigateway:',
              self.region,
              ':lambda:path/2015-03-31/functions/',
              executionLogReadLambdaFunction.attr_arn,
              '/invocations',
            ]),
          },
          method_responses = [
          ],
        )
    apiGatewayMethodExecutionKeyVarGet.add_dependency(executionLogReadLambdaPermissionApiGateway)

    apiGatewayMethodExecutionKeyVarOptions = apigateway.CfnMethod(self, 'ApiGatewayMethodExecutionKeyVarOptions',
          authorization_type = 'NONE',
          http_method = 'OPTIONS',
          method_responses = [
            {
              'statusCode': '200',
              'responseParameters': {
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True,
                'method.response.header.Access-Control-Allow-Methods': True,
              },
              'responseModels': {
              },
            },
          ],
          request_parameters = {
          },
          integration = {
            'type': 'MOCK',
            'requestTemplates': {
              'application/json': '{statusCode:200}',
            },
            'contentHandling': 'CONVERT_TO_TEXT',
            'integrationResponses': [
              {
                'statusCode': '200',
                'responseParameters': {
                  'method.response.header.Access-Control-Allow-Origin': '\'*\'',
                  'method.response.header.Access-Control-Allow-Headers': '\'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id\'',
                  'method.response.header.Access-Control-Allow-Methods': '\'OPTIONS,GET\'',
                },
                'responseTemplates': {
                  'application/json': '',
                },
              },
            ],
          },
          resource_id = apiGatewayResourceExecutionKeyVar.ref,
          rest_api_id = apiGatewayRestApi.ref,
        )

    apiGatewayMethodSettingsServiceOptions = apigateway.CfnMethod(self, 'ApiGatewayMethodSettingsServiceOptions',
          authorization_type = 'NONE',
          http_method = 'OPTIONS',
          method_responses = [
            {
              'statusCode': '200',
              'responseParameters': {
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True,
                'method.response.header.Access-Control-Allow-Methods': True,
              },
              'responseModels': {
              },
            },
          ],
          request_parameters = {
          },
          integration = {
            'type': 'MOCK',
            'requestTemplates': {
              'application/json': '{statusCode:200}',
            },
            'contentHandling': 'CONVERT_TO_TEXT',
            'integrationResponses': [
              {
                'statusCode': '200',
                'responseParameters': {
                  'method.response.header.Access-Control-Allow-Origin': '\'*\'',
                  'method.response.header.Access-Control-Allow-Headers': '\'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id\'',
                  'method.response.header.Access-Control-Allow-Methods': '\'OPTIONS,GET\'',
                },
                'responseTemplates': {
                  'application/json': '',
                },
              },
            ],
          },
          resource_id = apiGatewayResourceSettingsService.ref,
          rest_api_id = apiGatewayRestApi.ref,
        )

    serviceReadLambdaPermissionApiGateway = aws_lambda.CfnPermission(self, 'ServiceReadLambdaPermissionApiGateway',
          function_name = serviceReadLambdaFunction.attr_arn,
          action = 'lambda:InvokeFunction',
          principal = 'apigateway.amazonaws.com',
          source_arn = ''.join([
            'arn:',
            self.partition,
            ':execute-api:',
            self.region,
            ':',
            self.account,
            ':',
            apiGatewayRestApi.ref,
            '/*/*',
          ]),
        )

    serviceReadLambdaVersionZzidO5uOkYbPtcjSDa91v2yIxmAm9jAeaHtgK7te = aws_lambda.CfnVersion(self, 'ServiceReadLambdaVersionZzidO5UOkYbPtcjSDa91v2yIxmAM9jAeaHtgK7TE',
          function_name = serviceReadLambdaFunction.ref,
          code_sha256 = 'gGizJWQjAzbjgwHIX7smVoP9AYOkQxfwC1MXOoE1L/Y=',
          description = 'Returns AWS services supported by Auto Cleanup',
        )
    serviceReadLambdaVersionZzidO5uOkYbPtcjSDa91v2yIxmAm9jAeaHtgK7te.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

    apiGatewayMethodAllowlistEntryPost = apigateway.CfnMethod(self, 'ApiGatewayMethodAllowlistEntryPost',
          http_method = 'POST',
          request_parameters = {
          },
          resource_id = apiGatewayResourceAllowlistEntry.ref,
          rest_api_id = apiGatewayRestApi.ref,
          api_key_required = True,
          authorization_type = 'NONE',
          integration = {
            'integrationHttpMethod': 'POST',
            'type': 'AWS_PROXY',
            'uri': ''.join([
              'arn:',
              self.partition,
              ':apigateway:',
              self.region,
              ':lambda:path/2015-03-31/functions/',
              allowlistCreateLambdaFunction.attr_arn,
              '/invocations',
            ]),
          },
          method_responses = [
          ],
        )
    apiGatewayMethodAllowlistEntryPost.add_dependency(allowlistCreateLambdaPermissionApiGateway)

    apiGatewayMethodAllowlistEntryPut = apigateway.CfnMethod(self, 'ApiGatewayMethodAllowlistEntryPut',
          http_method = 'PUT',
          request_parameters = {
          },
          resource_id = apiGatewayResourceAllowlistEntry.ref,
          rest_api_id = apiGatewayRestApi.ref,
          api_key_required = True,
          authorization_type = 'NONE',
          integration = {
            'integrationHttpMethod': 'POST',
            'type': 'AWS_PROXY',
            'uri': ''.join([
              'arn:',
              self.partition,
              ':apigateway:',
              self.region,
              ':lambda:path/2015-03-31/functions/',
              allowlistUpdateLambdaFunction.attr_arn,
              '/invocations',
            ]),
          },
          method_responses = [
          ],
        )
    apiGatewayMethodAllowlistEntryPut.add_dependency(allowlistUpdateLambdaPermissionApiGateway)

    apiGatewayMethodSettingsServiceGet = apigateway.CfnMethod(self, 'ApiGatewayMethodSettingsServiceGet',
          http_method = 'GET',
          request_parameters = {
          },
          resource_id = apiGatewayResourceSettingsService.ref,
          rest_api_id = apiGatewayRestApi.ref,
          api_key_required = True,
          authorization_type = 'NONE',
          integration = {
            'integrationHttpMethod': 'POST',
            'type': 'AWS_PROXY',
            'uri': ''.join([
              'arn:',
              self.partition,
              ':apigateway:',
              self.region,
              ':lambda:path/2015-03-31/functions/',
              serviceReadLambdaFunction.attr_arn,
              '/invocations',
            ]),
          },
          method_responses = [
          ],
        )
    apiGatewayMethodSettingsServiceGet.add_dependency(serviceReadLambdaPermissionApiGateway)

    apiGatewayDeployment1724203629186 = apigateway.CfnDeployment(self, 'ApiGatewayDeployment1724203629186',
          rest_api_id = apiGatewayRestApi.ref,
          stage_name = 'prod',
        )
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodAllowlistEntryOptions)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodAllowlistOptions)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodSettingsServiceOptions)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodExecutionOptions)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodExecutionKeyVarOptions)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodAllowlistEntryPost)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodAllowlistGet)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodAllowlistEntryPut)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodAllowlistEntryDelete)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodSettingsServiceGet)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodExecutionGet)
    apiGatewayDeployment1724203629186.add_dependency(apiGatewayMethodExecutionKeyVarGet)

    apiGatewayApiKey1 = apigateway.CfnApiKey(self, 'ApiGatewayApiKey1',
          enabled = True,
          name = 'auto-cleanup-api-prod-api-key',
          stage_keys = [
            {
              'restApiId': apiGatewayRestApi.ref,
              'stageName': 'prod',
            },
          ],
        )
    apiGatewayApiKey1.add_dependency(apiGatewayDeployment1724203629186)

    apiGatewayUsagePlan = apigateway.CfnUsagePlan(self, 'ApiGatewayUsagePlan',
          api_stages = [
            {
              'apiId': apiGatewayRestApi.ref,
              'stage': 'prod',
            },
          ],
          description = 'Usage plan for auto-cleanup-api prod stage',
          usage_plan_name = 'auto-cleanup-api-prod',
        )
    apiGatewayUsagePlan.add_dependency(apiGatewayDeployment1724203629186)

    apiGatewayUsagePlanKey1 = apigateway.CfnUsagePlanKey(self, 'ApiGatewayUsagePlanKey1',
          key_id = apiGatewayApiKey1.ref,
          key_type = 'API_KEY',
          usage_plan_id = apiGatewayUsagePlan.ref,
        )

    # Outputs
    self.serverless_deployment_bucket_name = serverlessDeploymentBucket.ref
    cdk.CfnOutput(self, 'CfnOutputServerlessDeploymentBucketName', 
      key = 'ServerlessDeploymentBucketName',
      export_name = 'sls-auto-cleanup-api-prod-ServerlessDeploymentBucketName',
      value = str(self.serverless_deployment_bucket_name),
    )

    """
      Current Lambda layer version
    """
    self.python_requirements_lambda_layer_qualified_arn = pythonRequirementsLambdaLayer.ref
    cdk.CfnOutput(self, 'CfnOutputPythonRequirementsLambdaLayerQualifiedArn', 
      key = 'PythonRequirementsLambdaLayerQualifiedArn',
      description = 'Current Lambda layer version',
      export_name = 'sls-auto-cleanup-api-prod-PythonRequirementsLambdaLayerQualifiedArn',
      value = str(self.python_requirements_lambda_layer_qualified_arn),
    )

    """
      Current Lambda layer hash
    """
    self.python_requirements_lambda_layer_hash = '1f60a842c3c342533d8aabf642b6efe1ed323243'
    cdk.CfnOutput(self, 'CfnOutputPythonRequirementsLambdaLayerHash', 
      key = 'PythonRequirementsLambdaLayerHash',
      description = 'Current Lambda layer hash',
      export_name = 'sls-auto-cleanup-api-prod-PythonRequirementsLambdaLayerHash',
      value = str(self.python_requirements_lambda_layer_hash),
    )

    """
      Current Lambda layer S3Key
    """
    self.python_requirements_lambda_layer_s3_key = 'serverless/auto-cleanup-api/prod/1724203520580-2024-08-21T01:25:20.580Z/pythonRequirements.zip'
    cdk.CfnOutput(self, 'CfnOutputPythonRequirementsLambdaLayerS3Key', 
      key = 'PythonRequirementsLambdaLayerS3Key',
      description = 'Current Lambda layer S3Key',
      export_name = 'sls-auto-cleanup-api-prod-PythonRequirementsLambdaLayerS3Key',
      value = str(self.python_requirements_lambda_layer_s3_key),
    )

    """
      Current Lambda function version
    """
    self.allowlist_read_lambda_function_qualified_arn = allowlistReadLambdaVersioniIkLkvxiCxm5ce7WoxsbbKbSmCmuioCjphJ1hyWw.ref
    cdk.CfnOutput(self, 'CfnOutputAllowlistReadLambdaFunctionQualifiedArn', 
      key = 'AllowlistReadLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-api-prod-AllowlistReadLambdaFunctionQualifiedArn',
      value = str(self.allowlist_read_lambda_function_qualified_arn),
    )

    """
      Current Lambda function version
    """
    self.allowlist_delete_lambda_function_qualified_arn = allowlistDeleteLambdaVersionqxFZimqVhCwPcXxKqBcpQw82PnWrtpIOwGJqnB8Kos.ref
    cdk.CfnOutput(self, 'CfnOutputAllowlistDeleteLambdaFunctionQualifiedArn', 
      key = 'AllowlistDeleteLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-api-prod-AllowlistDeleteLambdaFunctionQualifiedArn',
      value = str(self.allowlist_delete_lambda_function_qualified_arn),
    )

    """
      Current Lambda function version
    """
    self.execution_log_list_lambda_function_qualified_arn = executionLogListLambdaVersionDm1f0OyFvzDstsKtrrEmauzAukEvWdiXDv19YtU.ref
    cdk.CfnOutput(self, 'CfnOutputExecutionLogListLambdaFunctionQualifiedArn', 
      key = 'ExecutionLogListLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-api-prod-ExecutionLogListLambdaFunctionQualifiedArn',
      value = str(self.execution_log_list_lambda_function_qualified_arn),
    )

    """
      Current Lambda function version
    """
    self.execution_log_read_lambda_function_qualified_arn = executionLogReadLambdaVersion7HsnSlUb64Db58zb1Yzny7ZmrJaMqg29ySzgq.ref
    cdk.CfnOutput(self, 'CfnOutputExecutionLogReadLambdaFunctionQualifiedArn', 
      key = 'ExecutionLogReadLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-api-prod-ExecutionLogReadLambdaFunctionQualifiedArn',
      value = str(self.execution_log_read_lambda_function_qualified_arn),
    )

    """
      Current Lambda function version
    """
    self.allowlist_create_lambda_function_qualified_arn = allowlistCreateLambdaVersionOiGvRisA6vlZcwsDkJbuHvboBpdfu6Syw2jKPfM5dH8.ref
    cdk.CfnOutput(self, 'CfnOutputAllowlistCreateLambdaFunctionQualifiedArn', 
      key = 'AllowlistCreateLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-api-prod-AllowlistCreateLambdaFunctionQualifiedArn',
      value = str(self.allowlist_create_lambda_function_qualified_arn),
    )

    """
      Current Lambda function version
    """
    self.allowlist_update_lambda_function_qualified_arn = allowlistUpdateLambdaVersionjVNghuqLm4pfDdyyJbTa7pXyxiHhrl8bYrMfMb3ekXs.ref
    cdk.CfnOutput(self, 'CfnOutputAllowlistUpdateLambdaFunctionQualifiedArn', 
      key = 'AllowlistUpdateLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-api-prod-AllowlistUpdateLambdaFunctionQualifiedArn',
      value = str(self.allowlist_update_lambda_function_qualified_arn),
    )

    """
      Current Lambda function version
    """
    self.service_read_lambda_function_qualified_arn = serviceReadLambdaVersionZzidO5uOkYbPtcjSDa91v2yIxmAm9jAeaHtgK7te.ref
    cdk.CfnOutput(self, 'CfnOutputServiceReadLambdaFunctionQualifiedArn', 
      key = 'ServiceReadLambdaFunctionQualifiedArn',
      description = 'Current Lambda function version',
      export_name = 'sls-auto-cleanup-api-prod-ServiceReadLambdaFunctionQualifiedArn',
      value = str(self.service_read_lambda_function_qualified_arn),
    )

    """
      URL of the service endpoint
    """
    self.service_endpoint = ''.join([
      'https://',
      apiGatewayRestApi.ref,
      '.execute-api.',
      self.region,
      '.',
      self.url_suffix,
      '/prod',
    ])
    cdk.CfnOutput(self, 'CfnOutputServiceEndpoint', 
      key = 'ServiceEndpoint',
      description = 'URL of the service endpoint',
      export_name = 'sls-auto-cleanup-api-prod-ServiceEndpoint',
      value = str(self.service_endpoint),
    )

    """
      REST API ID
    """
    self.rest_api_id_for_apig_caching = apiGatewayRestApi.ref
    cdk.CfnOutput(self, 'CfnOutputRestApiIdForApigCaching', 
      key = 'RestApiIdForApigCaching',
      description = 'REST API ID',
      export_name = 'sls-auto-cleanup-api-prod-RestApiIdForApigCaching',
      value = str(self.rest_api_id_for_apig_caching),
    )

    self.account_id = self.account
    cdk.CfnOutput(self, 'CfnOutputAccountID', 
      key = 'AccountID',
      value = str(self.account_id),
    )



