from aws_cdk import Stack
import aws_cdk as cdk
import aws_cdk.aws_cloudfront as cloudfront
import aws_cdk.aws_s3 as s3
from constructs import Construct

"""
  The AWS CloudFormation template for this Serverless application
"""
class AwsAutoCleanupWebStack(Stack):
  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # Resources
    originAccessIdentity = cloudfront.CfnCloudFrontOriginAccessIdentity(self, 'OriginAccessIdentity',
          cloud_front_origin_access_identity_config = {
            'comment': 'OAI for auto-cleanup-web',
          },
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

    webBucket = s3.CfnBucket(self, 'WebBucket',
          bucket_name = 'auto-cleanup-web-prod-site-550767824695',
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

    addSecurityHeadersFunction = cloudfront.CfnFunction(self, 'addSecurityHeadersFunction',
          name = 'add-security-headers',
          auto_publish = True,
          function_config = {
            'comment': 'Adds security headers to the response',
            'runtime': 'cloudfront-js-1.0',
          },
          function_code = 'function handler(event) {\n    var response = event.response;\n    var headers = response.headers;\n    // Set HTTP security headers\n    // Since JavaScript doesn\'t allow for hyphens in variable names, we use the dict[\"key\"] notation\n    headers[\'strict-transport-security\'] = { value: \'max-age=63072000; includeSubdomains; preload\'};\n    headers[\'x-content-type-options\'] = { value: \'nosniff\'};\n    headers[\'x-frame-options\'] = {value: \'DENY\'};\n    headers[\'x-xss-protection\'] = {value: \'1; mode=block\'};\n    // Return the response to viewers\n    return response;\n}\n',
        )

    cloudFrontDistribution = cloudfront.CfnDistribution(self, 'CloudFrontDistribution',
          distribution_config = {
            'enabled': True,
            'comment': 'auto-cleanup-web',
            'priceClass': 'PriceClass_100',
            'origins': [
              {
                'domainName': webBucket.attr_domain_name,
                'id': 'WebBucketOrigin',
                's3OriginConfig': {
                  'originAccessIdentity': f"""origin-access-identity/cloudfront/{originAccessIdentity.ref}""",
                },
              },
            ],
            'defaultCacheBehavior': {
              'allowedMethods': [
                'GET',
                'HEAD',
              ],
              'targetOriginId': 'WebBucketOrigin',
              'forwardedValues': {
                'queryString': False,
                'cookies': {
                  'forward': 'none',
                },
              },
              'viewerProtocolPolicy': 'redirect-to-https',
              'functionAssociations': [
                {
                  'eventType': 'viewer-response',
                  'functionArn': addSecurityHeadersFunction.attr_function_metadata_function_arn,
                },
              ],
            },
            'defaultRootObject': 'index.html',
            'aliases': [
              'cleanup.troydieter.com',
            ],
            'viewerCertificate': {
              'acmCertificateArn': 'arn:aws:acm:us-east-1:550767824695:certificate/2a3ce036-6f1c-40ea-a117-e2d2772e98ab',
              'sslSupportMethod': 'sni-only',
              'minimumProtocolVersion': 'TLSv1.2_2021',
            },
          },
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

    webBucketPolicy = s3.CfnBucketPolicy(self, 'WebBucketPolicy',
          bucket = webBucket.ref,
          policy_document = {
            'Statement': [
              {
                'Effect': 'Allow',
                'Principal': {
                  'AWS': f"""arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity {originAccessIdentity.ref}""",
                },
                'Action': 's3:GetObject',
                'Resource': f"""{webBucket.attr_arn}/*""",
              },
            ],
          },
        )

    # Outputs
    self.serverless_deployment_bucket_name = serverlessDeploymentBucket.ref
    cdk.CfnOutput(self, 'CfnOutputServerlessDeploymentBucketName', 
      key = 'ServerlessDeploymentBucketName',
      export_name = 'sls-auto-cleanup-web-prod-ServerlessDeploymentBucketName',
      value = str(self.serverless_deployment_bucket_name),
    )



