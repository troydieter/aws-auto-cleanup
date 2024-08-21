import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_auto_cleanup_web.aws_auto_cleanup_web_stack import AwsAutoCleanupWebStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_auto_cleanup_web/aws_auto_cleanup_web_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsAutoCleanupWebStack(app, "aws-auto-cleanup-web")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
