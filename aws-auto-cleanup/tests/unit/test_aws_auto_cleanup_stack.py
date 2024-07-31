import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_auto_cleanup.aws_auto_cleanup_stack import AwsAutoCleanupStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_auto_cleanup/aws_auto_cleanup_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsAutoCleanupStack(app, "aws-auto-cleanup")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
