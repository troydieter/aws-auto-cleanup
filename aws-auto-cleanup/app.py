import os

from aws_cdk import App, Environment
from aws_auto_cleanup.aws_auto_cleanup_stack import AwsAutoCleanupStack

app = App()

context = {
    "project": app.node.try_get_context("project")
}

AwsAutoCleanupStack(app, "AwsAutoCleanupStack",
                    env=Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'),
                                    region=os.getenv('CDK_DEFAULT_REGION')), stage="dev",
                    context=context
                    )

app.synth()
