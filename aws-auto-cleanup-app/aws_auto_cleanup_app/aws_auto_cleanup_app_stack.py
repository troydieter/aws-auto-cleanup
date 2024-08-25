import os
import subprocess
from aws_cdk import (
    aws_lambda as _lambda,
    App,
    RemovalPolicy,
    Stack,
    Duration,
)
from constructs import Construct


class AwsAutoCleanupAppStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        ac_function = _lambda.Function(self, "ac_function",
                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                       handler="./aws_auto_cleanup_app/src/main.lambda_handler",
                                       code=_lambda.Code.from_asset("./aws_auto_cleanup_app/src/"),
                                       memory_size=512,
                                       timeout=Duration.seconds(900),
                                       retry_attempts=0,
                                       description="Removes unused AWS resources based on time of creation",
                                       layers=[self.create_dependencies_layer(self.stack_name, "ac_cleanup")])

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
