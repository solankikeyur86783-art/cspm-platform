"""
AWS Lambda scanner — detects overly permissive Lambda execution roles.
Add to: backend/app/scanners/aws/lambda_scanner.py
Register in: backend/app/scanners/aws/__init__.py
"""

import time
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSLambdaScanner(BaseScanner):
    provider = "aws"
    service  = "lambda"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.regions: List[str] = account_config.get("aws_regions") or ["ap-south-1"]

    async def scan(self) -> ScannerResult:
        start = time.time()
        for region in self.regions:
            self.lam = boto3.client("lambda", region_name=region)
            self.iam = boto3.client("iam",    region_name=region)
            await self._check_functions(region)
        return self.build_result(duration=time.time() - start)

    async def _check_functions(self, region: str) -> None:
        try:
            paginator = self.lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    self.resources_scanned += 1
                    fn_name = fn["FunctionName"]
                    fn_arn  = fn["FunctionArn"]
                    role_arn = fn.get("Role", "")

                    await self._check_role_permissions(fn_name, fn_arn, role_arn, region)
                    await self._check_env_vars(fn_name, fn_arn, fn, region)
                    await self._check_public_url(fn_name, fn_arn, region)

        except ClientError as exc:
            self.add_error(f"Lambda [{region}]: {exc}")

    async def _check_role_permissions(self, fn_name, fn_arn, role_arn, region):
        """Check if Lambda execution role has admin or wildcard permissions."""
        try:
            role_name = role_arn.split("/")[-1]
            policies = self.iam.list_attached_role_policies(RoleName=role_name)

            dangerous = []
            for policy in policies["AttachedPolicies"]:
                policy_name = policy["PolicyName"]
                if "AdministratorAccess" in policy_name:
                    dangerous.append(policy_name)
                elif policy_name in ("PowerUserAccess", "IAMFullAccess"):
                    dangerous.append(policy_name)

            if dangerous:
                self.add_finding(ScanFinding(
                    rule_id="LAMBDA-ROLE-001",
                    rule_name=f"Lambda function has overly permissive execution role",
                    rule_description=(
                        "Lambda execution roles should follow least privilege. "
                        "Admin access means a compromised function can do anything in your account."
                    ),
                    severity="critical",
                    resource_id=fn_arn,
                    resource_name=fn_name,
                    resource_type="lambda:function",
                    cloud_provider="aws",
                    region=region,
                    evidence={
                        "role_arn": role_arn,
                        "dangerous_policies": dangerous,
                        "function_name": fn_name,
                    },
                    cvss_score=9.0,
                    mitre_attack_techniques=["T1078.004", "T1098"],
                    remediation_steps=(
                        f"Create a minimal IAM role for {fn_name} with only the permissions it needs. "
                        "Remove AdministratorAccess."
                    ),
                    remediation_code=(
                        f"# Create minimal policy\n"
                        f"aws iam create-policy --policy-name {fn_name}-minimal-policy \\\n"
                        f"  --policy-document file://minimal-policy.json\n\n"
                        f"# Attach minimal, detach admin\n"
                        f"aws iam detach-role-policy --role-name {role_arn.split('/')[-1]} \\\n"
                        f"  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                    ),
                ))

            # Check inline policies for wildcards
            inline = self.iam.list_role_policies(RoleName=role_name)
            for policy_name in inline["PolicyNames"]:
                policy_doc = self.iam.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                statements = policy_doc["PolicyDocument"].get("Statement", [])
                for stmt in statements:
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "*" in actions and stmt.get("Effect") == "Allow":
                        self.add_finding(ScanFinding(
                            rule_id="LAMBDA-ROLE-002",
                            rule_name="Lambda execution role has wildcard (*) action in inline policy",
                            severity="high",
                            resource_id=fn_arn,
                            resource_name=fn_name,
                            resource_type="lambda:function",
                            cloud_provider="aws",
                            region=region,
                            evidence={"policy_name": policy_name, "wildcard_statement": stmt},
                            cvss_score=8.0,
                            mitre_attack_techniques=["T1078.004"],
                            remediation_steps="Replace wildcard actions with specific required permissions.",
                        ))

        except ClientError as exc:
            self.add_error(f"Lambda role check {fn_name}: {exc}")

    async def _check_env_vars(self, fn_name, fn_arn, fn_config, region):
        """Check for secrets in Lambda environment variables."""
        env_vars = fn_config.get("Environment", {}).get("Variables", {})
        secret_keywords = ["password", "secret", "key", "token", "credential", "passwd"]

        for var_name, var_value in env_vars.items():
            if any(kw in var_name.lower() for kw in secret_keywords):
                self.add_finding(ScanFinding(
                    rule_id="LAMBDA-ENV-001",
                    rule_name=f"Lambda function stores sensitive data in environment variable: {var_name}",
                    severity="high",
                    resource_id=fn_arn,
                    resource_name=fn_name,
                    resource_type="lambda:function",
                    cloud_provider="aws",
                    region=region,
                    evidence={"suspicious_var": var_name, "note": "Value not logged for security"},
                    cvss_score=7.5,
                    mitre_attack_techniques=["T1552.001"],
                    remediation_steps=(
                        f"Move {var_name} from environment variables to AWS Secrets Manager. "
                        "Lambda functions can fetch secrets at runtime using the Secrets Manager SDK."
                    ),
                    remediation_code=(
                        f"# Store in Secrets Manager instead\n"
                        f"aws secretsmanager create-secret --name {fn_name}/{var_name} \\\n"
                        f"  --secret-string 'YOUR_VALUE'\n\n"
                        f"# In Lambda code, use:\n"
                        f"import boto3\n"
                        f"sm = boto3.client('secretsmanager')\n"
                        f"secret = sm.get_secret_value(SecretId='{fn_name}/{var_name}')"
                    ),
                ))

    async def _check_public_url(self, fn_name, fn_arn, region):
        """Check for public Lambda function URLs without auth."""
        try:
            url_config = self.lam.get_function_url_config(FunctionName=fn_name)
            auth_type = url_config.get("AuthType", "")
            if auth_type == "NONE":
                self.add_finding(ScanFinding(
                    rule_id="LAMBDA-URL-001",
                    rule_name="Lambda function URL has no authentication (AuthType: NONE)",
                    severity="high",
                    resource_id=fn_arn,
                    resource_name=fn_name,
                    resource_type="lambda:function",
                    cloud_provider="aws",
                    region=region,
                    evidence={
                        "function_url": url_config.get("FunctionUrl"),
                        "auth_type": auth_type,
                    },
                    cvss_score=8.0,
                    mitre_attack_techniques=["T1190"],
                    remediation_steps=f"Set AuthType to AWS_IAM for function URL on {fn_name}.",
                    remediation_code=(
                        f"aws lambda update-function-url-config \\\n"
                        f"  --function-name {fn_name} \\\n"
                        f"  --auth-type AWS_IAM \\\n"
                        f"  --region {region}"
                    ),
                ))
        except ClientError as exc:
            if "ResourceNotFoundException" not in str(exc):
                self.add_error(f"Lambda URL check {fn_name}: {exc}")
