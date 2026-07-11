from typing import Dict, Any
from app.ai.groq_client import GroqClient


SYSTEM_PROMPT = """You are a senior DevSecOps engineer specializing in cloud security hardening.
You write precise, runnable remediation code for cloud security misconfigurations.
Always include both CLI (AWS CLI/gcloud/az) and infrastructure-as-code (Terraform) options.
Respond only in valid JSON."""


class RemediationAdvisor:
    def __init__(self, client: GroqClient):
        self.client = client

    async def generate_terraform(self, finding_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate Terraform and CLI remediation code for a finding.
        """
        user_prompt = f"""Generate remediation code for this cloud security finding:

Rule: {finding_data.get('rule_id')} — {finding_data.get('rule_name')}
Provider: {finding_data.get('cloud_provider', '').upper()}
Resource Type: {finding_data.get('resource_type')}
Resource ID: {finding_data.get('resource_id')}
Severity: {finding_data.get('severity', '').upper()}
Evidence: {finding_data.get('evidence', {})}

Respond with JSON:
{{
  "cli_command": "The exact CLI command(s) to remediate (AWS CLI / gcloud / az)",
  "terraform_code": "Terraform HCL block to enforce the correct configuration",
  "explanation": "One sentence explaining what the code does",
  "caveats": "Any warnings, prerequisites, or side effects the engineer should know"
}}"""

        return await self.client.complete_json(SYSTEM_PROMPT, user_prompt, max_tokens=800)

    async def generate_policy_fix(self, policy_type: str, current_policy: str) -> Dict[str, str]:
        """Generate a corrected IAM/bucket policy."""
        user_prompt = f"""Fix this {policy_type} policy to follow least-privilege principles:

Current policy:
{current_policy[:2000]}

Return JSON:
{{
  "fixed_policy": "The corrected policy JSON",
  "changes_made": "Bullet list of what was changed and why",
  "risk_reduction": "How this fix reduces the attack surface"
}}"""

        return await self.client.complete_json(SYSTEM_PROMPT, user_prompt, max_tokens=1000)
