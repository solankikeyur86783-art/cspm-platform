from typing import List, Dict, Any
from jinja2 import Template


EXECUTIVE_SUMMARY_TEMPLATE = """
You are a CISO presenting to the board. Write a 3-paragraph executive summary for this cloud security scan.

## Scan Details
- Account: {{ account_name }} ({{ provider.upper() }})
- Date: {{ scan_date }}
- Risk Score: {{ risk_score }}/100
- Resources Scanned: {{ resources_scanned }}

## Findings Summary
- Critical: {{ critical }}
- High: {{ high }}
- Medium: {{ medium }}
- Low: {{ low }}

## Top Issues
{% for rule in top_rules[:5] %}
- {{ rule.rule_name }} ({{ rule.severity }}, {{ rule.count }} occurrences)
{% endfor %}

Write: (1) Overall posture paragraph, (2) Key risks paragraph, (3) Immediate actions paragraph.
Be concise, business-focused, and avoid technical jargon.
"""

FINDING_BATCH_TEMPLATE = """
Analyze these {{ count }} cloud security findings and provide:
1. A one-line plain-English explanation for each
2. The most critical risk to address first
3. Common root cause across findings

Findings:
{% for f in findings %}
[{{ loop.index }}] {{ f.rule_id }} | {{ f.severity.upper() }} | {{ f.resource_type }} | {{ f.rule_name }}
{% endfor %}

Respond in JSON:
{
  "explanations": {"rule_id": "one-line explanation"},
  "top_priority": "rule_id of most critical",
  "common_root_cause": "pattern you see across findings",
  "quick_wins": ["rule_id of easy fixes"]
}
"""


class PromptBuilder:
    @staticmethod
    def executive_summary(scan_stats: Dict[str, Any]) -> str:
        template = Template(EXECUTIVE_SUMMARY_TEMPLATE)
        return template.render(**scan_stats)

    @staticmethod
    def finding_batch(findings: List[Dict[str, Any]]) -> str:
        template = Template(FINDING_BATCH_TEMPLATE)
        return template.render(findings=findings, count=len(findings))

    @staticmethod
    def single_finding(finding: Dict[str, Any]) -> str:
        return (
            f"Cloud security finding:\n"
            f"Rule: {finding.get('rule_id')} — {finding.get('rule_name')}\n"
            f"Severity: {finding.get('severity', '').upper()} | CVSS: {finding.get('cvss_score')}\n"
            f"Resource: {finding.get('resource_type')} / {finding.get('resource_id')}\n"
            f"Provider: {finding.get('cloud_provider', '').upper()} | Region: {finding.get('region', 'global')}\n"
            f"Evidence: {finding.get('evidence', {})}\n"
            f"CIS Refs: {', '.join(finding.get('cis_benchmark_refs', []))}\n"
            f"MITRE ATT&CK: {', '.join(finding.get('mitre_attack_techniques', []))}"
        )
