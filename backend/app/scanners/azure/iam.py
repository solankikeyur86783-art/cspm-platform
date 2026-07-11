import time
from typing import Any, Dict

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AzureIAMScanner(BaseScanner):
    provider = "azure"
    service = "iam"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.subscription_id = account_config.get("azure_subscription_id", "")

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting Azure IAM scan for subscription {self.subscription_id}")

        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.resource import SubscriptionClient

            self.creds = DefaultAzureCredential()
            self.auth_client = AuthorizationManagementClient(self.creds, self.subscription_id)

            await self._check_subscription_owners()
            await self._check_custom_roles()
            await self._check_guest_accounts()
            await self._check_mfa_via_policy()

        except ImportError:
            self.add_error("azure-mgmt-authorization not installed")
        except Exception as exc:
            self.add_error(f"Azure IAM scan failed: {exc}")

        return self.build_result(duration=time.time() - start)

    async def _check_subscription_owners(self) -> None:
        """CIS Azure 1.15 — Ensure no more than 3 subscription owners."""
        try:
            role_assignments = list(self.auth_client.role_assignments.list_for_subscription())
            owner_role_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner built-in role GUID

            owners = [
                ra for ra in role_assignments
                if ra.role_definition_id and owner_role_id in ra.role_definition_id
                and ra.principal_type != "ServicePrincipal"
            ]
            self.resources_scanned += len(owners)

            if len(owners) > 3:
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-1.15",
                    rule_name=f"Subscription has {len(owners)} owners (max recommended: 3)",
                    severity="high",
                    resource_id=f"/subscriptions/{self.subscription_id}",
                    resource_type="azure:subscription",
                    cloud_provider="azure",
                    evidence={"owner_count": len(owners), "owners": [o.principal_id for o in owners[:5]]},
                    cvss_score=7.5,
                    cis_benchmark_refs=["CIS Azure 1.15"],
                    mitre_attack_techniques=["T1078.004"],
                    remediation_steps=f"Reduce subscription owners to 3 or fewer. Current count: {len(owners)}.",
                ))

            if len(owners) < 2:
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-1.14",
                    rule_name="Subscription has fewer than 2 owners (single point of failure)",
                    severity="high",
                    resource_id=f"/subscriptions/{self.subscription_id}",
                    resource_type="azure:subscription",
                    cloud_provider="azure",
                    evidence={"owner_count": len(owners)},
                    cvss_score=6.5,
                    cis_benchmark_refs=["CIS Azure 1.14"],
                    remediation_steps="Add at least one more subscription owner for redundancy.",
                ))

        except Exception as exc:
            self.add_error(f"Subscription owners check: {exc}")

    async def _check_custom_roles(self) -> None:
        """CIS Azure 1.23 — Custom roles should not have excessive permissions."""
        try:
            role_defs = list(self.auth_client.role_definitions.list(
                scope=f"/subscriptions/{self.subscription_id}",
                filter="type eq 'CustomRole'",
            ))

            for role in role_defs:
                self.resources_scanned += 1
                if not role.permissions:
                    continue
                for perm in role.permissions:
                    actions = perm.actions or []
                    # Check for wildcard actions
                    if "*" in actions:
                        self.add_finding(ScanFinding(
                            rule_id="CIS-AZ-1.23",
                            rule_name=f"Custom role '{role.role_name}' has wildcard (*) permissions",
                            severity="high",
                            resource_id=role.id or "",
                            resource_name=role.role_name or "",
                            resource_type="azure:role_definition",
                            cloud_provider="azure",
                            evidence={"role_name": role.role_name, "actions": actions[:5]},
                            cvss_score=8.0,
                            cis_benchmark_refs=["CIS Azure 1.23"],
                            mitre_attack_techniques=["T1078.004"],
                            remediation_steps=f"Replace wildcard '*' actions in custom role '{role.role_name}' with specific permissions.",
                        ))
                        break

        except Exception as exc:
            self.add_error(f"Custom roles check: {exc}")

    async def _check_guest_accounts(self) -> None:
        """CIS Azure 1.3 — Guest accounts should be reviewed."""
        try:
            # Graph API needed for full guest listing; use role assignments as proxy
            role_assignments = list(self.auth_client.role_assignments.list_for_subscription())
            guest_assignments = [
                ra for ra in role_assignments
                if ra.principal_type == "User" and "#EXT#" in (ra.principal_id or "")
            ]

            for ga in guest_assignments:
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-1.3",
                    rule_name="Guest user has Azure role assignment at subscription level",
                    severity="medium",
                    resource_id=f"/subscriptions/{self.subscription_id}/roleAssignments/{ga.name}",
                    resource_name=ga.principal_id or "",
                    resource_type="azure:role_assignment",
                    cloud_provider="azure",
                    evidence={"principal_id": ga.principal_id, "scope": ga.scope},
                    cvss_score=5.5,
                    cis_benchmark_refs=["CIS Azure 1.3"],
                    mitre_attack_techniques=["T1078"],
                    remediation_steps="Review and remove unnecessary guest user role assignments.",
                ))

        except Exception as exc:
            self.add_error(f"Guest accounts check: {exc}")

    async def _check_mfa_via_policy(self) -> None:
        """CIS Azure 1.1 — MFA should be enabled for high-privilege accounts (informational check)."""
        # Full MFA check requires MS Graph API / AAD Premium
        # Flag as informational for manual verification
        self.add_finding(ScanFinding(
            rule_id="CIS-AZ-1.1-INFO",
            rule_name="MFA status for privileged accounts requires manual verification via Azure AD",
            severity="info",
            resource_id=f"/subscriptions/{self.subscription_id}",
            resource_type="azure:subscription",
            cloud_provider="azure",
            cvss_score=1.0,
            cis_benchmark_refs=["CIS Azure 1.1"],
            remediation_steps=(
                "Verify MFA is enabled for all privileged accounts in Azure AD > Users > "
                "Per-user MFA. Consider enforcing via Conditional Access policies."
            ),
        ))
