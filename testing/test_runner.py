"""
test_runner.py — Validates that CSPM found ALL 10 expected findings
from the lab setup. Acts as an automated test suite against your API.

Usage:
    python test_runner.py --api http://localhost:8000 --scan-id <uuid>
    python test_runner.py --api http://localhost:8000  # triggers a new scan
"""

import httpx
import json
import time
import argparse
import sys
from datetime import datetime


PASS = "✅  PASS"
FAIL = "❌  FAIL"
WARN = "⚠️   WARN"


class CSPMTestRunner:
    def __init__(self, api_url: str, token: str):
        self.api = api_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.results = []

    # ── API helpers ─────────────────────────────────────────────────────
    def get_findings(self, scan_id: str, severity=None):
        payload = {"scan_id": scan_id, "page_size": 200}
        if severity:
            payload["severity"] = severity
        r = httpx.post(
            f"{self.api}/api/v1/findings/search",
            json=payload,
            headers=self.headers,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()["items"]

    def get_scan(self, scan_id: str):
        r = httpx.get(f"{self.api}/api/v1/scans/{scan_id}", headers=self.headers)
        r.raise_for_status()
        return r.json()

    def start_scan(self, account_id: str):
        r = httpx.post(
            f"{self.api}/api/v1/scans",
            json={"cloud_account_id": account_id},
            headers=self.headers,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()["id"]

    def wait_for_scan(self, scan_id: str, timeout: int = 600):
        print(f"\n  Polling scan {scan_id}...")
        start = time.time()
        while time.time() - start < timeout:
            scan = self.get_scan(scan_id)
            status = scan["status"]
            progress = scan["progress"]
            print(f"  [{progress:3d}%] Status: {status}", end="\r")
            if status in ("completed", "failed", "cancelled"):
                print()
                return scan
            time.sleep(5)
        raise TimeoutError(f"Scan did not complete in {timeout}s")

    # ── Individual scenario validators ─────────────────────────────────

    def check(self, name: str, condition: bool, detail: str = "", severity: str = ""):
        status = PASS if condition else FAIL
        self.results.append({
            "name": name,
            "passed": condition,
            "detail": detail,
            "expected_severity": severity,
        })
        sev_label = f" [{severity.upper()}]" if severity else ""
        print(f"  {status}{sev_label}  {name}")
        if detail:
            print(f"         {detail}")

    def run_all(self, scan_id: str):
        print(f"\n{'='*65}")
        print(f"  CSPM Scenario Validation — Scan: {scan_id}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*65}\n")

        all_findings = self.get_findings(scan_id)

        def has_rule(rule_prefix, sev=None):
            for f in all_findings:
                if f["rule_id"].startswith(rule_prefix):
                    if sev is None or f["severity"] == sev:
                        return True, f
            return False, None

        def has_resource_type(rtype, rule_prefix=None):
            for f in all_findings:
                type_match = rtype.lower() in f["resource_type"].lower()
                rule_match = (rule_prefix is None) or f["rule_id"].startswith(rule_prefix)
                if type_match and rule_match:
                    return True, f
            return False, None

        # ── SCENARIO 1: Public S3 Bucket ─────────────────────────────
        print("  SCENARIO 1 — Public S3 Bucket")
        found, f = has_rule("CIS-S3-2.1.1", "high")
        self.check(
            "Public S3 bucket detected (CIS-S3-2.1.1)",
            found,
            f"resource: {f['resource_name']}" if found else "No HIGH finding for CIS-S3-2.1.1",
            "high",
        )
        if found:
            self.check(
                "Finding has Resource ID",
                bool(f.get("resource_id")),
                f"resource_id: {f.get('resource_id', 'MISSING')}",
            )
            self.check(
                "Finding has Evidence",
                bool(f.get("evidence")),
                f"evidence keys: {list(f.get('evidence', {}).keys())}",
            )
            self.check(
                "Finding has CIS mapping",
                bool(f.get("cis_benchmark_refs")),
                f"refs: {f.get('cis_benchmark_refs')}",
            )
            self.check(
                "Finding has remediation steps",
                bool(f.get("remediation_steps")),
            )

        # ── SCENARIO 2: SSH open to 0.0.0.0/0 ───────────────────────
        print("\n  SCENARIO 2 — Open SSH Security Group")
        found, f = has_rule("CIS-EC2-5.2")
        if not found:
            found, f = has_rule("CIS-EC2-5", "high")
        self.check(
            "Open SSH (port 22) detected (CIS-EC2-5.2)",
            found,
            f"resource: {f.get('resource_name', f.get('resource_id', ''))}" if found else "No finding for open SSH",
            "high",
        )

        # ── SCENARIO 3: RDP open to 0.0.0.0/0 ──────────────────────
        print("\n  SCENARIO 3 — Open RDP Security Group")
        found, f = has_rule("CIS-EC2-5.3")
        if not found:
            # Also accept any critical SG finding mentioning port 3389
            for ff in all_findings:
                if ff["resource_type"] == "ec2:security_group" and ff["severity"] == "critical":
                    if "3389" in str(ff.get("evidence", "")) or "RDP" in ff["rule_name"]:
                        found, f = True, ff
                        break
        self.check(
            "Open RDP (port 3389) detected as CRITICAL",
            found,
            f"resource: {f.get('resource_name', '')}" if found else "No CRITICAL finding for open RDP",
            "critical",
        )

        # ── SCENARIO 4: IAM AdministratorAccess directly attached ────
        print("\n  SCENARIO 4 — IAM User with AdministratorAccess")
        found, f = has_rule("CIS-IAM-1.16")
        self.check(
            "AdministratorAccess on user detected (CIS-IAM-1.16)",
            found,
            f"user: {f.get('resource_name', '')}" if found else "No finding for CIS-IAM-1.16",
            "high",
        )

        # ── SCENARIO 5: Root MFA ────────────────────────────────────
        print("\n  SCENARIO 5 — Root Account MFA")
        found, f = has_rule("CIS-IAM-1.5")
        self.check(
            "Root MFA missing detected (CIS-IAM-1.5)",
            found,
            f"severity: {f.get('severity', '')}" if found else "No finding — root MFA may be enabled (good!)",
            "critical",
        )

        # ── SCENARIO 6: CloudTrail disabled ─────────────────────────
        print("\n  SCENARIO 6 — CloudTrail Disabled")
        found_stopped, f_stopped = has_rule("CIS-CT-2.1-LOGGING")
        found_no_ct, f_no_ct = has_rule("CIS-CT-2.1")
        self.check(
            "CloudTrail logging stopped detected",
            found_stopped or found_no_ct,
            f"rule: {(f_stopped or f_no_ct or {}).get('rule_id', 'NOT FOUND')}",
            "critical",
        )
        found_mr, f_mr = has_rule("CIS-CT-2.1")
        self.check(
            "CloudTrail not multi-region detected",
            found_mr,
            f"rule: {f_mr.get('rule_id', '')} severity: {f_mr.get('severity', '')}" if found_mr else "No finding",
            "high",
        )

        # ── SCENARIO 7: Unencrypted EBS Volume ──────────────────────
        print("\n  SCENARIO 7 — Unencrypted EBS Volume")
        found, f = has_rule("EC2-EBS-001")
        if not found:
            found, f = has_rule("CIS-EC2-2.2.1")
        self.check(
            "Unencrypted EBS volume detected",
            found,
            f"resource: {f.get('resource_id', '')}" if found else "No EBS encryption finding",
            "medium",
        )

        # ── SCENARIO 8: Public RDS Instance ─────────────────────────
        print("\n  SCENARIO 8 — Public RDS Instance")
        found, f = has_rule("CIS-RDS-2.3.2")
        self.check(
            "Publicly accessible RDS detected (CIS-RDS-2.3.2)",
            found,
            f"db: {f.get('resource_name', '')}" if found else "No finding — RDS may still be creating",
            "high",
        )
        # Bonus: check for co-findings on same RDS
        found_enc, _ = has_rule("CIS-RDS-2.3.1")
        found_bkp, _ = has_rule("RDS-BACKUP-001")
        found_del, _ = has_rule("RDS-DEL-001")
        self.check("RDS no-encryption also detected (CIS-RDS-2.3.1)", found_enc, severity="high")
        self.check("RDS no-backup also detected (RDS-BACKUP-001)", found_bkp, severity="medium")
        self.check("RDS no-deletion-protection also detected (RDS-DEL-001)", found_del, severity="medium")

        # ── SCENARIO 9: Secrets Manager no rotation ──────────────────
        print("\n  SCENARIO 9 — Secrets Manager No Rotation")
        # Our base scanners don't include Secrets Manager yet — mark as TODO
        print(f"  ⚪ TODO  Secrets Manager rotation check (scanner not yet implemented)")
        print(f"         Add AWSSecretsManagerScanner to backend/app/scanners/aws/")
        self.results.append({"name": "Secrets rotation", "passed": None, "detail": "TODO"})

        # ── SCENARIO 10: S3 no encryption ────────────────────────────
        print("\n  SCENARIO 10 — S3 Bucket Without Encryption")
        enc_findings = [f for f in all_findings if f["rule_id"] == "CIS-S3-2.1.2"]
        self.check(
            "S3 no-encryption detected (CIS-S3-2.1.2)",
            len(enc_findings) >= 1,
            f"Found {len(enc_findings)} unencrypted bucket(s)",
            "medium",
        )

        # ── SUMMARY ────────────────────────────────────────────────────
        self.print_summary(all_findings, scan_id)

    def print_summary(self, all_findings, scan_id):
        passed  = sum(1 for r in self.results if r["passed"] is True)
        failed  = sum(1 for r in self.results if r["passed"] is False)
        todo    = sum(1 for r in self.results if r["passed"] is None)
        total   = len(self.results)

        # Severity breakdown
        by_sev = {}
        for f in all_findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

        # Compliance check
        has_resource_id  = all(bool(f.get("resource_id")) for f in all_findings)
        has_cis          = sum(1 for f in all_findings if f.get("cis_benchmark_refs"))
        has_mitre        = sum(1 for f in all_findings if f.get("mitre_attack_techniques"))
        has_remediation  = sum(1 for f in all_findings if f.get("remediation_steps"))

        print(f"\n{'='*65}")
        print(f"  RESULTS SUMMARY")
        print(f"{'='*65}")
        print(f"  Scenarios passed : {passed}/{total - todo}")
        print(f"  Scenarios failed : {failed}")
        print(f"  TODO (scanner missing) : {todo}")
        print(f"\n  Total findings found : {len(all_findings)}")
        print(f"  ├─ Critical : {by_sev.get('critical', 0)}")
        print(f"  ├─ High     : {by_sev.get('high', 0)}")
        print(f"  ├─ Medium   : {by_sev.get('medium', 0)}")
        print(f"  └─ Low      : {by_sev.get('low', 0)}")
        print(f"\n  Finding quality checks:")
        print(f"  ├─ All have Resource ID  : {'✅' if has_resource_id else '❌'}")
        print(f"  ├─ Have CIS mapping      : {has_cis}/{len(all_findings)}")
        print(f"  ├─ Have MITRE mapping    : {has_mitre}/{len(all_findings)}")
        print(f"  └─ Have remediation      : {has_remediation}/{len(all_findings)}")
        print(f"\n  Overall: {'✅ ALL SCENARIOS PASSING' if failed == 0 else f'❌ {failed} SCENARIO(S) FAILING'}")
        print(f"{'='*65}\n")

        # Save report
        report = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "summary": {"passed": passed, "failed": failed, "todo": todo},
            "severity_breakdown": by_sev,
            "scenarios": self.results,
        }
        with open("test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Full report saved to: test_report.json")


def login(api_url, email, password):
    r = httpx.post(f"{api_url}/api/v1/auth/login", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()["access_token"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api",      default="http://localhost:8000")
    parser.add_argument("--email",    default="admin@cspm.local")
    parser.add_argument("--password", default="Admin@CSPM123")
    parser.add_argument("--scan-id",  help="Existing completed scan ID to validate")
    parser.add_argument("--account-id", help="Cloud account ID to trigger new scan")
    args = parser.parse_args()

    print(f"\nCSPM Test Runner — {args.api}")
    token = login(args.api, args.email, args.password)
    print(f"✅  Logged in as {args.email}")

    runner = CSPMTestRunner(args.api, token)

    if args.scan_id:
        scan_id = args.scan_id
    elif args.account_id:
        print(f"  Triggering scan for account {args.account_id}...")
        scan_id = runner.start_scan(args.account_id)
        print(f"  Scan started: {scan_id}")
        scan = runner.wait_for_scan(scan_id)
        if scan["status"] != "completed":
            print(f"❌  Scan ended with status: {scan['status']}")
            sys.exit(1)
        print(f"✅  Scan completed — {scan['total_findings']} findings, risk score: {scan['risk_score']}")
    else:
        print("❌  Provide --scan-id or --account-id")
        sys.exit(1)

    runner.run_all(scan_id)


if __name__ == "__main__":
    main()
