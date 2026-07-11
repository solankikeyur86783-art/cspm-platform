"""
test_scan.py — Trigger a full scan via the API for manual testing.

Usage:
  python scripts/test_scan.py --account-id <uuid> --email admin@cspm.local --password Admin@CSPM123
"""
import asyncio
import argparse
import httpx
import json


BASE_URL = "http://localhost:8000/api/v1"


async def run(account_id: str, email: str, password: str) -> None:
    async with httpx.AsyncClient(timeout=60.0) as client:
        # Login
        login_res = await client.post(f"{BASE_URL}/auth/login", json={"email": email, "password": password})
        login_res.raise_for_status()
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"✅ Logged in as {email}")

        # Start scan
        scan_res = await client.post(
            f"{BASE_URL}/scans",
            json={"cloud_account_id": account_id, "scan_type": "full"},
            headers=headers,
        )
        scan_res.raise_for_status()
        scan = scan_res.json()
        scan_id = scan["id"]
        print(f"🚀 Scan started: {scan_id}")

        # Poll status
        print("⏳ Polling scan status...")
        while True:
            await asyncio.sleep(5)
            status_res = await client.get(f"{BASE_URL}/scans/{scan_id}/status", headers=headers)
            status = status_res.json()
            progress = status.get("progress", 0)
            scan_status = status.get("status")
            print(f"   [{progress}%] Status: {scan_status}")

            if scan_status in ("completed", "failed", "cancelled"):
                break

        # Get results
        result_res = await client.get(f"{BASE_URL}/scans/{scan_id}", headers=headers)
        result = result_res.json()
        print("\n" + "="*60)
        print(f"✅ Scan Complete!")
        print(f"   Risk Score:   {result.get('risk_score')}/100")
        print(f"   Total:        {result.get('total_findings')} findings")
        print(f"   Critical:     {result.get('critical_findings')}")
        print(f"   High:         {result.get('high_findings')}")
        print(f"   Medium:       {result.get('medium_findings')}")
        print(f"   Duration:     {result.get('duration_seconds')}s")
        print("="*60)

        # Show top findings
        findings_res = await client.post(
            f"{BASE_URL}/findings/search",
            json={"scan_id": scan_id, "severity": ["critical", "high"], "page_size": 5},
            headers=headers,
        )
        findings = findings_res.json().get("items", [])
        if findings:
            print("\nTop Critical/High Findings:")
            for f in findings:
                print(f"  [{f['severity'].upper()}] {f['rule_id']}: {f['rule_name']}")
                print(f"    Resource: {f.get('resource_name') or f['resource_id']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--email", default="admin@cspm.local")
    parser.add_argument("--password", default="Admin@CSPM123")
    args = parser.parse_args()

    asyncio.run(run(args.account_id, args.email, args.password))
