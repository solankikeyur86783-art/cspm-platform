import pytest


@pytest.mark.asyncio
async def test_dashboard_summary(client, auth_headers):
    res = await client.get("/api/v1/dashboard/summary", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "cloud_accounts" in data
    assert "total_open_findings" in data
    assert "findings_by_severity" in data
    assert "average_risk_score" in data


@pytest.mark.asyncio
async def test_dashboard_risk_trend(client, auth_headers):
    res = await client.get("/api/v1/dashboard/risk-trend", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


@pytest.mark.asyncio
async def test_dashboard_top_risks(client, auth_headers):
    res = await client.get("/api/v1/dashboard/top-risks", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


@pytest.mark.asyncio
async def test_dashboard_compliance(client, auth_headers):
    res = await client.get("/api/v1/dashboard/compliance", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "CIS AWS" in data


@pytest.mark.asyncio
async def test_dashboard_requires_auth(client):
    res = await client.get("/api/v1/dashboard/summary")
    assert res.status_code == 401
