import pytest


@pytest.mark.asyncio
async def test_list_frameworks(client, auth_headers):
    res = await client.get("/api/v1/compliance/frameworks", headers=auth_headers)
    assert res.status_code == 200
    frameworks = res.json()
    assert "CIS AWS" in frameworks
    assert "SOC 2" in frameworks
    assert "HIPAA" in frameworks


@pytest.mark.asyncio
async def test_compliance_posture(client, auth_headers):
    res = await client.get("/api/v1/compliance/posture", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "posture" in data
    assert "CIS AWS" in data["posture"]
    cis_aws = data["posture"]["CIS AWS"]
    assert "score_percent" in cis_aws
    assert 0 <= cis_aws["score_percent"] <= 100


@pytest.mark.asyncio
async def test_compliance_posture_specific_framework(client, auth_headers):
    res = await client.get("/api/v1/compliance/posture/CIS AWS", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["framework"] == "CIS AWS"
    assert "controls" in data
    assert isinstance(data["controls"], list)
    assert len(data["controls"]) > 0


@pytest.mark.asyncio
async def test_compliance_posture_unknown_framework(client, auth_headers):
    res = await client.get("/api/v1/compliance/posture/UNKNOWN-FRAMEWORK", headers=auth_headers)
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_compliance_requires_auth(client):
    res = await client.get("/api/v1/compliance/posture")
    assert res.status_code == 401
