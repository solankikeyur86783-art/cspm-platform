import pytest
import uuid
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_start_scan_success(client, auth_headers, test_cloud_account):
    with patch("app.workers.scan_tasks.run_scan") as mock_task:
        mock_task.delay.return_value = type("T", (), {"id": "mock-task-id"})()
        res = await client.post(
            "/api/v1/scans",
            json={"cloud_account_id": str(test_cloud_account.id)},
            headers=auth_headers,
        )
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "pending"
    assert data["cloud_account_id"] == str(test_cloud_account.id)


@pytest.mark.asyncio
async def test_start_scan_invalid_account(client, auth_headers):
    res = await client.post(
        "/api/v1/scans",
        json={"cloud_account_id": str(uuid.uuid4())},
        headers=auth_headers,
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_list_scans_empty(client, auth_headers):
    res = await client.get("/api/v1/scans", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_get_scan_not_found(client, auth_headers):
    res = await client.get(f"/api/v1/scans/{uuid.uuid4()}", headers=auth_headers)
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_scan_requires_auth(client):
    res = await client.get("/api/v1/scans")
    assert res.status_code == 401
