import pytest
import uuid
from unittest.mock import patch


@pytest.mark.asyncio
async def test_create_aws_account(client, auth_headers):
    with patch("app.api.v1.accounts._validate_credentials_bg"):
        res = await client.post(
            "/api/v1/accounts",
            json={
                "name": "My AWS Account",
                "provider": "aws",
                "aws_account_id": "123456789012",
                "aws_role_arn": "arn:aws:iam::123456789012:role/CSPMRole",
                "aws_regions": ["us-east-1", "eu-west-1"],
            },
            headers=auth_headers,
        )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "My AWS Account"
    assert data["provider"] == "aws"
    assert data["aws_account_id"] == "123456789012"


@pytest.mark.asyncio
async def test_create_gcp_account(client, auth_headers):
    with patch("app.api.v1.accounts._validate_credentials_bg"):
        res = await client.post(
            "/api/v1/accounts",
            json={
                "name": "My GCP Project",
                "provider": "gcp",
                "gcp_project_id": "my-gcp-project-123",
            },
            headers=auth_headers,
        )
    assert res.status_code == 201
    data = res.json()
    assert data["provider"] == "gcp"
    assert data["gcp_project_id"] == "my-gcp-project-123"


@pytest.mark.asyncio
async def test_list_accounts(client, auth_headers, test_cloud_account):
    res = await client.get("/api/v1/accounts", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1


@pytest.mark.asyncio
async def test_get_account(client, auth_headers, test_cloud_account):
    res = await client.get(
        f"/api/v1/accounts/{test_cloud_account.id}",
        headers=auth_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == str(test_cloud_account.id)


@pytest.mark.asyncio
async def test_get_account_not_owned(client, db_session, admin_user, admin_headers, test_cloud_account):
    """Account owned by test_user should not be visible to admin_user."""
    res = await client.get(
        f"/api/v1/accounts/{test_cloud_account.id}",
        headers=admin_headers,
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_update_account(client, auth_headers, test_cloud_account):
    res = await client.put(
        f"/api/v1/accounts/{test_cloud_account.id}",
        json={"name": "Updated Name"},
        headers=auth_headers,
    )
    assert res.status_code == 200
    assert res.json()["name"] == "Updated Name"


@pytest.mark.asyncio
async def test_delete_account(client, auth_headers, db_session):
    with patch("app.api.v1.accounts._validate_credentials_bg"):
        create_res = await client.post(
            "/api/v1/accounts",
            json={"name": "To Delete", "provider": "aws"},
            headers=auth_headers,
        )
    account_id = create_res.json()["id"]

    delete_res = await client.delete(f"/api/v1/accounts/{account_id}", headers=auth_headers)
    assert delete_res.status_code == 204

    get_res = await client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers)
    assert get_res.status_code == 404


@pytest.mark.asyncio
async def test_create_account_invalid_provider(client, auth_headers):
    res = await client.post(
        "/api/v1/accounts",
        json={"name": "Bad", "provider": "digitalocean"},
        headers=auth_headers,
    )
    assert res.status_code == 422
