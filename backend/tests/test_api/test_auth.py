import pytest


@pytest.mark.asyncio
async def test_register_user(client):
    res = await client.post("/api/v1/auth/register", json={
        "email": "newuser@cspm.local",
        "full_name": "New User",
        "password": "NewPass1!",
    })
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == "newuser@cspm.local"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client, test_user):
    res = await client.post("/api/v1/auth/register", json={
        "email": test_user.email,
        "full_name": "Dup",
        "password": "NewPass1!",
    })
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_login_success(client, test_user):
    res = await client.post("/api/v1/auth/login", json={
        "email": "test@cspm.local",
        "password": "Test1234!",
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client, test_user):
    res = await client.post("/api/v1/auth/login", json={
        "email": test_user.email,
        "password": "WrongPass1!",
    })
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_get_me(client, auth_headers):
    res = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["email"] == "test@cspm.local"


@pytest.mark.asyncio
async def test_get_me_no_auth(client):
    res = await client.get("/api/v1/auth/me")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_generate_api_key(client, auth_headers):
    res = await client.post("/api/v1/auth/api-key", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["api_key"].startswith("cspm_")
    assert len(data["api_key"]) > 20
