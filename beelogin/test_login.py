from base64 import b64encode
from http.cookies import SimpleCookie
from typing import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from beelogin import config
from beelogin.login import user_store
from beelogin.main import app
from beelogin.session_store import session_store


@pytest.fixture
def enable_email_codes() -> Iterator[config.Settings]:
    settings = config.Settings()
    settings.email_enabled = True
    settings.fixed_codes = False

    app.dependency_overrides[config.get_settings] = lambda: settings
    try:
        yield settings
    finally:
        # not great since we remove all overrides, but works for now
        app.dependency_overrides = {}


@pytest.mark.usefixtures("enable_email_codes")
def test_verify_code(client: TestClient):
    username = "dm"
    user = user_store.get_or_create(username)
    code = user.create_login_code()

    response = client.post(
        "/verify_code",
        data={
            "username": username,
            "code": code.code,
        },
        follow_redirects=False,  # we lose the set-cookie header on redirect
    )
    # verify the cookie details
    assert response.is_success or response.is_redirect
    cookies_header = response.headers.get("set-cookie")
    assert cookies_header
    cookies = SimpleCookie(cookies_header)
    session_cookie = cookies.get("session_id")
    assert session_cookie
    assert session_cookie.get("httponly")

    # verify login
    session_id = client.cookies.get("session_id")
    assert session_id

    session_data = session_store.get(session_id)
    assert session_data
    assert session_data.user == "dm"


@pytest.mark.usefixtures("enable_email_codes")
def test_verify_code_fail(client: TestClient):
    response = client.post(
        "/verify_code",
        data={
            "username": "dm",
            "code": "invalid",
        },
    )
    assert response.is_success

    session_id = client.cookies.get("session_id")
    assert session_id

    session_data = session_store.get(session_id)
    assert session_data
    # login invalid - no user set
    assert session_data.user == ""


def test_logout(client: TestClient):
    session_data = session_store.get_or_create("")
    session_data.set_user("admin", "test")
    session_id = session_data.session_id

    client.cookies.set("session_id", session_id)
    response = client.post(
        "/logout",
    )
    assert response.is_success

    session_data = session_store.get_or_create(session_id)
    assert not session_data.user


def test_basic_auth(client: TestClient):
    username = "carl"
    password = "cats"

    def validate_carl(usr: str, pwd: str) -> bool:
        return usr == username and pwd == password

    # ensure valid user+pwd login is successful
    with patch("beelogin.login.validate_password", validate_carl):
        token = b64encode(f"{username}:{password}".encode("ascii")).decode("ascii")
        resp = client.get("/caddy", headers={"authorization": f"Basic {token}"})
    assert resp.is_success

    # ensure invalid pwd login is unsuccessful
    with patch("beelogin.login.validate_password", validate_carl):
        token = b64encode(f"{username}:not-cats".encode("ascii")).decode("ascii")
        resp = client.get("/caddy", headers={"authorization": f"Basic {token}"})
    assert resp.is_client_error


def test_caddy_already_logged_in(client: TestClient):
    session_data = session_store.get_or_create("")
    session_data.set_user("admin", "test")
    session_id = session_data.session_id

    client.cookies.set("session_id", session_id)
    response = client.get(
        "/caddy",
    )
    assert response.is_success


def test_caddy_not_logged_in(client: TestClient):
    session_data = session_store.get_or_create("")
    session_data.logout()
    session_id = session_data.session_id

    client.cookies.set("session_id", session_id)
    # expect 3xx redirect
    response = client.get(
        "/caddy",
        follow_redirects=False,
    )
    assert not response.is_success
