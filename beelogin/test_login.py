from base64 import b64encode
from typing import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from beelogin import config
from beelogin.local_users import LocalUser
from beelogin.main import app
from beelogin.session_store import session_store


@pytest.fixture(scope="function")
def settings() -> Iterator[config.Settings]:
    settings = config.Settings()

    app.dependency_overrides[config.get_settings] = lambda: settings
    try:
        yield settings
    finally:
        app.dependency_overrides = {}


def test_verify_form(client: TestClient, settings: config.Settings):
    settings.local_users = True
    settings.email_enabled = True

    username = "dm"
    password = "test"

    with patch("beelogin.local_users._load_users") as mock:
        mock.return_value = {
            username: LocalUser(
                username=username,
                password=password,
            )
        }

        response = client.post(
            "/verify_form",
            data={
                "username": username,
                "password": password,
            },
            follow_redirects=False,
        )
    assert response.is_redirect
    # verify login
    session_id = client.cookies.get("session_id")
    assert session_id

    session_data = session_store.get(session_id)
    assert session_data
    assert session_data.user == username


def test_verify_form_fail(client: TestClient, settings: config.Settings):
    settings.local_users = True
    settings.email_enabled = True

    username = "dm"
    password = "test"

    with patch("beelogin.local_users._load_users") as mock:
        mock.return_value = {
            username: LocalUser(
                username=username,
                password=password,
            )
        }

        response = client.post(
            "/verify_form",
            data={
                "username": username,
                "password": password + "-invalid",
            },
            follow_redirects=False,
        )
    response.raise_for_status()
    # verify login
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
    with patch("beelogin.login.local_users.validate_password", validate_carl):
        token = b64encode(f"{username}:{password}".encode("ascii")).decode("ascii")
        resp = client.get("/caddy", headers={"authorization": f"Basic {token}"})
    assert resp.is_success

    # ensure invalid pwd login is unsuccessful
    with patch("beelogin.login.local_users.validate_password", validate_carl):
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
