from http.cookies import SimpleCookie

from fastapi.testclient import TestClient

from beelogin.login import user_store
from beelogin.session_store import session_store


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
    session_data.user = "admin"
    session_id = session_data.session_id

    client.cookies.set("session_id", session_id)
    response = client.post(
        "/logout",
    )
    assert response.is_success

    session_data = session_store.get_or_create(session_id)
    assert not session_data.user
