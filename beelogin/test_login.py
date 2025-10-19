from http.cookies import SimpleCookie

from fastapi.testclient import TestClient


def test_verify_code(client: TestClient):
    response = client.post(
        "/verify_code",
        data={
            "username": "dm",
            "code": "123",
        },
        follow_redirects=False,  # we lose the set-cookie header on redirect
    )
    assert response.is_success or response.is_redirect
    cookies_header = response.headers.get("set-cookie")
    assert cookies_header
    cookies = SimpleCookie(cookies_header)
    session_cookie = cookies.get("session_id")
    assert session_cookie
    assert session_cookie.get("httponly")

    # this could serve as a basic check, but the header above is needed
    # for checking details
    assert client.cookies.get("session_id")


def test_verify_code_fail(client: TestClient):
    response = client.post(
        "/verify_code",
        data={
            "username": "dm",
            "code": "invalid",
        },
    )
    assert response.is_success

    assert not client.cookies.get("session_id")


def test_logout(client: TestClient):
    response = client.post(
        "/logout",
        cookies={"session_id": "edfc-xvfk"},
    )
    assert response.is_success
    assert not client.cookies.get("session_id")
