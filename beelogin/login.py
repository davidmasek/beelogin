import base64
import datetime
import hashlib
import json
import os
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from beelogin import config
from beelogin.session_store import SessionData, get_session

router = APIRouter()

_current_dir = Path(__file__).parent
templates = Jinja2Templates(directory=_current_dir / "templates")


@dataclass
class LoginCode:
    code: str
    expires: datetime.datetime


def generate_secure_code(length: int) -> str:
    """Generates a cryptographically secure random string."""
    # Define the characters to choose from (e.g., uppercase letters and digits)
    chars = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


@dataclass
class UserData:
    user: str
    login_codes: list[LoginCode] = field(default_factory=list)
    sessions: list[str] = field(default_factory=list)

    def create_login_code(self) -> LoginCode:
        # clear old ones
        self.login_codes = [
            code for code in self.login_codes if code.expires > datetime.datetime.now()
        ]
        code = LoginCode(
            generate_secure_code(length=6),
            datetime.datetime.now() + datetime.timedelta(minutes=30),
        )
        self.login_codes.append(code)
        return code

    def validate_login_code(self, input_code: str) -> bool:
        for code in self.login_codes:
            if code.code == input_code:
                if code.expires > datetime.datetime.now():
                    return True
        return False


class UserStore:
    users: dict[str, UserData]

    def __init__(self):
        self.users = {}

    def get(self, user: str) -> UserData | None:
        return self.users.get(user)

    def get_or_create(self, user: str) -> UserData:
        if user not in self.users:
            self.users[user] = UserData(user=user)
        return self.users[user]

    def store(self, user: str, data: UserData) -> None:
        self.users[user] = data


class LoginRequest(BaseModel):
    username: str
    code: str


class LoginVerifyRequest(BaseModel):
    username: str
    code: str


user_store = UserStore()


@router.get("/", response_class=HTMLResponse)
def root(
    request: Request,
    redirect: str = "",
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
):
    # Create a state token to prevent request forgery.
    # https://developers.google.com/identity/openid-connect/openid-connect#python
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    session.state = state

    nonce = secrets.token_urlsafe(32)
    session.nonce = nonce

    base = settings.localhost_uri

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "username": session.user,
            "g_client_id": settings.g_client_id,
            "s_client_id": settings.s_client_id,
            "gh_client_id": settings.gh_client_id,
            "g_redirect_uri": f"{base}{settings.g_redirect_uri}",
            "s_redirect_uri": f"{base}{settings.s_redirect_uri}",
            "gh_redirect_uri": f"{base}{settings.gh_redirect_uri}",
            "g_state": session.state,
            "g_nonce": session.nonce,
            "session_id": session.session_id,
            "redirect": redirect,
        },
    )


@router.get("/caddy")
def caddy(
    request: Request,
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
):
    proto = request.headers.get("x-forwarded-proto") or ""
    host = request.headers.get("x-forwarded-host") or ""
    uri = request.headers.get("x-forwarded-uri") or ""
    original_uri = f"{proto}://{host}{uri}"

    if session.user:
        return Response(
            "OK",
            status_code=200,
            headers={
                "X-BeeLogin-User": session.user,
            },
        )
    return RedirectResponse(
        f"https://localhost:3000/?redirect={original_uri}",
        status_code=303,
    )


@router.get("/github/callback")
def gh_callback(
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
    state: str = "",
    code: str = "",
):
    # 1. State Validation
    # Checks if the 'state' parameter from the GitHub redirect matches the one stored in the session.
    if not state or not session.state or state != session.state:
        raise HTTPException(401, detail="State mismatch.")

    # Clear the state once it's been used to prevent replay.
    session.state = None

    # 2. Check for Authorization Code
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing.")

    # 3. Exchange Code for Access Token
    token_url = "https://github.com/login/oauth/access_token"
    base = (
        settings.localhost_uri
    )  # Use 'base' if 'gh_redirect_uri' is configured to be local

    with httpx.Client(base_url=token_url) as client:
        try:
            # GitHub expects 'Accept: application/json' header to return JSON instead of a form-encoded string
            response = client.post(
                "",  # Empty string since base_url is already the token_url
                headers={"Accept": "application/json"},
                data={
                    "code": code,
                    "client_id": settings.gh_client_id,
                    "client_secret": settings.gh_client_secret,
                    "redirect_uri": f"{base}{settings.gh_redirect_uri}",
                    # GitHub does not require a grant_type parameter for this step
                },
            )
            response.raise_for_status()  # Raises an exception for 4xx/5xx status codes
            tokens = response.json()

        except httpx.HTTPStatusError as e:
            print(f"GitHub Token exchange failed: {e.response.text}")
            raise HTTPException(
                status_code=400, detail="Failed to exchange code for GitHub tokens."
            )

    access_token = tokens.get("access_token")
    if not access_token:
        # Check if an error was returned instead of tokens
        error = tokens.get("error_description") or "Access token not found in response."
        raise HTTPException(status_code=400, detail=f"GitHub token error: {error}")

    # 4. Fetch User Information using Access Token
    user_api_url = "https://api.github.com/user"
    with httpx.Client() as client:
        try:
            # Use the access token in the Authorization header
            user_response = client.get(
                user_api_url,
                headers={
                    "Authorization": f"token {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            user_response.raise_for_status()
            user_info = user_response.json()

        except httpx.HTTPStatusError as e:
            print(f"GitHub User info fetch failed: {e.response.text}")
            raise HTTPException(
                status_code=400, detail="Failed to retrieve user info from GitHub."
            )

    # 5. Extract and Store User Identifier
    # GitHub provides 'login' (username) and 'id'. 'email' may be null if private or not exposed.
    github_username = user_info.get("login")
    github_id = user_info.get("id")

    # Prioritize username or ID for the session user.
    if github_username:
        session.user = github_username
    elif github_id:
        session.user = str(github_id)
    else:
        raise HTTPException(status_code=500, detail="Unexpected user info from GitHub.")

    # 6. Redirect to the main page
    return RedirectResponse("/", status_code=303)


@router.get("/seznam/callback")
def s_callback(
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
    state: str = "",
    code: str = "",
):
    if not state or not session.state or state != session.state:
        raise HTTPException(401, detail="State mismatch.")

    session.state = None

    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing.")

    token_url = "https://login.szn.cz/api/v1/oauth/token"
    base = settings.localhost_uri

    with httpx.Client() as client:
        try:
            response = client.post(
                token_url,
                data={
                    "code": code,
                    "client_id": settings.s_client_id,
                    "client_secret": settings.s_client_secret,
                    "redirect_uri": f"{base}{settings.s_redirect_uri}",
                    "grant_type": "authorization_code",
                },
            )
            response.raise_for_status()  # Raises an exception for 4xx/5xx status codes
            tokens = response.json()

        except httpx.HTTPStatusError as e:
            print(f"Token exchange failed: {e.response.text}")
            raise HTTPException(
                status_code=400, detail="Failed to exchange code for tokens."
            )

    # `tokens` keys: token_type, access_token, refresh_token, expires_in, scopes, account_name, oauth_user_id, status, message
    s_user_id = tokens.get("oauth_user_id")
    email = tokens.get("account_name")

    if email:
        session.user = email
    elif s_user_id:
        session.user = email
    else:
        raise HTTPException(status_code=500, detail="Unexpected user info.")

    return RedirectResponse("/", status_code=303)


@router.get("/google/callback")
def g_callback(
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
    state: str = "",
    code: str = "",
):
    if not state or not session.state or state != session.state:
        raise HTTPException(401, detail="State mismatch.")

    session.state = None

    # Check for stored nonce
    expected_nonce = session.nonce
    if not expected_nonce:
        # A nonce should always be present if the flow started correctly
        raise HTTPException(401, detail="Nonce missing from session.")

    # Clear the session nonce before processing
    session.nonce = None

    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing.")

    token_url = "https://oauth2.googleapis.com/token"
    with httpx.Client() as client:
        try:
            response = client.post(
                token_url,
                data={
                    "code": code,
                    "client_id": settings.g_client_id,
                    "client_secret": settings.g_client_secret,
                    "redirect_uri": settings.g_redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            response.raise_for_status()  # Raises an exception for 4xx/5xx status codes
            tokens = response.json()

        except httpx.HTTPStatusError as e:
            print(f"Token exchange failed: {e.response.text}")
            raise HTTPException(
                status_code=400, detail="Failed to exchange code for tokens."
            )

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(
            status_code=400, detail="ID token missing from Google response."
        )

    # For a simple solution, we'll extract the user info by decoding the token
    # (since the token came directly from Google over a secure connection).
    try:
        # The payload is the second part of the JWT
        payload_base64 = id_token.split(".")[1]
        # Base64 strings must be padded for correct decoding
        payload_base64_padded = payload_base64 + "=" * (-len(payload_base64) % 4)

        user_info = json.loads(base64.urlsafe_b64decode(payload_base64_padded).decode())
    except (IndexError, json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=500, detail="Failed to decode Google ID token.")

    if user_info.get("aud") != settings.g_client_id:
        raise HTTPException(status_code=400, detail="ID token audience mismatch.")
    if not user_info.get("email_verified"):
        raise HTTPException(status_code=400, detail="Google email not verified.")

    actual_nonce = user_info.get("nonce")
    if actual_nonce != expected_nonce:  # <--- COMPARE STORED NONCE WITH TOKEN NONCE
        raise HTTPException(
            401, detail="Nonce mismatch in ID token. Possible replay attack."
        )

    google_user_id = user_info.get("sub")
    email = user_info.get("email")
    if email:
        session.user = email
    elif google_user_id:
        session.user = email
    else:
        raise HTTPException(status_code=500, detail="Unexpected user info.")
    return RedirectResponse("/", status_code=303)


@router.post("/request_code", response_class=HTMLResponse)
def request_code(
    request: Request,
    username: Annotated[str, Form()],
    redirect: str = "",
):
    user = user_store.get_or_create(username)
    code = user.create_login_code()
    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={
            "req_username": username,
            "code": code.code,
            "redirect": redirect,
        },
    )


@router.post("/verify_code", response_class=HTMLResponse)
def verify_code(
    request: Request,
    username: Annotated[str, Form()],
    code: Annotated[str, Form()],
    redirect: str = "",
    session: SessionData = Depends(get_session),
):
    valid_code = False
    user = user_store.get(username)
    if user:
        valid_code = user.validate_login_code(code)

    if valid_code:
        session.user = username
        if redirect:
            # TODO: might want to check the URL...
            return RedirectResponse(redirect, status_code=303)
        response = RedirectResponse("/", status_code=303)
        return response

    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={
            "req_username": username,
            "invalid_code": True,
            "redirect": redirect,
        },
    )


@router.post("/logout", response_class=HTMLResponse)
def logout(session: SessionData = Depends(get_session)):
    session.logout()
    response = RedirectResponse("/", status_code=303)
    return response
