import datetime
import hashlib
import logging
import os
import secrets
import string
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

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
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
):
    # Create a state token to prevent request forgery.
    # https://developers.google.com/identity/openid-connect/openid-connect#python
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    session.state = state

    base = settings.localhost_uri

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "username": session.user,
            "email_enabled": settings.email_enabled,
            "gh_enabled": settings.gh_enabled,
            "g_client_id": settings.gh_enabled,
            "gh_client_id": settings.gh_client_id,
            "gh_redirect_uri": f"{base}{settings.gh_redirect_uri}",
            "g_state": session.state,
            "session_id": session.session_id,
            "provider": session.identity_provider,
            "redirect": session.redirect,
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
                "X-BeeLogin-Provider": session.identity_provider,
            },
        )

    session.set_redirect(
        original_uri, datetime.datetime.now() + datetime.timedelta(minutes=15)
    )
    return RedirectResponse(
        settings.localhost_uri,
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
        session.set_user(github_username, "github-username")
    elif github_id:
        session.set_user(str(github_id), "github-id")
    else:
        raise HTTPException(status_code=500, detail="Unexpected user info from GitHub.")

    redirect_uri = session.redirect
    if redirect_uri:
        session.remove_redirect()

        # TODO: might want to check the URL against a whitelist
        return RedirectResponse(
            redirect_uri,
            status_code=303,
        )

    # 6. Redirect to the main page
    return RedirectResponse("/", status_code=303)


@router.post("/request_code", response_class=RedirectResponse)
def request_code_post(
    request: Request,
    username: Annotated[str, Form()],
    settings: config.Settings = Depends(config.get_settings),
):
    user = user_store.get_or_create(username)
    _ = user.create_login_code()
    return RedirectResponse(
        f"/request_code?{urlencode({'username': username})}",
        status_code=303,
    )


@router.get("/request_code", response_class=HTMLResponse)
def request_code(
    request: Request,
    username: str = "",
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
):
    user = user_store.get_or_create(username)
    # for demo purposes - display the code to user
    if user.login_codes:
        code = user.login_codes[0].code
    else:
        code = ""
    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={
            "req_username": username,
            "code": code,
            "redirect": session.redirect,
            "fixed_codes": settings.fixed_codes,
        },
    )


@router.post("/verify_code", response_class=HTMLResponse)
def verify_code(
    request: Request,
    username: Annotated[str, Form()],
    code: Annotated[str, Form()],
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
):
    if not settings.email_enabled:
        raise HTTPException(403)

    valid_code = False
    if settings.fixed_codes:
        try:
            with open(Path(Path.home() / ".beelogin").absolute(), "rb") as fh:
                cfg = tomllib.load(fh)
            for user in cfg.get("users") or []:
                name = user.get("name") or ""
                if name == username:
                    pwd = user.get("password")
                    if pwd and code == pwd:
                        valid_code = True
                        break
        except (FileNotFoundError, tomllib.TOMLDecodeError):
            logging.exception("Fixed codes not configured")
            raise HTTPException(500, "Fixed codes not configured")
    else:
        user = user_store.get(username)
        if user:
            valid_code = user.validate_login_code(code)

    redirect = session.redirect
    if valid_code:
        session.set_user(username, "beelogin-email")
        if redirect:
            # TODO: might want to check the URL against a whitelist
            return RedirectResponse(
                redirect,
                status_code=303,
            )
        response = RedirectResponse("/", status_code=303)
        return response

    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={
            "req_username": username,
            "invalid_code": True,
            "redirect": redirect,
            "fixed_codes": settings.fixed_codes,
        },
    )


@router.post("/logout", response_class=HTMLResponse)
def logout(session: SessionData = Depends(get_session)):
    session.logout()
    response = RedirectResponse("/", status_code=303)
    return response
