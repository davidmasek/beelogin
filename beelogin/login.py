import base64
import datetime
import hashlib
import os
import secrets
import string
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from beelogin import config, local_users
from beelogin.session_store import SessionData, get_session

router = APIRouter()

_current_dir = Path(__file__).parent
templates = Jinja2Templates(directory=_current_dir / "templates")


def generate_secure_code(length: int) -> str:
    """Generates a cryptographically secure random string."""
    # Define the characters to choose from (e.g., uppercase letters and digits)
    chars = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


class LoginRequest(BaseModel):
    username: str
    code: str


class LoginVerifyRequest(BaseModel):
    username: str
    code: str


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

    base = settings.prod_uri

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "username": session.user,
            "email_enabled": settings.email_enabled,
            "gh_enabled": settings.gh_enabled,
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
    # explicit auth provided via header
    auth = request.headers.get("authorization")
    if auth:
        if auth.startswith("Basic "):
            token = auth[len("Basic ") :]
            print(f"Decoding '{token}'")
            try:
                parts = base64.b64decode(token).decode().split(":")
            except Exception:
                raise HTTPException(400, "Invalid auth")
            if len(parts) != 2:
                raise HTTPException(400, "Invalid auth")
            username, pwd = parts
            if local_users.validate_password(username, pwd):
                session.set_user(username, "local")
            else:
                raise HTTPException(401, "Invalid username or password")
            return Response("TODO")
        elif auth.startswith("Bearer "):
            token = auth[len("Bearer ") :]
            # TODO: currently not supported
            raise HTTPException(400, "Unsuported auth")
        else:
            raise HTTPException(400, "Unsuported auth")

    # already logged in
    if session.user:
        return Response(
            "OK",
            status_code=200,
            headers={
                "X-BeeLogin-User": session.user,
                "X-BeeLogin-Provider": session.identity_provider,
            },
        )

    # save original_uri to later return the user there
    proto = request.headers.get("x-forwarded-proto") or ""
    host = request.headers.get("x-forwarded-host") or ""
    uri = request.headers.get("x-forwarded-uri") or ""
    original_uri = f"{proto}://{host}{uri}"

    if settings.redirect_whitelist:
        if host not in settings.redirect_whitelist:
            raise HTTPException(403, f"Redirect to {host} not allowed")
    session.set_redirect(
        original_uri, datetime.datetime.now() + datetime.timedelta(minutes=15)
    )

    # redirect to root to allow standard login
    return RedirectResponse(
        settings.prod_uri,
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
        settings.prod_uri
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

    if not github_username:
        raise HTTPException(status_code=500, detail="Unexpected user info from GitHub.")

    if settings.local_users:
        user = local_users.find_by_github_username(github_username)
        if not user:
            raise HTTPException(
                403,
                "Given user is not registered on this site. Contact site administrator or check your configuration.",
            )
        session.set_user(user.username, "github")
    else:
        session.set_user(github_username, "github")

    redirect_uri = session.redirect
    if redirect_uri:
        session.remove_redirect()

        return RedirectResponse(
            redirect_uri,
            status_code=303,
        )

    # 6. Redirect to the main page
    return RedirectResponse("/", status_code=303)


@router.post("/verify_form", response_class=HTMLResponse)
def verify_code(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    session: SessionData = Depends(get_session),
    settings: config.Settings = Depends(config.get_settings),
):
    if not settings.email_enabled:
        raise HTTPException(403, "Username login not allowed")
    if not settings.local_users:
        raise HTTPException(400, "Username login not configured")

    valid_code = False
    if settings.local_users:
        valid_code = local_users.validate_password(username, password)

    redirect = session.redirect
    if valid_code:
        session.set_user(username, "local")
        if redirect:
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
            "local_users": settings.local_users,
        },
    )


@router.post("/logout", response_class=HTMLResponse)
def logout(session: SessionData = Depends(get_session)):
    session.logout()
    response = RedirectResponse("/", status_code=303)
    return response
