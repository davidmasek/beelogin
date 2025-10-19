from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

router = APIRouter()

_current_dir = Path(__file__).parent
templates = Jinja2Templates(directory=_current_dir / "templates")


class SessionStore:
    def get(self, session_id: str) -> str:
        return "dm"

    def add(self, user: str) -> str:
        # session_id
        return "foobar-defcv"


class LoginRequest(BaseModel):
    username: str
    code: str


class LoginVerifyRequest(BaseModel):
    username: str
    code: str


sesion_store = SessionStore()


def get_current_user(session_id: Annotated[str, Cookie()] = "") -> str:
    if not session_id:
        print("no session_id")
        return ""
    return sesion_store.get(session_id)


@router.get("/", response_class=HTMLResponse)
def root(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse(
        request=request, name="index.html", context={"username": user}
    )


@router.post("/request_code", response_class=HTMLResponse)
def request_code(request: Request, username: Annotated[str, Form()]):
    print("Sending email: 123")
    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={"req_username": username},
    )


@router.post("/verify_code", response_class=HTMLResponse)
def verify_code(
    request: Request,
    username: Annotated[str, Form()],
    code: Annotated[str, Form()],
):
    if code == "123":
        print("will set cookie")
        session_id = sesion_store.add(username)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            "session_id",
            session_id,
            max_age=60 * 60 * 24,  # 24h in seconds
            secure=False,
            httponly=True,
            samesite="strict",
        )
        return response
    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={
            "req_username": username,
            "invalid_code": True,
        },
    )


@router.post("/logout", response_class=HTMLResponse)
def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session_id")
    return response
