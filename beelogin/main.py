from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse

from beelogin import login
from beelogin.session_store import session_store

SESSION_COOKIE_NAME = "session_id"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24  # 24h


_current_dir = Path(__file__).parent

app = FastAPI()

app.include_router(login.router)

_current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=_current_dir / "static"), name="static")


@app.get("/privacy", response_class=FileResponse)
def privacy():
    return FileResponse(_current_dir / "static" / "privacy.txt")


@app.get("/tos", response_class=FileResponse)
def tos():
    return FileResponse(_current_dir / "static" / "tos.txt")


@app.middleware("http")
async def refresh_session_cookie_middleware(request: Request, call_next):
    # 1. Pre-process: Get or create the session data (similar to get_session logic)
    session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
    session_data = session_store.get_or_create(session_id)
    request.state.session_data = session_data

    # 2. Process the request
    response = await call_next(request)

    # 3. Set the cookie if a valid session ID was determined.
    session_id = session_data.session_id
    if session_id:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            max_age=SESSION_MAX_AGE_SECONDS,
            secure=True,
            httponly=True,
            samesite="lax",
            domain=".optimisticotter.me",  # TODO: add to config
        )

    return response
