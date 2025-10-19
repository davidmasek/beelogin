from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from beelogin import login

app = FastAPI()

app.include_router(login.router)

_current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=_current_dir / "static"), name="static")
