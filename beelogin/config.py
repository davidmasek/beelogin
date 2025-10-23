from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_current_dir = Path(__file__).parent


class Settings(BaseSettings):
    app_name: str = "BeeLogin"
    # Google Login
    g_client_id: str
    g_client_secret: str
    # https://beelogin.optimisticotter.me/google/callback
    g_redirect_uri: str = "http://localhost:8000/google/callback"

    model_config = SettingsConfigDict(env_file=_current_dir / ".env")


@lru_cache
def get_settings():
    return Settings()
