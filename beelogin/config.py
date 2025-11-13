from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_current_dir = Path(__file__).parent


class Settings(BaseSettings):
    app_name: str = "BeeLogin"
    prod_uri: str = "https://beelogin.optimisticotter.me"
    localhost_uri: str = "http://localhost:8000"
    # Google Login
    g_client_id: str = ""
    g_client_secret: str = ""
    g_redirect_uri: str = "/google/callback"
    # Seznam Login
    s_client_id: str = ""
    s_client_secret: str = ""
    s_redirect_uri: str = "/seznam/callback"
    # GitHub
    gh_client_id: str = ""
    gh_client_secret: str = ""
    gh_redirect_uri: str = "/github/callback"

    model_config = SettingsConfigDict(env_file=_current_dir / ".env")


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore
