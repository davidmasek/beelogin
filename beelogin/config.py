from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_current_dir = Path(__file__).parent


class Settings(BaseSettings):
    app_name: str = "BeeLogin"
    prod_uri: str = "https://beelogin.optimisticotter.me"
    localhost_uri: str = "http://localhost:8000"
    # email login
    email_enabled: bool = True
    # Google Login
    g_enabled: bool = False
    g_client_id: str = ""
    g_client_secret: str = ""
    g_redirect_uri: str = "/google/callback"
    # Seznam Login
    s_enabled: bool = True
    s_client_id: str = ""
    s_client_secret: str = ""
    s_redirect_uri: str = "/seznam/callback"
    # GitHub
    gh_enabled: bool = True
    gh_client_id: str = ""
    gh_client_secret: str = ""
    gh_redirect_uri: str = "/github/callback"

    # fixed codes option was very quickly hacked together,
    # but it let's you easily set a list of fixed users and passwords
    fixed_codes: bool = False
    # the list is loaded from ~/.beelogin (inside your homedir)
    # and must be specified as a TOML file, with the following format:
    # [[users]]
    # name = "user1@gmail.com"
    # password = "pwd"
    # # [[users]]
    # name = "another-user@gmail.com"
    # password = "differentpwd"

    model_config = SettingsConfigDict(env_file=_current_dir / ".env")


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore
