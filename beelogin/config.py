from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_current_dir = Path(__file__).parent


class Settings(BaseSettings):
    app_name: str = "BeeLogin"
    prod_uri: str = "https://beelogin.optimisticotter.me"
    localhost_uri: str = "http://localhost:8000"
    # username/email login
    email_enabled: bool = True
    # GitHub login
    gh_enabled: bool = True
    gh_client_id: str = ""
    gh_client_secret: str = ""
    gh_redirect_uri: str = "/github/callback"

    # Users are configured via local TOML file
    local_users: bool = True
    # the config is loaded from ~/.beelogin (inside your homedir)
    # and must be specified as a TOML file, with the following format:
    # [[users]]
    # username = "user1@gmail.com" # username is mandatory
    # password = "pwd" # include password to enable password login
    # [[users]]
    # username = "another-user@gmail.com"
    # password = "differentpwd"
    # [[users]]
    # username = "carl"
    # github_username = "carlgg" # will be used for login via github

    model_config = SettingsConfigDict(env_file=_current_dir / ".env")


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore
