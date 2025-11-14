import logging
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_current_dir = Path(__file__).parent


class Settings(BaseSettings):
    # All the settings can be ovewritten with ENV variables.
    # You can use .env if appropriate.
    app_name: str = "BeeLogin"
    # TODO: switching between prod_uri and localhost_uri or unifying to one
    prod_uri: str = "https://beelogin.optimisticotter.me"
    localhost_uri: str = "http://localhost:8000"
    # username/email login
    email_enabled: bool = True
    # GitHub login
    gh_enabled: bool = True
    gh_client_id: str = ""
    gh_client_secret: str = ""
    gh_redirect_uri: str = "/github/callback"

    # expects JSON-encoded ENV  variable
    # for example: REDIRECT_WHITELIST='["a.com","b.com"]'
    redirect_whitelist: list[str] = []

    @field_validator("redirect_whitelist", mode="after")
    @classmethod
    def check_whitelist_not_empty(cls, value: list[str]) -> list[str]:
        """Logs a warning if the domain whitelist is empty."""
        if not value:
            logging.warning("redirect_whitelist is empty. Consider setting it.")
        return value

    @model_validator(mode="after")
    def validate_github_settings(self) -> "Settings":
        if self.gh_enabled:
            if not self.gh_client_id:
                logging.warning("gh_client_id not set.")
            if not self.gh_client_secret:
                logging.warning("gh_client_secret not set.")
        return self

    # Users are configured via local TOML file
    local_users: bool = True
    # the config is loaded from ~/.beelogin (inside your homedir)
    # and must be specified as a TOML file, with the following format:
    # [[users]]
    # username = "user1@gmail.com" # username is mandatory
    # password = "pwd" # include password to enable username+password login
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
