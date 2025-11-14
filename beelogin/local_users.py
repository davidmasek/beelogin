import logging
import tomllib
from pathlib import Path

from pydantic import BaseModel, ValidationError

USERS_FILE_PATH = Path(Path.home() / ".beelogin").absolute()


class LocalUser(BaseModel):
    username: str
    password: str | None = None
    github_username: str | None = None


# TODO: might want to cache the loaded config
def _load_users() -> dict[str, LocalUser]:
    try:
        with open(USERS_FILE_PATH, "rb") as fh:
            cfg = tomllib.load(fh)
    except FileNotFoundError:
        logging.exception("Local users not configured")
        return {}
    except tomllib.TOMLDecodeError:
        logging.exception("Local users not configured correctly")
        return {}

    users = {}
    for user_data in cfg.get("users") or []:
        try:
            user = LocalUser(**user_data)
        except ValidationError:
            logging.exception(f"Invalid user data: {user_data}")
            continue
        users[user.username] = user
    return users


def validate_password(username: str, password: str) -> bool:
    users = _load_users()
    user = users.get(username)
    if user:
        # TODO: store hashed
        pwd = user.password
        if pwd and password == pwd:
            return True
    return False


def find_by_github_username(github_username: str) -> LocalUser | None:
    for user in _load_users().values():
        if user.github_username == github_username:
            return user
    return None
