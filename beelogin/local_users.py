import logging
import tomllib
from pathlib import Path

USERS_FILE_PATH = Path(Path.home() / ".beelogin").absolute()


def validate_password(username: str, password: str) -> bool:
    try:
        with open(USERS_FILE_PATH, "rb") as fh:
            cfg = tomllib.load(fh)
        for user in cfg.get("users") or []:
            name = user.get("name") or ""
            if name == username:
                # TODO: store hashed
                pwd = user.get("password")
                if pwd and password == pwd:
                    return True
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        logging.exception("Fixed codes not configured")
        return False
    return False
