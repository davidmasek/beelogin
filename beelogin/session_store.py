import datetime
import uuid
from typing import Annotated
from dataclasses import dataclass

from fastapi import Cookie

from beelogin import config


@dataclass
class SessionData:
    session_id: str
    expires: datetime.datetime 
    user: str = ""
    state: str | None = None
    nonce: str | None = None

    def logout(self):
        self.user = ""


class SessionStore:
    store: dict[str, SessionData]

    def __init__(self):
        self.store = {}

    def get(self, session_id: str) -> SessionData | None:
        session = self.store.get(session_id)
        if session:
            if session.expires < datetime.datetime.now():
                print("deleting expired session", session_id)
                self.delete(session_id)
                return None
        return session

    def create(self) -> str:
        session_id = str(uuid.uuid4())
        expires = datetime.datetime.now() + datetime.timedelta(days=1)
        self.store[session_id] = SessionData(session_id=session_id, expires=expires)
        print("saved session", session_id)
        return session_id
    
    def get_or_create(self, session_id: str) -> SessionData:
        data = self.get(session_id)
        if not session_id or not data:
            print("creating new session")
            session_id = self.create()
        data = self.store[session_id]
        return data
    
    def delete(self, session_id: str) -> None:
        try:
            del self.store[session_id]
        except KeyError:
            pass


session_store = SessionStore()


def get_session(session_id: Annotated[str, Cookie()] = "") -> SessionData:
    return session_store.get_or_create(session_id)
