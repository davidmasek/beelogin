import datetime
import uuid
from typing import Generic, Optional, TypeVar

from fastapi import Request

# Define a TypeVar to make the ExpiringWrapper generic.
# T can represent any type of object being wrapped.
T = TypeVar("T")


class ExpiringWrapper(Generic[T]):
    """
    A class that wraps an object of type T and controls access based on
    an expiration datetime.

    The wrapped object is only returned if the current time is before
    the expiration time.
    """

    _item: T
    expires: datetime.datetime

    def __init__(self, item: T, expires: datetime.datetime):
        self._item = item
        self.expires = expires

    def expired(self) -> bool:
        current_time = datetime.datetime.now()
        return self.expires < current_time

    @property
    def item(self) -> Optional[T]:
        """
        Returns the wrapped object if it has not yet expired.
        """
        if self.expired():
            return None
        else:
            return self._item


class SessionData:
    _session_id: ExpiringWrapper[str]
    _user: str | None
    identity_provider: str | None
    state: str | None
    nonce: str | None
    _redirect: ExpiringWrapper[str] | None

    def __init__(
        self,
        session_id: str,
        session_id_expiry: datetime.datetime,
    ):
        self.set_session_id(session_id, session_id_expiry)
        self._user = None
        self.identity_provider = None
        self.state = None
        self.nonce = None
        self._redirect = None

    @property
    def user(self) -> str:
        return self._user or ""

    def set_user(self, user: str, identity_provider: str) -> None:
        self._user = user
        self.identity_provider = identity_provider

    @property
    def session_id(self) -> str:
        return self._session_id.item or ""

    def expired(self) -> bool:
        return self._session_id.expired()

    def set_session_id(
        self, session_id: str, session_id_expiry: datetime.datetime
    ) -> None:
        self._session_id = ExpiringWrapper(session_id, session_id_expiry)

    def set_redirect(self, redirect: str, redirect_expiry: datetime.datetime) -> None:
        self._redirect = ExpiringWrapper(redirect, redirect_expiry)

    def remove_redirect(self) -> None:
        self._redirect = None

    @property
    def redirect(self) -> str:
        if self._redirect is None:
            return ""
        return self._redirect.item or ""

    def logout(self):
        self._user = None
        self.identity_provider = None


class SessionStore:
    store: dict[str, SessionData]

    def __init__(self):
        self.store = {}

    def get(self, session_id: str) -> SessionData | None:
        session = self.store.get(session_id)
        if session:
            if session.expired():
                print("deleting expired session", session_id)
                self.delete(session_id)
                return None
        return session

    def create(self) -> str:
        session_id = str(uuid.uuid4())
        expires = datetime.datetime.now() + datetime.timedelta(days=1)
        self.store[session_id] = SessionData(
            session_id,
            expires,
        )
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


def get_session(request: Request) -> SessionData:
    session = request.state.session_data
    assert session
    return session
