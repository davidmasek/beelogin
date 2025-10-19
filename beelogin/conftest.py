import pytest
from fastapi.testclient import TestClient

from beelogin.main import app


@pytest.fixture
def client():
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()
