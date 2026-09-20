import os

# Only this explicitly test-only variable may override the disposable database.
os.environ["CLOUDSHIELD_DATABASE_URL"] = os.environ.get(
    "CLOUDSHIELD_TEST_DATABASE_URL", "sqlite://"
)
os.environ["CLOUDSHIELD_ENV"] = "test"
os.environ["CLOUDSHIELD_DEMO_MODE"] = "true"
os.environ["CLOUDSHIELD_API_KEYS"] = "[]"
os.environ["CLOUDSHIELD_AWS_CONNECTIONS"] = "{}"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

import pytest
from fastapi.testclient import TestClient

from app.db.session import engine
from app.main import app


@pytest.fixture(autouse=True)
def clean_database() -> None:
    from app.db.models import Base

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client
