"""Shared test fixtures for the Security Guardrail Auditor test suite."""

import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.db import Base, get_db
from app.models import Scan, Finding  # noqa: F401 — ensure Base.metadata knows all tables
from app.main import app
from app.engine.rules import RuleFinding


# --- Database Fixtures ---

@pytest.fixture()
def client():
    """FastAPI TestClient with fresh in-memory SQLite per test.

    Uses StaticPool so all connections share the same in-memory DB.
    """
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


# --- Sample Config Fixtures ---

SAMPLE_DIR = Path(__file__).parent.parent / "sample_configs"


@pytest.fixture(scope="session")
def clean_tf():
    return (SAMPLE_DIR / "clean.tf").read_text()


@pytest.fixture(scope="session")
def moderate_tf():
    return (SAMPLE_DIR / "moderate_risk.tf").read_text()


@pytest.fixture(scope="session")
def terrible_tf():
    return (SAMPLE_DIR / "terrible.tf").read_text()


@pytest.fixture(scope="session")
def bad_cf_yaml():
    return (SAMPLE_DIR / "bad_cloudformation.yaml").read_text()


# --- Helper Fixtures ---

@pytest.fixture()
def make_finding():
    """Factory fixture to create RuleFinding objects for scorer tests."""
    def _make(rule_id="TEST-001", severity="Medium", weight=5,
              resource_type="test_resource", resource_name="test_name",
              description="Test finding", remediation="Fix it"):
        return RuleFinding(
            rule_id=rule_id,
            severity=severity,
            weight=weight,
            resource_type=resource_type,
            resource_name=resource_name,
            description=description,
            remediation=remediation,
        )
    return _make
