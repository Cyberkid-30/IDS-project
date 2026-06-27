from typing import Generator
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

from app.database.base import Base
from app.database.session import get_db
from app.api.deps import get_database, get_detector, get_alerts_manager
from app.services.detector import DetectionEngine
from app.services.alert_manager import AlertManager
from app.models.signature import Signature, SeverityLevel, ProtocolType
from app.main import app

TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(
        TEST_DATABASE_URL, connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(db_engine) -> Generator[Session, None, None]:
    connection = db_engine.connect()
    transaction = connection.begin()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=connection)
    session = SessionLocal()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def sample_signature(db_session: Session) -> Signature:
    sig = Signature(
        name="Test SQL Injection",
        description="Detects SQL injection attempts",
        protocol=ProtocolType.TCP,
        source_ip=None,
        source_port=None,
        dest_ip=None,
        dest_port="80,443",
        pattern=r"(?i)(select|union|insert|drop|delete).*from",
        severity=SeverityLevel.CRITICAL,
        enabled=True,
        category="web-attack",
    )
    db_session.add(sig)
    db_session.commit()
    return sig


@pytest.fixture
def sample_signatures(db_session: Session) -> list[Signature]:
    sigs = [
        Signature(
            name="SSH Brute Force",
            description="Detects SSH brute force attempts",
            protocol=ProtocolType.TCP,
            dest_port="22",
            pattern=r"(?i)ssh.*(failed|invalid|error)",
            severity=SeverityLevel.HIGH,
            enabled=True,
            category="brute-force",
        ),
        Signature(
            name="Ping Sweep",
            description="Detects ICMP ping sweeps",
            protocol=ProtocolType.ICMP,
            severity=SeverityLevel.LOW,
            enabled=True,
            category="reconnaissance",
        ),
        Signature(
            name="Disabled Test",
            description="Inactive signature",
            protocol=ProtocolType.ANY,
            severity=SeverityLevel.MEDIUM,
            enabled=False,
            category="test",
        ),
    ]
    for s in sigs:
        db_session.add(s)
    db_session.commit()
    return sigs


class MockDetectionEngine:
    def __init__(self):
        self.is_running = False
        self._status = {
            "running": False,
            "signatures_loaded": 0,
            "packets_processed": 0,
            "alerts_generated": 0,
            "start_time": None,
            "uptime_seconds": 0.0,
            "interface": "lo",
            "capture_filter": "ip",
            "queue_size": 0,
        }

    def start_detection(self) -> bool:
        if self.is_running:
            return False
        self.is_running = True
        self._status["running"] = True
        self._status["start_time"] = datetime.utcnow().isoformat()
        return True

    def stop_detection(self):
        self.is_running = False
        self._status["running"] = False

    def reload_signatures(self) -> int:
        return 0

    def get_status(self) -> dict:
        return self._status


@pytest.fixture
def mock_detector() -> MockDetectionEngine:
    return MockDetectionEngine()


@pytest.fixture(autouse=True)
def _patch_permissions(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "app.core.permissions.verify_capture_permissions",
        lambda: (True, "Mock: permissions OK"),
    )
    monkeypatch.setattr(
        "app.core.permissions.check_root_privileges",
        lambda: True,
    )


@pytest.fixture
def client(db_session: Session, mock_detector: MockDetectionEngine) -> Generator[TestClient, None, None]:
    def override_get_database():
        yield db_session

    def override_get_detector():
        return mock_detector

    app.dependency_overrides[get_database] = override_get_database
    app.dependency_overrides[get_detector] = override_get_detector

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers() -> dict:
    return {}
