import os
import sys
import pytest
import io
from pathlib import Path
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Setup path so app can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app
from app.database import Base, get_db
from app.config import settings
from app.models import User, Document, DocumentShare, OTPRecord, AuditLog
from app.core.security import hash_password
from app.core.otp import hash_otp

# Setup test DB and test vault directory
TEST_DIR = Path(__file__).resolve().parent / "test_scratch"
TEST_VAULT = TEST_DIR / "vault"
TEST_DB_PATH = TEST_DIR / "test_legavault.db"
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_PATH.as_posix()}"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# Override dependencies and config
app.dependency_overrides[get_db] = override_get_db
settings.VAULT_DIR = TEST_VAULT
settings.OTP_COOLDOWN_SECONDS = 0  # Allow immediate re-requests during tests
settings.LAWYER_REGISTRATION_CODE = "test-only-lawyer-setup-code"

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    TEST_VAULT.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=test_engine)
    yield
    # Cleanup after session
    Base.metadata.drop_all(bind=test_engine)
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    import shutil
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR, ignore_errors=True)

client = TestClient(app)

# Test state shared across steps
state = {
    "lawyer_token": None,
    "associate_token": None,
    "client_token": None,
    "doc_id": None,
    "raw_pdf_content": b"%PDF-1.4\n%Confidential Legal Contract Between Party A and Party B\n%%EOF"
}

# ---------------------------------------------------------
# Test 1: Register Lawyer
# ---------------------------------------------------------
def test_01_register_lawyer():
    resp = client.post("/api/auth/register", json={
        "email": "lawyer_t@test.com",
        "full_name": "Advocate Senior Test",
        "role": "lawyer",
        "password": "StrongPassword123!",
        "lawyer_registration_code": settings.LAWYER_REGISTRATION_CODE
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "lawyer_t@test.com"
    assert data["role"] == "lawyer"

# ---------------------------------------------------------
# Test 2: Register Associate
# ---------------------------------------------------------
def test_02_register_associate():
    resp = client.post("/api/auth/register", json={
        "email": "associate_t@test.com",
        "full_name": "Junior Associate Test",
        "role": "associate",
        "password": "StrongPassword123!"
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "associate_t@test.com"
    assert data["role"] == "associate"

# ---------------------------------------------------------
# Test 3: Register Client
# ---------------------------------------------------------
def test_03_register_client():
    resp = client.post("/api/auth/register", json={
        "email": "client_t@test.com",
        "full_name": "Client User Test",
        "role": "client",
        "password": "StrongPassword123!"
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "client_t@test.com"
    assert data["role"] == "client"

# ---------------------------------------------------------
# Test 4: Login with correct credentials (triggers OTP)
# ---------------------------------------------------------
def test_04_login_correct_credentials():
    resp = client.post("/api/auth/login", json={
        "email": "lawyer_t@test.com",
        "password": "StrongPassword123!"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "otp_required"
    assert data["email"] == "lawyer_t@test.com"

# ---------------------------------------------------------
# Test 5: Reject incorrect password
# ---------------------------------------------------------
def test_05_reject_incorrect_password():
    resp = client.post("/api/auth/login", json={
        "email": "lawyer_t@test.com",
        "password": "WrongPassword999!"
    })
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]

# ---------------------------------------------------------
# Test 6: Generate OTP
# ---------------------------------------------------------
def test_06_generate_otp():
    # Login generated an OTP. Let's verify an OTP record was securely created in DB (hashed, not plaintext)
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "lawyer_t@test.com").first()
    otp_record = db.query(OTPRecord).filter(
        OTPRecord.user_id == user.id,
        OTPRecord.is_used == False
    ).order_by(OTPRecord.created_at.desc()).first()
    
    assert otp_record is not None
    assert len(otp_record.hashed_otp) == 64  # SHA-256 hash length
    db.close()

# ---------------------------------------------------------
# Test 7: Verify correct OTP
# ---------------------------------------------------------
def test_07_verify_correct_otp():
    # Set a known OTP hash directly in DB for testing verification
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "lawyer_t@test.com").first()
    test_otp = "123456"
    
    # Store hashed OTP in DB
    record = OTPRecord(
        user_id=user.id,
        hashed_otp=hash_otp(test_otp),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        is_used=False,
        attempts=0,
        created_at=datetime.now(timezone.utc)
    )
    db.add(record)
    db.commit()
    db.close()

    resp = client.post("/api/auth/verify-otp", json={
        "email": "lawyer_t@test.com",
        "otp": test_otp
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "lawyer"
    state["lawyer_token"] = data["access_token"]

    # Also log in associate and client for later tests
    db = TestingSessionLocal()
    for role_email, key in [("associate_t@test.com", "associate_token"), ("client_t@test.com", "client_token")]:
        u = db.query(User).filter(User.email == role_email).first()
        rec = OTPRecord(
            user_id=u.id,
            hashed_otp=hash_otp("654321"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            is_used=False,
            attempts=0,
            created_at=datetime.now(timezone.utc)
        )
        db.add(rec)
        db.commit()
        r = client.post("/api/auth/verify-otp", json={"email": role_email, "otp": "654321"})
        assert r.status_code == 200
        state[key] = r.json()["access_token"]
    db.close()

# ---------------------------------------------------------
# Test 8: Reject incorrect OTP
# ---------------------------------------------------------
def test_08_reject_incorrect_otp():
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "lawyer_t@test.com").first()
    rec = OTPRecord(
        user_id=user.id,
        hashed_otp=hash_otp("999999"),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        is_used=False,
        attempts=0,
        created_at=datetime.now(timezone.utc)
    )
    db.add(rec)
    db.commit()
    db.close()

    resp = client.post("/api/auth/verify-otp", json={
        "email": "lawyer_t@test.com",
        "otp": "000000"  # Incorrect code
    })
    assert resp.status_code == 400
    assert "Invalid OTP code" in resp.json()["detail"]

# ---------------------------------------------------------
# Test 9: Reject expired OTP
# ---------------------------------------------------------
def test_09_reject_expired_otp():
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "lawyer_t@test.com").first()
    # Invalidate prior unused records as the real app does when generating a fresh OTP
    db.query(OTPRecord).filter(OTPRecord.user_id == user.id, OTPRecord.is_used == False).update({"is_used": True})
    now = datetime.now(timezone.utc)
    rec = OTPRecord(
        user_id=user.id,
        hashed_otp=hash_otp("888888"),
        expires_at=now - timedelta(minutes=1),  # Expired
        is_used=False,
        attempts=0,
        created_at=now
    )
    db.add(rec)
    db.commit()
    db.close()

    resp = client.post("/api/auth/verify-otp", json={
        "email": "lawyer_t@test.com",
        "otp": "888888"
    })
    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"].lower()

# ---------------------------------------------------------
# Test 10: Lawyer uploads a test PDF
# ---------------------------------------------------------
def test_10_lawyer_uploads_pdf():
    files = {
        "file": ("confidential_agreement.pdf", io.BytesIO(state["raw_pdf_content"]), "application/pdf")
    }
    data = {
        "title": "Confidential NDA Agreement",
        "description": "High-value acquisition non-disclosure agreement."
    }
    headers = {"Authorization": f"Bearer {state['lawyer_token']}"}
    resp = client.post("/api/documents/upload", files=files, data=data, headers=headers)
    assert resp.status_code == 201
    doc_data = resp.json()
    assert doc_data["title"] == "Confidential NDA Agreement"
    assert doc_data["original_filename"] == "confidential_agreement.pdf"
    assert doc_data["file_size"] == len(state["raw_pdf_content"])
    state["doc_id"] = doc_data["id"]

# ---------------------------------------------------------
# Test 11: Verify that stored file is encrypted and cannot be opened directly
# ---------------------------------------------------------
def test_11_verify_stored_file_is_encrypted():
    db = TestingSessionLocal()
    doc = db.query(Document).filter(Document.id == state["doc_id"]).first()
    assert doc is not None
    
    stored_path = settings.VAULT_DIR / doc.encrypted_filename
    assert stored_path.exists()
    
    # Read the raw file stored in the vault
    with open(stored_path, "rb") as f:
        stored_bytes = f.read()
        
    # 1. The stored bytes MUST NOT contain the original PDF header or plaintext string
    assert b"%PDF-1.4" not in stored_bytes
    assert b"Confidential Legal Contract" not in stored_bytes
    
    # 2. The stored file has nonce (12 bytes) + ciphertext + 16 bytes auth tag
    assert len(stored_bytes) >= len(state["raw_pdf_content"]) + 28
    db.close()

# ---------------------------------------------------------
# Test 12: Lawyer shares document with Associate
# ---------------------------------------------------------
def test_12_lawyer_shares_with_associate():
    db = TestingSessionLocal()
    associate = db.query(User).filter(User.email == "associate_t@test.com").first()
    db.close()

    headers = {"Authorization": f"Bearer {state['lawyer_token']}"}
    resp = client.post(
        f"/api/documents/{state['doc_id']}/share",
        json={"recipient_id": associate.id, "permission": "view"},
        headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["recipient_id"] == associate.id
    assert data["permission"] == "view"

# ---------------------------------------------------------
# Test 13: Associate can download/decrypt shared document
# ---------------------------------------------------------
def test_13_associate_downloads_and_decrypts():
    headers = {"Authorization": f"Bearer {state['associate_token']}"}
    resp = client.get(f"/api/documents/{state['doc_id']}/download", headers=headers)
    assert resp.status_code == 200
    # Decrypted bytes must match the exact original plaintext PDF!
    assert resp.content == state["raw_pdf_content"]
    assert b"%PDF-1.4" in resp.content

# ---------------------------------------------------------
# Test 14: Client cannot access Associate's document
# ---------------------------------------------------------
def test_14_client_cannot_access_unshared_document():
    headers = {"Authorization": f"Bearer {state['client_token']}"}
    resp = client.get(f"/api/documents/{state['doc_id']}", headers=headers)
    assert resp.status_code == 403
    assert "Access denied" in resp.json()["detail"]

# ---------------------------------------------------------
# Test 15: Unauthorized user receives Access Denied on download (ID Manipulation attack test)
# ---------------------------------------------------------
def test_15_unauthorized_download_denied():
    headers = {"Authorization": f"Bearer {state['client_token']}"}
    resp = client.get(f"/api/documents/{state['doc_id']}/download", headers=headers)
    assert resp.status_code == 403
    assert "Access denied" in resp.json()["detail"]

# ---------------------------------------------------------
# Test 16: Lawyer revokes access
# ---------------------------------------------------------
def test_16_lawyer_revokes_access():
    db = TestingSessionLocal()
    associate = db.query(User).filter(User.email == "associate_t@test.com").first()
    db.close()

    headers = {"Authorization": f"Bearer {state['lawyer_token']}"}
    resp = client.delete(
        f"/api/documents/{state['doc_id']}/share/{associate.id}",
        headers=headers
    )
    assert resp.status_code == 200
    assert "revoked" in resp.json()["message"].lower()

# ---------------------------------------------------------
# Test 17: Previously authorized user can no longer access revoked document
# ---------------------------------------------------------
def test_17_associate_denied_after_revocation():
    headers = {"Authorization": f"Bearer {state['associate_token']}"}
    # Metadata access rejected
    resp_meta = client.get(f"/api/documents/{state['doc_id']}", headers=headers)
    assert resp_meta.status_code == 403

    # Decrypted download rejected
    resp_down = client.get(f"/api/documents/{state['doc_id']}/download", headers=headers)
    assert resp_down.status_code == 403
    assert "Access denied" in resp_down.json()["detail"]

# ---------------------------------------------------------
# Test 18: Audit logs contain important actions & Associate/Client cannot read them
# ---------------------------------------------------------
def test_18_audit_logs_recorded_and_rbac_protected():
    # 1. Associate tries to access audit logs -> MUST be rejected with 403 Forbidden!
    resp_associate = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {state['associate_token']}"})
    assert resp_associate.status_code == 403

    # 2. Client tries to access audit logs -> MUST be rejected with 403 Forbidden!
    resp_client = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {state['client_token']}"})
    assert resp_client.status_code == 403

    # 3. Lawyer accesses audit logs -> MUST succeed with 200 OK!
    resp_lawyer = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {state['lawyer_token']}"})
    assert resp_lawyer.status_code == 200
    logs = resp_lawyer.json()
    assert len(logs) > 0

    actions_recorded = {l["action"] for l in logs}
    expected_actions = {
        "Registration",
        "Login success",
        "OTP requested",
        "OTP verification",
        "Document uploaded",
        "Document encrypted",
        "Document shared",
        "Document decrypted",
        "Document downloaded",
        "Access denied",
        "Access revoked"
    }
    
    # Check that crucial security actions are in the audit trail
    for action in expected_actions:
        assert action in actions_recorded, f"Expected action '{action}' missing from audit logs: {actions_recorded}"

def test_19_lawyer_registration_requires_setup_code():
    resp = client.post("/api/auth/register", json={
        "email": "unverified_lawyer@test.com",
        "full_name": "Unverified Lawyer",
        "role": "lawyer",
        "password": "StrongPassword123!",
        "lawyer_registration_code": "wrong-code",
    })
    assert resp.status_code == 403

def test_20_logout_revokes_bearer_token():
    headers = {"Authorization": f"Bearer {state['associate_token']}"}
    resp = client.post("/api/auth/logout", headers=headers)
    assert resp.status_code == 200
    replay = client.get("/api/auth/me", headers=headers)
    assert replay.status_code == 401

def test_21_associates_cannot_enumerate_users():
    resp = client.get("/api/users", headers={"Authorization": f"Bearer {state['client_token']}"})
    assert resp.status_code == 403
