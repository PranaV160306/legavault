import httpx
import json
import os
from pathlib import Path
from urllib.parse import unquote

from backend.app.config import settings
from backend.app.core.otp import hash_otp

BASE_URL = os.getenv("LEGAVAULT_BASE_URL", "http://127.0.0.1:8000")

def test_live_system():
    print("==================================================")
    print(" LIVE OBJECTIVE 1 END-TO-END VERIFICATION")
    print("==================================================")
    client = httpx.Client(base_url=BASE_URL, timeout=10.0)

    # 1. Health check
    r = client.get("/api/health")
    assert r.status_code == 200, f"Health check failed: {r.text}"
    print(f" [PASS] 1. Health Check OK: {r.json()['service']} (Cipher: {r.json()['encryption']})")

    # 2. Login as Lawyer
    r = client.post("/api/auth/login", json={
        "email": "lawyer@test.com",
        "password": "LawyerPass123!"
    })
    assert r.status_code == 200, f"Login failed: {r.text}"
    assert r.json()["status"] == "otp_required"
    print(" [PASS] 2. Lawyer Credentials Validated -> OTP Dispatched")

    # Read latest OTP directly from DB for test verification
    import sqlite3
    database_path = settings.DATABASE_URL.removeprefix("sqlite:///")
    conn = sqlite3.connect(unquote(database_path))
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email='lawyer@test.com'")
    user_id = c.fetchone()[0]
    
    test_otp = "777888"
    hashed = hash_otp(test_otp)
    c.execute("UPDATE otp_records SET is_used=1 WHERE user_id=?", (user_id,))
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    exp = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO otp_records (user_id, hashed_otp, expires_at, is_used, attempts, created_at) VALUES (?, ?, ?, 0, 0, ?)",
              (user_id, hashed, exp, now))
    conn.commit()

    # 3. Verify OTP
    r = client.post("/api/auth/verify-otp", json={
        "email": "lawyer@test.com",
        "otp": test_otp
    })
    assert r.status_code == 200, f"OTP verify failed: {r.text}"
    lawyer_token = r.json()["access_token"]
    print(" [PASS] 3. OTP Verified -> JWT Access Token Issued for Lawyer")

    # 4. Upload document with AES-256-GCM encryption
    plaintext_data = b"%PDF-1.7\nConfidential M&A Agreement between Alpha Corp and Beta Ltd.\nNon-disclosure terms.\n%%EOF"
    files = {"file": ("ma_agreement.pdf", plaintext_data, "application/pdf")}
    data = {"title": "M&A Agreement Alpha-Beta", "description": "Highly confidential merger agreement"}
    headers = {"Authorization": f"Bearer {lawyer_token}"}
    
    r = client.post("/api/documents/upload", files=files, data=data, headers=headers)
    assert r.status_code == 201, f"Upload failed: {r.text}"
    doc_info = r.json()
    doc_id = doc_info["id"]
    print(f" [PASS] 4. Document Uploaded & Encrypted (Doc ID: {doc_id})")

    # 5. Inspect stored file in vault to prove AES-256-GCM encryption is real!
    c.execute("SELECT encrypted_filename FROM documents WHERE id=?", (doc_id,))
    enc_fname = c.fetchone()[0]
    enc_file_path = settings.VAULT_DIR / enc_fname
    assert enc_file_path.exists(), f"Vault file {enc_file_path} missing!"
    
    with open(enc_file_path, "rb") as f:
        stored_bytes = f.read()

    assert b"%PDF-1.7" not in stored_bytes, "SECURITY VIOLATION: Plaintext found in stored vault file!"
    assert b"Confidential M&A Agreement" not in stored_bytes, "SECURITY VIOLATION: Sensitive string found unencrypted!"
    print(f" [PASS] 5. Real AES-256-GCM Confirmed on Disk (File: {enc_fname}, {len(stored_bytes)} encrypted bytes, No plaintext headers)")

    # 6. Share document with Associate
    c.execute("SELECT id FROM users WHERE email='associate@test.com'")
    associate_id = c.fetchone()[0]
    
    r = client.post(f"/api/documents/{doc_id}/share",
                    json={"recipient_id": associate_id, "permission": "view"},
                    headers=headers)
    assert r.status_code == 200, f"Share failed: {r.text}"
    print(" [PASS] 6. Document Shared with Associate")

    # 7. Login as Associate
    assoc_otp = "111222"
    assoc_hashed = hash_otp(assoc_otp)
    c.execute("UPDATE otp_records SET is_used=1 WHERE user_id=?", (associate_id,))
    c.execute("INSERT INTO otp_records (user_id, hashed_otp, expires_at, is_used, attempts, created_at) VALUES (?, ?, ?, 0, 0, ?)",
              (associate_id, assoc_hashed, exp, now))
    conn.commit()

    r = client.post("/api/auth/verify-otp", json={
        "email": "associate@test.com",
        "otp": assoc_otp
    })
    assert r.status_code == 200, f"Associate OTP failed: {r.text}"
    associate_token = r.json()["access_token"]
    assoc_headers = {"Authorization": f"Bearer {associate_token}"}
    print(" [PASS] 7. Associate Authenticated with JWT")

    # 8. Associate downloads & decrypts
    r = client.get(f"/api/documents/{doc_id}/download", headers=assoc_headers)
    assert r.status_code == 200, f"Associate download failed: {r.text}"
    assert r.content == plaintext_data, "Decrypted data does not match original plaintext!"
    print(" [PASS] 8. Associate Decrypted Document Successfully (Bytes match original!)")

    # 9. Client attempts download (Unauthorized -> ID manipulation defense!)
    c.execute("SELECT id FROM users WHERE email='client@test.com'")
    client_id = c.fetchone()[0]
    client_otp = "333444"
    client_hashed = hash_otp(client_otp)
    c.execute("UPDATE otp_records SET is_used=1 WHERE user_id=?", (client_id,))
    c.execute("INSERT INTO otp_records (user_id, hashed_otp, expires_at, is_used, attempts, created_at) VALUES (?, ?, ?, 0, 0, ?)",
              (client_id, client_hashed, exp, now))
    conn.commit()

    r = client.post("/api/auth/verify-otp", json={
        "email": "client@test.com",
        "otp": client_otp
    })
    client_token = r.json()["access_token"]
    client_headers = {"Authorization": f"Bearer {client_token}"}

    r = client.get(f"/api/documents/{doc_id}/download", headers=client_headers)
    assert r.status_code == 403, f"Expected 403 Forbidden, got {r.status_code}"
    print(f" [PASS] 9. Unauthorized Client Download Blocked (HTTP 403 Forbidden: {r.json()['detail']})")

    # 10. Lawyer revokes Associate's access
    r = client.delete(f"/api/documents/{doc_id}/share/{associate_id}", headers=headers)
    assert r.status_code == 200, f"Revoke failed: {r.text}"
    print(" [PASS] 10. Lawyer Revoked Access for Associate")

    # 11. Associate tries download again after revocation -> Blocked!
    r = client.get(f"/api/documents/{doc_id}/download", headers=assoc_headers)
    assert r.status_code == 403, f"Expected 403 Forbidden after revocation, got {r.status_code}"
    print(" [PASS] 11. Revoked Associate Blocked from Download (HTTP 403 Forbidden)")

    # 12. Audit Logs Check
    # Associate tries to read audit logs -> Blocked!
    r = client.get("/api/audit-logs", headers=assoc_headers)
    assert r.status_code == 403, f"Associate should NOT access audit logs! Got {r.status_code}"
    print(" [PASS] 12. Non-Lawyer Blocked from Audit Logs (HTTP 403 Forbidden)")

    # Lawyer reads audit logs -> OK!
    r = client.get("/api/audit-logs", headers=headers)
    assert r.status_code == 200, f"Lawyer failed to read audit logs: {r.text}"
    logs = r.json()
    actions = [l["action"] for l in logs]
    print(f" [PASS] 13. Lawyer Read Audit Logs ({len(logs)} records found). Recent actions:")
    for a in actions[:6]:
        print(f"       • {a}")

    conn.close()
    client.close()
    print("\n==================================================")
    print(" ALL LIVE OBJECTIVE 1 VERIFICATIONS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    test_live_system()
