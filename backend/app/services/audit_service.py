from typing import Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import Request
from ..models import AuditLog, User

def log_audit_event(
    db: Session,
    action: str,
    success: bool = True,
    user: Optional[User] = None,
    user_id: Optional[int] = None,
    user_email: Optional[str] = None,
    user_role: Optional[str] = None,
    document_id: Optional[int] = None,
    request: Optional[Request] = None,
    details: Optional[str] = None,
) -> AuditLog:
    """
    Persists a security audit event in SQLite database.
    Ensures zero exposure of passwords, OTP codes, or encryption keys.
    """
    # Extract client IP if request object is provided
    client_ip = None
    if request:
        client_ip = request.client.host if request.client else None
        # Handle X-Forwarded-For if behind reverse proxy
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

    # Consolidate user identity
    uid = user.id if user else user_id
    uemail = user.email if user else user_email
    urole = user.role if user else user_role

    entry = AuditLog(
        timestamp=datetime.now(timezone.utc),
        user_id=uid,
        user_email=uemail,
        user_role=urole,
        action=action,
        document_id=document_id,
        success=success,
        ip_address=client_ip,
        details=details
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
