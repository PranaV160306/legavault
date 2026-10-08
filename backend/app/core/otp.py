import secrets
import hmac
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional
from sqlalchemy.orm import Session
from ..models import OTPRecord, User
from ..config import settings

def hash_otp(otp_code: str) -> str:
    """Keyed hash prevents offline recovery of low-entropy OTPs from a DB dump."""
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), otp_code.strip().encode("utf-8"), "sha256").hexdigest()

def generate_secure_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP."""
    # secrets.randbelow(900000) produces [0, 899999]; adding 100000 gives [100000, 999999]
    return str(secrets.randbelow(900000) + 100000)

def log_dev_otp(email: str, otp_code: str, expires_at: datetime):
    """
    Outputs OTP to backend development console only.
    Clearly labeled for local student project testing.
    Never exposed through API responses or web frontend.
    """
    if settings.OTP_DEV_MODE:
        border = "=" * 64
        print(f"\n{border}")
        print(" [DEVELOPMENT ONLY] TWO-FACTOR AUTHENTICATION OTP DISPATCH")
        print(f" Recipient : {email}")
        print(f" OTP Code  : {otp_code}")
        print(f" Expires At: {expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')} ({settings.OTP_EXPIRE_MINUTES} minutes)")
        print(" NOTE      : In production, this OTP is delivered via secure SMS/Email.")
        print(f"{border}\n", flush=True)

def create_and_store_otp(db: Session, user: User) -> Tuple[bool, str, Optional[int]]:
    """
    Checks cooldown, creates a fresh 6-digit OTP, stores its keyed HMAC-SHA-256 hash in SQLite,
    and logs the code to dev console.
    Returns (success, message, remaining_cooldown_seconds_if_failed).
    """
    now = datetime.now(timezone.utc)
    
    # Check cooldown against the most recent unexpired or recent OTP
    last_otp = db.query(OTPRecord).filter(
        OTPRecord.user_id == user.id
    ).order_by(OTPRecord.created_at.desc()).first()
    
    if last_otp:
        # SQLite may return naive datetime; ensure comparison is in UTC
        created_time = last_otp.created_at
        if created_time.tzinfo is None:
            created_time = created_time.replace(tzinfo=timezone.utc)
            
        elapsed = (now - created_time).total_seconds()
        if elapsed < settings.OTP_COOLDOWN_SECONDS and not last_otp.is_used:
            remaining = int(settings.OTP_COOLDOWN_SECONDS - elapsed)
            return False, f"Please wait {remaining} seconds before requesting a new OTP.", remaining

    # Invalidate prior unused OTPs for this user
    db.query(OTPRecord).filter(
        OTPRecord.user_id == user.id,
        OTPRecord.is_used == False
    ).update({"is_used": True})

    # Generate fresh OTP and expiration
    otp_code = generate_secure_otp()
    hashed = hash_otp(otp_code)
    expires_at = now + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    record = OTPRecord(
        user_id=user.id,
        hashed_otp=hashed,
        expires_at=expires_at,
        is_used=False,
        attempts=0,
        created_at=now
    )
    db.add(record)
    db.commit()

    # Output to dev console
    log_dev_otp(user.email, otp_code, expires_at)
    return True, "OTP generated and sent successfully.", None

def verify_user_otp(db: Session, user: User, candidate_otp: str) -> Tuple[bool, str]:
    """
    Verifies candidate OTP against the user's latest active OTP record.
    Checks:
    - Existence of active OTP
    - Single-use constraint
    - 5-minute expiration
    - Maximum failed attempts (3 attempts)
    - Constant-time keyed HMAC-SHA-256 match
    """
    now = datetime.now(timezone.utc)
    
    # Find latest unused OTP for user
    record = db.query(OTPRecord).filter(
        OTPRecord.user_id == user.id,
        OTPRecord.is_used == False
    ).order_by(OTPRecord.created_at.desc()).first()

    if not record:
        return False, "No active OTP request found. Please request a new OTP."

    # Expiry check
    exp_time = record.expires_at
    if exp_time.tzinfo is None:
        exp_time = exp_time.replace(tzinfo=timezone.utc)

    if now > exp_time:
        record.is_used = True
        db.commit()
        return False, "OTP has expired. Please request a new OTP."

    # Max attempts check
    if record.attempts >= 3:
        record.is_used = True
        db.commit()
        return False, "Too many failed attempts. OTP has been invalidated. Please request a new OTP."

    candidate_hash = hash_otp(candidate_otp)
    if not hmac.compare_digest(candidate_hash, record.hashed_otp):
        record.attempts += 1
        db.commit()
        return False, "Invalid OTP code. Please check and try again."

    # Successful verification - mark as used immediately (single-use constraint)
    record.is_used = True
    db.commit()
    return True, "OTP verified successfully."
