from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import hmac
import jwt

from ..database import get_db
from ..models import User, UserRole, RevokedToken
from ..schemas import (
    UserRegister, UserLogin, OTPVerify, OTPRequest,
    UserResponse, TokenResponse, LoginInitResponse
)
from ..core.security import hash_password, verify_password, create_access_token
from ..core.otp import create_and_store_otp, verify_user_otp
from ..core.rbac import get_current_user, oauth2_scheme
from ..config import settings
from ..services.audit_service import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication & OTP"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserRegister, request: Request, db: Session = Depends(get_db)):
    """
    Register a new user with role 'lawyer', 'associate', or 'client'.
    Enforces strong password hashing via bcrypt and creates an audit record.
    """
    role_normalized = user_in.role.strip().lower()
    if role_normalized not in ["lawyer", "associate", "client"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'lawyer', 'associate', or 'client'."
        )

    if role_normalized == UserRole.LAWYER.value:
        configured_code = settings.LAWYER_REGISTRATION_CODE
        if not configured_code or not user_in.lawyer_registration_code or not hmac.compare_digest(
            configured_code, user_in.lawyer_registration_code
        ):
            log_audit_event(db=db, action="Registration", success=False, user_email=user_in.email.lower(),
                            user_role=role_normalized, request=request,
                            details="Lawyer registration rejected: valid setup code required.")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Lawyer registration requires a valid setup code.")

    # Check for existing email
    existing = db.query(User).filter(User.email == user_in.email.lower()).first()
    if existing:
        log_audit_event(
            db=db,
            action="Registration",
            success=False,
            user_email=user_in.email.lower(),
            request=request,
            details="Registration attempted with existing email."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    hashed_pw = hash_password(user_in.password)
    user = User(
        email=user_in.email.lower(),
        full_name=user_in.full_name.strip(),
        hashed_password=hashed_pw,
        role=role_normalized,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db=db,
        action="Registration",
        success=True,
        user=user,
        request=request,
        details=f"User successfully registered with role '{user.role}'."
    )
    return user

@router.post("/login", response_model=LoginInitResponse)
def login(login_in: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Step 1 of Authentication: Verify credentials and issue 2FA OTP.
    Logs failed attempts and prints OTP to development console in dev mode.
    """
    user = db.query(User).filter(User.email == login_in.email.lower()).first()
    
    if not user or not verify_password(login_in.password, user.hashed_password):
        log_audit_event(
            db=db,
            action="Login failure",
            success=False,
            user_email=login_in.email.lower(),
            user_id=user.id if user else None,
            user_role=user.role if user else None,
            request=request,
            details="Invalid email or password credentials provided."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    # Generate and store OTP
    try:
        success, msg, remaining = create_and_store_otp(db, user)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    if not success:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=msg
        )

    log_audit_event(
        db=db,
        action="OTP requested",
        success=True,
        user=user,
        request=request,
        details="OTP generated for user authentication login sequence."
    )

    return LoginInitResponse(
        status="otp_required",
        email=user.email,
        message="Credentials verified. A 6-digit OTP has been sent to your registered email address."
    )

@router.post("/request-otp")
@router.post("/resend-otp")
def resend_otp(otp_req: OTPRequest, request: Request, db: Session = Depends(get_db)):
    """
    Resends OTP with cooldown rate limiting.
    """
    user = db.query(User).filter(User.email == otp_req.email.lower()).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account associated with this email."
        )

    try:
        success, msg, remaining = create_and_store_otp(db, user)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    if not success:
        log_audit_event(
            db=db,
            action="OTP requested",
            success=False,
            user=user,
            request=request,
            details=f"Rate limit triggered for OTP resend: {msg}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=msg
        )

    log_audit_event(
        db=db,
        action="OTP requested",
        success=True,
        user=user,
        request=request,
        details="Resent 6-digit OTP code."
    )
    return {"message": "A new OTP code has been sent to your registered email address."}

@router.post("/verify-otp", response_model=TokenResponse)
def verify_otp(verify_in: OTPVerify, request: Request, db: Session = Depends(get_db)):
    """
    Step 2 of Authentication: Verifies 6-digit OTP and generates JWT access token.
    Enforces expiration, single-use, and attempt count limits.
    """
    user = db.query(User).filter(User.email == verify_in.email.lower()).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    success, message = verify_user_otp(db, user, verify_in.otp)
    if not success:
        log_audit_event(
            db=db,
            action="OTP verification",
            success=False,
            user=user,
            request=request,
            details=f"OTP verification failed: {message}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    # Issue JWT token
    token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role}
    )

    log_audit_event(
        db=db,
        action="OTP verification",
        success=True,
        user=user,
        request=request,
        details="OTP verified successfully."
    )
    log_audit_event(
        db=db,
        action="Login success",
        success=True,
        user=user,
        request=request,
        details=f"User successfully signed in with role '{user.role}'."
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )

@router.get("/me", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_user)):
    """Retrieve currently authenticated user information."""
    return current_user

@router.post("/logout")
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
):
    """
    Records logout in security audit logs.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti")
        if jti:
            db.add(RevokedToken(jti=jti, user_id=current_user.id,
                                expires_at=datetime.fromtimestamp(payload["exp"], timezone.utc)))
            db.commit()
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired authentication token.")

    log_audit_event(
        db=db,
        action="Logout",
        success=True,
        user=current_user,
        request=request,
        details="User logged out."
    )
    return {"message": "Successfully logged out."}
