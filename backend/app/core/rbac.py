from typing import List, Callable
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import jwt

from ..database import get_db
from ..models import User, UserRole, RevokedToken
from ..core.security import decode_access_token
from ..services.audit_service import log_audit_event

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Validates JWT Bearer token and returns authenticated User entity.
    Raises 401 Unauthorized if token is missing or invalid.
    """
    if not token:
        # Check Authorization header manually in case auto_error was disabled
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    try:
        payload = decode_access_token(token)
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = int(user_id_str)
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    token_jti = payload.get("jti")
    if not token_jti or db.query(RevokedToken.id).filter(RevokedToken.jti == token_jti).first():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked or is invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return user

def require_roles(allowed_roles: List[str]) -> Callable:
    """
    Factory creating a FastAPI dependency enforcing Role-Based Access Control (RBAC).
    Rejects unauthorized access with 403 Forbidden and records an audit log entry.
    """
    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        if current_user.role not in allowed_roles:
            # Audit log security violation
            log_audit_event(
                db=db,
                action="Access denied",
                success=False,
                user=current_user,
                request=request,
                details=f"RBAC violation: User role '{current_user.role}' attempted to access endpoint requiring {allowed_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Insufficient permissions for role '{current_user.role}'. Required: {allowed_roles}",
            )
        return current_user

    return role_checker

# Predefined role dependencies
require_lawyer = require_roles(["lawyer"])
require_associate = require_roles(["associate"])
require_client = require_roles(["client"])
require_lawyer_or_associate = require_roles(["lawyer", "associate"])
require_any_user = require_roles(["lawyer", "associate", "client"])
