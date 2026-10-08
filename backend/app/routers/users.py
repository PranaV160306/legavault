from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import UserResponse
from ..core.rbac import require_lawyer

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("", response_model=List[UserResponse])
def list_users(
    current_user: User = Depends(require_lawyer),
    db: Session = Depends(get_db)
):
    """
    List registered users for sharing destination selection.
    Excludes password hashes and sensitive authentication secrets.
    """
    users = db.query(User).filter(User.is_active == True).order_by(User.full_name).all()
    return users
