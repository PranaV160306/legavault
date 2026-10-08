from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict

# User schemas
class UserRegister(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=12, max_length=128)
    role: str = Field(..., description="Role must be one of: lawyer, associate, client")
    lawyer_registration_code: Optional[str] = Field(None, max_length=128)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6)

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class LoginInitResponse(BaseModel):
    status: str = "otp_required"
    email: str
    message: str

# Document schemas
class DocumentShareCreate(BaseModel):
    recipient_id: int
    permission: str = "view"

class DocumentShareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    document_id: int
    shared_by_id: int
    recipient_id: int
    recipient_email: Optional[str] = None
    recipient_name: Optional[str] = None
    recipient_role: Optional[str] = None
    permission: str
    created_at: datetime

class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    title: str
    description: Optional[str] = None
    original_filename: str
    file_size: int
    mime_type: str
    owner_id: int
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    sha256_hash: str
    created_at: datetime
    is_owner: bool = False
    shares: List[DocumentShareResponse] = []

# Audit Log schemas
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    timestamp: datetime
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    user_role: Optional[str] = None
    action: str
    document_id: Optional[int] = None
    success: bool
    ip_address: Optional[str] = None
    details: Optional[str] = None
