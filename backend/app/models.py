import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Enum
)
from sqlalchemy.orm import relationship
from .database import Base

class UserRole(str, enum.Enum):
    LAWYER = "lawyer"
    ASSOCIATE = "associate"
    CLIENT = "client"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)  # "lawyer", "associate", "client"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    owned_documents = relationship("Document", back_populates="owner", cascade="all, delete-orphan")
    shares_given = relationship("DocumentShare", foreign_keys="DocumentShare.shared_by_id", back_populates="shared_by")
    shares_received = relationship("DocumentShare", foreign_keys="DocumentShare.recipient_id", back_populates="recipient")
    otp_records = relationship("OTPRecord", back_populates="user", cascade="all, delete-orphan")
    revoked_tokens = relationship("RevokedToken", back_populates="user", cascade="all, delete-orphan")

class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    original_filename = Column(String(255), nullable=False)
    encrypted_filename = Column(String(255), unique=True, nullable=False)
    file_size = Column(Integer, nullable=False)  # plaintext size in bytes
    mime_type = Column(String(100), default="application/octet-stream", nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    sha256_hash = Column(String(64), nullable=False)  # SHA-256 of plaintext for tamper detection
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    owner = relationship("User", back_populates="owned_documents")
    shares = relationship("DocumentShare", back_populates="document", cascade="all, delete-orphan")

class DocumentShare(Base):
    __tablename__ = "document_shares"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    shared_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    permission = Column(String(50), default="view", nullable=False)  # "view", "download"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    document = relationship("Document", back_populates="shares")
    shared_by = relationship("User", foreign_keys=[shared_by_id], back_populates="shares_given")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="shares_received")

class OTPRecord(Base):
    __tablename__ = "otp_records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    hashed_otp = Column(String(64), nullable=False)  # HMAC-SHA-256 of 6-digit OTP
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = relationship("User", back_populates="otp_records")

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user = relationship("User", back_populates="revoked_tokens")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user_id = Column(Integer, nullable=True)
    user_email = Column(String(255), nullable=True)
    user_role = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)  # e.g., "Registration", "Login success", "Document encrypted"
    document_id = Column(Integer, nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    ip_address = Column(String(50), nullable=True)
    details = Column(Text, nullable=True)
