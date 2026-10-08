import io
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Document, DocumentShare, User, UserRole
from ..schemas import (
    DocumentResponse, DocumentShareCreate, DocumentShareResponse
)
from ..core.rbac import (
    get_current_user, require_lawyer, require_any_user
)
from ..core.encryption import (
    save_encrypted_file, read_and_decrypt_file
)
from ..services.audit_service import log_audit_event

router = APIRouter(prefix="/documents", tags=["Documents & AES-256 Encryption"])

def _format_doc_response(doc: Document, current_user: User) -> DocumentResponse:
    is_owner = (doc.owner_id == current_user.id)
    share_responses = []
    if is_owner:
        for s in doc.shares:
            share_responses.append(DocumentShareResponse(
                id=s.id,
                document_id=s.document_id,
                shared_by_id=s.shared_by_id,
                recipient_id=s.recipient_id,
                recipient_email=s.recipient.email if s.recipient else None,
                recipient_name=s.recipient.full_name if s.recipient else None,
                recipient_role=s.recipient.role if s.recipient else None,
                permission=s.permission,
                created_at=s.created_at
            ))
    return DocumentResponse(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        original_filename=doc.original_filename,
        file_size=doc.file_size,
        mime_type=doc.mime_type,
        owner_id=doc.owner_id,
        owner_email=doc.owner.email if doc.owner else None,
        owner_name=doc.owner.full_name if doc.owner else None,
        sha256_hash=doc.sha256_hash,
        created_at=doc.created_at,
        is_owner=is_owner,
        shares=share_responses
    )

@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: User = Depends(require_lawyer),
    db: Session = Depends(get_db)
):
    """
    Lawyer-only: Uploads and immediately encrypts document using AES-256-GCM.
    1. Reads plaintext file stream.
    2. Encrypts bytes with AES-256-GCM and unique 96-bit nonce.
    3. Saves ONLY the encrypted payload to the isolated vault directory.
    4. Computes SHA-256 checksum of original plaintext for integrity audit.
    5. Records audit events: 'Document uploaded' and 'Document encrypted'.
    """
    contents = await file.read()
    if not contents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty."
        )

    # Generate unique encrypted vault filename
    encrypted_filename = f"{uuid.uuid4().hex}.enc"
    
    try:
        vault_path, sha256_hash = save_encrypted_file(contents, encrypted_filename)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AES-256 encryption failure: {str(e)}"
        )

    # Create document record
    doc = Document(
        title=title.strip(),
        description=description.strip() if description else None,
        original_filename=file.filename or "unnamed_document",
        encrypted_filename=encrypted_filename,
        file_size=len(contents),
        mime_type=file.content_type or "application/octet-stream",
        owner_id=current_user.id,
        sha256_hash=sha256_hash
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    # Log audit events
    log_audit_event(
        db=db,
        action="Document uploaded",
        success=True,
        user=current_user,
        document_id=doc.id,
        request=request,
        details=f"Document '{doc.title}' ({doc.original_filename}, {doc.file_size} bytes) uploaded."
    )
    log_audit_event(
        db=db,
        action="Document encrypted",
        success=True,
        user=current_user,
        document_id=doc.id,
        request=request,
        details=f"Document encrypted via AES-256-GCM (Ciphertext file: {encrypted_filename})."
    )

    return _format_doc_response(doc, current_user)

@router.get("", response_model=List[DocumentResponse])
def list_documents(
    current_user: User = Depends(require_any_user),
    db: Session = Depends(get_db)
):
    """
    List documents accessible to current user.
    - Lawyers: View owned documents and any documents shared with them.
    - Associates & Clients: View ONLY documents explicitly shared with them.
    """
    if current_user.role == UserRole.LAWYER.value:
        # Owned docs + docs shared with this lawyer
        shared_doc_ids = db.query(DocumentShare.document_id).filter(
            DocumentShare.recipient_id == current_user.id
        ).all()
        shared_ids = [s[0] for s in shared_doc_ids]
        
        docs = db.query(Document).filter(
            (Document.owner_id == current_user.id) | (Document.id.in_(shared_ids))
        ).order_by(Document.created_at.desc()).all()
    else:
        # Strictly shared documents only
        shared_doc_ids = db.query(DocumentShare.document_id).filter(
            DocumentShare.recipient_id == current_user.id
        ).all()
        shared_ids = [s[0] for s in shared_doc_ids]
        
        docs = db.query(Document).filter(
            Document.id.in_(shared_ids)
        ).order_by(Document.created_at.desc()).all()

    return [_format_doc_response(d, current_user) for d in docs]

@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_details(
    document_id: int,
    request: Request,
    current_user: User = Depends(require_any_user),
    db: Session = Depends(get_db)
):
    """
    Retrieve document metadata.
    Enforces authorization check and protects against ID manipulation attacks:
    If requester is neither the owner nor an active recipient, raises 403 Forbidden.
    """
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    # Permission verification
    is_owner = (doc.owner_id == current_user.id)
    is_shared = False
    if not is_owner:
        is_shared = db.query(DocumentShare).filter(
            DocumentShare.document_id == document_id,
            DocumentShare.recipient_id == current_user.id
        ).first() is not None

    if not is_owner and not is_shared:
        log_audit_event(
            db=db,
            action="Access denied",
            success=False,
            user=current_user,
            document_id=document_id,
            request=request,
            details=f"Unauthorized access attempt to document #{document_id} (ID manipulation prevented)."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not have permission to access this confidential document."
        )

    log_audit_event(
        db=db,
        action="Document accessed",
        success=True,
        user=current_user,
        document_id=document_id,
        request=request,
        details=f"Document metadata accessed by {current_user.email} ({current_user.role})."
    )

    return _format_doc_response(doc, current_user)

@router.post("/{document_id}/share", response_model=DocumentShareResponse)
def share_document(
    document_id: int,
    share_in: DocumentShareCreate,
    request: Request,
    current_user: User = Depends(require_lawyer),
    db: Session = Depends(get_db)
):
    """
    Lawyer-only: Share document with a specific registered Associate or Client.
    """
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    # Must be document owner to share
    if doc.owner_id != current_user.id:
        log_audit_event(
            db=db,
            action="Access denied",
            success=False,
            user=current_user,
            document_id=document_id,
            request=request,
            details="Attempted to share document not owned by requester."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can share this document."
        )

    # Verify recipient exists
    recipient = db.query(User).filter(User.id == share_in.recipient_id).first()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient user not found."
        )

    if recipient.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot share document with yourself."
        )

    if recipient.role not in {UserRole.ASSOCIATE.value, UserRole.CLIENT.value}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Documents can only be shared with an associate or client account.",
        )

    # Check existing share
    existing_share = db.query(DocumentShare).filter(
        DocumentShare.document_id == document_id,
        DocumentShare.recipient_id == recipient.id
    ).first()

    if existing_share:
        existing_share.permission = share_in.permission
        db.commit()
        db.refresh(existing_share)
        share_record = existing_share
    else:
        share_record = DocumentShare(
            document_id=document_id,
            shared_by_id=current_user.id,
            recipient_id=recipient.id,
            permission=share_in.permission
        )
        db.add(share_record)
        db.commit()
        db.refresh(share_record)

    log_audit_event(
        db=db,
        action="Document shared",
        success=True,
        user=current_user,
        document_id=document_id,
        request=request,
        details=f"Document shared with recipient {recipient.email} (Role: {recipient.role}, Permission: {share_in.permission})."
    )

    return DocumentShareResponse(
        id=share_record.id,
        document_id=share_record.document_id,
        shared_by_id=share_record.shared_by_id,
        recipient_id=share_record.recipient_id,
        recipient_email=recipient.email,
        recipient_name=recipient.full_name,
        recipient_role=recipient.role,
        permission=share_record.permission,
        created_at=share_record.created_at
    )

@router.delete("/{document_id}/share/{recipient_id}")
def revoke_document_share(
    document_id: int,
    recipient_id: int,
    request: Request,
    current_user: User = Depends(require_lawyer),
    db: Session = Depends(get_db)
):
    """
    Lawyer-only: Revoke a user's access to a document.
    """
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    if doc.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can revoke access."
        )

    share = db.query(DocumentShare).filter(
        DocumentShare.document_id == document_id,
        DocumentShare.recipient_id == recipient_id
    ).first()

    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active share record found for this recipient."
        )

    recipient_email = share.recipient.email if share.recipient else f"User #{recipient_id}"
    db.delete(share)
    db.commit()

    log_audit_event(
        db=db,
        action="Access revoked",
        success=True,
        user=current_user,
        document_id=document_id,
        request=request,
        details=f"Document access revoked for user {recipient_email} (ID: {recipient_id})."
    )

    return {"message": f"Access successfully revoked for user {recipient_email}."}

@router.get("/{document_id}/download")
def download_document(
    document_id: int,
    request: Request,
    current_user: User = Depends(require_any_user),
    db: Session = Depends(get_db)
):
    """
    Download and decrypt document using AES-256-GCM.
    1. Verifies caller is document owner OR authorized share recipient.
    2. If unauthorized: returns 403 Forbidden and logs 'Access denied'.
    3. Reads ciphertext from vault and decrypts in-memory using AES-256-GCM.
    4. Validates GCM authentication tag to prevent tampering.
    5. Logs 'Document downloaded' and 'Document decrypted'.
    6. Streams original decrypted file to client.
    """
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    # Permission check
    is_owner = (doc.owner_id == current_user.id)
    is_shared = False
    if not is_owner:
        is_shared = db.query(DocumentShare).filter(
            DocumentShare.document_id == document_id,
            DocumentShare.recipient_id == current_user.id
        ).first() is not None

    if not is_owner and not is_shared:
        log_audit_event(
            db=db,
            action="Access denied",
            success=False,
            user=current_user,
            document_id=document_id,
            request=request,
            details=f"Unauthorized download attempt for document #{document_id} by {current_user.email}."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not have permission to download this document."
        )

    try:
        decrypted_bytes = read_and_decrypt_file(doc.encrypted_filename)
    except Exception as e:
        log_audit_event(
            db=db,
            action="Document decrypted",
            success=False,
            user=current_user,
            document_id=document_id,
            request=request,
            details=f"AES-256-GCM decryption failed: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document decryption failed: cryptographic integrity check failed."
        )

    log_audit_event(
        db=db,
        action="Document decrypted",
        success=True,
        user=current_user,
        document_id=document_id,
        request=request,
        details=f"AES-256-GCM authenticated decryption succeeded for {doc.original_filename}."
    )
    log_audit_event(
        db=db,
        action="Document downloaded",
        success=True,
        user=current_user,
        document_id=document_id,
        request=request,
        details=f"Decrypted document {doc.original_filename} streamed to {current_user.email}."
    )

    return StreamingResponse(
        io.BytesIO(decrypted_bytes),
        media_type=doc.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{doc.original_filename}"',
            "Content-Length": str(len(decrypted_bytes)),
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )
