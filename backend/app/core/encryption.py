import os
import secrets
import hashlib
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from ..config import settings

def get_aes_key() -> bytes:
    """
    Retrieve or derive a 256-bit (32-byte) key for AES-256-GCM.
    If the configured key is 64 hex characters, converts it directly to 32 bytes.
    Otherwise, uses HKDF-SHA256 to derive a cryptographically sound 32-byte key.
    """
    raw_key = settings.AES_SECRET_KEY.strip()
    if len(raw_key) == 64:
        try:
            return bytes.fromhex(raw_key)
        except ValueError:
            pass
    
    # Derive 32 bytes using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"legavault_doc_aes_salt_v1",
        info=b"legavault_document_encryption",
    )
    return hkdf.derive(raw_key.encode("utf-8"))

def encrypt_document_bytes(plaintext: bytes) -> bytes:
    """
    Encrypts plaintext document bytes using AES-256-GCM.
    
    1. Generates a fresh, unique 12-byte (96-bit) cryptographically random nonce.
    2. Encrypts plaintext with AES-256-GCM (produces ciphertext + 16-byte authentication tag).
    3. Prepends the 12-byte nonce to the encrypted payload.
    
    Format of returned payload:
    [ 12-byte Nonce ] + [ Ciphertext ] + [ 16-byte Authentication Tag ]
    """
    key = get_aes_key()
    aesgcm = AESGCM(key)
    
    # 96-bit nonce as recommended by NIST SP 800-38D for GCM
    nonce = secrets.token_bytes(12)
    
    # Encrypt (AESGCM appends 16-byte GCM authentication tag automatically)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    
    # Prepend nonce so decryption has access to the exact IV used
    encrypted_payload = nonce + ciphertext_with_tag
    return encrypted_payload

def decrypt_document_bytes(encrypted_payload: bytes) -> bytes:
    """
    Decrypts AES-256-GCM encrypted payload and verifies data integrity.
    
    1. Extracts the 12-byte nonce from the beginning of the payload.
    2. Decrypts the remaining ciphertext and validates the 16-byte GCM tag.
    3. Returns original plaintext bytes.
    
    Raises cryptography.exceptions.InvalidTag if ciphertext or tag was altered.
    """
    if len(encrypted_payload) < 28: # 12 bytes nonce + 16 bytes tag minimum
        raise ValueError("Invalid encrypted payload: data too short to contain nonce and GCM tag.")
    
    key = get_aes_key()
    aesgcm = AESGCM(key)
    
    nonce = encrypted_payload[:12]
    ciphertext_with_tag = encrypted_payload[12:]
    
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    return plaintext

def save_encrypted_file(plaintext: bytes, target_filename: str) -> Tuple[Path, str]:
    """
    Encrypts plaintext bytes with AES-256-GCM and writes only the encrypted payload to disk.
    Returns (path_to_encrypted_file, sha256_hash_of_plaintext).
    """
    # Calculate SHA-256 hash of original plaintext for integrity recording
    plaintext_hash = hashlib.sha256(plaintext).hexdigest()
    
    encrypted_data = encrypt_document_bytes(plaintext)
    
    file_path = settings.VAULT_DIR / target_filename
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
        
    return file_path, plaintext_hash

def read_and_decrypt_file(target_filename: str) -> bytes:
    """
    Reads an AES-256-GCM encrypted file from the vault and returns decrypted plaintext.
    """
    file_path = settings.VAULT_DIR / target_filename
    if not file_path.exists():
        raise FileNotFoundError(f"Encrypted document file {target_filename} not found in vault.")
        
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
        
    return decrypt_document_bytes(encrypted_data)
