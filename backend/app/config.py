import os
from pathlib import Path
from dotenv import load_dotenv

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_VAULT_DIR = BASE_DIR / "storage" / "vault"
DEFAULT_DB_PATH = BASE_DIR / "legavault_secure.db"

# Load the project-level .env before reading settings. Values already present in
# the process environment take precedence, which is useful for deployments.
PROJECT_ROOT = BASE_DIR.parent
load_dotenv(PROJECT_ROOT / ".env")

class Settings:
    PROJECT_NAME: str = "LegaVault - Secure Document System (Objective 1)"
    VERSION: str = "1.0.0"
    
    # Environment
    ENV: str = os.getenv("ENV", "development")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}")
    
    # JWT Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours
    
    # AES-256-GCM Document Encryption Key
    # Must be 32 bytes (64 hex characters) or a high-entropy string that will be HKDF-derived
    AES_SECRET_KEY: str = os.getenv("AES_SECRET_KEY", "")

    # Lawyer accounts can only be registered by someone holding this
    # out-of-band setup code. Keep it secret and rotate it after setup.
    LAWYER_REGISTRATION_CODE: str = os.getenv("LAWYER_REGISTRATION_CODE", "")
    CORS_ORIGINS: list[str] = [origin.strip() for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",") if origin.strip()]
    
    # Vault storage directory for AES-256 encrypted files
    VAULT_DIR: Path = Path(os.getenv("VAULT_DIR", str(DEFAULT_VAULT_DIR)))
    
    # OTP Configuration
    OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRE_MINUTES", "5"))
    OTP_COOLDOWN_SECONDS: int = int(os.getenv("OTP_COOLDOWN_SECONDS", "60"))
    OTP_DEV_MODE: bool = os.getenv("OTP_DEV_MODE", "True").lower() in ("true", "1", "yes")
    # SMTP delivery is used whenever development-console delivery is disabled.
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "")
    SMTP_USE_SSL: bool = os.getenv("SMTP_USE_SSL", "False").lower() in ("true", "1", "yes")

settings = Settings()

if not settings.OTP_DEV_MODE and not all((settings.SMTP_HOST, settings.SMTP_USERNAME, settings.SMTP_PASSWORD, settings.SMTP_FROM_EMAIL)):
    raise RuntimeError("Production OTP email requires SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, and SMTP_FROM_EMAIL.")

if len(settings.SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be set to at least 32 characters in the project .env or process environment.")
aes_secret = settings.AES_SECRET_KEY.strip()
try:
    valid_aes_key = len(bytes.fromhex(aes_secret)) == 32
except ValueError:
    valid_aes_key = False
if not valid_aes_key:
    raise RuntimeError("AES_SECRET_KEY must be exactly 64 hexadecimal characters (32 random bytes).")

settings.VAULT_DIR.mkdir(parents=True, exist_ok=True)
