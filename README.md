# LegaVault – AI-Powered Legal Document Management and Analysis System

## OBJECTIVE 1: Secure Role-Based Document Transfer System
**Author:** Final-Year Engineering Project – Objective 1 Implementation  
**Security Standards:** AES-256-GCM (Authenticated Encryption), Backend RBAC, Two-Factor OTP, Cryptographic Tamper Detection, SQLite Audit Logs.

---

## 1. Project Overview

**LegaVault** is an AI-powered legal document management and intelligence platform. 

This repository houses the complete, working production implementation for **OBJECTIVE 1**:
> *"Design a secure, role-based document transfer system using AES-256 encryption, RBAC, OTP-based authentication, and audit logs for confidential lawyer-client-associate sharing."*

This implementation is **fully functional** (not a mock/UI-only prototype). Document files stored on disk in the vault are encrypted with real authenticated **AES-256-GCM** using unique 96-bit nonces. Access control is strictly enforced on the FastAPI backend to prevent ID manipulation attacks, OTP verification is backed by keyed HMAC-SHA-256 and rate limiting, and access attempts (both authorized and unauthorized) are captured in SQLite audit logs.

---

## 2. System Architecture

The architecture separates concerns cleanly into modular components designed for straightforward integration with teammates' modules (Objective 2: OCR/NLP, Objective 3: RAG Semantic Search, Objective 4: Outcome Prediction/XAI).

```
                      +-----------------------------+
                      | React Frontend (Vite / SPA) |
                      |  - Role Indicator Badges    |
                      |  - 2FA OTP Screen           |
                      |  - Vault Document Manager   |
                      |  - Sharing & Revoke Modals  |
                      |  - Forensic Audit Viewer    |
                      +--------------+--------------+
                                     | HTTP / JSON (Bearer JWT)
                                     v
                      +-----------------------------+
                      |    FastAPI Backend Server   |
                      |     (Port 8000 / Uvicorn)   |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+-----------------+         +-----------------+         +-----------------+
|  Core Security  |         |   Encryption    |         |  Audit Service  |
|  - JWT HS256    |         |  - AES-256-GCM  |         |  - Forensic Log |
|  - bcrypt Salt  |         |  - 96-bit Nonce |         |  - Lawyer Only  |
|  - Backend RBAC |         |  - Isolated     |         |  - Zero Secret  |
|  - OTP Engine   |         |    Vault Storage|         |    Exposure     |
+--------+--------+         +--------+--------+         +--------+--------+
         |                           |                           |
         +---------------------------+---------------------------+
                                     |
                                     v
                       +---------------------------+
                       | SQLite Database Engine    |
                       |  - users                  |
                       |  - documents              |
                       |  - document_shares        |
                       |  - otp_records            |
                       |  - audit_logs             |
                       +---------------------------+
```

---

## 3. Core Features

1. **Backend Role-Based Access Control (RBAC):**
   - Three distinct roles: **Lawyer**, **Associate**, and **Client**.
   - Enforced via FastAPI dependencies; requests with manipulated IDs or invalid roles are rejected with `HTTP 403 Forbidden` regardless of client state.
2. **Real AES-256-GCM Document Encryption:**
   - Authenticated symmetric cipher (`AESGCM` from Python `cryptography`).
   - Unique 12-byte (96-bit) cryptographically random nonce generated per document.
   - Plaintext files are never written to disk. The isolated vault directory stores only `[Nonce (12B)] + [Ciphertext] + [GCM Tag (16B)]`.
3. **Two-Factor Authentication (2FA OTP):**
   - 6-digit cryptographically random OTP generated via `secrets.randbelow`.
   - Expires in 5 minutes; single-use invalidation; 60-second cooldown rate limit.
   - Stored in SQLite as a keyed HMAC-SHA-256 hash (never plain text; a database-only leak is not enough to brute force the six-digit code offline).
   - Local development can print OTP to the backend console. Production mode sends codes to the user's registered email through authenticated SMTP with STARTTLS (or SMTP SSL).
4. **Confidential Sharing & Immediate Revocation:**
   - Document owners (Lawyers) can share documents with registered Associates or Clients.
   - Access can be revoked instantly.
   - Revoked users are barred from downloading or reading document metadata.
5. **Security Audit Trails:**
   - Logs registration, login successes/failures, OTP requests/verifications, document uploads, encryptions, sharing events, downloads, decryptions, access denials, and revocations.
   - Passwords, OTP codes, and encryption keys are strictly omitted.
   - Accessible only to authenticated Lawyers.

---

## 4. Technology Stack

- **Backend:** Python 3.10+ with FastAPI and Uvicorn
- **Database:** SQLite (SQLAlchemy ORM)
- **Encryption:** Python `cryptography` library (`AESGCM` AEAD)
- **Passwords & Auth:** `bcrypt` salted hashing + `PyJWT` (JSON Web Tokens)
- **Frontend:** React 18, Vite, Lucide Icons, Modern CSS
- **Testing:** Pytest, HTTPX

---

## 5. Folder Structure

```
LegaVault/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── encryption.py     # AES-256-GCM encryption & decryption
│   │   │   ├── otp.py            # 6-digit OTP generation, keyed hash, dev console logger
│   │   │   ├── rbac.py           # Backend RBAC dependency enforcement
│   │   │   └── security.py       # bcrypt hashing & JWT token issuance
│   │   ├── routers/
│   │   │   ├── auth.py           # /auth endpoints (register, login, OTP verify)
│   │   │   ├── documents.py      # /documents endpoints (upload, AES encrypt, share, download)
│   │   │   ├── audit.py          # /audit-logs endpoint (Lawyer only)
│   │   │   └── users.py          # /users listing endpoint
│   │   ├── services/
│   │   │   └── audit_service.py  # Audit logging engine
│   │   ├── config.py             # Settings, environment loading, vault path
│   │   ├── database.py           # SQLite engine & session maker
│   │   ├── models.py             # SQLAlchemy models (users, documents, shares, OTPs, revoked tokens, audits)
│   │   ├── schemas.py            # Pydantic V2 request & response schemas
│   │   └── main.py               # FastAPI application entry point & static mount
│   ├── storage/
│   │   └── vault/                # Isolated directory holding AES-256 encrypted .enc files
│   ├── tests/
│   │   └── test_objective1.py    # Automated Objective 1 security and workflow tests
│   ├── legavault_secure.db       # SQLite database file
│   ├── seed_data.py              # Script to populate default test users
│   ├── requirements.txt          # Python backend dependencies
│   └── .env.example              # Template configuration
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx        # Top brand & role badge
│   │   │   ├── AuthView.jsx      # Login, Register & 2FA OTP forms
│   │   │   ├── Dashboard.jsx     # Main workspace tabs & stats
│   │   │   ├── DocumentList.jsx  # Encrypted records table with Decrypt & Download
│   │   │   ├── UploadModal.jsx   # Encrypt & Upload form
│   │   │   ├── ShareModal.jsx    # User sharing & revocation manager
│   │   │   └── AuditLogViewer.jsx# Compliance log viewer
│   │   ├── api.js                # Frontend API client with JWT handling
│   │   ├── App.jsx               # Root React component
│   │   └── index.css             # High-contrast legal security console styling
│   ├── dist/                     # Pre-built production assets
│   ├── package.json              # Node dependencies
│   └── vite.config.js            # Vite configuration with API proxy
├── run_backend.sh                # Bash launcher for backend (macOS / Linux)
├── run_backend.bat               # Batch launcher for backend (Windows)
├── run_frontend.sh               # Bash launcher for frontend (macOS / Linux)
├── run_frontend.bat              # Batch launcher for frontend (Windows)
├── verify_live_api.py            # Live end-to-end verification script
├── .env.example                  # Root environment template
└── README.md                     # Comprehensive documentation
```

---

## 6. Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Node.js 18+ and npm

### 1. Python Virtual Environment Setup

#### On Windows:
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r backend/requirements.txt
```

#### On macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Ensure `.env` contains:
```ini
SECRET_KEY=<64 random hexadecimal characters>
AES_SECRET_KEY=<64 random hexadecimal characters>
LAWYER_REGISTRATION_CODE=<long random setup code>
DATABASE_URL=sqlite:///./backend/legavault_secure.db
VAULT_DIR=./backend/storage/vault
OTP_DEV_MODE=True
OTP_EXPIRE_MINUTES=5
OTP_COOLDOWN_SECONDS=60
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```
Generate secrets with `python -c "import secrets; print(secrets.token_hex(32))"`. `AES_SECRET_KEY` must be exactly 64 hex characters. The backend fails to start if either cryptographic secret is missing or malformed. Keep `.env` private; `.env.example` contains placeholders only. Lawyer signup requires the setup code from `LAWYER_REGISTRATION_CODE`; ordinary users cannot assign themselves lawyer privileges.

The standalone Flask app (`python app.py` or `bash start.sh`) also supports Gemini-powered legal Q&A. Add your key to the project `.env` file as `GEMINI_API_KEY=your_key`, optionally set `GEMINI_MODEL=gemini-3.5-flash`, then restart the Flask app. The key is read server-side and `.env` is ignored by Git. The FastAPI/React Objective 1 interface does not currently call Gemini.

### 2FA OTP delivery

OTP verification is part of sign-in: enter the account email and password, then enter the code delivered to that email. Codes expire after `OTP_EXPIRE_MINUTES`, can be used once, and resend requests are limited by `OTP_COOLDOWN_SECONDS`. The database stores only a keyed OTP hash.

For local development, keep `OTP_DEV_MODE=True`; the 6-digit code appears only in the terminal running the FastAPI backend. For actual email delivery, set `OTP_DEV_MODE=False` and configure SMTP in the project-root `.env` file:

```ini
OTP_DEV_MODE=False
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-sender@gmail.com
SMTP_PASSWORD=your-provider-app-password
SMTP_FROM_EMAIL=your-sender@gmail.com
SMTP_USE_SSL=False
```

Use SMTP credentials or an app password from your mail provider, not your normal email account password. Port 587 uses STARTTLS. For an SSL-only SMTP service (commonly port 465), set its host and port and use `SMTP_USE_SSL=True`. Restart the backend after changing `.env`. The backend reports `otp_mode: EMAIL` at `/api/health`; `DEVELOPMENT` means it is writing codes to the backend terminal. If email delivery fails, login returns an error and the undelivered code is invalidated; check the SMTP host, port, credential, sender authorization, and server connectivity.

To try the full flow locally:

1. Copy `.env.example` to `.env`, generate `SECRET_KEY` and `AES_SECRET_KEY` with `python -c "import secrets; print(secrets.token_hex(32))"`, and set `LAWYER_REGISTRATION_CODE` to a private random value.
2. Install backend dependencies and seed accounts using the installation steps below. Keep `OTP_DEV_MODE=True` if you do not have an SMTP account configured.
3. Start the backend from the project root with `bash run_backend.sh` and the React app in another terminal with `bash run_frontend.sh`.
4. Open `http://localhost:5173`, sign in using one of the seeded account credentials, then copy the OTP from the backend terminal (development) or email inbox (SMTP mode) into the verification screen.
5. To verify delivery via email, configure the SMTP values above, set `OTP_DEV_MODE=False`, restart the backend, and repeat sign-in. `http://localhost:8000/api/health` should report `EMAIL`.

For macOS/Linux the backend setup commands from the repository root are `python3 -m venv venv`, `source venv/bin/activate`, and `pip install -r backend/requirements.txt`; use `python backend/seed_data.py` once to create the sample users. In another terminal, run `cd frontend && npm install` once, then `npm run dev`. On Windows use the supplied `.bat` launchers and create/activate a virtual environment with the corresponding Windows commands.

For the standalone Flask app, clients and associates can upload files to their own submitted cases, while judges can upload files to cases in the judge panel. The uploader sets and confirms an 8–128 character code for each file; the same code is required to download it. Files are encrypted before storage and incorrect download codes are rate-limited. Share each file's code privately with its intended reviewer.

When sharing a vault document, the owner sets and confirms a new 8–128 character code for that recipient. The same code cannot be reused for another share. The owner gives it to the recipient separately, and the recipient enters it in the vault to unlock download and analysis access for 30 minutes. Only keyed code hashes are stored; re-sharing requires a fresh code, and revoking access removes the grant.

After enabling this manual-code flow, owners should re-share any older active grants so recipients can use a code the owner selected. Case files uploaded before per-file codes were added must be uploaded again to attach an unlock code.

### 3. Database Initialization & Seeding Test Users
Run the database seed script to populate default test accounts:
```bash
python backend/seed_data.py
```
This initializes the SQLite tables and seeds the fictional test users:
- **Lawyer:** `lawyer@test.com` / `LawyerPass123!`
- **Associate:** `associate@test.com` / `AssociatePass123!`
- **Client:** `client@test.com` / `ClientPass123!`

### 4. Node.js & React Frontend Setup
```bash
cd frontend
npm install
npm run build
cd ..
```

---

## 7. How to Start the Application

### Option A: Running Both Servers Concurrently (Recommended for Development)

1. **Start the Backend:**
   - **Windows:** Double-click `run_backend.bat` or run:
     ```cmd
     python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
     ```
   - **macOS / Linux:** Run `bash run_backend.sh`

   Backend will be running at `http://127.0.0.1:8000`.  
   Interactive OpenAPI Swagger docs: `http://127.0.0.1:8000/docs`.

2. **Start the Frontend:**
   - **Windows:** Double-click `run_frontend.bat` or run:
     ```cmd
     cd frontend
     npm run dev
     ```
   - **macOS / Linux:** Run `bash run_frontend.sh`

   Open `http://localhost:5173` in your web browser.

### Option B: Single-Server Unified Mode
The FastAPI backend is configured to automatically serve the pre-built React frontend at `http://127.0.0.1:8000/app/`. Simply start the backend, and you can access the full interactive web application directly!

---

## 8. How Security Features Work

### 8.1. How Two-Factor OTP Works
1. When a user submits valid email and password credentials, the backend generates a random 6-digit code:
   `code = str(secrets.randbelow(900000) + 100000)`
2. A keyed HMAC-SHA-256 hash is saved in the `otp_records` table along with a 5-minute UTC expiration timestamp.
3. In **DEVELOPMENT MODE** (`OTP_DEV_MODE=True`), the plain OTP code is logged directly to the backend development console:
   ```
   ================================================================
    [DEVELOPMENT ONLY] TWO-FACTOR AUTHENTICATION OTP DISPATCH
    Recipient : lawyer@test.com
    OTP Code  : 849201
    Expires At: 2026-10-08 14:15:00 UTC (5 minutes)
    NOTE      : In production, this OTP is delivered via SMS/Email.
   ================================================================
   ```
4. The user copies the 6-digit code into the web application.
5. Upon verification, the record is immediately marked `is_used = True` (single-use constraint).
6. A signed JWT bearer token is issued. Logout saves its token ID to `revoked_tokens`, so the backend rejects replay of that token.

### 8.2. How AES-256-GCM Encryption Works
1. **Master Key:** `AES_SECRET_KEY` must decode to exactly 32 cryptographically random bytes (256 bits) and is held only by the backend.
2. **Per-File Nonce:** For every uploaded document, `secrets.token_bytes(12)` generates a fresh 96-bit Initialization Vector (Nonce).
3. **Authenticated Encryption:** `AESGCM(key).encrypt(nonce, plaintext, None)` generates ciphertext and appends a 16-byte GCM authentication tag.
4. **Storage Format:** Stored in `backend/storage/vault/<uuid>.enc` as:
   `[ 12-byte Nonce ] + [ Ciphertext ] + [ 16-byte Authentication Tag ]`
   Plaintext files are never stored on disk.
5. **Decryption & Tamper Check:** Authorized download requests read the encrypted file, extract the nonce, and call `AESGCM.decrypt()`. If the ciphertext or tag was altered in any way, decryption fails with a cryptographic integrity error.

### 8.3. How Role-Based Access Control (RBAC) Works
Permissions are enforced at the HTTP router level using FastAPI dependency injection. The JWT identifies a user; the current role is loaded from SQLite for each request, so the server does not trust a role value supplied by the browser or token.
- `require_lawyer`: Used on `/documents/upload`, `/documents/{id}/share`, `/documents/{id}/share/{user_id}`, `/users`, and `/audit-logs`.
- `require_any_user`: Validates caller is authenticated.
- **ID Manipulation Prevention:** On `/documents/{id}` and `/documents/{id}/download`, the server queries the database:
  1. Is `doc.owner_id == current_user.id`?
  2. Does a record exist in `document_shares` where `recipient_id == current_user.id`?
  If neither condition is true, access is immediately rejected with `403 Forbidden`, and an `Access denied` event is written to the audit log.

### 8.4. How Audit Logging Works
The `audit_logs` table records all security events:
- **Logged fields:** Timestamp (UTC), User ID, User Role, User Email, Action, Document ID, Success/Failure flag, IP Address, Details.
- **Strict Privacy Rule:** Passwords, OTP codes, and encryption keys are NEVER recorded.
- **Role Clearance:** Only users with the `lawyer` role can query the `/audit-logs` endpoint. Requests by Associates or Clients return `403 Forbidden`.

### 8.5. API Endpoints

All routes are available under `/api` (the root aliases are retained for compatibility). Protected routes require `Authorization: Bearer <JWT>`.

| Method | Endpoint | Access |
| --- | --- | --- |
| `POST` | `/auth/register` | Public; lawyer role additionally requires setup code |
| `POST` | `/auth/login` | Public; validates password and starts OTP challenge |
| `POST` | `/auth/request-otp` or `/auth/resend-otp` | Public; cooldown limited |
| `POST` | `/auth/verify-otp` | Public; consumes the OTP and returns JWT |
| `GET` | `/auth/me` | Authenticated |
| `POST` | `/auth/logout` | Authenticated; revokes current JWT |
| `GET` | `/users` | Lawyer only; recipient directory |
| `POST` | `/documents/upload` | Lawyer only; encrypts before writing to vault |
| `GET` | `/documents` | Authenticated; owned/shared documents only |
| `GET` | `/documents/{id}` | Owner or active share recipient |
| `POST` | `/documents/{id}/share` | Owning lawyer only; Associate or Client recipients |
| `DELETE` | `/documents/{id}/share/{recipient_id}` | Owning lawyer only |
| `GET` | `/documents/{id}/download` | Owner or active share recipient; decrypts server-side |
| `GET` | `/audit-logs` | Lawyer only |
| `GET` | `/health` | Public health and mode summary |

---

## 9. Testing & Verification

### Running the Automated Pytest Suite
The automated suite covers the requested workflows plus lawyer setup-code protection, server-side logout, and user-directory RBAC:
```bash
python -m pytest backend/tests/test_objective1.py -v
```
**Test Coverage:**
- `test_01_register_lawyer`: Lawyer registration
- `test_02_register_associate`: Associate registration
- `test_03_register_client`: Client registration
- `test_04_login_correct_credentials`: Verification of credentials triggering OTP dispatch
- `test_05_reject_incorrect_password`: 401 Unauthorized on invalid password
- `test_06_generate_otp`: Verify OTP record is created with a keyed HMAC hash
- `test_07_verify_correct_otp`: Successful OTP verification and JWT token issuance
- `test_08_reject_incorrect_otp`: 400 Bad Request on invalid OTP code
- `test_09_reject_expired_otp`: 400 Bad Request on expired OTP code
- `test_10_lawyer_uploads_pdf`: Uploading and storing PDF
- `test_11_verify_stored_file_is_encrypted`: Validates stored disk file is ciphertext (no `%PDF` header or plaintext)
- `test_12_lawyer_shares_with_associate`: Lawyer shares document with Associate
- `test_13_associate_downloads_and_decrypts`: Associate downloads and verifies decrypted bytes match original
- `test_14_client_cannot_access_unshared_document`: 403 Forbidden when Client accesses unshared document
- `test_15_unauthorized_download_denied`: 403 Forbidden on ID manipulation download attack
- `test_16_lawyer_revokes_access`: Lawyer revokes access for Associate
- `test_17_associate_denied_after_revocation`: Associate blocked from accessing revoked document
- `test_18_audit_logs_recorded_and_rbac_protected`: Audit log populated and blocked from non-lawyers
- `test_19_lawyer_registration_requires_setup_code`: Lawyer signup without the configured code is rejected
- `test_20_logout_revokes_bearer_token`: Replaying a logged-out JWT returns 401
- `test_21_associates_cannot_enumerate_users`: Non-lawyer user-directory request returns 403

### Running the Live End-to-End Verification Script
With the backend running on port 8000, run:
```bash
python verify_live_api.py
```
The test setup injects its own lawyer setup code into isolated test configuration. It does not use project credentials and writes test data to a temporary database and vault.
This performs a full live test against the active HTTP server and prints confirmation of all passes.

---

## 10. How to Test Manually via the Web Interface

1. Open `http://localhost:5173` (or `http://127.0.0.1:8000/app/`).
2. Run `python backend/seed_data.py` to create the fictional local test accounts, or register a Lawyer using the setup code in `.env` and register an Associate/Client in the form. The seed accounts are for local development only.
3. Click **Verify Credentials & Request OTP** after choosing an account.
4. Check your backend terminal window for the 6-digit OTP code banner.
5. Enter the 6-digit code and click **Verify OTP & Access Vault**.
6. Click **Encrypt & Upload Document**, choose a test PDF or text file, and click **Encrypt & Store**. Notice the AES-256 badge and SHA-256 checksum.
7. Click **Share / Revoke** on the document, choose a registered Associate or Client, and click **Grant**.
8. Sign out.
9. Log in as **Associate** (`associate@test.com` / `AssociatePass123!`). Retrieve the OTP from the backend console.
10. Click **Shared With Me**, click **Decrypt & Download**, and confirm the file opens properly.
11. Sign out and log in as **Client** (`client@test.com` / `ClientPass123!`).
12. Confirm that the Client cannot see or download the Associate's document (access denied).
13. Log back in as **Lawyer**, click the **Audit Logs** tab, and observe the complete forensic trail of all actions and access denials.

---

## 11. Security Limitations & Production Considerations

1. **Development OTP Mode:** The dev console OTP mode is intended for local academic evaluation. In production, connect `backend/app/core/otp.py` to Twilio (SMS) or AWS SES / SendGrid (Email).
2. **Key Storage:** In this local project, `AES_SECRET_KEY` is loaded from `.env`. In enterprise production, store keys in an external Hardware Security Module (HSM) or AWS KMS / HashiCorp Vault.
3. **Transport Security:** For local testing, HTTP is used. Production deployments must enforce HTTPS / TLS 1.3 to protect JWT tokens in transit.

---

## 12. Future Integration Guide for Teammates

This Objective 1 module is built to be the foundational security core for the full LegaVault system:

- **Objective 2 (OCR & Document Summarization):**
  When the OCR worker needs to process a document, it can invoke `read_and_decrypt_file(encrypted_filename)` in memory, extract text using Tesseract/DistilBART, and encrypt generated summaries using `save_encrypted_file()`. Plaintext is never left on the filesystem.
- **Objective 3 (RAG Semantic Search):**
  Embeddings can be indexed with document ID references. When a user executes a search, the RAG router queries `DocumentShare` to filter search results so users only retrieve passages from documents they have clearance to view.
- **Objective 4 (Case Outcome Prediction & XAI):**
  Case prediction endpoints can be protected using the `require_any_user` or `require_lawyer` dependencies from `backend.app.core.rbac`, and prediction queries can be audited using `log_audit_event()`.
