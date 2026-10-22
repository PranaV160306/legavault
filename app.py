import os, json, sqlite3, urllib.request, io, uuid, time, base64, hashlib, hmac, secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ocr_nlp, rag, predict as pred, shutil, importlib.util
from functools import wraps
from flask import Flask, g, render_template, request, redirect, session, url_for, flash, jsonify, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash

def load_local_env():
    """Load optional local settings without overriding values already in the environment."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

load_local_env()

app = Flask(__name__)
def _secret():   # unique per install, so cookies from any other project on 127.0.0.1 are never valid here
    if os.environ.get("SECRET_KEY"): return os.environ["SECRET_KEY"]
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret.key")
    if not os.path.exists(p):
        with open(p, "w") as f: f.write(secrets.token_hex(32))
    os.chmod(p, 0o600)
    with open(p, encoding="utf-8") as f: return f.read().strip()
app.secret_key = _secret()
app.config["SESSION_COOKIE_NAME"] = "legavault_session"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"},
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)
DB = os.path.join(os.path.dirname(__file__), "legal.db")
JUDGE_CODE = os.environ.get("JUDGE_CODE", "").strip()   # judge registration stays disabled until an owner sets an invite code
API_KEY = os.environ.get("GEMINI_API_KEY")                # optional: enables Gemini-powered answers
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")

SYSTEM = ("You are a careful legal information assistant for Indian users. Explain in plain language, "
          "cite retrieved legal sources by their supplied citations, never invent a statute or judgment, and say when "
          "the retrieved materials do not answer the question. List practical next steps and remind the user you give "
          "general information, not legal advice.")

FALLBACK = {
    "consumer": "Consumer disputes: send a written notice to the seller, then file a complaint with the District Consumer Commission under the Consumer Protection Act, 2019 (e-Daakhil portal). Keep invoices and chats as evidence.",
    "rent": "Tenancy issues: check your rent agreement and the State Rent Control Act. A landlord generally cannot evict without notice or court order. Keep rent receipts and send notices in writing.",
    "fir": "To report a cognisable offence, file an FIR at the nearest police station (or online / Zero FIR). If refused, send the complaint to the Superintendent of Police or approach a Magistrate under BNSS s.173/175.",
    "divorce": "Divorce can be by mutual consent (after 6 months' separation, waivable by court) or contested on legal grounds under the applicable personal law. Maintenance and custody are decided separately.",
    "bail": "Bail depends on whether the offence is bailable. For non-bailable offences apply to the Magistrate/Sessions Court; anticipatory bail is sought before arrest. A lawyer should file this urgently.",
    "cheque": "Cheque bounce (s.138 NI Act): send a legal notice within 30 days of the return memo; if unpaid in 15 days, file a complaint within one month.",
}

def ai_answer(q):
    if API_KEY:
        try:
            req = urllib.request.Request(
                f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
                data=json.dumps({"systemInstruction": {"parts": [{"text": SYSTEM}]},
                                 "contents": [{"role": "user", "parts": [{"text": ctx_prompt(q)}]}],
                                 "generationConfig": {"maxOutputTokens": 1000}}).encode(),
                headers={"x-goog-api-key": API_KEY, "content-type": "application/json"}, method="POST")
            result = json.load(urllib.request.urlopen(req, timeout=40))
            return "\n".join(part.get("text", "") for part in result["candidates"][0]["content"]["parts"] if part.get("text"))
        except Exception as e:
            app.logger.error("AI service request failed (%s)", type(e).__name__)
            return "The AI service is temporarily unavailable. Please try again or use Legal Research to review the local sources."
    for k, v in FALLBACK.items():
        if k in q.lower():
            return v + "\n\n(Demo mode: set GEMINI_API_KEY for full AI answers. This is general information, not legal advice.)"
    hits = rag.get().search(q, 3)
    if hits:
        return "Closest matches in the LegaVault knowledge base:\n\n" + "\n\n".join(f"{h['title']} ({h['citation']}): {h['text']}" for h in hits) + "\n\n(Demo mode: set GEMINI_API_KEY for full AI answers. General information, not legal advice.)"
    return ("Demo mode: I know basics on consumer, rent, FIR, divorce, bail and cheque issues. "
            "Set GEMINI_API_KEY to get full AI answers to any question.")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d: d.close()

def csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = session["_csrf_token"] = secrets.token_urlsafe(32)
    return token

@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_state_changes():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("_csrf_token", "")
        supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(400, "The form expired. Reload the page and try again.")

@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

@app.errorhandler(400)
def bad_request(error):
    message = getattr(error, "description", "The request could not be processed.")
    if request.is_json: return jsonify(error=message), 400
    return render_template("error.html", code=400, heading="Please refresh and try again", message=message), 400

@app.errorhandler(404)
def not_found(_error):
    if request.is_json: return jsonify(error="The requested item was not found."), 404
    return render_template("error.html", code=404, heading="Page not found", message="The page or item may have been removed or the address may be incorrect."), 404

@app.errorhandler(413)
def payload_too_large(_error):
    message = "Uploads are limited to 16 MB. Choose a smaller file and try again."
    if request.is_json: return jsonify(error=message), 413
    return render_template("error.html", code=413, heading="Upload is too large", message=message), 413

@app.errorhandler(500)
def server_error(_error):
    app.logger.exception("Unhandled application error")
    if request.is_json: return jsonify(error="Something went wrong. Please try again."), 500
    return render_template("error.html", code=500, heading="Something went wrong", message="The request could not be completed. Please try again."), 500

def init():
    with sqlite3.connect(DB) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, description TEXT,
            status TEXT DEFAULT 'Pending', ruling TEXT, judge_id INTEGER, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS case_files(id TEXT PRIMARY KEY, case_id INTEGER NOT NULL, owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, code_hash TEXT,
            created TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(case_id) REFERENCES cases(id), FOREIGN KEY(owner_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS case_file_code_throttle(ip TEXT PRIMARY KEY, failures INTEGER NOT NULL,
            window_start REAL NOT NULL, blocked_until REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS docs(id TEXT PRIMARY KEY, owner_id INTEGER, filename TEXT, size INTEGER, sha256 TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS access(doc_id TEXT, user_id INTEGER, granted_by INTEGER, code_hash TEXT, share_id TEXT,
            manual_code INTEGER NOT NULL DEFAULT 0, UNIQUE(doc_id,user_id));
        CREATE TABLE IF NOT EXISTS share_code_history(code_hash TEXT PRIMARY KEY, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS share_code_throttle(ip TEXT PRIMARY KEY, failures INTEGER NOT NULL,
            window_start REAL NOT NULL, blocked_until REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS auth_throttle(ip TEXT PRIMARY KEY, failures INTEGER, window_start REAL, blocked_until REAL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, email TEXT, action TEXT, doc_id TEXT, detail TEXT, ip TEXT, created TEXT, prev_hash TEXT, hash TEXT);
        CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, user_id INTEGER, q TEXT, a TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit(user_id, id);
        CREATE INDEX IF NOT EXISTS idx_docs_owner ON docs(owner_id, created);
        CREATE INDEX IF NOT EXISTS idx_access_user ON access(user_id, doc_id);""")
        access_columns = {row[1] for row in c.execute("PRAGMA table_info(access)").fetchall()}
        if "code_hash" not in access_columns:
            c.execute("ALTER TABLE access ADD COLUMN code_hash TEXT")
        if "share_id" not in access_columns:
            c.execute("ALTER TABLE access ADD COLUMN share_id TEXT")
        if "manual_code" not in access_columns:
            c.execute("ALTER TABLE access ADD COLUMN manual_code INTEGER NOT NULL DEFAULT 0")
        case_file_columns = {row[1] for row in c.execute("PRAGMA table_info(case_files)").fetchall()}
        if "code_hash" not in case_file_columns:
            c.execute("ALTER TABLE case_files ADD COLUMN code_hash TEXT")
    os.chmod(DB, 0o600)

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "uid" not in session: return redirect(url_for("login"))
            if not db().execute("SELECT 1 FROM users WHERE id=?", (session["uid"],)).fetchone():   # stale cookie from an old database
                session.clear(); return redirect(url_for("login"))
            if roles and session.get("role") not in roles:
                flash("You do not have access to that page."); return redirect(home_url())
            return f(*a, **k)
        return w
    return deco

def home_url():
    return url_for("login") if "uid" not in session else url_for("judge" if session.get("role") == "judge" else "dashboard")

@app.route("/")
def home():
    return redirect(home_url())

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name, email = request.form.get("name", "").strip(), request.form.get("email", "").strip().lower()
        pw, role = request.form.get("password", ""), request.form.get("role", "client")
        if not name or len(name) > 120 or not email or len(email) > 254: flash("Enter a name (up to 120 characters) and a valid email address.")
        elif len(pw) < 8: flash("Password must be at least 8 characters.")
        elif role not in ROLES: flash("Invalid role.")
        elif role == "judge" and (not JUDGE_CODE or request.form.get("code") != JUDGE_CODE):
            flash("Judge registration is disabled or the invite code is invalid.")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                             (name, email, generate_password_hash(pw), role)); db().commit()
                flash("Account created. Please log in."); return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.")
    return render_template("signup.html", judge_enabled=bool(JUDGE_CODE))

@app.route("/login", methods=["GET", "POST"])
def login():
    # Discard queued messages from older app versions, including the retired OTP failure.
    if request.method == "GET":
        session.pop("_flashes", None)
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if login_throttled(ip):
            audit("LOGIN_THROTTLED", detail=ip[:80]); flash("Too many sign-in attempts. Please wait before trying again.")
            return render_template("login.html")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and check_password_hash(u["password"], password):
            db().execute("DELETE FROM auth_throttle WHERE ip=?", (ip,)); db().commit()
            session.clear(); session.update(uid=u["id"], name=u["name"], role=u["role"], email=u["email"])
            session.permanent = True
            audit("LOGIN_SUCCESS", user=u)
            return redirect(url_for("judge" if u["role"] == "judge" else "dashboard"))
        record_login_failure(ip)
        audit("LOGIN_FAILED", detail=email[:80]); flash("Email or password is incorrect.")
    return render_template("login.html")

def login_throttled(ip):
    row = db().execute("SELECT failures, window_start, blocked_until FROM auth_throttle WHERE ip=?", (ip,)).fetchone()
    if not row: return False
    now = time.time()
    if now < row["blocked_until"]: return True
    if now - row["window_start"] >= 900:
        db().execute("DELETE FROM auth_throttle WHERE ip=?", (ip,)); db().commit(); return False
    return False

def record_login_failure(ip):
    now = time.time()
    row = db().execute("SELECT failures, window_start FROM auth_throttle WHERE ip=?", (ip,)).fetchone()
    if not row or now - row["window_start"] >= 900:
        db().execute("INSERT OR REPLACE INTO auth_throttle(ip,failures,window_start,blocked_until) VALUES(?,1,?,0)", (ip, now))
    else:
        failures = row["failures"] + 1
        blocked_until = row["window_start"] + 900 if failures >= 8 else 0
        db().execute("UPDATE auth_throttle SET failures=?,blocked_until=? WHERE ip=?", (failures, blocked_until, ip))
    db().commit()

@app.route("/logout", methods=["POST"])
def logout():
    if "uid" in session: audit("LOGOUT")
    session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required("client", "lawyer", "associate", "judge")
def dashboard():
    cases = db().execute("SELECT * FROM cases WHERE user_id=? ORDER BY id DESC", (session["uid"],)).fetchall()
    chats = db().execute("SELECT * FROM chats WHERE user_id=? ORDER BY id DESC LIMIT 5", (session["uid"],)).fetchall()
    return render_template("dashboard.html", cases=cases, files_by_case=case_files_by_case(cases), chats=chats, ai_enabled=bool(API_KEY))

@app.route("/ask", methods=["POST"])
@login_required("client", "lawyer", "associate", "judge")
def ask():
    payload = request.get_json(silent=True) or {}
    q = payload.get("q", "")
    if not isinstance(q, str): return jsonify(a="Please type a question."), 400
    q = q.strip()[:2000]
    if not q: return jsonify(a="Please type a question."), 400
    a = ai_answer(q)
    db().execute("INSERT INTO chats(user_id,q,a) VALUES(?,?,?)", (session["uid"], q, a)); db().commit()
    return jsonify(a=a)

@app.route("/cases/new", methods=["POST"])
@login_required("client", "lawyer", "associate", "judge")
def new_case():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    if not title or len(title) > 200 or not description or len(description) > 10000:
        flash("Enter a title (up to 200 characters) and case details (up to 10,000 characters).")
        return redirect(url_for("dashboard"))
    db().execute("INSERT INTO cases(user_id,title,description) VALUES(?,?,?)",
                 (session["uid"], title, description)); db().commit()
    flash("Case submitted to the judge panel."); return redirect(url_for("dashboard"))

@app.route("/judge")
@login_required("judge")
def judge():
    cases = db().execute("SELECT c.*, u.name AS client FROM cases c JOIN users u ON u.id=c.user_id ORDER BY (c.status='Pending') DESC, c.id DESC").fetchall()
    files_by_case = case_files_by_case(cases)
    return render_template("judge.html", cases=cases, files_by_case=files_by_case, pending=sum(1 for c in cases if c["status"] == "Pending"))

@app.route("/judge/<int:cid>", methods=["POST"])
@login_required("judge")
def rule(cid):
    status = request.form.get("status", "")
    ruling = request.form.get("ruling", "").strip()
    if status not in {"Pending", "Under Review", "Resolved", "Dismissed"} or not ruling or len(ruling) > 10000:
        flash("Choose a valid status and enter a ruling or remark (up to 10,000 characters).")
        return redirect(url_for("judge"))
    if not db().execute("SELECT 1 FROM cases WHERE id=?", (cid,)).fetchone(): abort(404)
    db().execute("UPDATE cases SET status=?, ruling=?, judge_id=? WHERE id=?",
                 (status, ruling, session["uid"], cid)); db().commit()
    flash(f"Case #{cid} updated."); return redirect(url_for("judge"))

@app.route("/judge/<int:cid>/ai", methods=["POST"])
@login_required("judge")
def ai_brief(cid):
    c = db().execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    if not c: return jsonify(error="Case not found."), 404
    return jsonify(a=ai_answer(f"Summarise the key legal issues and relevant law for a judge:\n{c['title']}\n{c['description']}"))


# ---------- Secure document transfer: AES-256-GCM, RBAC, hash-chained audit log ----------
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
ROLES = {"client", "lawyer", "associate", "judge"}
PERMS = {
    "client": {"upload", "share", "audit"},
    "lawyer": {"upload", "share", "audit"},
    "associate": {"upload", "share", "audit"},
    "judge": {"audit"},
}
SHARE_TO = {"client": {"lawyer"}, "lawyer": {"client", "associate"},
            "associate": {"client", "lawyer"}, "judge": set()}
VAULT = os.path.join(os.path.dirname(__file__), "vault"); os.makedirs(VAULT, mode=0o700, exist_ok=True); os.chmod(VAULT, 0o700)
DOC_ROLES = ("client", "lawyer", "associate", "judge")

CASE_UPLOAD_ROLES = {"client", "associate", "judge"}
CASE_FILE_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "tif", "tiff"}

def hash_unlock_code(code):
    return hmac.new(str(app.secret_key).encode("utf-8"), code.encode("utf-8"), hashlib.sha256).hexdigest()

def case_files_by_case(cases):
    if not cases:
        return {}
    ids = [case["id"] for case in cases]
    marks = ",".join("?" for _ in ids)
    rows = db().execute(
        f"SELECT * FROM case_files WHERE case_id IN ({marks}) ORDER BY created DESC, id DESC", ids
    ).fetchall()
    grouped = {case_id: [] for case_id in ids}
    for row in rows:
        grouped[row["case_id"]].append(row)
    return grouped

def record_case_file_code_failure():
    """Throttle incorrect case-file codes by client IP."""
    ip = request.remote_addr or "unknown"
    now = time.time()
    row = db().execute(
        "SELECT failures, window_start, blocked_until FROM case_file_code_throttle WHERE ip=?", (ip,)
    ).fetchone()
    if row and now < row["blocked_until"]:
        audit("CASE_FILE_CODE_BLOCKED", detail="case-file code rate limit")
        return False
    if row and now - row["window_start"] < 900 and row["failures"] >= 5:
        db().execute("UPDATE case_file_code_throttle SET blocked_until=? WHERE ip=?", (row["window_start"] + 900, ip))
        db().commit()
        audit("CASE_FILE_CODE_BLOCKED", detail="case-file code rate limit")
        return False

    if not row or now - row["window_start"] >= 900:
        db().execute(
            "INSERT OR REPLACE INTO case_file_code_throttle(ip,failures,window_start,blocked_until) VALUES(?,?,?,0)",
            (ip, 1, now),
        )
    else:
        db().execute("UPDATE case_file_code_throttle SET failures=failures+1 WHERE ip=?", (ip,))
    db().commit()
    audit("CASE_FILE_CODE_REJECTED", detail="incorrect case-file code")
    return True

def record_share_code_failure():
    ip = request.remote_addr or "unknown"
    now = time.time()
    row = db().execute("SELECT failures,window_start,blocked_until FROM share_code_throttle WHERE ip=?", (ip,)).fetchone()
    if row and now < row["blocked_until"]:
        audit("SHARE_CODE_BLOCKED", detail="share-code rate limit")
        return False
    blocked = bool(row and now - row["window_start"] < 900 and row["failures"] >= 4)
    if not row or now - row["window_start"] >= 900:
        db().execute("INSERT OR REPLACE INTO share_code_throttle(ip,failures,window_start,blocked_until) VALUES(?,?,?,0)",
                     (ip, 1, now))
    else:
        db().execute("UPDATE share_code_throttle SET failures=failures+1 WHERE ip=?", (ip,))
        if blocked:
            db().execute("UPDATE share_code_throttle SET blocked_until=? WHERE ip=?", (row["window_start"] + 900, ip))
    db().commit()
    audit("SHARE_CODE_BLOCKED" if blocked else "SHARE_CODE_REJECTED", detail="share-code rate limit" if blocked else "incorrect recipient code")
    return not blocked

def can(perm): return perm in PERMS.get(session.get("role"), ())

@app.route("/cases/<int:cid>/files", methods=["POST"])
@login_required(*DOC_ROLES)
def upload_case_file(cid):
    if session.get("role") not in CASE_UPLOAD_ROLES:
        audit("CASE_FILE_UPLOAD_DENIED", detail="role not allowed")
        flash("Only clients, associates and judges can upload case files.")
        return redirect(home_url())

    if session["role"] == "judge":
        case = db().execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    else:
        case = db().execute("SELECT * FROM cases WHERE id=? AND user_id=?", (cid, session["uid"])).fetchone()
    if not case:
        audit("CASE_FILE_UPLOAD_DENIED", detail=f"case {cid} not accessible")
        abort(404)

    secret_code = request.form.get("secret_code", "").strip()
    confirm_code = request.form.get("confirm_secret_code", "").strip()
    if len(secret_code) < 8 or len(secret_code) > 128:
        flash("Set a case-file code between 8 and 128 characters.")
        return redirect(home_url())
    if not secrets.compare_digest(secret_code, confirm_code):
        flash("The case-file code and confirmation do not match. Please try again.")
        return redirect(home_url())

    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a case file to upload.")
        return redirect(home_url())
    extension = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if extension not in CASE_FILE_EXTENSIONS:
        flash("Upload a PDF, DOC, DOCX, TXT, PNG, JPG or TIFF case file.")
        return redirect(home_url())

    data = file.read()
    if not data:
        flash("The selected case file is empty.")
        return redirect(home_url())

    from werkzeug.utils import secure_filename
    file_id = uuid.uuid4().hex
    filename = secure_filename(file.filename) or "case-file"
    digest = hashlib.sha256(data).hexdigest()
    path = os.path.join(VAULT, file_id + ".case")
    try:
        with open(path, "xb") as encrypted_file:
            encrypted_file.write(enc(data, "case-file:" + file_id))
        os.chmod(path, 0o600)
        db().execute(
            "INSERT INTO case_files(id,case_id,owner_id,filename,size,sha256,code_hash) VALUES(?,?,?,?,?,?,?)",
            (file_id, cid, session["uid"], filename, len(data), digest,
             hash_unlock_code(secret_code)),
        )
        db().commit()
    except Exception:
        db().rollback()
        try:
            os.remove(path)
        except OSError:
            app.logger.exception("Could not clean up an incomplete case-file upload")
        app.logger.exception("Case-file upload failed")
        flash("The case file could not be stored. Please try again.")
        return redirect(home_url())

    audit("CASE_FILE_UPLOAD", file_id, f"case={cid}, {filename}, {len(data)} bytes, sha256={digest[:16]}")
    flash("Case file encrypted and uploaded successfully.")
    return redirect(home_url())

@app.route("/cases/files/<file_id>/download", methods=["POST"])
@login_required(*DOC_ROLES)
def download_case_file(file_id):
    record = db().execute(
        "SELECT cf.*, c.user_id AS case_owner FROM case_files cf JOIN cases c ON c.id=cf.case_id WHERE cf.id=?",
        (file_id,),
    ).fetchone()
    if not record or (session.get("role") != "judge" and record["case_owner"] != session["uid"]):
        audit("CASE_FILE_ACCESS_DENIED", file_id)
        abort(404)
    if not record["code_hash"]:
        flash("This older case file has no unlock code. Upload it again and set a code.")
        return redirect(home_url())
    if not secrets.compare_digest(
        hash_unlock_code(request.form.get("secret_code", "").strip()),
        record["code_hash"],
    ):
        if record_case_file_code_failure():
            flash("The case-file code is incorrect.")
        else:
            flash("Too many incorrect codes. Try again in 15 minutes.")
        return redirect(home_url())
    db().execute("DELETE FROM case_file_code_throttle WHERE ip=?", (request.remote_addr or "unknown",))
    db().commit()
    try:
        with open(os.path.join(VAULT, file_id + ".case"), "rb") as encrypted_file:
            data = dec(encrypted_file.read(), "case-file:" + file_id)
    except (OSError, ValueError):
        audit("CASE_FILE_INTEGRITY_FAILURE", file_id)
        abort(404)
    audit("CASE_FILE_DOWNLOAD", file_id, f"case={record['case_id']}")
    return send_file(io.BytesIO(data), as_attachment=True, download_name=record["filename"])

def master_key():  # 32 bytes = AES-256. Use DOC_KEY (urlsafe base64) in production, else a local key file is created.
    if os.environ.get("DOC_KEY"):
        key = base64.urlsafe_b64decode(os.environ["DOC_KEY"])
        if len(key) != 32: raise RuntimeError("DOC_KEY must decode to exactly 32 bytes for AES-256-GCM.")
        return key
    p = os.path.join(os.path.dirname(__file__), "master.key")
    if not os.path.exists(p):
        with open(p, "wb") as f: f.write(AESGCM.generate_key(256))
        os.chmod(p, 0o600)
    os.chmod(p, 0o600)
    with open(p, "rb") as key_file: return key_file.read()

def audit(action, doc_id=None, detail="", user=None):
    uid = user["id"] if user else session.get("uid")
    email = user["email"] if user else session.get("email", "-")
    p = db().execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = p["hash"] if p else "0" * 64
    ts, ip = datetime.utcnow().isoformat(timespec="seconds"), request.remote_addr
    h = hashlib.sha256(f"{prev}|{uid}|{action}|{doc_id}|{detail}|{ip}|{ts}".encode()).hexdigest()
    db().execute("INSERT INTO audit(user_id,email,action,doc_id,detail,ip,created,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)",
                 (uid, email, action, doc_id, detail, ip, ts, prev, h)); db().commit()

def my_doc(did):
    return db().execute("SELECT * FROM docs WHERE id=? AND (owner_id=? OR id IN (SELECT doc_id FROM access WHERE user_id=?))",
                        (did, session["uid"], session["uid"])).fetchone()

@app.route("/vault")
@login_required(*DOC_ROLES)
def vault():
    docs = db().execute("""SELECT d.*, u.name AS owner
        FROM docs d JOIN users u ON u.id=d.owner_id WHERE d.owner_id=? OR d.id IN (SELECT doc_id FROM access WHERE user_id=?)
        ORDER BY d.created DESC""", (session["uid"], session["uid"])).fetchall()
    shares_by_doc = {d["id"]: db().execute("SELECT u.id, u.name, u.email FROM access a JOIN users u ON u.id=a.user_id WHERE a.doc_id=? ORDER BY u.name", (d["id"],)).fetchall() for d in docs}
    unlocked_by_doc = {d["id"]: d["owner_id"] == session["uid"] or share_code_is_verified(d["id"]) for d in docs}
    return render_template("vault.html", docs=docs, shares=can("share"), shares_by_doc=shares_by_doc,
                           unlocked_by_doc=unlocked_by_doc)

@app.route("/vault/upload", methods=["POST"])
@login_required(*DOC_ROLES)
def upload():
    f = request.files.get("file")
    if not can("upload") or not f or not f.filename:
        flash("Your role cannot upload files." if not can("upload") else "Choose a file to upload."); return redirect(url_for("vault"))
    if f.filename.rsplit(".", 1)[-1].lower() not in {"pdf", "png", "jpg", "jpeg", "tif", "tiff", "txt"}:
        flash("Upload a PDF, image (PNG, JPG, TIFF) or TXT file."); return redirect(url_for("vault"))
    data, did = f.read(), uuid.uuid4().hex
    if not data: flash("The selected file is empty."); return redirect(url_for("vault"))
    from werkzeug.utils import secure_filename
    name, digest = secure_filename(f.filename) or "document", hashlib.sha256(data).hexdigest()
    written = []
    try:
        encrypted_path = os.path.join(VAULT, did + ".enc")
        with open(encrypted_path, "xb") as fh: fh.write(enc(data, did))
        os.chmod(encrypted_path, 0o600); written.append(encrypted_path)
        text, how = ocr_nlp.extract_text(data, name)
        ana = {"method": how, "text": text, "summary": ocr_nlp.summarize(text), "facts": ocr_nlp.key_facts(text),
               "related": rag.get().search(text[:3000], 5) if text.strip() else []}
        analysis_path = os.path.join(VAULT, did + ".ana")
        with open(analysis_path, "xb") as fh: fh.write(enc(json.dumps(ana).encode(), did + ".ana"))
        os.chmod(analysis_path, 0o600); written.append(analysis_path)
        db().execute("INSERT INTO docs(id,owner_id,filename,size,sha256) VALUES(?,?,?,?,?)", (did, session["uid"], name, len(data), digest)); db().commit()
    except Exception:
        db().rollback()
        for path in written:
            try: os.remove(path)
            except OSError: app.logger.exception("Could not clean up an incomplete upload")
        app.logger.exception("Document upload failed")
        flash("The document could not be stored. Check available disk space and encryption key configuration, then try again.")
        return redirect(url_for("vault"))
    audit("UPLOAD", did, f"{name}, {len(data)} bytes, sha256={digest[:16]}")
    audit("ANALYSED", did, how[:60]); flash("Document encrypted, analysed and stored."); return redirect(url_for("vault"))

@app.route("/vault/share/<did>", methods=["POST"])
@login_required(*DOC_ROLES)
def share(did):
    d = db().execute("SELECT * FROM docs WHERE id=? AND owner_id=?", (did, session["uid"])).fetchone()
    email = request.form.get("email", "").strip().lower()
    t = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not d or not can("share"): audit("SHARE_DENIED", did); flash("You cannot share this document."); return redirect(url_for("vault"))
    if not t or t["role"] not in SHARE_TO.get(session["role"], ()):
        audit("SHARE_DENIED", did, "recipient not allowed"); flash(f"A {session['role']} can only share with: {', '.join(sorted(SHARE_TO[session['role']]))} accounts."); return redirect(url_for("vault"))
    code = request.form.get("share_code", "").strip()
    confirm_code = request.form.get("confirm_share_code", "").strip()
    if len(code) < 8 or len(code) > 128:
        flash("Set a recipient code between 8 and 128 characters.")
        return redirect(url_for("vault"))
    if not secrets.compare_digest(code, confirm_code):
        flash("The recipient code and confirmation do not match.")
        return redirect(url_for("vault"))
    code_digest = hash_unlock_code(code)
    used_code = db().execute(
        "SELECT 1 FROM share_code_history WHERE code_hash=? UNION ALL SELECT 1 FROM access WHERE code_hash=? LIMIT 1",
        (code_digest, code_digest),
    ).fetchone()
    if used_code:
        flash("Choose a new code that has not been used for another share.")
        return redirect(url_for("vault"))
    share_id = secrets.token_urlsafe(18)
    db().execute("INSERT INTO share_code_history(code_hash) VALUES(?)", (code_digest,))
    db().execute("""INSERT INTO access(doc_id,user_id,granted_by,code_hash,share_id,manual_code) VALUES(?,?,?,?,?,1)
        ON CONFLICT(doc_id,user_id) DO UPDATE SET granted_by=excluded.granted_by,
        code_hash=excluded.code_hash, share_id=excluded.share_id, manual_code=1""",
                 (did, t["id"], session["uid"], code_digest, share_id))
    db().commit()
    audit("SHARE", did, f"to {t['email']} ({t['role']})")
    flash(f"Shared with {t['name']}. Give them the code you set, using a private channel.")
    return redirect(url_for("vault"))

@app.route("/vault/unlock/<did>", methods=["POST"])
@login_required(*DOC_ROLES)
def unlock_shared_doc(did):
    doc = my_doc(did)
    access = db().execute("SELECT code_hash, share_id, manual_code FROM access WHERE doc_id=? AND user_id=?",
                          (did, session["uid"])).fetchone()
    if not doc or doc["owner_id"] == session["uid"] or not access:
        audit("SHARE_CODE_DENIED", did, "no active share")
        abort(404)
    supplied = request.form.get("share_code", "").strip()
    supplied_hash = hash_unlock_code(supplied)
    ip = request.remote_addr or "unknown"
    throttle = db().execute("SELECT failures,window_start,blocked_until FROM share_code_throttle WHERE ip=?", (ip,)).fetchone()
    if throttle and (time.time() < throttle["blocked_until"] or
                     (throttle["failures"] >= 5 and time.time() - throttle["window_start"] < 900)):
        audit("SHARE_CODE_BLOCKED", did, "share-code rate limit")
        flash("Too many incorrect codes. Try again in 15 minutes.")
        return redirect(url_for("vault"))
    if not access["manual_code"]:
        flash("The owner must share this file again and set a new code.")
        return redirect(url_for("vault"))
    if not access["code_hash"] or not secrets.compare_digest(supplied_hash, access["code_hash"]):
        allowed = record_share_code_failure()
        flash("The share code is incorrect. Try again." if allowed else "Too many incorrect codes. Try again in 15 minutes.")
        return redirect(url_for("vault"))

    verified = session.get("share_code_verified", {})
    if not isinstance(verified, dict):
        verified = {}
    now = time.time()
    verified = {key: value for key, value in verified.items()
                if isinstance(value, dict) and now - value.get("verified_at", 0) < 1800}
    verified[did] = {"share_id": access["share_id"], "verified_at": now}
    session["share_code_verified"] = verified
    db().execute("DELETE FROM share_code_throttle WHERE ip=?", (ip,))
    db().commit()
    audit("SHARE_CODE_ACCEPTED", did)
    flash("Shared file unlocked for 30 minutes.")
    return redirect(url_for("vault"))

def share_code_is_verified(did):
    access = db().execute("SELECT share_id, manual_code FROM access WHERE doc_id=? AND user_id=?",
                          (did, session["uid"])).fetchone()
    verified_map = session.get("share_code_verified", {})
    verified = verified_map.get(did) if isinstance(verified_map, dict) else None
    return bool(access and access["manual_code"] and access["share_id"] and isinstance(verified, dict) and
                verified.get("share_id") == access["share_id"] and
                time.time() - verified.get("verified_at", 0) < 1800)

@app.route("/vault/share/<did>/<int:recipient_id>/revoke", methods=["POST"])
@login_required(*DOC_ROLES)
def revoke_share(did, recipient_id):
    doc = db().execute("SELECT id FROM docs WHERE id=? AND owner_id=?", (did, session["uid"])).fetchone()
    if not doc or not can("share"):
        audit("REVOKE_SHARE_DENIED", did); flash("You cannot change sharing for this document."); return redirect(url_for("vault"))
    recipient = db().execute("SELECT name FROM users WHERE id=?", (recipient_id,)).fetchone()
    removed = db().execute("DELETE FROM access WHERE doc_id=? AND user_id=?", (did, recipient_id)).rowcount
    db().commit()
    if removed:
        audit("REVOKE_SHARE", did, f"from user {recipient_id}"); flash(f"Access revoked for {recipient['name'] if recipient else 'recipient'}.")
    else:
        flash("That account did not have access to this document.")
    return redirect(url_for("vault"))

@app.route("/vault/download/<did>")
@login_required(*DOC_ROLES)
def download(did):
    d = my_doc(did)
    if not d: audit("ACCESS_DENIED", did); flash("You do not have access to that document."); return redirect(url_for("vault"))
    if d["owner_id"] != session["uid"] and not share_code_is_verified(did):
        flash("Enter the current share code to unlock this document before downloading it.")
        return redirect(url_for("vault"))
    blob = open(os.path.join(VAULT, did + ".enc"), "rb").read()
    try: data = AESGCM(master_key()).decrypt(blob[:12], blob[12:], did.encode())
    except Exception:
        audit("TAMPER_DETECTED", did); flash("Integrity check failed. This file may have been altered."); return redirect(url_for("vault"))
    audit("DOWNLOAD", did, d["filename"])
    return send_file(io.BytesIO(data), as_attachment=True, download_name=d["filename"])

@app.route("/audit")
@login_required(*DOC_ROLES)
def audit_log():
    rows = db().execute("SELECT a.*, d.filename FROM audit a LEFT JOIN docs d ON d.id=a.doc_id WHERE d.owner_id=? OR a.user_id=? ORDER BY a.id DESC LIMIT 300",
                        (session["uid"], session["uid"])).fetchall()
    bad, prev = None, "0" * 64
    for r in db().execute("SELECT * FROM audit ORDER BY id").fetchall():
        h = hashlib.sha256(f"{prev}|{r['user_id']}|{r['action']}|{r['doc_id']}|{r['detail']}|{r['ip']}|{r['created']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h: bad = r["id"]; break
        prev = r["hash"]
    return render_template("audit.html", rows=rows, bad=bad)

# ---------- LegaVault analysis, search and prediction ----------
def enc(data, aad):
    n = os.urandom(12); return n + AESGCM(master_key()).encrypt(n, data, aad.encode())

def dec(blob, aad): return AESGCM(master_key()).decrypt(blob[:12], blob[12:], aad.encode())

def ctx_prompt(q):
    h = rag.get().search(q, 4)
    return ("Relevant sources:\n" + "\n".join(f"- {x['title']} ({x['citation']}): {x['text']}" for x in h) + "\n\n" if h else "") + "Question: " + q

@app.route("/vault/analysis/<did>")
@login_required(*DOC_ROLES)
def analysis(did):
    d = my_doc(did)
    if not d: audit("ACCESS_DENIED", did); flash("You do not have access to that document."); return redirect(url_for("vault"))
    if d["owner_id"] != session["uid"] and not share_code_is_verified(did):
        flash("Enter the current share code to unlock this document before viewing its analysis.")
        return redirect(url_for("vault"))
    p = os.path.join(VAULT, did + ".ana")
    if not os.path.exists(p): flash("No analysis was stored for this document."); return redirect(url_for("vault"))
    try: ana = json.loads(dec(open(p, "rb").read(), did + ".ana"))
    except Exception: audit("TAMPER_DETECTED", did); flash("Integrity check failed."); return redirect(url_for("vault"))
    audit("ANALYSIS_VIEW", did); return render_template("analysis.html", d=d, a=ana)

@app.route("/search", methods=["GET", "POST"])
@login_required()
def search():
    q, res = request.form.get("q", "").strip()[:500], []
    if q: res = rag.get().search(q, 6); audit("SEARCH")
    return render_template("search.html", q=q, res=res, mode=rag.get().mode)

@app.route("/predict", methods=["GET", "POST"])
@login_required("client", "lawyer", "associate", "judge")
def predict_view():
    out = None
    if request.method == "POST":
        f = request.form
        try:
            facts = f.get("facts", "")[:3000]
            prec = [r for r in rag.get().search(facts or f["case_type"], 10) if r["type"] == "precedent"][:3]
            support = min(1.0, prec[0]["score"] * rag.get().scale) if (facts and prec) else 0.5
            out = pred.predict(dict(case_type=f["case_type"], evidence=int(f["evidence"]), docs=int("docs" in f), notice=int("notice" in f),
                                    delay=float(f.get("delay") or 0), claim=float(f.get("claim") or 0), precedent=support), f.get("how", "shap"))
            out["precedents"], out["bert"] = prec, pred.bert_view(facts); audit("PREDICTION_RUN", detail=f["case_type"])
        except (ValueError, KeyError, IndexError):
            flash("Please check the numbers you entered.")
    return render_template("predict.html", out=out, types=pred.TYPES, acc=pred.ACC, model_kind=pred.MODEL_KIND)

@app.route("/status")
@login_required()
def status():
    has = lambda m: importlib.util.find_spec(m) is not None
    vision_enabled = os.environ.get("GOOGLE_VISION", "").lower() in {"1", "true", "yes"}
    transformer_enabled = os.environ.get("USE_TRANSFORMER", "").lower() in {"1", "true", "yes"}
    items = [("OCR engine", "Google Vision selected (credentials required)" if vision_enabled else ("Tesseract ready" if shutil.which("tesseract") and has("pytesseract") else "Not ready: install Tesseract and pytesseract")),
             ("Summariser", "Transformer (DistilBART) selected" if transformer_enabled and has("transformers") else "Extractive summary (install optional AI dependencies for Transformer)"),
             ("Semantic search", rag.get().mode),
             ("Explainability", ", ".join(n for n, m in [("SHAP", "shap"), ("LIME", "lime")] if has(m)) or "feature ablation only"),
             ("BERT outcome model", "Fine-tuned model available" if os.path.isdir(pred.BERT_DIR) else "Not trained: provide labelled case outcomes"),
             ("Outcome model data", pred.MODEL_KIND + ("; not suitable for real case decisions" if "synthetic" in pred.MODEL_KIND else "; independently validate before real use")),
             ("Encryption at rest", "AES-256-GCM with a per-file nonce"),
             ("Login security", "Password login with failed-attempt throttling"),
             ("Transport security", "HTTPS required outside localhost"),
             ("Role access", "Case owners manage their cases; judges review cases and their files")]
    return render_template("status.html", items=items)

if __name__ == "__main__":
    init(); app.run(host=os.environ.get("HOST", "127.0.0.1"), debug=os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}, port=int(os.environ.get("PORT", 5001)))
