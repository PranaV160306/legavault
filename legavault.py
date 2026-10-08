#!/usr/bin/env python3
"""LegaVault: AI-based legal document analysis with encrypted sharing. Everything in ONE file.

Run:      pip install flask cryptography scikit-learn numpy pymupdf pytesseract pillow
          brew install tesseract          (macOS; needed for OCR)
          python legavault.py             then open http://127.0.0.1:5001
Optional env vars: SECRET_KEY, DOC_KEY, JUDGE_CODE, GEMINI_API_KEY, GEMINI_MODEL, USE_TRANSFORMER, USE_LANGCHAIN, GOOGLE_VISION, PORT.
Files created next to this script: legal.db (SQLite), vault/ (AES-encrypted files), master.key and secret.key. Back up master.key.
"""
import os, re, json, sqlite3, urllib.request, io, uuid, time, base64, hashlib, secrets, shutil, importlib.util
from collections import Counter
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from functools import wraps
from jinja2 import DictLoader
from flask import Flask, g, render_template, request, redirect, session, url_for, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash

# =====================================================================================
# 1. OCR + NLP  (Tesseract or Google Vision; Transformer or extractive summary; fact extraction)
# =====================================================================================
STOP = set("that this with from have which their shall would there been were will also such than them into upon being other these those under after before between about".split())
DOC_TYPES = {"legal notice": ["legal notice", "hereby call upon", "notice under"], "FIR / police complaint": ["first information report", "fir no", "police station"],
             "agreement / contract": ["agreement", "hereinafter", "witnesseth", "party of the first part"], "court judgment / order": ["judgment", "hon'ble", "appellant", "respondent", "petitioner"],
             "affidavit": ["affidavit", "solemnly affirm", "deponent"], "rent / lease": ["lease", "tenant", "landlord", "rent"], "cheque / bank memo": ["cheque", "returned unpaid", "insufficient funds"]}
OCR_EXT = {"pdf", "png", "jpg", "jpeg", "tif", "tiff", "bmp", "webp", "txt"}
OCR_LANG_NAMES = {"eng": "English", "hin": "Hindi", "mar": "Marathi", "guj": "Gujarati", "tam": "Tamil", "tel": "Telugu", "ben": "Bengali", "kan": "Kannada", "urd": "Urdu"}
_pipe = None

def ocr_ready():
    if os.environ.get("GOOGLE_VISION"): return True
    return bool(shutil.which("tesseract") and importlib.util.find_spec("pytesseract") and importlib.util.find_spec("PIL"))

def ocr_langs():
    """Languages installed in this Tesseract (so the OCR page only offers what works). Add more with: brew install tesseract-lang"""
    try:
        import pytesseract
        have = set(pytesseract.get_languages(config=""))
    except Exception:
        have = set()
    out = {k: v for k, v in OCR_LANG_NAMES.items() if k in have} or {"eng": "English"}
    if "eng" in have:
        for k, v in list(out.items()):
            if k != "eng": out[f"eng+{k}"] = f"English + {v}"
    return out

def _prep(img):
    """Clean a page image so Tesseract reads it better: fix rotation tag, greyscale, upscale small scans, boost contrast, sharpen."""
    from PIL import Image, ImageOps, ImageFilter
    img = ImageOps.exif_transpose(img).convert("L")
    if min(img.size) < 1000:
        s = min(3.0, 1000 / min(img.size)); img = img.resize((int(img.width * s), int(img.height * s)), Image.LANCZOS)
    return ImageOps.autocontrast(img).filter(ImageFilter.SHARPEN)

def ocr_image(b, lang="eng"):
    """OCR one image. Returns (text, mean_confidence_percent_or_None). Frames of multi-page TIFFs are all read."""
    if os.environ.get("GOOGLE_VISION"):   # needs google-cloud-vision + GOOGLE_APPLICATION_CREDENTIALS
        from google.cloud import vision
        return vision.ImageAnnotatorClient().document_text_detection(image=vision.Image(content=b)).full_text_annotation.text, None
    import pytesseract
    from PIL import Image, ImageSequence
    have = set(pytesseract.get_languages(config=""))
    use = "+".join(l for l in lang.split("+") if l in have) or "eng"
    texts, confs = [], []
    for frame in list(ImageSequence.Iterator(Image.open(io.BytesIO(b))))[:20]:
        d = pytesseract.image_to_data(_prep(frame), lang=use, output_type=pytesseract.Output.DICT)
        lines, order = {}, []
        for i, w in enumerate(d["text"]):
            if not w.strip(): continue
            key = (d["block_num"][i], d["par_num"][i], d["line_num"][i])
            if key not in lines: lines[key] = []; order.append(key)
            lines[key].append(w)
            try:
                c = float(d["conf"][i])
                if c >= 0: confs.append(c)
            except ValueError: pass
        out, prev = [], None
        for key in order:
            if prev and key[:2] != prev[:2]: out.append("")      # blank line between paragraphs
            out.append(" ".join(lines[key])); prev = key
        texts.append("\n".join(out))
    return "\n\n".join(texts), (round(sum(confs) / len(confs)) if confs else None)

def read_document(data, filename, lang="eng"):
    """Core OCR function. Returns dict(text, how, conf, pages). Never raises: problems come back in `how`."""
    ext = filename.rsplit(".", 1)[-1].lower()
    try:
        if ext == "txt": return dict(text=data.decode("utf-8", "ignore"), how="plain text", conf=None, pages=1)
        if ext == "pdf":
            import fitz
            doc = fitz.open(stream=data, filetype="pdf")
            txt = "\n".join(p.get_text() for p in doc)
            if len(txt.strip()) > 50: return dict(text=txt, how="PDF text layer", conf=None, pages=len(doc))
            res = [ocr_image(p.get_pixmap(dpi=200).tobytes("png"), lang) for p in list(doc)[:20]]
            cs = [c for _, c in res if c is not None]
            return dict(text="\n\n".join(t for t, _ in res), how="OCR (scanned PDF)", conf=round(sum(cs) / len(cs)) if cs else None, pages=min(len(doc), 20))
        text, conf = ocr_image(data, lang)
        return dict(text=text, how="OCR (image)", conf=conf, pages=1)
    except Exception as e:
        return dict(text="", how=f"OCR unavailable: {e}. Install Tesseract (brew install tesseract) and run: pip install pytesseract pillow pymupdf", conf=None, pages=0)

def extract_text(data, filename, lang="eng"):
    r = read_document(data, filename, lang)
    return r["text"], r["how"] + (f", {r['conf']}% confidence" if r["conf"] is not None else "")

def summarize(text, n=5):
    text = re.sub(r"\s+", " ", text).strip()
    if len(text.split()) < 40: return text
    global _pipe
    if os.environ.get("USE_TRANSFORMER"):
        try:
            from transformers import pipeline
            _pipe = _pipe or pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
            parts = [text[i:i + 3000] for i in range(0, min(len(text), 9000), 3000)]
            return " ".join(_pipe(p, max_length=130, min_length=30, truncation=True)[0]["summary_text"] for p in parts)
        except Exception:
            pass   # fall back to extractive
    freq = Counter(w for w in re.findall(r"[a-z]{4,}", text.lower()) if w not in STOP)
    sents = [(i, s) for i, s in enumerate(re.split(r"(?<=[.!?])\s+", text)) if 6 < len(s.split()) < 60]
    scored = sorted(sents, key=lambda t: -sum(freq[w] for w in re.findall(r"[a-z]{4,}", t[1].lower())) / (len(t[1].split()) + 5))[:n]
    return " ".join(s for _, s in sorted(scored))

def key_facts(t):
    low = t.lower()
    kind = max(DOC_TYPES, key=lambda k: sum(low.count(w) for w in DOC_TYPES[k]))
    return {"type": kind if sum(low.count(w) for w in DOC_TYPES[kind]) else "unclassified",
            "amounts": sorted(set(re.findall(r"(?:Rs\.?|INR|₹)\s?[\d,]+(?:\.\d+)?", t)))[:8],
            "dates": sorted(set(re.findall(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?,?\s+\d{4}\b", t)))[:8],
            "sections": sorted(set(re.findall(r"(?:Section|Sec\.)\s?\d+[A-Z]?", t)))[:8]}

# =====================================================================================
# 2. Semantic search over statutes and precedents (knowledge base embedded below)
#    USE_LANGCHAIN=1 -> LangChain + FAISS (or Pinecone with PINECONE_API_KEY); default -> TF-IDF
# =====================================================================================
KB = json.loads(r'''[
{"type":"statute","title":"Dishonour of cheque (s.138 NI Act)","citation":"Negotiable Instruments Act 1881, s.138","text":"Cheque returned unpaid for insufficient funds is an offence punishable with up to 2 years prison or fine up to twice the cheque amount. Send a demand notice within 30 days of the return memo; the drawer has 15 days to pay; file the complaint within one month after that period."},
{"type":"statute","title":"Consumer complaint to District Commission","citation":"Consumer Protection Act 2019, s.35 and s.69","text":"A consumer can file a complaint about defective goods or deficient services with the District Consumer Commission, online through e-Daakhil. The complaint must be filed within two years from the cause of action."},
{"type":"statute","title":"Information in cognisable cases (FIR)","citation":"Bharatiya Nagarik Suraksha Sanhita 2023, s.173","text":"Information about a cognisable offence can be given orally, in writing or electronically to the police, who must register it and give the informant a free copy. Zero FIR can be registered at any station regardless of jurisdiction."},
{"type":"statute","title":"Anticipatory bail","citation":"Bharatiya Nagarik Suraksha Sanhita 2023, s.482","text":"A person who fears arrest for a non-bailable offence may apply to the High Court or Court of Session for a direction to be released on bail if arrested."},
{"type":"statute","title":"Cheating","citation":"Bharatiya Nyaya Sanhita 2023, s.318","text":"Dishonestly deceiving a person to deliver property or to act to their loss is cheating, punishable with imprisonment and fine; cheating that induces delivery of property carries up to 7 years. Replaces IPC s.415 and s.420."},
{"type":"statute","title":"Murder","citation":"Bharatiya Nyaya Sanhita 2023, s.103","text":"Murder is punishable with death or imprisonment for life, and fine. Replaces IPC s.302."},
{"type":"statute","title":"Compensation for breach of contract","citation":"Indian Contract Act 1872, s.73","text":"The party who suffers from a breach is entitled to compensation for loss that naturally arose from the breach or that both parties knew was likely. Remote or indirect loss is not compensated."},
{"type":"statute","title":"Valid contract","citation":"Indian Contract Act 1872, s.10","text":"Agreements are contracts if made with free consent of competent parties, for a lawful consideration and a lawful object, and not expressly declared void."},
{"type":"statute","title":"Termination of tenancy notice","citation":"Transfer of Property Act 1882, s.106","text":"A month-to-month tenancy can be ended by 15 days written notice and a year-to-year tenancy by 6 months notice, unless the contract or local rent law says otherwise. A landlord cannot evict without following due process."},
{"type":"statute","title":"Divorce by mutual consent","citation":"Hindu Marriage Act 1955, s.13B","text":"Spouses living separately for one year or more who cannot live together can jointly petition for divorce. A second motion is made after a cooling period of 6 to 18 months."},
{"type":"statute","title":"Limitation period for suits","citation":"Limitation Act 1963, s.3","text":"A suit filed after the prescribed period is dismissed even if the claim is valid. Most money recovery and breach of contract suits must be filed within 3 years."},
{"type":"statute","title":"Electronic evidence","citation":"Bharatiya Sakshya Adhiniyam 2023, s.63","text":"Electronic records such as emails, chats and call logs are admissible if accompanied by the required certificate. Replaces s.65B of the Indian Evidence Act."},
{"type":"statute","title":"Domestic violence relief","citation":"Protection of Women from Domestic Violence Act 2005, s.12","text":"An aggrieved woman can apply to a Magistrate for protection orders, residence orders, monetary relief and custody orders."},
{"type":"statute","title":"Protection of life and personal liberty","citation":"Constitution of India, Article 21","text":"No person can be deprived of life or personal liberty except by a procedure established by law, and that procedure must be fair, just and reasonable. Includes the right to speedy trial and legal aid."},
{"type":"precedent","title":"Arnesh Kumar v. State of Bihar","citation":"(2014) 8 SCC 273","text":"Arrest is not automatic for offences punishable up to 7 years. Police must record reasons for arrest and Magistrates must check them before authorising detention. Relevant to bail and wrongful arrest."},
{"type":"precedent","title":"Lalita Kumari v. Govt. of U.P.","citation":"(2014) 2 SCC 1","text":"Police must register an FIR when information discloses a cognisable offence. A preliminary inquiry is allowed only in limited categories such as matrimonial, commercial and medical negligence cases."},
{"type":"precedent","title":"Maneka Gandhi v. Union of India","citation":"(1978) 1 SCC 248","text":"The procedure that restricts personal liberty under Article 21 must be fair, just and reasonable, not arbitrary. Articles 14, 19 and 21 are read together."},
{"type":"precedent","title":"Amardeep Singh v. Harveen Kaur","citation":"(2017) 8 SCC 746","text":"The 6 month cooling period in mutual consent divorce under s.13B(2) is directory and courts may waive it where reconciliation is impossible and the parties have settled all issues."},
{"type":"precedent","title":"Indian Medical Association v. V.P. Shantha","citation":"(1995) 6 SCC 651","text":"Medical services paid for are services under consumer law, so patients can claim compensation for deficiency in service or negligence before consumer forums."},
{"type":"precedent","title":"Vishaka v. State of Rajasthan","citation":"(1997) 6 SCC 241","text":"The Supreme Court laid down binding guidelines to prevent sexual harassment of women at the workplace, later codified in the POSH Act 2013."},
{"type":"precedent","title":"Gurbaksh Singh Sibbia v. State of Punjab","citation":"(1980) 2 SCC 565","text":"Anticipatory bail should not be hedged by rigid conditions. Courts decide on the facts of each case, considering the nature of the accusation and likelihood of absconding."},
{"type":"precedent","title":"Rangappa v. Sri Mohan","citation":"(2010) 11 SCC 441","text":"Under s.139 NI Act the court presumes a cheque was issued for a legally enforceable debt. The accused can rebut it by showing the debt probably did not exist."},
{"type":"precedent","title":"Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal","citation":"(2020) 7 SCC 1","text":"A certificate under s.65B(4) of the Evidence Act is mandatory to admit electronic evidence given as a copy. Same principle now sits in s.63 BSA."}
]
''')
_r = None

def _embeddings():
    try: from langchain_huggingface import HuggingFaceEmbeddings
    except ImportError: from langchain_community.embeddings import HuggingFaceEmbeddings
    return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2", encode_kwargs={"normalize_embeddings": True})

class Retriever:
    def __init__(self):
        self.texts = [f"{k['title']}. {k['citation']}. {k['text']}" for k in KB]
        self.mode, self.scale = "TF-IDF vectors", 3.0
        if os.environ.get("USE_LANGCHAIN"):
            try:
                from langchain_core.documents import Document
                docs = [Document(page_content=t, metadata={"i": i}) for i, t in enumerate(self.texts)]
                if os.environ.get("PINECONE_API_KEY"):   # index must exist: dimension 384, cosine metric
                    from langchain_pinecone import PineconeVectorStore
                    self.store = PineconeVectorStore.from_documents(docs, _embeddings(), index_name=os.environ.get("PINECONE_INDEX", "legavault"))
                    self.mode = "LangChain + Pinecone"
                else:
                    from langchain_community.vectorstores import FAISS
                    self.store, self.mode = FAISS.from_documents(docs, _embeddings()), "LangChain + FAISS"
                self.scale = 1.5
                return
            except Exception as e:
                self.mode = f"TF-IDF vectors (LangChain unavailable: {str(e)[:90]})"
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
        self.mat = self.vec.fit_transform(self.texts)

    def search(self, q, k=4):
        if not q.strip(): return []
        if hasattr(self, "store"):
            hits = self.store.similarity_search_with_score(q, k=k)
            pairs = [(d.metadata["i"], s if "Pinecone" in self.mode else max(0.0, 1 - s / 2)) for d, s in hits]   # FAISS returns squared L2; convert to cosine
        else:
            sims = (self.mat @ self.vec.transform([q]).T).toarray().ravel()
            pairs = [(j, sims[j]) for j in sims.argsort()[::-1][:k]]
        return [dict(KB[int(i)], score=round(float(s), 3)) for i, s in pairs if s > 0.02]

def rag_get():
    global _r
    _r = _r or Retriever()
    return _r

# =====================================================================================
# 3. Case outcome prediction: Random Forest + SHAP/LIME (SYNTHETIC training data: demo only)
# =====================================================================================
CASE_TYPES = ["consumer", "cheque_bounce", "tenancy", "contract", "bail", "family"]
_BIAS = [.4, .5, 0, .1, -.2, -.1]
FEATURE_NAMES = ["Case type", "Evidence strength", "Documents complete", "Legal notice sent", "Delay before filing (months)", "Claim size (lakh)", "Precedent support"]
BERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "bert_outcome")
_PM = None

def _pm():   # trained on first use so the app starts fast
    global _PM
    if _PM is None:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        r, n, bias = np.random.default_rng(7), 3000, np.array(_BIAS)
        X = np.c_[r.integers(0, 6, n), r.integers(1, 6, n), r.integers(0, 2, n), r.integers(0, 2, n), r.integers(0, 48, n), r.uniform(0, 60, n), r.uniform(0, 1, n)]
        s = .9 * (X[:, 1] - 3) + .8 * X[:, 2] + .7 * X[:, 3] - .04 * X[:, 4] - .01 * X[:, 5] + 1.5 * X[:, 6] + bias[X[:, 0].astype(int)] - .8 + r.normal(0, .6, n)
        y = (s > 0).astype(int)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.2, random_state=7)
        m = RandomForestClassifier(150, max_depth=8, random_state=7).fit(Xtr, ytr)
        _PM = dict(np=np, model=m, Xtr=Xtr, base=Xtr.mean(0), acc=round(m.score(Xte, yte) * 100))
    return _PM

def pred_acc(): return _pm()["acc"]
def _vec(x): return [CASE_TYPES.index(x["case_type"]), x["evidence"], x["docs"], x["notice"], x["delay"], x["claim"], x["precedent"]]

def _contribs(v, how="shap"):
    P = _pm(); np, MODEL, Xtr, BASE = P["np"], P["model"], P["Xtr"], P["base"]
    if how == "lime":
        try:
            from lime.lime_tabular import LimeTabularExplainer
            ex = LimeTabularExplainer(Xtr, feature_names=FEATURE_NAMES, class_names=["Unfavourable", "Favourable"], categorical_features=[0],
                                      categorical_names={0: CASE_TYPES}, discretize_continuous=True, random_state=7)
            m = dict(ex.explain_instance(np.array(v), MODEL.predict_proba, num_features=len(v)).as_map()[1])
            return [m.get(j, 0) for j in range(len(v))], "LIME (tabular)"
        except Exception:
            pass
    try:
        import shap
        sv = shap.TreeExplainer(MODEL).shap_values(np.array([v]))
        sv = sv[1][0] if isinstance(sv, list) else (sv[0, :, 1] if sv.ndim == 3 else sv[0])
        return list(sv), "SHAP (TreeExplainer)"
    except Exception:
        p, out = MODEL.predict_proba([v])[0][1], []
        for j in range(len(v)):
            w = list(v); w[j] = BASE[j]; out.append(p - MODEL.predict_proba([w])[0][1])
        return out, "feature ablation (pip install shap lime for SHAP and LIME)"

def predict_case(x, how="shap"):
    c = lambda a, lo, hi: min(hi, max(lo, a))
    x = dict(x, evidence=c(x["evidence"], 1, 5), delay=c(x["delay"], 0, 60), claim=c(x["claim"], 0, 100), precedent=c(x["precedent"], 0, 1))
    v = _vec(x); p = float(_pm()["model"].predict_proba([v])[0][1]); con, method = _contribs(v, how)
    shown = [x["case_type"].replace("_", " "), x["evidence"], "yes" if x["docs"] else "no", "yes" if x["notice"] else "no", f"{x['delay']:g}", f"{x['claim']:g}", f"{x['precedent']:.2f}"]
    facts = []
    for j in sorted(range(len(v)), key=lambda j: -abs(con[j])):
        pts = round(con[j] * 100)
        if pts: facts.append(dict(pts=pts, text=f"{FEATURE_NAMES[j]} ({shown[j]}) {'raises' if pts > 0 else 'lowers'} the estimated chance by about {abs(pts)} points."))
    return dict(prob=round(p * 100), label="Favourable" if p >= .5 else "Unfavourable", factors=facts[:6], method=method)

def bert_view(text):
    """Optional BERT view of the case facts, explained word by word with LIME. None unless models/bert_outcome exists."""
    if not text.strip() or not os.path.isdir(BERT_DIR): return None
    try:
        import numpy as np
        from transformers import pipeline
        from lime.lime_text import LimeTextExplainer
        clf = pipeline("text-classification", model=BERT_DIR, top_k=None, truncation=True, max_length=256)
        def probs(texts):
            res = clf(list(texts)); get = lambda o, l: next(d["score"] for d in o if d["label"] == l)
            return np.array([[get(o, "LABEL_0"), get(o, "LABEL_1")] for o in res])
        ex = LimeTextExplainer(class_names=["Unfavourable", "Favourable"]).explain_instance(text, probs, num_features=8, num_samples=200)
        return dict(prob=round(float(probs([text])[0][1]) * 100), words=[(w, round(s * 100)) for w, s in ex.as_list()])
    except Exception as e:
        return dict(error=str(e)[:120])

# =====================================================================================
# 4. Web app: accounts, password login, AES-256-GCM vault, RBAC, hash-chained audit log
# =====================================================================================
def _load_env():   # tiny .env reader (no extra dependency): KEY=value lines next to app.py
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
_load_env()

app = Flask(__name__)
def _secret():   # unique per install, so cookies from any other project on 127.0.0.1 are never valid here
    if os.environ.get("SECRET_KEY"): return os.environ["SECRET_KEY"]
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret.key")
    if not os.path.exists(p):
        with open(p, "w") as f: f.write(secrets.token_hex(32))
    return open(p).read().strip()
app.secret_key = _secret()
app.config["SESSION_COOKIE_NAME"] = "legavault_session"
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "legal.db")
JUDGE_CODE = os.environ.get("JUDGE_CODE", "JUDGE2026")   # invite code needed to register as a judge
API_KEY = os.environ.get("GEMINI_API_KEY")                # optional: enables Gemini-powered answers
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")

SYSTEM = ("You are a careful legal information assistant for Indian users. Explain in plain language, "
          "cite relevant statutes (BNS, BNSS, BSA, Consumer Protection Act 2019, etc.) where sure, list practical "
          "next steps, and remind the user you give general information, not legal advice.")

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
            return f"AI service error ({e}). Please try again."
    for k, v in FALLBACK.items():
        if k in q.lower():
            return v + "\n\n(Demo mode: set GEMINI_API_KEY for full AI answers. This is general information, not legal advice.)"
    hits = rag_get().search(q, 3)
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

def init():
    with sqlite3.connect(DB) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, description TEXT,
            status TEXT DEFAULT 'Pending', ruling TEXT, judge_id INTEGER, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS docs(id TEXT PRIMARY KEY, owner_id INTEGER, filename TEXT, size INTEGER, sha256 TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS access(doc_id TEXT, user_id INTEGER, granted_by INTEGER, UNIQUE(doc_id,user_id));
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, email TEXT, action TEXT, doc_id TEXT, detail TEXT, ip TEXT, created TEXT, prev_hash TEXT, hash TEXT);
        CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, user_id INTEGER, q TEXT, a TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);""")

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "uid" not in session: return redirect(url_for("login"))
            if not db().execute("SELECT 1 FROM users WHERE id=?", (session["uid"],)).fetchone():   # stale cookie from an old database
                session.clear(); return redirect(url_for("login"))
            if roles and session["role"] not in roles:
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
        name, email = request.form["name"].strip(), request.form["email"].strip().lower()
        pw, role = request.form["password"], request.form.get("role", "client")
        if len(pw) < 8: flash("Password must be at least 8 characters.")
        elif role not in ROLES: flash("Invalid role.")
        elif role == "judge" and request.form.get("code") != JUDGE_CODE: flash("Invalid judge invite code.")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                             (name, email, generate_password_hash(pw), role)); db().commit()
                flash("Account created. Please log in."); return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?", (request.form["email"].strip().lower(),)).fetchone()
        if u and check_password_hash(u["password"], request.form["password"]):
            session.clear(); session.update(uid=u["id"], name=u["name"], role=u["role"], email=u["email"])
            session.permanent = True
            audit("LOGIN_SUCCESS", user=u)
            return redirect(url_for("judge" if u["role"] == "judge" else "dashboard"))
        audit("LOGIN_FAILED", detail=request.form["email"][:80]); flash("Email or password is incorrect.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if "uid" in session: audit("LOGOUT")
    session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required("client", "lawyer", "associate", "judge")
def dashboard():
    cases = [dec_case(r) for r in db().execute("SELECT * FROM cases WHERE user_id=? ORDER BY id DESC", (session["uid"],)).fetchall()]
    chats = [dec_chat(r) for r in db().execute("SELECT * FROM chats WHERE user_id=? ORDER BY id DESC LIMIT 5", (session["uid"],)).fetchall()]
    return render_template("dashboard.html", cases=cases, chats=chats)

@app.route("/ask", methods=["POST"])
@login_required("client", "lawyer", "associate", "judge")
def ask():
    q = (request.json or {}).get("q", "").strip()[:2000]
    if not q: return jsonify(a="Please type a question."), 400
    a = ai_answer(q)
    uid = session["uid"]
    db().execute("INSERT INTO chats(user_id,q,a) VALUES(?,?,?)", (uid, fenc(q, f"chats.q:{uid}"), fenc(a, f"chats.a:{uid}"))); db().commit()
    return jsonify(a=a)

@app.route("/cases/new", methods=["POST"])
@login_required("client", "lawyer", "associate", "judge")
def new_case():
    uid = session["uid"]
    db().execute("INSERT INTO cases(user_id,title,description) VALUES(?,?,?)",
                 (uid, fenc(request.form["title"].strip(), f"cases.title:{uid}"),
                  fenc(request.form["description"].strip(), f"cases.description:{uid}"))); db().commit()
    flash("Case submitted to the judge panel."); return redirect(url_for("dashboard"))

@app.route("/judge")
@login_required("judge")
def judge():
    cases = [dec_case(r) for r in db().execute("SELECT c.*, u.name AS client FROM cases c JOIN users u ON u.id=c.user_id ORDER BY (c.status='Pending') DESC, c.id DESC").fetchall()]
    return render_template("judge.html", cases=cases, pending=sum(1 for c in cases if c["status"] == "Pending"))

@app.route("/judge/<int:cid>", methods=["POST"])
@login_required("judge")
def rule(cid):
    db().execute("UPDATE cases SET status=?, ruling=?, judge_id=? WHERE id=?",
                 (request.form["status"], fenc(request.form["ruling"].strip(), f"cases.ruling:{cid}"), session["uid"], cid)); db().commit()
    flash(f"Case #{cid} updated."); return redirect(url_for("judge"))

@app.route("/judge/<int:cid>/ai", methods=["POST"])
@login_required("judge")
def ai_brief(cid):
    c = dec_case(db().execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone())
    return jsonify(a=ai_answer(f"Summarise the key legal issues and relevant law for a judge:\n{c['title']}\n{c['description']}"))


# ---------- Secure document transfer: AES-256-GCM, RBAC, hash-chained audit log ----------
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
ROLES = {"client", "lawyer", "associate", "judge"}
PERMS = {r: {"upload", "share", "audit"} for r in ("lawyer", "associate", "client", "judge")}   # every role can use every feature
SHARE_TO = {r: ROLES - {r} for r in ROLES}   # who each role may send files to; tighten here if you want stricter rules
VAULT = os.path.join(HERE, "vault"); os.makedirs(VAULT, exist_ok=True)
DOC_ROLES = ("client", "lawyer", "associate", "judge")

def can(perm): return perm in PERMS.get(session.get("role"), ())

def master_key():  # 32 bytes = AES-256. Use DOC_KEY (urlsafe base64) in production, else a local key file is created.
    if os.environ.get("DOC_KEY"): return base64.urlsafe_b64decode(os.environ["DOC_KEY"])
    p = os.path.join(os.path.dirname(__file__), "master.key")
    if not os.path.exists(p):
        with open(p, "wb") as f: f.write(AESGCM.generate_key(256))
        os.chmod(p, 0o600)
    return open(p, "rb").read()

# ---- AES-256-GCM field encryption for data at rest (case text, rulings, chat history) ----
# A separate 256-bit sub-key is derived from the master key with HKDF, so field encryption and
# document encryption never share a key. Each value gets a fresh 96-bit nonce and is bound to its
# context (table.column:owner) as AAD, so ciphertext copied to another row/column fails to decrypt.
_FIELD_PREFIX = "enc1:"
def _field_key():
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"legavault-field-v1").derive(master_key())

def fenc(text, ctx):
    if text is None or str(text).startswith(_FIELD_PREFIX): return text
    n = os.urandom(12)
    ct = AESGCM(_field_key()).encrypt(n, str(text).encode(), ctx.encode())
    return _FIELD_PREFIX + base64.urlsafe_b64encode(n + ct).decode()

def fdec(val, ctx):
    if val is None or not str(val).startswith(_FIELD_PREFIX): return val      # legacy plaintext rows still display
    try:
        raw = base64.urlsafe_b64decode(val[len(_FIELD_PREFIX):])
        return AESGCM(_field_key()).decrypt(raw[:12], raw[12:], ctx.encode()).decode()
    except Exception:
        return "[unreadable: integrity check failed]"

def dec_case(r):
    d = dict(r)
    d["title"] = fdec(d["title"], f"cases.title:{d['user_id']}")
    d["description"] = fdec(d["description"], f"cases.description:{d['user_id']}")
    d["ruling"] = fdec(d["ruling"], f"cases.ruling:{d['id']}")
    return d

def dec_chat(r):
    d = dict(r)
    d["q"] = fdec(d["q"], f"chats.q:{d['user_id']}"); d["a"] = fdec(d["a"], f"chats.a:{d['user_id']}")
    return d

def audit(action, doc_id=None, detail="", user=None):
    uid = user["id"] if user else session.get("uid")
    email = user["email"] if user else session.get("email", "-")
    p = db().execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = p["hash"] if p else "0" * 64
    ts, ip = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds"), request.remote_addr
    h = hashlib.sha256(f"{prev}|{uid}|{action}|{doc_id}|{detail}|{ip}|{ts}".encode()).hexdigest()
    db().execute("INSERT INTO audit(user_id,email,action,doc_id,detail,ip,created,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)",
                 (uid, email, action, doc_id, detail, ip, ts, prev, h)); db().commit()

def my_doc(did):
    return db().execute("SELECT * FROM docs WHERE id=? AND (owner_id=? OR id IN (SELECT doc_id FROM access WHERE user_id=?))",
                        (did, session["uid"], session["uid"])).fetchone()

@app.route("/vault")
@login_required(*DOC_ROLES)
def vault():
    docs = db().execute("""SELECT d.*, u.name AS owner, (SELECT GROUP_CONCAT(x.name, ', ') FROM access a JOIN users x ON x.id=a.user_id WHERE a.doc_id=d.id) AS shared
        FROM docs d JOIN users u ON u.id=d.owner_id WHERE d.owner_id=? OR d.id IN (SELECT doc_id FROM access WHERE user_id=?)
        ORDER BY d.created DESC""", (session["uid"], session["uid"])).fetchall()
    return render_template("vault.html", docs=docs, shares=can("share"), langs=ocr_langs())

@app.route("/vault/upload", methods=["POST"])
@login_required(*DOC_ROLES)
def upload():
    f = request.files.get("file")
    if not can("upload") or not f or not f.filename: flash("Choose a file to upload."); return redirect(url_for("vault"))
    if f.filename.rsplit(".", 1)[-1].lower() not in OCR_EXT:
        flash("Upload a PDF, image (PNG, JPG, TIFF, BMP, WEBP) or TXT file."); return redirect(url_for("vault"))
    data, did = f.read(), uuid.uuid4().hex
    with open(os.path.join(VAULT, did + ".enc"), "wb") as fh: fh.write(enc(data, did))
    text, how = extract_text(data, f.filename, request.form.get('lang', 'eng'))      # analysis happens in memory; results are stored encrypted too
    ana = {"method": how, "text": text, "summary": summarize(text), "facts": key_facts(text),
           "related": rag_get().search(text[:3000], 5) if text.strip() else []}
    with open(os.path.join(VAULT, did + ".ana"), "wb") as fh: fh.write(enc(json.dumps(ana).encode(), did + ".ana"))
    from werkzeug.utils import secure_filename
    name, digest = secure_filename(f.filename) or "document", hashlib.sha256(data).hexdigest()
    db().execute("INSERT INTO docs(id,owner_id,filename,size,sha256) VALUES(?,?,?,?,?)", (did, session["uid"], name, len(data), digest)); db().commit()
    audit("UPLOAD", did, f"{name}, {len(data)} bytes, sha256={digest[:16]}")
    audit("ANALYSED", did, how[:60]); flash("Document encrypted, analysed and stored."); return redirect(url_for("vault"))

@app.route("/vault/share/<did>", methods=["POST"])
@login_required(*DOC_ROLES)
def share(did):
    d = db().execute("SELECT * FROM docs WHERE id=? AND owner_id=?", (did, session["uid"])).fetchone()
    t = db().execute("SELECT * FROM users WHERE email=?", (request.form["email"].strip().lower(),)).fetchone()
    if not d or not can("share"): audit("SHARE_DENIED", did); flash("You cannot share this document."); return redirect(url_for("vault"))
    if not t or t["role"] not in SHARE_TO.get(session["role"], ()):
        audit("SHARE_DENIED", did, "recipient not allowed"); flash(f"A {session['role']} can only share with: {', '.join(sorted(SHARE_TO[session['role']]))} accounts."); return redirect(url_for("vault"))
    db().execute("INSERT OR IGNORE INTO access(doc_id,user_id,granted_by) VALUES(?,?,?)", (did, t["id"], session["uid"])); db().commit()
    audit("SHARE", did, f"to {t['email']} ({t['role']})"); flash(f"Shared with {t['name']}."); return redirect(url_for("vault"))

@app.route("/vault/download/<did>")
@login_required(*DOC_ROLES)
def download(did):
    d = my_doc(did)
    if not d: audit("ACCESS_DENIED", did); flash("You do not have access to that document."); return redirect(url_for("vault"))
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
    h = rag_get().search(q, 4)
    return ("Relevant sources:\n" + "\n".join(f"- {x['title']} ({x['citation']}): {x['text']}" for x in h) + "\n\n" if h else "") + "Question: " + q

@app.route("/vault/analysis/<did>")
@login_required(*DOC_ROLES)
def analysis(did):
    d = my_doc(did)
    if not d: audit("ACCESS_DENIED", did); flash("You do not have access to that document."); return redirect(url_for("vault"))
    p = os.path.join(VAULT, did + ".ana")
    if not os.path.exists(p): flash("No analysis was stored for this document."); return redirect(url_for("vault"))
    try: ana = json.loads(dec(open(p, "rb").read(), did + ".ana"))
    except Exception: audit("TAMPER_DETECTED", did); flash("Integrity check failed."); return redirect(url_for("vault"))
    audit("ANALYSIS_VIEW", did); return render_template("analysis.html", d=d, a=ana)

@app.route("/search", methods=["GET", "POST"])
@login_required()
def search():
    q, res = request.form.get("q", "").strip()[:500], []
    if q: res = rag_get().search(q, 6); audit("SEARCH")
    return render_template("search.html", q=q, res=res, mode=rag_get().mode)

@app.route("/predict", methods=["GET", "POST"])
@login_required("client", "lawyer", "associate", "judge")
def predict_view():
    out = None
    if request.method == "POST":
        f = request.form
        try:
            facts = f.get("facts", "")[:3000]
            prec = [r for r in rag_get().search(facts or f["case_type"], 10) if r["type"] == "precedent"][:3]
            support = min(1.0, prec[0]["score"] * rag_get().scale) if (facts and prec) else 0.5
            out = predict_case(dict(case_type=f["case_type"], evidence=int(f["evidence"]), docs=int("docs" in f), notice=int("notice" in f),
                                    delay=float(f.get("delay") or 0), claim=float(f.get("claim") or 0), precedent=support), f.get("how", "shap"))
            out["precedents"], out["bert"] = prec, bert_view(facts); audit("PREDICTION_RUN", detail=f["case_type"])
        except (ValueError, KeyError):
            flash("Please check the numbers you entered.")
    return render_template("predict.html", out=out, types=CASE_TYPES, acc=pred_acc())

@app.route("/status")
@login_required()
def status():
    has = lambda m: importlib.util.find_spec(m) is not None
    items = [("OCR engine", "Google Vision" if os.environ.get("GOOGLE_VISION") else (("Tesseract ready, languages: " + ", ".join(ocr_langs().values())) if ocr_ready() else "Not ready: run brew install tesseract, then pip install pytesseract pillow pymupdf")),
             ("Summariser", "Transformer (DistilBART)" if os.environ.get("USE_TRANSFORMER") and has("transformers") else "Extractive fallback (set USE_TRANSFORMER=1 and install requirements-ai.txt)"),
             ("Semantic search", rag_get().mode),
             ("Explainability", ", ".join(n for n, m in [("SHAP", "shap"), ("LIME", "lime")] if has(m)) or "feature ablation only"),
             ("BERT outcome model", "Loaded from models/bert_outcome" if os.path.isdir(BERT_DIR) else "Not trained yet (see train_bert.py)"),
             ("Encryption", "AES-256-GCM: documents + analyses, and case/chat text (HKDF sub-key, per-value nonce, AAD-bound)"), ("Login", "Email and password")]
    return render_template("status.html", items=items)


@app.route("/ocr", methods=["GET", "POST"])
@login_required(*DOC_ROLES)
def ocr_tool():
    """Stand-alone OCR: read text from a scan, photo or PDF. The file is processed in memory and is NOT stored."""
    res, langs = None, ocr_langs()
    if request.method == "POST":
        f, lang = request.files.get("file"), request.form.get("lang", "eng")
        if not f or not f.filename or f.filename.rsplit(".", 1)[-1].lower() not in OCR_EXT:
            flash("Choose a PDF, image (PNG, JPG, TIFF, BMP, WEBP) or TXT file.")
        elif lang not in langs: flash("That language is not installed.")
        else:
            from werkzeug.utils import secure_filename
            r = read_document(f.read(), f.filename, lang); name = secure_filename(f.filename) or "document"
            audit("OCR_RUN", detail=f"{name}, {r['how'][:40]}, {len(r['text'])} chars")
            res = dict(r, name=name, words=len(r["text"].split()), facts=key_facts(r["text"]) if r["text"].strip() else None)
    return render_template("ocr.html", res=res, langs=langs, ready=ocr_ready())

# =====================================================================================
# 5. Templates and stylesheet (embedded so this whole app is one file)
# =====================================================================================
TEMPLATES = {
    'base.html': r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}LegaVault{% endblock %}</title>
<style>{{ CSS|safe }}</style></head><body>
<header class="bar"><a class="brand" href="/">Lega<span>Vault</span></a>
{% if session.uid %}<nav>{% if session.role == "judge" %}<a href="/judge">Judge panel</a>{% endif %}<a href="/dashboard">Assistant</a><a href="/vault">Vault</a><a href="/ocr">OCR</a><a href="/search">Search</a><a href="/predict">Predict</a><a href="/audit">Audit log</a><a href="/status">Status</a><span class="who">{{ session.name }} ({{ session.role }})</span><a href="/logout">Log out</a></nav>{% endif %}</header>
<main>{% for m in get_flashed_messages() %}<p class="flash">{{ m }}</p>{% endfor %}{% block body %}{% endblock %}</main>
<footer>General legal information only. Not a substitute for a licensed advocate.</footer>
</body></html>
''',
    '_tiles.html': r'''<div class="tiles">
{% if session.role == "judge" %}<a class="tile" href="/judge"><b>Review cases</b><span>{% if pending is defined %}{{ pending }} awaiting a ruling{% else %}Give rulings and AI case briefs{% endif %}</span></a>{% endif %}
<a class="tile" href="/vault"><b>Secure vault</b><span>Upload, analyse and share encrypted documents</span></a>
<a class="tile" href="/ocr"><b>OCR reader</b><span>Extract text from scans, photos and PDFs</span></a>
<a class="tile" href="/dashboard#assistant"><b>Legal assistant</b><span>Ask a question, or submit a case to a judge</span></a>
<a class="tile" href="/search"><b>Search law</b><span>Find statutes and precedents by describing the issue</span></a>
<a class="tile" href="/predict"><b>Estimate an outcome</b><span>Explainable case outcome estimate</span></a>
<a class="tile" href="/audit"><b>Audit log</b><span>See who opened or shared each document</span></a>
<a class="tile" href="/status"><b>System status</b><span>See which AI modules are running</span></a>
</div>
''',
    'analysis.html': r'''{% extends "base.html" %}{% block title %}Analysis · LegaVault{% endblock %}
{% block body %}<h2>{{ d.filename }}</h2>
<p class="muted">Read by: {{ a.method }}. Detected type: {{ a.facts.type }}.</p>
<article class="case"><h3>Summary</h3><p>{{ a.summary or 'No readable text was found in this file.' }}</p></article>
<article class="case"><h3>Key details found</h3>
<p><b>Amounts:</b> {{ a.facts.amounts|join(', ') or 'none found' }}</p>
<p><b>Dates:</b> {{ a.facts.dates|join(', ') or 'none found' }}</p>
<p><b>Sections cited:</b> {{ a.facts.sections|join(', ') or 'none found' }}</p></article>
<article class="case"><h3>Related statutes and precedents</h3>
{% for r in a.related %}<p><span class="tag">{{ r.type }}</span><b>{{ r.title }}</b> <span class="muted">{{ r.citation }}</span><br>{{ r.text }}</p>
{% else %}<p class="muted">No close matches in the knowledge base.</p>{% endfor %}</article>
<details class="case"><summary>Extracted text</summary><pre class="brief">{{ a.text }}</pre></details>
<p><a class="btn" href="/vault/download/{{ d.id }}">Download original</a> <a href="/vault">Back to vault</a></p>{% endblock %}
''',
    'audit.html': r'''{% extends "base.html" %}{% block title %}Audit log · LegaVault{% endblock %}
{% block body %}<h2>Audit log</h2>
{% if bad %}<p class="flash bad">Tamper warning: the log chain breaks at entry #{{ bad }}.</p>{% else %}<p class="ok">Log chain verified: no entries have been altered.</p>{% endif %}
<div style="overflow-x:auto"><table><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Document</th><th>Detail</th><th>IP</th></tr>
{% for r in rows %}<tr><td>{{ r.created }}</td><td>{{ r.email }}</td><td>{{ r.action }}</td><td>{{ r.filename or '' }}</td><td>{{ r.detail or '' }}</td><td>{{ r.ip }}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No activity yet.</td></tr>{% endfor %}</table></div>{% endblock %}
''',
    'dashboard.html': r'''{% extends "base.html" %}{% block title %}Dashboard · LegaVault{% endblock %}
{% block body %}{% include "_tiles.html" %}<div class="grid">
<section id="assistant"><h2>Ask the legal assistant</h2>
<div id="log" class="log">{% for c in chats|reverse %}<div class="q">{{ c.q }}</div><div class="a">{{ c.a }}</div>{% endfor %}
{% if not chats %}<p class="muted">Ask about rent, cheque bounce, FIRs, consumer complaints, bail or divorce.</p>{% endif %}</div>
<div class="ask"><textarea id="q" rows="2" placeholder="Describe your situation"></textarea><button id="send">Ask</button></div></section>
<section><h2>Submit a case to a judge</h2>
<form method="post" action="/cases/new"><label>Title<input name="title" required></label>
<label>Details<textarea name="description" rows="4" required></textarea></label><button>Submit case</button></form>
<h2>Your cases</h2>
{% for c in cases %}<article class="case"><b>#{{ c.id }} {{ c.title }}</b><span class="tag {{ c.status|lower }}">{{ c.status }}</span>
{% if c.ruling %}<p><i>Judge's ruling:</i> {{ c.ruling }}</p>{% endif %}</article>
{% else %}<p class="muted">No cases yet. Submit one above to get a judge's ruling.</p>{% endfor %}</section></div>
<script>
const log=document.getElementById('log'),q=document.getElementById('q');
function add(c,t){const d=document.createElement('div');d.className=c;d.textContent=t;log.appendChild(d);log.scrollTop=log.scrollHeight;return d}
document.getElementById('send').onclick=async()=>{const t=q.value.trim();if(!t)return;add('q',t);q.value='';const w=add('a','Thinking…');
const r=await fetch('/ask',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q:t})});w.textContent=(await r.json()).a};
log.scrollTop=log.scrollHeight;</script>{% endblock %}
''',
    'judge.html': r'''{% extends "base.html" %}{% block title %}Judge panel · LegaVault{% endblock %}
{% block body %}<h2>Judge panel</h2>{% include "_tiles.html" %}<h3>Cases</h3>
{% for c in cases %}<article class="case"><b>#{{ c.id }} {{ c.title }}</b> <span class="muted">by {{ c.client }}</span>
<span class="tag {{ c.status|lower }}">{{ c.status }}</span><p>{{ c.description }}</p>
<button type="button" class="ghost" onclick="brief({{ c.id }},this)">AI case brief</button><div class="brief" id="b{{ c.id }}"></div>
<form method="post" action="/judge/{{ c.id }}"><select name="status">{% for s in ['Pending','Under Review','Resolved','Dismissed'] %}<option {{ 'selected' if s==c.status }}>{{ s }}</option>{% endfor %}</select>
<textarea name="ruling" rows="2" placeholder="Ruling or remarks" required>{{ c.ruling or '' }}</textarea><button>Save ruling</button></form></article>
{% else %}<p class="muted">No cases have been submitted yet.</p>{% endfor %}
<script>async function brief(id,b){b.textContent='Working…';const r=await fetch('/judge/'+id+'/ai',{method:'POST'});
document.getElementById('b'+id).textContent=(await r.json()).a;b.textContent='AI case brief'}</script>{% endblock %}
''',
    'login.html': r'''{% extends "base.html" %}{% block title %}Log in · LegaVault{% endblock %}
{% block body %}<section class="auth"><h1>LegaVault</h1><p class="muted">AI-based legal document analysis with encrypted sharing</p><h2>Log in</h2>
<form method="post"><label>Email<input type="email" name="email" required autofocus></label>
<label>Password<input type="password" name="password" required></label>
<button>Log in</button></form>
<p>New here? <a href="/signup">Create an account</a></p></section>{% endblock %}
''',
    'predict.html': r'''{% extends "base.html" %}{% block title %}Outcome prediction · LegaVault{% endblock %}
{% block body %}<h2>Case outcome estimate</h2>
<p class="flash">Demonstration model: a Random Forest trained on synthetic data (holdout accuracy {{ acc }}%). It shows how explainable prediction works and is not a forecast of any real case.</p>
<div class="grid"><form method="post"><label>Case type<select name="case_type">{% for t in types %}<option value="{{ t }}">{{ t.replace('_',' ') }}</option>{% endfor %}</select></label>
<label>Evidence strength<select name="evidence">{% for i in range(1,6) %}<option value="{{ i }}" {{ 'selected' if i==3 }}>{{ i }} of 5</option>{% endfor %}</select></label>
<label>Months between the dispute and filing<input type="number" name="delay" min="0" max="60" value="0"></label>
<label>Claim size in lakh rupees<input type="number" name="claim" min="0" max="100" step="0.1" value="5"></label>
<label><input type="checkbox" name="docs" style="width:auto"> Documents are complete</label>
<label><input type="checkbox" name="notice" style="width:auto"> Legal notice already sent</label>
<label>Explanation method<select name="how"><option value="shap">SHAP</option><option value="lime">LIME</option></select></label>
<label>Facts of the case (used to find supporting precedents)<textarea name="facts" rows="4"></textarea></label><button>Estimate outcome</button></form>
<section>{% if out %}<article class="case"><h3>{{ out.label }}: {{ out.prob }}% estimated chance</h3>
{% for f in out.factors %}<p>{{ f.text }}</p><div class="meter"><i class="{{ 'neg' if f.pts < 0 }}" style="width:{{ [f.pts|abs * 3, 100]|min }}%"></i></div>{% endfor %}
<p class="muted">Explained with {{ out.method }}.</p></article>
{% if out.precedents %}<article class="case"><h3>Closest precedents</h3>{% for r in out.precedents %}<p><b>{{ r.title }}</b> <span class="muted">{{ r.citation }}</span><br>{{ r.text }}</p>{% endfor %}</article>{% endif %}
{% if out.bert and out.bert.prob is defined %}<article class="case"><h3>BERT view of the facts: {{ out.bert.prob }}% favourable</h3>
<p>Words that moved it most (LIME): {% for w, s in out.bert.words %}{{ w }} ({{ '%+d'|format(s) }}){{ ', ' if not loop.last }}{% endfor %}</p></article>
{% elif out.bert and out.bert.error %}<p class="muted">BERT model could not run: {{ out.bert.error }}</p>{% endif %}
{% else %}<p class="muted">Fill in the details and press Estimate outcome. Each factor's effect on the result is shown in plain language.</p>{% endif %}</section></div>{% endblock %}
''',
    'search.html': r'''{% extends "base.html" %}{% block title %}Legal search · LegaVault{% endblock %}
{% block body %}<h2>Search statutes and precedents</h2>
<form method="post" class="ask"><input name="q" value="{{ q }}" placeholder="Describe the issue, e.g. landlord refusing to return deposit" required autofocus><button>Search</button></form>
<p class="muted">Semantic retrieval using {{ mode }}. Verify every citation against the official text before relying on it.</p>
{% for r in res %}<article class="case"><span class="tag">{{ r.type }}</span><b>{{ r.title }}</b> <span class="muted">{{ r.citation }}</span><p>{{ r.text }}</p><span class="muted">Relevance {{ r.score }}</span></article>
{% else %}{% if q %}<p class="muted">No matches. Try different words describing the legal problem.</p>{% endif %}{% endfor %}{% endblock %}
''',
    'signup.html': r'''{% extends "base.html" %}{% block title %}Sign up · LegaVault{% endblock %}
{% block body %}<section class="auth"><h1>Create your account</h1>
<form method="post"><label>Full name<input name="name" required></label>
<label>Email<input type="email" name="email" required></label>
<label>Password (8+ characters)<input type="password" name="password" minlength="8" required></label>
<label>I am a<select name="role" id="role"><option value="client">Client</option><option value="lawyer">Lawyer</option><option value="associate">Associate</option><option value="judge">Judge</option></select></label>
<label id="codebox" hidden>Judge invite code<input name="code"></label>
<button>Sign up</button></form>
<p>Already registered? <a href="/login">Log in</a></p></section>
<script>const r=document.getElementById('role'),b=document.getElementById('codebox');r.onchange=()=>b.hidden=r.value!=='judge';</script>{% endblock %}
''',
    'status.html': r'''{% extends "base.html" %}{% block title %}System status · LegaVault{% endblock %}
{% block body %}<h2>System status</h2><p class="muted">Shows which AI modules are active in this running copy.</p>
<table>{% for k, v in items %}<tr><th>{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}</table>{% endblock %}
''',
    'vault.html': r'''{% extends "base.html" %}{% block title %}Secure vault · LegaVault{% endblock %}
{% block body %}<h2>Secure document vault</h2>
<p class="muted">Files are encrypted with AES-256-GCM, read with OCR and summarised on upload; the analysis is stored encrypted too. Each download needs a one-time code, and every action is logged.</p>
<form method="post" action="/vault/upload" enctype="multipart/form-data" class="case"><label>Upload a scanned document, PDF or image (max 16 MB)<input type="file" name="file" accept=".pdf,.png,.jpg,.jpeg,.tif,.tiff,.bmp,.webp,.txt" required></label><label>OCR language<select name="lang">{% for k, v in langs.items() %}<option value="{{ k }}">{{ v }}</option>{% endfor %}</select></label><button>Encrypt and upload</button></form>
{% for d in docs %}<article class="case"><b>{{ d.filename }}</b> <span class="muted">{{ d.size // 1024 }} KB, owner: {{ d.owner }}</span>
<div class="row"><a class="btn" href="/vault/analysis/{{ d.id }}">View analysis</a><a class="btn" href="/vault/download/{{ d.id }}">Download</a>
{% if d.owner_id == session.uid and shares %}<form method="post" action="/vault/share/{{ d.id }}" class="inline"><input type="email" name="email" placeholder="Recipient email" required><button class="ghost">Share</button></form>{% endif %}</div>
{% if d.shared %}<p class="muted">Shared with: {{ d.shared }}</p>{% endif %}</article>
{% else %}<p class="muted">No documents yet. Upload one to start.</p>{% endfor %}{% endblock %}
''',
    'ocr.html': r'''{% extends "base.html" %}{% block title %}OCR reader · LegaVault{% endblock %}
{% block body %}<h2>OCR reader</h2>
<p class="muted">Upload a scan, phone photo or PDF and get the text back. The file is read in memory and is not stored. To keep a document, use the Secure vault instead.</p>
{% if not ready %}<p class="flash bad">OCR engine is not installed. Run <code>brew install tesseract</code> and <code>pip install pytesseract pillow pymupdf</code>, then restart.</p>{% endif %}
<form method="post" enctype="multipart/form-data" class="case"><label>Document (PDF, PNG, JPG, TIFF, BMP, WEBP, TXT, max 16 MB)<input type="file" name="file" accept=".pdf,.png,.jpg,.jpeg,.tif,.tiff,.bmp,.webp,.txt" required></label>
<label>Language of the document<select name="lang">{% for k, v in langs.items() %}<option value="{{ k }}">{{ v }}</option>{% endfor %}</select></label><button>Read text</button></form>
{% if res %}<article class="case"><h3>{{ res.name }}</h3>
<p class="muted">Method: {{ res.how }}{% if res.conf is not none %} · Confidence: {{ res.conf }}%{% endif %} · Pages: {{ res.pages }} · Words: {{ res.words }}{% if res.facts %} · Looks like: {{ res.facts.type }}{% endif %}</p>
{% if res.conf is not none and res.conf < 60 %}<p class="flash">Low confidence. Try a sharper, straighter, well-lit scan for better results.</p>{% endif %}
{% if res.text.strip() %}<textarea id="out" rows="14" style="width:100%">{{ res.text }}</textarea>
<div class="row"><button type="button" onclick="navigator.clipboard.writeText(document.getElementById('out').value)">Copy text</button>
<button type="button" class="ghost" onclick="dl()">Download .txt</button></div>
{% if res.facts %}<p><b>Amounts:</b> {{ res.facts.amounts|join(', ') or 'none found' }}<br><b>Dates:</b> {{ res.facts.dates|join(', ') or 'none found' }}<br><b>Sections cited:</b> {{ res.facts.sections|join(', ') or 'none found' }}</p>{% endif %}
<script>function dl(){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([document.getElementById('out').value],{type:'text/plain'}));a.download={{ (res.name.rsplit('.',1)[0] ~ '.txt')|tojson }};a.click()}</script>
{% else %}<p class="muted">No readable text was found.</p>{% endif %}</article>{% endif %}{% endblock %}
''',
}
CSS = r''':root{--bg:#f4f6f8;--ink:#14213d;--red:#8c2f39;--line:#dde2e8;--card:#fff;--muted:#6b7686}
@media(prefers-color-scheme:dark){:root{--bg:#0f1624;--ink:#e8ecf3;--red:#d4636f;--line:#2a3550;--card:#172036;--muted:#98a3b8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,sans-serif}
h1,h2,.brand{font-family:"Iowan Old Style",Palatino,Georgia,serif;font-weight:700}
.bar{flex-wrap:wrap;gap:8px 16px;display:flex;justify-content:space-between;align-items:center;padding:14px 5vw;border-bottom:3px double var(--red);background:var(--card)}
.brand{font-size:1.6rem;color:var(--ink);text-decoration:none}.brand span{color:var(--red);margin-left:2px}
nav{display:flex;flex-wrap:wrap;gap:6px 16px;align-items:center}.who{color:var(--muted);font-size:.9rem}a{color:var(--red)}
main{max-width:1100px;margin:32px auto;padding:0 5vw;min-height:70vh}
.grid{display:grid;grid-template-columns:1.2fr 1fr;gap:32px}@media(max-width:800px){.grid{grid-template-columns:1fr}}
.auth{max-width:420px;margin:6vh auto;background:var(--card);padding:32px;border:1px solid var(--line);border-top:4px solid var(--red)}
label{display:block;margin:12px 0;font-size:.9rem;font-weight:600}
input,select,textarea{width:100%;margin-top:4px;padding:10px;border:1px solid var(--line);border-radius:3px;background:var(--bg);color:var(--ink);font:inherit}
input:focus,select:focus,textarea:focus,button:focus-visible{outline:2px solid var(--red);outline-offset:1px}
button{background:var(--red);color:#fff;border:0;padding:10px 20px;border-radius:3px;font:inherit;font-weight:600;cursor:pointer;margin-top:8px}
button.ghost{background:none;color:var(--red);border:1px solid var(--red);padding:5px 12px}
.flash{background:var(--card);border-left:4px solid var(--red);padding:10px 14px}
.log{height:380px;overflow:auto;background:var(--card);border:1px solid var(--line);padding:14px}
.q{margin:10px 0 4px auto;max-width:80%;background:var(--ink);color:var(--bg);padding:8px 12px;border-radius:10px 10px 0 10px}
.a{max-width:90%;white-space:pre-wrap;background:var(--bg);border:1px solid var(--line);padding:8px 12px;border-radius:10px 10px 10px 0}
.ask{display:flex;gap:8px;margin-top:10px}.ask button{margin:0}
.case{background:var(--card);border:1px solid var(--line);padding:14px;margin:12px 0}
.tag{float:right;font-size:.8rem;padding:2px 10px;border:1px solid var(--line);border-radius:20px}
.tag.resolved{border-color:#2e7d4f;color:#2e7d4f}.tag.dismissed{border-color:var(--red);color:var(--red)}
.muted{color:var(--muted)}.brief{white-space:pre-wrap;margin:8px 0}
footer{text-align:center;color:var(--muted);font-size:.85rem;padding:24px}
.btn{display:inline-block;background:var(--red);color:#fff;padding:6px 14px;border-radius:3px;text-decoration:none;font-weight:600}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.inline{display:flex;gap:8px}.inline input{margin:0}.inline button{margin:0}
table{width:100%;border-collapse:collapse;font-size:.85rem;background:var(--card)}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left}
.ok{color:#2e7d4f;font-weight:600}.bad{color:var(--red)}nav a+a{margin-left:0}
.meter{background:var(--line);height:6px;border-radius:3px;margin:-8px 0 10px}.meter i{display:block;height:6px;border-radius:3px;background:#2e7d4f}.meter i.neg{background:var(--red)}
pre.brief{max-height:320px;overflow:auto;font-size:.85rem}details summary{cursor:pointer;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin:12px 0 28px}
.tile{display:block;padding:26px 22px;min-height:112px;background:var(--card);border:1px solid var(--line);border-left:6px solid var(--red);border-radius:4px;color:var(--ink);text-decoration:none}
.tile b{display:block;font-family:"Iowan Old Style",Palatino,Georgia,serif;font-size:1.35rem;margin-bottom:4px}
.tile span{color:var(--muted);font-size:.92rem}
.tile:hover,.tile:focus-visible{border-color:var(--red);box-shadow:0 0 0 2px var(--red) inset}
'''
app.jinja_loader = DictLoader(TEMPLATES)

@app.context_processor
def _inject(): return {"CSS": CSS}

if __name__ == "__main__":
    init(); app.run(debug=True, port=int(os.environ.get("PORT", 5001)))
