"""OCR (Tesseract or Google Vision) + summarisation (Transformer or extractive fallback) + fact extraction."""
import io, os, re
from collections import Counter

STOP = set("that this with from have which their shall would there been were will also such than them into upon being other these those under after before between about".split())
TYPES = {"legal notice": ["legal notice", "hereby call upon", "notice under"], "FIR / police complaint": ["first information report", "fir no", "police station"],
         "agreement / contract": ["agreement", "hereinafter", "witnesseth", "party of the first part"], "court judgment / order": ["judgment", "hon'ble", "appellant", "respondent", "petitioner"],
         "affidavit": ["affidavit", "solemnly affirm", "deponent"], "rent / lease": ["lease", "tenant", "landlord", "rent"], "cheque / bank memo": ["cheque", "returned unpaid", "insufficient funds"]}
_pipe = None

def ocr_image(b):
    if os.environ.get("GOOGLE_VISION", "").lower() in {"1", "true", "yes"}:   # needs google-cloud-vision + GOOGLE_APPLICATION_CREDENTIALS
        from google.cloud import vision
        result = vision.ImageAnnotatorClient().document_text_detection(image=vision.Image(content=b))
        if result.error.message: raise RuntimeError("Google Vision returned an OCR error")
        return result.full_text_annotation.text
    import pytesseract
    from PIL import Image
    return pytesseract.image_to_string(Image.open(io.BytesIO(b)))

def extract_text(data, filename):
    """Returns (text, method). Never raises: errors come back as a method string."""
    ext = filename.rsplit(".", 1)[-1].lower()
    try:
        if ext == "txt": return data.decode("utf-8", "ignore"), "plain text"
        if ext == "pdf":
            import fitz
            with fitz.open(stream=data, filetype="pdf") as doc:
                txt = "\n".join(p.get_text() for p in doc)
                if len(txt.strip()) > 50: return txt, "PDF text layer"
                return "\n".join(ocr_image(p.get_pixmap(dpi=200).tobytes("png")) for p in doc), "OCR (scanned PDF)"
        return ocr_image(data), "OCR (image)"
    except Exception as e:
        return "", f"OCR unavailable ({type(e).__name__}). Check Tesseract or Google Vision setup."

def summarize(text, n=5):
    text = re.sub(r"\s+", " ", text).strip()
    if len(text.split()) < 40: return text
    global _pipe
    if os.environ.get("USE_TRANSFORMER", "").lower() in {"1", "true", "yes"}:
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
    kind = max(TYPES, key=lambda k: sum(low.count(w) for w in TYPES[k]))
    return {"type": kind if sum(low.count(w) for w in TYPES[kind]) else "unclassified",
            "amounts": sorted(set(re.findall(r"(?:Rs\.?|INR|₹)\s?[\d,]+(?:\.\d+)?", t)))[:8],
            "dates": sorted(set(re.findall(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?,?\s+\d{4}\b", t)))[:8],
            "sections": sorted(set(re.findall(r"(?:Section|Sec\.)\s?\d+[A-Z]?", t)))[:8]}
