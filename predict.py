"""Case outcome prediction: Random Forest + SHAP or LIME explanations, plus an optional fine-tuned BERT text model (see train_bert.py).
NOTE: the Random Forest is trained on a SYNTHETIC dataset generated from plausible rules. It demonstrates the pipeline; use real labelled case data before relying on it."""
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

TYPES = ["consumer", "cheque_bounce", "tenancy", "contract", "bail", "family"]
BIAS = np.array([.4, .5, 0, .1, -.2, -.1])
NAMES = ["Case type", "Evidence strength", "Documents complete", "Legal notice sent", "Delay before filing (months)", "Claim size (lakh)", "Precedent support"]
BERT_DIR = os.path.join(os.path.dirname(__file__), "models", "bert_outcome")
_bert_classifier = None

def vec(x): return [TYPES.index(x["case_type"]), x["evidence"], x["docs"], x["notice"], x["delay"], x["claim"], x["precedent"]]

def _data(n=3000):
    r = np.random.default_rng(7)
    X = np.c_[r.integers(0, 6, n), r.integers(1, 6, n), r.integers(0, 2, n), r.integers(0, 2, n), r.integers(0, 48, n), r.uniform(0, 60, n), r.uniform(0, 1, n)]
    s = .9 * (X[:, 1] - 3) + .8 * X[:, 2] + .7 * X[:, 3] - .04 * X[:, 4] - .01 * X[:, 5] + 1.5 * X[:, 6] + BIAS[X[:, 0].astype(int)] - .8 + r.normal(0, .6, n)
    return X, (s > 0).astype(int)

X, y = _data()
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.2, random_state=7)
MODEL = RandomForestClassifier(150, max_depth=8, random_state=7).fit(Xtr, ytr)
ACC, BASE = round(MODEL.score(Xte, yte) * 100), Xtr.mean(0)
MODEL_KIND = "synthetic demonstration model"
RF_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "rf_outcome.joblib")
if os.path.isfile(RF_MODEL_PATH):
    try:
        import joblib
        trained = joblib.load(RF_MODEL_PATH)
        if isinstance(trained, dict) and trained.get("model") is not None:
            MODEL = trained["model"]
            ACC = int(trained.get("accuracy", 0))
            Xtr = np.asarray(trained.get("background", Xtr), dtype=float)
            BASE = Xtr.mean(0)
            MODEL_KIND = "trained on labelled case data"
    except Exception:
        MODEL_KIND = "synthetic demonstration model (saved model could not be loaded)"

def _contribs(v, how="shap"):
    if how == "lime":
        try:
            from lime.lime_tabular import LimeTabularExplainer
            ex = LimeTabularExplainer(Xtr, feature_names=NAMES, class_names=["Unfavourable", "Favourable"], categorical_features=[0],
                                      categorical_names={0: TYPES}, discretize_continuous=True, random_state=7)
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

def predict(x, how="shap"):
    c = lambda a, lo, hi: min(hi, max(lo, a))
    x = dict(x, evidence=c(x["evidence"], 1, 5), delay=c(x["delay"], 0, 60), claim=c(x["claim"], 0, 100), precedent=c(x["precedent"], 0, 1))
    v = vec(x); p = float(MODEL.predict_proba([v])[0][1]); con, method = _contribs(v, how)
    shown = [x["case_type"].replace("_", " "), x["evidence"], "yes" if x["docs"] else "no", "yes" if x["notice"] else "no", f"{x['delay']:g}", f"{x['claim']:g}", f"{x['precedent']:.2f}"]
    facts = []
    for j in sorted(range(len(v)), key=lambda j: -abs(con[j])):
        pts = round(con[j] * 100)
        if pts: facts.append(dict(pts=pts, text=f"{NAMES[j]} ({shown[j]}) {'raises' if pts > 0 else 'lowers'} the estimated chance by about {abs(pts)} points."))
    return dict(prob=round(p * 100), label="Favourable" if p >= .5 else "Unfavourable", factors=facts[:6], method=method)

def bert_view(text):
    """Optional BERT view of the case facts, explained word by word with LIME. None unless models/bert_outcome exists."""
    global _bert_classifier
    if not text.strip() or not os.path.isdir(BERT_DIR): return None
    try:
        from transformers import pipeline
        from lime.lime_text import LimeTextExplainer
        _bert_classifier = _bert_classifier or pipeline("text-classification", model=BERT_DIR, top_k=None, truncation=True, max_length=256)
        clf = _bert_classifier
        def probs(texts):
            res = clf(list(texts)); get = lambda o, l: next(d["score"] for d in o if d["label"] == l)
            return np.array([[get(o, "LABEL_0"), get(o, "LABEL_1")] for o in res])
        ex = LimeTextExplainer(class_names=["Unfavourable", "Favourable"]).explain_instance(text, probs, num_features=8, num_samples=200)
        return dict(prob=round(float(probs([text])[0][1]) * 100), words=[(w, round(s * 100)) for w, s in ex.as_list()])
    except Exception as e:
        return dict(error=f"Optional BERT explanation unavailable ({type(e).__name__}).")
