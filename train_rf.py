"""Train a Random Forest from labelled cases.

CSV columns: case_type,evidence,docs,notice,delay,claim,precedent,label
case_type must be one of predict.TYPES; docs and notice are 0/1; label is
0 (unfavourable) or 1 (favourable). Use lawful, representative, de-identified
data and validate on an independent dataset before considering real use.
"""
import csv
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

import predict

FIELDS = {"case_type", "evidence", "docs", "notice", "delay", "claim", "precedent", "label"}

if len(sys.argv) != 2:
    raise SystemExit("Usage: python train_rf.py cases.csv (columns: case_type,evidence,docs,notice,delay,claim,precedent,label)")

with open(sys.argv[1], newline="", encoding="utf-8") as source:
    reader = csv.DictReader(source)
    if not FIELDS.issubset(reader.fieldnames or []):
        raise SystemExit("CSV is missing required feature or label columns.")
    rows = list(reader)
if len(rows) < 30:
    raise SystemExit("Provide at least 30 labelled cases; more representative data is strongly preferred.")

features, labels = [], []
try:
    for row in rows:
        case_type = row["case_type"].strip()
        if case_type not in predict.TYPES:
            raise ValueError("unknown case_type")
        evidence = float(row["evidence"])
        docs, notice = int(row["docs"]), int(row["notice"])
        delay, claim, precedent = float(row["delay"]), float(row["claim"]), float(row["precedent"])
        label = int(row["label"])
        if not 1 <= evidence <= 5 or docs not in (0, 1) or notice not in (0, 1) or not 0 <= delay <= 60 or not 0 <= claim <= 100 or not 0 <= precedent <= 1 or label not in (0, 1):
            raise ValueError("feature value out of range")
        features.append([predict.TYPES.index(case_type), evidence, docs, notice, delay, claim, precedent])
        labels.append(label)
except (TypeError, ValueError, KeyError):
    raise SystemExit("CSV has invalid values. Check case_type, 0/1 flags, numeric features and 0/1 labels.")

counts = np.bincount(labels, minlength=2)
if np.min(counts) < 5:
    raise SystemExit("Include at least five examples from both outcome classes; larger, balanced datasets are preferred.")
X = np.asarray(features, dtype=float)
y = np.asarray(labels, dtype=int)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.2, random_state=42, stratify=y)
model = RandomForestClassifier(n_estimators=400, min_samples_leaf=2, class_weight="balanced_subsample", random_state=42)
model.fit(X_train, y_train)
accuracy = round(model.score(X_test, y_test) * 100)

folder = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(folder, mode=0o700, exist_ok=True)
path = os.path.join(folder, "rf_outcome.joblib")
joblib.dump({"model": model, "accuracy": accuracy, "background": X_train[:min(500, len(X_train))]}, path)
os.chmod(path, 0o600)
print(f"Saved labelled-data model to {path}. Stratified holdout accuracy: {accuracy}% ({len(y_test)} cases).")
print("Treat this score as an initial check only; assess data quality, subgroup performance and external validation before any real use.")
