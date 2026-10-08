"""Fine-tune BERT on your own labelled cases.   python train_bert.py cases.csv
cases.csv needs two columns: text (facts of the case) and label (1 = favourable outcome, 0 = unfavourable).
Needs: pip install -r requirements-ai.txt. The saved model in models/bert_outcome is picked up automatically by the Predict page."""
import sys, csv, torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments

BASE = "nlpaueb/legal-bert-base-uncased"   # legal-domain BERT; use "bert-base-uncased" for general text
if len(sys.argv) != 2:
    raise SystemExit("Usage: python train_bert.py cases.csv (CSV columns: text,label; label is 1 favourable or 0 unfavourable)")
with open(sys.argv[1], newline="", encoding="utf-8") as source:
    reader = csv.DictReader(source)
    if not {"text", "label"}.issubset(reader.fieldnames or []):
        raise SystemExit("CSV must contain text and label columns.")
    rows = [r for r in reader if r.get("text", "").strip()]
if len(rows) < 10:
    raise SystemExit("Provide at least 10 labelled case examples; more representative data is strongly preferred.")
try:
    label_values = [int(r["label"]) for r in rows]
except (TypeError, ValueError):
    raise SystemExit("Every label must be 0 (unfavourable) or 1 (favourable).")
if set(label_values) != {0, 1} or min(label_values.count(0), label_values.count(1)) < 5:
    raise SystemExit("Training data must contain at least five examples from each outcome class (0 and 1); more is preferred.")
tok = AutoTokenizer.from_pretrained(BASE)
enc = tok([r["text"] for r in rows], truncation=True, padding=True, max_length=256, return_tensors="pt")
labels = torch.tensor(label_values)

class DS(torch.utils.data.Dataset):
    def __len__(self): return len(labels)
    def __getitem__(self, i): return {**{k: v[i] for k, v in enc.items()}, "labels": labels[i]}

model = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=2)
Trainer(model=model, args=TrainingArguments("models/tmp", num_train_epochs=3, per_device_train_batch_size=8, report_to=[]), train_dataset=DS()).train()
model.save_pretrained("models/bert_outcome"); tok.save_pretrained("models/bert_outcome")
print("Saved to models/bert_outcome")
