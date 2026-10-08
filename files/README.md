# LegaVault: AI-Based Legal Document Analysis
Roles: client, lawyer, associate, judge. Every role can use every feature (vault, assistant, search, prediction, audit log, case submission); only judges can give rulings. Access to each document is still limited to its owner and the people it is shared with.

## Run it (macOS)
1. Unzip, open Terminal, `cd` into the LegaVault folder.
2. `bash start.sh`   (first run installs everything, about 2 minutes)
3. Open http://127.0.0.1:5001
4. Sign in with the email and password you registered.
For full AI mode run `bash start.sh full`. For OCR of scanned images run `brew install tesseract` once.

## Try it
Sign up a Lawyer and a Client (different emails). Log in as the lawyer, upload a file in Vault, share it with the client's email, then log in as the client and download it. Lawyers can open the Audit log. Judge signup needs the code JUDGE2026.

## Modules
- `ocr_nlp.py` OCR (Tesseract / Google Vision with GOOGLE_VISION=1), Transformer or extractive summary, fact extraction
- `rag.py`, `kb.json` semantic search: TF-IDF by default, LangChain + FAISS with USE_LANGCHAIN=1, Pinecone with PINECONE_API_KEY
- `predict.py` Random Forest + SHAP/LIME (synthetic training data, demo only); `train_bert.py` fine-tunes BERT on your labelled cases
- `app.py` AES-256-GCM, RBAC, password sign-in, hash-chained audit log
Env vars: SECRET_KEY, DOC_KEY, JUDGE_CODE, GEMINI_API_KEY, GEMINI_MODEL, USE_TRANSFORMER, USE_LANGCHAIN, PORT.

## Database
Everything is stored in SQLite (`legal.db`, created on first run): users, cases, chats, encrypted documents and their encrypted analyses (BLOB columns), and the audit log. Documents are stored encrypted (AES-256-GCM) inside the database. In VS Code install the "SQLite Viewer" extension and click `legal.db` to browse the tables.

## Password sign-in
Sign in with the account email and password.
