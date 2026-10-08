#!/bin/bash
# Usage:  bash start.sh        (light mode, quick install)
#         bash start.sh full   (Transformer summaries + LangChain/FAISS search, big download on first run)
set -e
cd "$(dirname "$0")"
# Do not inherit another LegaVault install's Python modules into this environment.
unset PYTHONPATH PYTHONHOME
command -v python3 >/dev/null || { echo "Python 3 is not installed. Get it from https://www.python.org/downloads/"; exit 1; }
[ -d venv ] || python3 -m venv venv
source venv/bin/activate
if [ "$1" = "full" ]; then
  ./venv/bin/python -m pip install -r requirements-ai.txt
  export USE_TRANSFORMER=1 USE_LANGCHAIN=1
else
  ./venv/bin/python -m pip install -r requirements.txt
fi
./venv/bin/python -c 'import hashlib, sys; assert hasattr(hashlib, "scrypt"), f"{sys.version.split()[0]} lacks hashlib.scrypt; recreate venv with Python 3.11 or newer"'
# If the default port is occupied, choose the next available local port instead
# of failing with Flask's "Address already in use" message.
if [ -z "${PORT:-}" ]; then
  export PORT="$(./venv/bin/python - <<'PY'
import socket
for port in range(5001, 5101):
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
        print(port)
        break
    except OSError:
        pass
    finally:
        sock.close()
else:
    raise SystemExit("No available local port found in range 5001-5100; set PORT explicitly.")
PY
)"
fi
echo; echo "LegaVault is starting. Open http://127.0.0.1:${PORT:-5001} in your browser."
echo
exec ./venv/bin/python app.py
