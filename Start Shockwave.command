#!/bin/zsh
# Double-click this file in Finder to start Shockwave, then use the browser tab it opens.
# Close this Terminal window (or press Ctrl-C) to stop the workspace.

cd "${0:A:h}" || exit 1
PORT="${SHOCKWAVE_PORT:-8765}"
URL="http://127.0.0.1:$PORT"

echo ""
echo "  SHOCKWAVE · offline computer-vision assurance"
echo "  ---------------------------------------------"

# 1. Find a Python 3.12 that works with the bundled libraries in .runtime
PY=""
for candidate in \
  "$SHOCKWAVE_PYTHON" \
  "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3" \
  "$(command -v python3.12 2>/dev/null)" \
  "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12" \
  "/opt/homebrew/bin/python3.12" \
  "/usr/local/bin/python3.12"; do
  if [[ -n "$candidate" && -x "$candidate" ]] && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2]==(3,12) else 1)' 2>/dev/null; then
    PY="$candidate"; break
  fi
done
if [[ -z "$PY" ]]; then
  echo ""
  echo "  Python 3.12 was not found. Install it from https://www.python.org/downloads/ (3.12.x),"
  echo "  then double-click this file again."
  read -k1 "?  Press any key to close."; exit 1
fi
echo "  Python      $PY"

# 2. Check the offline dependencies and local model weights
if ! DOCTOR=$(SHOCKWAVE_PYTHON="$PY" "$PY" launch.py --doctor 2>&1); then
  echo ""
  echo "  Readiness check failed:"; echo "$DOCTOR"
  read -k1 "?  Press any key to close."; exit 1
fi
echo "  Readiness   offline dependencies and DINOv2 weights found"

# 3. If an older Shockwave server holds the port, restart it so the latest code is used
PID=$(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | head -1)
if [[ -n "$PID" ]]; then
  if ps -p "$PID" -o command= | grep -qiE "launch.py|shockwave|server.py"; then
    echo "  Restarting  an earlier Shockwave server (PID $PID)"
    kill "$PID" 2>/dev/null; sleep 1
  else
    echo ""
    echo "  Port $PORT is used by another program. Run with another port, for example:"
    echo "    SHOCKWAVE_PORT=8877 \"${0:A}\""
    read -k1 "?  Press any key to close."; exit 1
  fi
fi

# 4. Start the server (it opens the browser) and keep running until this window is closed
echo "  Workspace   $URL"
echo ""
echo "  Leave this window open while you use Shockwave. Press Ctrl-C here to stop."
echo ""
SHOCKWAVE_PYTHON="$PY" SHOCKWAVE_PORT="$PORT" exec "$PY" launch.py "$@"
