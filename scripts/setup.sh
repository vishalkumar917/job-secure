#!/usr/bin/env bash
# One-time local setup on Linux/macOS. Run from the repository root: ./scripts/setup.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== Backend"
cd "$ROOT/backend"
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install yara-python || echo "yara-python not installed (optional)"

echo "== Frontend"
cd "$ROOT/frontend"
npm install

if [ ! -f "$ROOT/.env" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  SECRET=$("$ROOT/backend/.venv/bin/python" -c "import secrets; print(secrets.token_urlsafe(48))")
  sed -i.bak "s/^SECRET_KEY=$/SECRET_KEY=$SECRET/" "$ROOT/.env" && rm -f "$ROOT/.env.bak"
  echo "Created .env with a random SECRET_KEY. Change ADMIN_PASSWORD before real use."
fi

"$ROOT/backend/.venv/bin/python" "$ROOT/scripts/generate_demo_data.py"
echo "Setup complete. Start with: ./scripts/run_dev.sh"
