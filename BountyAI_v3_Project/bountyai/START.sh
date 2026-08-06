#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║        BountyAI — Single-Click Launcher (Linux/macOS)       ║
# ║   Requires: Python 3.8+   |   Zero other dependencies       ║
# ╚══════════════════════════════════════════════════════════════╝
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; R='\033[0;31m'; B='\033[1m'; N='\033[0m'

echo -e "${G}${B}"
echo "  ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗ █████╗ ██╗"
echo "  ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗██║"
echo "  ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ ███████║██║"
echo "  ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  ██╔══██║██║"
echo "  ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   ██║  ██║██║"
echo "  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝"
echo -e "${N}"
echo -e "${C}  AI-Powered Bug Bounty Assistant for Ethical Hackers${N}"
echo -e "${Y}  Domain: AI + Full Stack + Cybersecurity  |  FYP 2025–26${N}"
echo ""

# ── Check Python ──────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "${R}  ✗ Python 3 not found!${N}"
  echo "    Install from: https://python.org"
  exit 1
fi

PV=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${G}  ✓ Python ${PV} found${N}"

# ── Copy .env if needed ───────────────────────────────────────
if [ ! -f "$ROOT/.env" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo -e "${Y}  ○ .env created from template${N}"
  echo -e "    → Edit .env to add ANTHROPIC_API_KEY for live AI reports"
else
  echo -e "${G}  ✓ .env found${N}"
fi

# ── Kill old instance ─────────────────────────────────────────
pkill -f "server/server.py" 2>/dev/null && sleep 0.5 || true

echo ""
echo -e "${G}${B}  Starting BountyAI...${N}"
echo ""
exec python3 "$ROOT/server/server.py"
