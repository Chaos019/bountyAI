# 🎯 BountyAI — AI-Powered Bug Bounty Assistant
### Final Year Project | AI + Full Stack + Cybersecurity | 2025–26

---

## ⚡ ONE-CLICK START

| OS | Command |
|----|---------|
| **Linux / macOS** | `chmod +x START.sh && ./START.sh` |
| **Windows** | Double-click `START.bat` |

**Browser opens automatically → http://localhost:8000**

> **Zero dependencies required.** Runs on pure Python 3.8+ stdlib. Nothing to install.

---

## 📁 Project Structure

```
bountyai/
├── START.sh              ← Linux/macOS launcher (chmod +x first)
├── START.bat             ← Windows launcher (double-click)
├── .env.example          ← API key template → copy to .env
├── README.md
│
├── server/
│   └── server.py         ← Complete backend (pure Python stdlib)
│                           • HTTP server (http.server)
│                           • REST API (custom router)
│                           • SQLite database (sqlite3)
│                           • Live crt.sh recon (urllib)
│                           • Claude AI integration (urllib → Anthropic)
│                           • CVSS scoring algorithm
│                           • PDF/MD report generation
│
└── frontend/
    └── index.html        ← Complete SPA frontend
                            • Dashboard with live stats
                            • 8 Indian bug bounty programs
                            • Live recon terminal
                            • Finding logger with CVSS calc
                            • AI report generator
                            • Learning path module
```

---

## 🔑 API Keys (ALL Optional)

| Key | Get It | Enables | Cost |
|-----|--------|---------|------|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | **Live Claude AI reports** | Free tier |
| `NVD_API_KEY` | [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) | **Real-time CVE lookup** | 100% Free |
| `SHODAN_API_KEY` | [shodan.io](https://shodan.io) | Port scanning | Free account |
| `WAPPALYZER_API_KEY` | [wappalyzer.com/api](https://www.wappalyzer.com/api/) | Tech detection | 500/mo free |
| `HACKERONE_API_TOKEN` | [hackerone.com/settings](https://hackerone.com/settings/api_token) | Live program sync | Free account |

**To add keys:** Copy `.env.example` → `.env`, fill in your keys.

> **crt.sh subdomain enumeration is ALWAYS live** — it's a free public API, no key needed.

---

## 📡 REST API Endpoints

```
GET  /api/health              App health + API key status
GET  /api/stats               Dashboard statistics
GET  /api/programs            List all bug bounty programs
POST /api/recon               Run full recon on a domain
GET  /api/findings            List all saved findings
POST /api/findings            Create new finding
GET  /api/findings/{id}       Get single finding
PUT  /api/findings/{id}       Update finding
DELETE /api/findings/{id}     Delete finding
POST /api/reports/generate    Generate AI vulnerability report
GET  /api/reports             List all reports
GET  /api/reports/{id}        Get single report
```

---

## 🤖 AI Agent Pipeline

```
User Input (domain)
       ↓
Agent 1 — Idea Parser
   Extracts domain, normalizes input
       ↓
Agent 2 — Recon Engine (runs in parallel)
   ├── crt.sh API     → Real subdomains (ALWAYS LIVE, free)
   ├── Tech DB        → Technology stack (mock, upgraded with Wappalyzer key)
   ├── NVD API        → Real CVEs (LIVE with free key)
   └── Shodan API     → Port data (LIVE with key)
       ↓
Agent 3 — AI Synthesis
   ├── Claude API     → Live AI vulnerability suggestions + reports
   └── Template       → Rich built-in reports (fallback, no key needed)
       ↓
Agent 4 — CVSS Scorer
   Custom weighted algorithm (not just AI guessing):
   • Base score from severity level
   • +/- adjustments for: attack vector, impact keywords,
     authentication requirements, scope, affected component
       ↓
Output → JSON API → Frontend Dashboard + Downloadable .md Report
```

## 🚀 Top Enterprise Features Built

1. **Global Live Platform Sync** — Pulls live, authorized bug bounty programs from platforms globally (HackerOne, Immunefi, YesWeHack, Intigriti, Bugcrowd, and open VDPs via ProjectDiscovery Chaos).
2. **Dynamic Recon Engine** — Live, multi-threaded sub-domain discovery via `crt.sh`, open-ports via `Shodan`, and known CVE lookups via `NVD`.
3. **Automated AI Reporting** — Hooks into Anthropic's Claude 3 Models to synthesize findings, evaluate CVSS vectors, and build fully compliant `.md` vulnerability reports.
4. **Learning & Essential ZIPs** — A live-synced library of the internet's most critical bug bounty resources: SecLists, PayloadsAllTheThings, Nuclei Templates, and GitHub repositories directly accessible from the UI.
5. **Ultra-Premium Dashboard** — Built with glass-morphic elements, dynamic typography (Outfit & IBM Plex Mono), SVGs, and responsive grids without any heavy external UI libraries like React or Tailwind.

---

## 🎓 For Presentation

**Live demo flow (90 seconds):**
1. Open `http://localhost:8000` → Dashboard shows live stats
2. **Programs tab** → Click **`⟳ Global Live Sync`** to fetch hundreds of Web3, Fintech, Mobile and open-source programs!
3. Click "Recon" on a target → Recon terminal animates → real subdomains load (`crt.sh` API)
4. **Log Finding** → Fill Sample → Save (saved to SQLite instantly)
5. **AI Report** → Generate → Watch 7-step generation → Download `.md` Report
6. **Learn tab** → Click **`⟳ Essential ZIPs`** to instantly retrieve the best wordlist and payload bundles for bug hunting.

**Key technical talking points:**
- Pure Python stdlib — zero install, runs anywhere, asynchronous-like request handling using ThreadingTCPServer.
- crt.sh API is **always live** — real subdomain data
- Multi-Source Integration — Chaos API, GitHub, HackerOne, Shodan, NVD.
- Claude AI integration — real AI when key is set
- Custom CVSS scoring algorithm (not just AI opinion)
- SQLite persistence — findings survive restarts
- 4-agent architecture matching academic research

**IEEE base paper:** *"AI-Powered Automated Bug Bounty Platform"* — Preprints, June 2025
DOI: 10.20944/preprints202506.1363.v1

---

## ⚠️ Ethical Notice

This tool is **exclusively for authorized bug bounty programs** —
companies that have publicly invited security researchers via
HackerOne, Bugcrowd, or Intigriti. No unauthorized scanning.

---

*Built with ❤️ for Final Year Project 2025–26*
