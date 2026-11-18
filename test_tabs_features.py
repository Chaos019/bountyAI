# -*- coding: utf-8 -*-
"""
BountyAI — Tab & Feature Test Suite (stdlib only, zero deps)
=============================================================
Checks that every tab and its features are working.

Layers:
  (default)  A. Static wiring  — every tab/panel/feature id present in index.html + JS functions defined
             B. Live API       — each tab's backend endpoints return valid data (fresh test account, auto-cleanup)
  --ai       C. AI endpoints   — Forge analyses + report generation through OpenRouter (slow: 10-90s each)
  --ui       D. Browser UI     — real chromium clicks each tab & verifies panel switches (needs: pip install playwright && python -m playwright install chromium)
  --recon    E. Live recon     — runs POST /api/recon against example.com (network scan, ~60s)

Usage:
  python test_tabs_features.py            # fast: layers A + B
  python test_tabs_features.py --ai       # also verify AI-powered features
  python test_tabs_features.py --ui       # also verify real browser tab clicking
  python test_tabs_features.py --base http://localhost:5000
"""
import argparse
import json
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).parent
HTML_PATH = ROOT / "BountyAI_v3_Project/bountyai/frontend/index.html"
SERVER_DIR = ROOT / "BountyAI_v3_Project/bountyai/server"
DEFAULT_BASE = "http://localhost:5000"


def seed_admin(username, password):
    """Create an admin user directly in SQLite and mint a valid JWT.

    Public registration intentionally cannot self-assign the admin role any
    more (privilege-escalation fix), so the test provisions its admin
    fixture through the database and signs the token with the server's own
    helper functions. Returns (token, error_message).
    """
    try:
        if str(SERVER_DIR) not in sys.path:
            sys.path.insert(0, str(SERVER_DIR))
        import server as srv  # noqa: E402  (import after sys.path tweak)
        conn = sqlite3.connect(str(srv.DB_PATH))
        try:
            conn.execute("DELETE FROM users WHERE username=?", (username,))
            cur = conn.execute(
                "INSERT INTO users (username,email,password_hash,role,is_active) VALUES (?,?,?,?,1)",
                (username, f"{username}@bountyai.test", srv.hash_password(password), "admin"))
            conn.commit()
            uid = cur.lastrowid
        finally:
            conn.close()
        return srv.create_token(username, "admin", uid), ""
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"

# ──────────────────────────────────────────────────────────────────────
# Tiny result collector
# ──────────────────────────────────────────────────────────────────────
RESULTS = []  # (status, layer, name, detail)

def record(status, layer, name, detail=""):
    RESULTS.append((status, layer, name, detail))
    icons = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIP": "[SKIP]", "WARN": "[WARN]"}
    print(f"{icons.get(status, '[????]')} {layer:8.8} {name}" + (f"  — {detail}" if detail else ""))

def summary():
    print("\n" + "=" * 78)
    by = {}
    for s, _, n, d in RESULTS:
        by.setdefault(s, []).append((n, d))
    parts = "  ".join(f"{k}: {len(v)}" for k, v in sorted(by.items()))
    print(f"  SUMMARY — {parts}")
    if "FAIL" in by:
        print("\n  FAILED CHECKS:")
        for n, d in by["FAIL"]:
            print(f"   ✗ {n}" + (f" — {d}" if d else ""))
    print("=" * 78)
    return 1 if "FAIL" in by else 0

# ──────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────
def req(base, method, path, token=None, body=None, timeout=30):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    result = (0, {"_conn_error": "not attempted"})
    for attempt in (1, 2):  # one retry: transient localhost hiccups right after boot
        r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8", "ignore") or "{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode("utf-8", "ignore") or "{}")
            except Exception:
                return e.code, {}
        except Exception as e:
            result = (0, {"_conn_error": str(e)})
            time.sleep(1)
    return result

def wait_alive(base, tries=40):
    for _ in range(tries):
        code, j = req(base, "GET", "/api/health", timeout=3)
        if code == 200:
            return j
        time.sleep(0.4)
    return None

# ──────────────────────────────────────────────────────────────────────
# A. STATIC WIRING — index.html contains every tab, panel & feature id
# ──────────────────────────────────────────────────────────────────────
TABS = [
    ("tab-dash",   "panel-dash",   "Dashboard"),
    ("tab-lab",    "panel-lab",    "AI Intelligence (Forge)"),
    ("tab-glab",   "panel-glab",   "AI Security Lab"),
    ("tab-recon",  "panel-recon",  "Recon & Discovery"),
    ("tab-log",    "panel-log",    "Log Finding"),
    ("tab-report", "panel-report", "AI Report Generator"),
    ("tab-prog",   "panel-prog",   "Target Scopes"),
    ("tab-learn",  "panel-learn",  "Learning Path"),
    ("tab-admin",  "panel-admin",  "Admin Panel (hidden until admin)"),
]
# panels reached via sub-buttons inside tabs
SUB_PANELS = ["panel-conn", "panel-disclose", "panel-ml", "panel-nuclei"]
# NOTE: orphan panels are now detected dynamically (every id="panel-*" in the
# DOM must have a matching go('<key>') call) — no hardcoded list needed.

# feature element ids each tab must have (verified against index.html)
FEATURE_IDS = {
    "panel-glab": ["glab-raw", "glab-results", "glab-vuln-name", "vflow-canvas", "glab-exploit-out"],
    "panel-log": ["fvt", "fvs", "fvp", "fvd", "fvu", "fvdesc", "fvsteps", "fvimpact"],
    "panel-dash": ["kv-total", "ks-total", "kv-earn", "ks-earn", "kv-crit", "kv-rate",
                   "ks-rate", "h-earn", "h-total", "h-crit", "dash-findings", "dash-progs"],
}
# JS functions each tab depends on
FEATURE_FNS = ["go", "api", "showToast", "doLogin", "doRegister",
               "glabAnalyze", "doRecon", "saveFinding", "loadFindings",
               "loadDash", "loadProgs", "syncH1", "updateUserPill", "checkAuthToken",
               "renderVisualFlow", "setAutonomy", "saveAgentConfig"]

def static_layer():
    if not HTML_PATH.exists():
        record("FAIL", "STATIC", "index.html exists", str(HTML_PATH))
        return
    html = HTML_PATH.read_text(encoding="utf-8", errors="ignore")

    # tabs: button exists AND wired via go('<tab-key>') — go() internally remaps lab→glab
    for tab_id, panel_id, label in TABS:
        tab_key = tab_id.replace("tab-", "")
        ok_btn = f'id="{tab_id}"' in html and f"go('{tab_key}')" in html
        ok_panel = f'id="{panel_id}"' in html
        status = "PASS" if (ok_btn and ok_panel) else "FAIL"
        detail = []
        if not ok_btn: detail.append("tab button / go() wiring missing")
        if not ok_panel: detail.append("panel missing")
        record(status, "STATIC", f"Tab {tab_id} → {label}", "; ".join(detail))

    for pid in SUB_PANELS:
        record("PASS" if f'id="{pid}"' in html else "FAIL", "STATIC", f"Sub-panel {pid}")

    # Every panel-* in the DOM must be reachable through some go('<key>')
    # call — otherwise it is dead markup that no user can ever open.
    all_panels = set(re.findall(r'id="panel-([A-Za-z0-9_-]+)"', html))
    go_targets = set(re.findall(r"go\('([A-Za-z0-9_-]+)'\)", html))
    for pid in sorted(all_panels):
        if pid in go_targets:
            record("PASS", "STATIC", f"Panel panel-{pid} reachable", f"go('{pid}')")
        else:
            record("WARN", "STATIC", f"Orphan panel panel-{pid}",
                   "exists in DOM but no go('x') path can ever display it")

    for panel, ids in FEATURE_IDS.items():
        missing = [i for i in ids if f'id="{i}"' not in html]
        record("PASS" if not missing else "FAIL", "STATIC",
               f"Feature ids in {panel}", ("missing: " + ", ".join(missing)) if missing else f"{len(ids)} required ids found")

    for fn in FEATURE_FNS:
        record("PASS" if re.search(rf"\bfunction {fn}\b", html) else "FAIL", "STATIC", f"JS function {fn}()")

    # only TOP-LEVEL functions count as duplicates (nested helpers share names legitimately)
    top_level = re.findall(r"^function\s+(\w+)\s*\(", html, re.M)
    dups = {n: top_level.count(n) for n in set(top_level) if top_level.count(n) > 1}
    record("PASS" if not dups else "FAIL", "STATIC", "No duplicate JS top-level functions",
           ", ".join(f"{k}(x{v})" for k, v in dups.items()) if dups else "")

# ──────────────────────────────────────────────────────────────────────
# B. LIVE API LAYER — per-tab feature endpoints with a fresh admin account
# ──────────────────────────────────────────────────────────────────────
def api_layer(base, ai=False, live_recon=False):
    if not wait_alive(base):
        record("FAIL", "LIVE-API", "Server reachable", f"{base}/api/health unreachable")
        return
    record("PASS", "LIVE-API", "Server reachable", f"{base}/api/health → 200")

    # unauthenticated security: protected route must 401
    code, _ = req(base, "GET", "/api/stats")
    record("PASS" if code == 401 else "FAIL", "LIVE-API", "Auth guard: /api/stats without token → 401", f"got {code}")

    # tampered token must 401
    code, _ = req(base, "GET", "/api/stats", token="a.b.c-tampered")
    record("PASS" if code == 401 else "FAIL", "LIVE-API", "Auth guard: tampered token → 401", f"got {code}")

    # ── auth: provision admin + viewer ────────────────────────────────
    # Public registration may NOT self-assign admin (privilege-escalation
    # fix), so the test provisions its admin account directly in SQLite and
    # mints a JWT with the server's own signing code. This is the correct
    # integration-test pattern: the fixture bypasses the public API on
    # purpose, so it does not depend on a security loophole.
    uname = "tabtest_" + str(int(time.time() * 1000) % 100000000)
    admin_token, admin_err = seed_admin(uname, "TabTest#123")
    record("PASS" if admin_token else "FAIL", "AUTH",
           f"Provision admin fixture ({uname}) → JWT", admin_err or "seeded directly in SQLite")

    code, viewer_reg = req(base, "POST", "/api/auth/register", body={
        "username": uname + "_v", "password": "TabTest#123", "role": "viewer"})
    viewer_token = viewer_reg.get("token", "")

    code, login = req(base, "POST", " /api/auth/login".replace(" ", ""), body={
        "username": uname, "password": "TabTest#123"})
    record("PASS" if code == 200 and login.get("token") else "FAIL", "AUTH",
           "Login with same credentials → 200 + JWT", f"got {code}")

    code, me = req(base, "GET", "/api/auth/me", token=admin_token)
    record("PASS" if code == 200 and me.get("username") else "FAIL", "AUTH", "Session check /api/auth/me", f"got {code}")

    # ── TAB: Dashboard ──
    code, stats = req(base, "GET", "/api/stats", token=admin_token)
    ok = code == 200 and "total_findings" in stats and "ai_mode" in stats
    record("PASS" if ok else "FAIL", "TAB-dash", "/api/stats → dashboard counters", f"got {code}, keys={list(stats)[:5]}")

    code, findings = req(base, "GET", "/api/findings", token=admin_token)
    ok = code == 200 and isinstance(findings.get("findings", None), (list, type(None)))
    record("PASS" if ok else "FAIL", "TAB-dash", "/api/findings → activity list", f"got {code}")

    code, progs = req(base, "GET", "/api/programs")
    n = len((progs or {}).get("programs", []))
    record("PASS" if code == 200 and n > 0 else "FAIL", "TAB-dash", "/api/programs → program cards", f"{n} programs")

    # ── TAB: Target Scopes ──
    code, sync = req(base, "POST", "/api/programs/sync", token=admin_token)
    ok = code == 200 and "synced" in sync
    record("PASS" if ok else "FAIL", "TAB-prog", "/api/programs/sync → H1 program sync", f"got {code}, synced={sync.get('synced')}")

    # ── TAB: Recon (offline pieces) ──
    code, tpl = req(base, "GET", "/api/nuclei/templates")
    ok = code == 200 and isinstance(tpl, dict)
    record("PASS" if ok else "FAIL", "TAB-recon", "/api/nuclei/templates → template catalog", f"got {code}, keys={list(tpl)[:4]}")

    code, ml = req(base, "POST", "/api/ml/predict", token=admin_token,
                   body={"domain": "example.com", "tech_stack": ["nginx", "react"]})
    ok = code == 200 and isinstance(ml, dict) and ml.get("predictions")
    record("PASS" if ok else "FAIL", "TAB-recon", "/api/ml/predict → ML vulnerability predictions", f"got {code}, keys={list(ml)[:4]}")

    # auto mode: empty body → target + stack auto-derived from the last recon scan
    code, ml_auto = req(base, "POST", "/api/ml/predict", token=admin_token, body={})
    aut = (ml_auto or {}).get("auto", {}) if isinstance(ml_auto, dict) else {}
    if code == 200 and (ml_auto or {}).get("predictions"):
        ok = True
    elif code == 200 and (ml_auto or {}).get("error"):
        ok = None  # acceptable on a fresh DB: no recon history yet
    else:
        ok = False
    if ok is None:
        record("WARN", "TAB-recon", "/api/ml/predict {} → auto-detect (needs recon history)", f"notice: {(ml_auto or {}).get('error')}")
    else:
        record("PASS" if ok else "FAIL", "TAB-recon", "/api/ml/predict {} → auto-detect from last recon",
               f"got {code}, source={aut.get('source')}, domain={aut.get('domain')}, stack={(aut.get('tech_stack') or [])[:4]}")

    if live_recon:
        code, rc = req(base, "POST", "/api/recon", token=admin_token, body={"domain": "example.com"}, timeout=150)
        ok = code == 200 and rc and not rc.get("error")
        n_mods = len((rc or {}).get("module_results", {}))
        dur = (rc or {}).get("scan_duration")
        record("PASS" if ok else "FAIL", "TAB-recon", "/api/recon → live scan of example.com",
               f"got {code}, modules={n_mods}, duration={dur}s" + (f", tools={list((rc.get('tools_used') or {}).items())}" if rc else ""))

    # ── TAB: Log Finding ──
    finding_payload = {
        "vuln_type": "TEST-TabSuite", "severity": "L",
        "program_name": "Local Test Program", "target_domain": "example.com",
        "affected_url": "https://example.com/api/v1/user",
        "description": "Tab test suite finding", "steps_to_reproduce": "n/a",
        "impact": "n/a",
    }
    code, nf = req(base, "POST", "/api/findings", token=admin_token, body=finding_payload)
    fid = nf.get("id") or nf.get("finding", {}).get("id") if isinstance(nf, dict) else None
    record("PASS" if code in (200, 201) and fid else "FAIL", "TAB-log", "Log Finding: POST /api/findings → created", f"got {code}, id={fid}")

    if fid:
        code, after = req(base, "GET", "/api/findings", token=admin_token)
        ids = [f.get("id") for f in after.get("findings", [])]
        record("PASS" if code == 200 and fid in ids else "FAIL", "TAB-log",
               "Finding appears in GET /api/findings", f"id {fid} {'in' if fid in ids else 'NOT in'} list")
        code, d = req(base, "DELETE", f"/api/findings/{fid}", token=admin_token)
        record("PASS" if code == 200 else "FAIL", "TAB-log", f"Cleanup: DELETE /api/findings/{fid}", f"got {code}")

    # ── TAB: Log Finding — vuln auto-classify (AI engine / pattern fallback) ──
    code, cls = req(base, "POST", "/api/analyze/classify", token=admin_token,
                    body={"description": "Reflected XSS in the search parameter q: unsanitized HTML is echoed back and <script> tags execute in the victim browser with no escaping.",
                          "url": "https://example.com/search?q=1"})
    cls_types = (cls or {}).get("types") if isinstance(cls, dict) else None
    ok = code == 200 and isinstance(cls_types, list) and len(cls_types) >= 1
    top_type = (cls_types[0].get("type") if cls_types and isinstance(cls_types[0], dict) else "?")
    record("PASS" if ok else "FAIL", "TAB-log", "/api/analyze/classify → auto-detect type+severity (chips)",
           f"got {code}, engine={(cls or {}).get('engine')}, top={top_type}, sev={(cls or {}).get('severity')}")

    code, cls2 = req(base, "POST", "/api/analyze/classify", token=admin_token,
                     body={"description": "SQL error shown: You have an error in your SQL syntax near union select", "url": ""})
    ok2 = code == 200 and any(isinstance(t, dict) and "SQL" in str(t.get("type", "")) for t in (cls2 or {}).get("types", []))
    record("PASS" if ok2 else "FAIL", "TAB-log", "/api/analyze/classify → SQL injection detected",
           f"got {code}, types=[{', '.join(str(t.get('type')) for t in (cls2 or {}).get('types', [])[:2])}]")

    # ── TAB: AI Forge (offline analysis) ──
    code, sec = req(base, "POST", "/api/analyze/js-secrets", token=admin_token,
                    body={"content": "var _shipment='AKIAIOSFODNN7EXAMPLE'; var cfg='https://x.firebaseio.com';"})
    ok = code == 200 and isinstance(sec.get("secrets"), list) and len(sec["secrets"]) >= 2
    record("PASS" if ok else "FAIL", "TAB-lab", "/api/analyze/js-secrets → secret scanner (offline)", f"got {code}, found={len((sec or {}).get('secrets', []))}")

    code, dup = req(base, "POST", "/api/analyze/duplicate-risk", token=admin_token,
                    body={"title": "XSS in search", "domain": "example.com", "url": "https://example.com/search", "desc": "reflected xss in q param"})
    record("PASS" if code == 200 and not dup.get("error") else "WARN", "TAB-lab",
           "/api/analyze/duplicate-risk (AI-backed)", f"got {code}" + (f", err={dup.get('error')}" if dup.get('error') else ""))

    # agent autonomy panel (part of Forge)
    code, l1 = req(base, "GET", "/api/agent/config", token=admin_token)
    code, sv = req(base, "POST", "/api/agent/config", token=admin_token, body={"autonomy_level": 4, "active_agent": "red"})
    code, l2 = req(base, "GET", "/api/agent/config", token=admin_token)
    ok = code == 200 and l2.get("autonomy_level") == 4 and l2.get("active_agent") == "red"
    record("PASS" if ok else "FAIL", "TAB-lab", "Autonomy save → survives reload, read-back matches", f"after={l2.get('autonomy_level')}/{l2.get('active_agent')}")
    # the config endpoint must not be readable anonymously
    code_anon, _ = req(base, "GET", "/api/agent/config")
    record("PASS" if code_anon == 401 else "FAIL", "TAB-lab",
           "Autonomy config requires auth", f"got {code_anon}")
    req(base, "POST", "/api/agent/config", token=admin_token, body={"autonomy_level": 3, "active_agent": "bb"})  # restore default

    # ── TAB: AI Reports ──
    code, reps = req(base, "GET", "/api/reports", token=admin_token)
    record("PASS" if code == 200 else "FAIL", "TAB-report", "/api/reports → reports list", f"got {code}")

    # ── TAB: Learning Path ──
    code, lr = req(base, "GET", "/api/learning")
    record("PASS" if code == 200 else "FAIL", "TAB-learn", "/api/learning → curated resources", f"got {code}")
    code, rs = req(base, "POST", "/api/resources/sync", token=admin_token)
    record("PASS" if code == 200 else "FAIL", "TAB-learn", "/api/resources/sync → refresh catalog", f"got {code}")

    # ── TAB: Admin Panel ──
    for path in ("/api/admin/stats", "/api/admin/users", "/api/admin/activity"):
        code, adm = req(base, "GET", path, token=admin_token)
        record("PASS" if code == 200 else "FAIL", "TAB-admin", f"{path} as admin", f"got {code}")
    code, _ = req(base, "GET", "/api/admin/users", token=viewer_token)
    ok = code in (401, 403)
    record("PASS" if ok else "FAIL", "TAB-admin", f"Role guard: /api/admin/users as viewer → {code}", f"got {code}")

    # ── Disclosure panel ──
    code, dis = req(base, "GET", "/api/disclosures")
    record("PASS" if code == 200 else "FAIL", "TAB-lab", "/api/disclosures → disclosure tracker", f"got {code}")

    # ── C. Optional: AI-powered features ──
    if ai:
        ai_checks(base, admin_token)
    else:
        for name in ("Forge Inspect API Risk", "Forge Audit Logic", "Forge Gen Payloads", "Report generation"):
            record("SKIP", "AI", f"{name} (run with --ai to test)", "skipped by default (slow, needs OpenRouter)")

# ──────────────────────────────────────────────────────────────────────
# C. AI layer — real OpenRouter calls through the app
# ──────────────────────────────────────────────────────────────────────
def ai_checks(base, token):
    SAMPLE = ("POST /api/v1/user/update HTTP/1.1\n"
              "Host: target.com\n"
              "Authorization: Bearer abc123\n\n"
              "{ 'user_id': '101', 'role': 'user' }")
    checks = [
        ("Forge Inspect API Risk", "POST", "/api/analyze/api-inspector", {"request": SAMPLE, "response": ""}, ("data",)),
        ("Forge Audit Logic", "POST", "/api/analyze/logic", {"app_context": SAMPLE}, ("data",)),
        ("Forge Gen Payloads", "POST", "/api/analyze/exploit", {"vulnerability": "BOLA on /api/v1/user"}, ("data",)),
        ("Visual Attack Flow", "POST", "/api/analyze/visual-flow", {"vulnerability_detail": "BOLA in /api/v1/user/update: user_id is client-controlled, no ownership check, JWT role not revalidated server-side."}, ("visual_flow", "nodes", "data")),
    ]
    for name, method, path, body, shape_keys in checks:
        code, res = req(base, method, path, token=token, timeout=120)
        ok = code == 200 and not res.get("error") and any(k in (res or {}) for k in shape_keys)
        # HTTP 200 with the failure text hidden inside `data` is NOT a pass
        if ok:
            blob = json.dumps(res)[:800]
            if "AI Generation Error" in blob or "AI Engine Offline" in blob or "HTTP Error 4" in blob:
                ok = False
        record("PASS" if ok else "FAIL", "AI", f"{name}: {path}",
               f"got {code}" + (f", err={res.get('error')}" if isinstance(res, dict) and res.get("error") else ""))

# ──────────────────────────────────────────────────────────────────────
# D. Playwright UI layer — real browser clicks through every tab
# ──────────────────────────────────────────────────────────────────────
def ui_layer(base, timeout_ms=45000):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        record("SKIP", "UI", "Playwright not installed",
               "run:  pip install playwright  &&  python -m playwright install chromium")
        return
    wait_alive(base)
    uname = "uitest_" + str(int(time.time() * 1000) % 100000000)
    token, seed_err = seed_admin(uname, "UITest#123")
    record("PASS" if token else "FAIL", "UI", "Provision admin fixture", seed_err or "seeded directly in SQLite")
    user = {"username": uname, "role": "admin"}

    console_errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 900})
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append(str(e)))
        page.goto(base, wait_until="domcontentloaded", timeout=timeout_ms)

        # inject the session the app expects, then reload
        page.evaluate("t => localStorage.setItem('bountyai_token', t)", token)
        page.evaluate("u => localStorage.setItem('bountyai_user', JSON.stringify(u))", user)
        page.reload(wait_until="domcontentloaded")
        page.wait_for_selector(".ntab", timeout=timeout_ms)

        # login overlay must be gone
        overlay_hidden = page.evaluate(
            "var o=document.getElementById('auth-overlay'); !o || getComputedStyle(o).display === 'none'")
        record("PASS" if overlay_hidden else "FAIL", "UI", "Login overlay dismissed (auth accepted)")

        for tab_id, panel_id, label in TABS:
            try:
                page.click(f"#{tab_id}", timeout=8000)
            except Exception as e:
                record("FAIL", "UI", f"Click {tab_id}", str(e)[:80]); continue
            page.wait_for_timeout(250)
            state = page.evaluate(
                "(ids) => { const t=document.getElementById(ids[0]); const e=document.getElementById(ids[1]);"
                " return { tabOn: t.classList.contains('on'),"
                "           panelVisible: !!e && getComputedStyle(e).display !== 'none',"
                "           panelHasContent: !!e && e.innerHTML.length > 200 }; }",
                [tab_id, panel_id])
            ok = state.get("tabOn") and state.get("panelVisible") and state.get("panelHasContent")
            record("PASS" if ok else "FAIL", "UI", f"Tab switch → {label}",
                   f"tab={state.get('tabOn')} visible={state.get('panelVisible')} filled={state.get('panelHasContent')}")

        # dashboard actually populated with numbers
        page.click("#tab-dash")
        page.wait_for_timeout(700)
        txt = page.evaluate("document.getElementById('panel-dash').innerText")
        has_numbers = any(ch.isdigit() for ch in txt)
        record("PASS" if has_numbers else "FAIL", "UI", "Dashboard shows live counters", f"{len(txt)} chars visible")

        # AI Security Lab smoke: offline secret scan via UI
        page.click("#tab-glab")
        page.wait_for_timeout(400)
        page.fill("#glab-raw", "POST /api/v1/user/update HTTP/1.1\nHost: t.com\nAuthorization: Bearer abc123\n\n{ 'user_id': '101' }")
        page.click("#panel-glab button:has-text('Inspect API Risk')", timeout=8000)
        page.wait_for_timeout(1500)
        forge_out = page.evaluate("var o=document.getElementById('glab-results'); (o && o.innerText || '').slice(0, 300)")
        record("PASS" if forge_out.strip() else "WARN", "UI", "AI Lab Inspect API Risk rendered output", forge_out[:120].replace("\n", " | "))

        # Forge Lab smoke: the multimodal source-code panel must be reachable
        page.click("#tab-lab")
        page.wait_for_timeout(400)
        forge_visible = page.evaluate(
            "var p=document.getElementById('panel-lab'); !!p && getComputedStyle(p).display !== 'none'")
        record("PASS" if forge_visible else "FAIL", "UI", "Forge Lab panel reachable from nav")

        # admin tab must be visible for admin role
        admin_visible = page.evaluate("var t=document.getElementById('tab-admin'); !!t && t.style.display !== 'none'")
        record("PASS" if admin_visible else "FAIL", "UI", "Admin tab visible for admin role")

        js_errors = [e for e in console_errors if "favicon" not in e.lower() and "404" not in e]
        record("PASS" if not js_errors else "FAIL", "UI", "No JS console errors",
               ("; ".join(js_errors)[:300]) if js_errors else "")
        browser.close()

def cleanup_test_users():
    """Remove the throwaway accounts this suite creates."""
    try:
        if str(SERVER_DIR) not in sys.path:
            sys.path.insert(0, str(SERVER_DIR))
        import server as srv  # noqa: E402
        conn = sqlite3.connect(str(srv.DB_PATH))
        try:
            conn.execute("DELETE FROM users WHERE username LIKE 'tabtest_%' OR username LIKE 'uitest_%'")
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def main():
    # Windows consoles default to cp1252; the test marker box contains unicode
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="BountyAI tab & feature test suite")
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--ai", action="store_true", help="test AI endpoints (slow)")
    ap.add_argument("--ui", action="store_true", help="test real browser tab clicks (needs playwright)")
    ap.add_argument("--recon", action="store_true", help="run a live recon scan of example.com (~60s)")
    args = ap.parse_args()

    print(f"\nBountyAI Tab & Feature Suite → {args.base}\n")
    try:
        static_layer()
        api_layer(args.base, ai=args.ai, live_recon=args.recon)
        if args.ui:
            ui_layer(args.base)
    finally:
        cleanup_test_users()
    sys.exit(summary())

if __name__ == "__main__":
    main()
