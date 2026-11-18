# -*- coding: utf-8 -*-
"""Full project diagnosis: python syntax, server import, frontend JS, config files."""
import os
import sys
import py_compile
import traceback

ROOT = r"C:\Users\ADMIN\Desktop\major major project clg final\BountyAI_v3_Project\bountyai"

errors = []
warnings = []

def err(msg):
    errors.append(msg)
    print("ERROR:", msg)

def warn(msg):
    warnings.append(msg)
    print("WARN :", msg)

print("=" * 70)
print("1. PYTHON SYNTAX CHECK (project .py files, excluding nuclei-templates)")
print("=" * 70)
py_files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in ("nuclei-templates", "__pycache__")]
    for f in filenames:
        if f.endswith(".py"):
            py_files.append(os.path.join(dirpath, f))

for p in py_files:
    rel = os.path.relpath(p, ROOT)
    try:
        py_compile.compile(p, doraise=True)
        print("OK   ", rel)
    except py_compile.PyCompileError as e:
        err(f"{rel}: SYNTAX ERROR -> {e.msg} (line {e.lineno})")

print()
print("=" * 70)
print("2. SERVER IMPORT CHECK (server.py stdlib-only)")
print("=" * 70)
server_dir = os.path.join(ROOT, "server")
sys.path.insert(0, server_dir)
try:
    import server  # noqa
    print("OK   server.py imports cleanly (module-level)")
    print("     -> has app/routes via:", [n for n in dir(server) if n in ("app", "main", "run", "start_server")])
except Exception:
    # server.py probably calls serve_forever at import; check the tail for auto-start
    tb = traceback.format_exc(limit=3)
    if "__main__" in tb or "Address already in use" in tb or "WinError 10048" in tb:
        warn("server.py runs the HTTP server at module import (top-level serve_forever) - syntax OK")
        print("     -> import attempted HTTP bind; treating as startup code, not an error")
    else:
        err("server.py failed to import:\n" + tb)

print()
print("=" * 70)
print("3. FRONTEND CHECK: extract <script> blocks from index.html, node syntax check")
print("=" * 70)
html_path = os.path.join(ROOT, "frontend", "index.html")
with open(html_path, "r", encoding="utf-8", errors="replace") as f:
    html = f.read()

import re
scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I)
print(f"found {len(scripts)} inline <script> block(s)")

tmp_dir = r"C:\Users\ADMIN\AppData\Local\Temp\opencode"
os.makedirs(tmp_dir, exist_ok=True)
js_path = os.path.join(tmp_dir, "index_inline.js")
with open(js_path, "w", encoding="utf-8") as f:
    f.write("\n;\n".join(scripts))

# syntax check via node
import subprocess
r = subprocess.run(["node", "--check", js_path], capture_output=True, text=True)
if r.returncode == 0:
    print("OK   index.html inline JavaScript passes node --check")
else:
    err("index.html inline JavaScript SYNTAX ERROR:\n" + r.stderr[:3000])

# duplicate id= attributes in HTML
ids = re.findall(r"\bid=[\"']?([\w-]+)", html)
from collections import Counter
dups = {k: v for k, v in Counter(ids).items() if v > 1}
if dups:
    warn(f"index.html has {len(dups)} DUPLICATE id= values: " + ", ".join(f"{k}({v})" for k, v in sorted(dups.items())[:20]))
else:
    print("OK   no duplicate id= values")

# duplicated TOP-LEVEL function declarations in the JS (classic AI-paste duplicate)
top_funcs = re.findall(r"^function\s+(\w+)\s*\(", html, re.M)
fdups = {k: v for k, v in Counter(top_funcs).items() if v > 1}
if fdups:
    warn(f"index.html defines {len(fdups)} DUPLICATE function names: " + ", ".join(f"{k}({v})" for k, v in list(fdups.items())[:30]))
else:
    print("OK   no duplicate JS function declarations")

print()
print("=" * 70)
print("4. CONFIG / ENV CHECK")
print("=" * 70)
env_example = os.path.join(ROOT, ".env.example")
no_tokens = []
for path in (os.path.join(ROOT, ".env"), os.path.join(ROOT, ".env.example")):
    name = os.path.relpath(path, ROOT)
    if not os.path.exists(path):
        warn(name + " missing")
        continue
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if "@" in line and "://" in line and not line.startswith("#"):
                no_tokens.append((name, line[:80]))
print("env entries with embedded credentials (truncated):", no_tokens if no_tokens else "none")

# docker-compose.yml / Dockerfile live at the project root, not the bountyai dir
base = os.path.dirname(ROOT)
compose = open(os.path.join(base, "docker-compose.yml"), encoding="utf-8", errors="replace").read()
dockerfile = open(os.path.join(base, "Dockerfile"), encoding="utf-8", errors="replace").read()
render = open(os.path.join(ROOT, "render.yaml"), encoding="utf-8", errors="replace").read()
print()
print("--- Dockerfile ---")
print(dockerfile.strip())
print("--- docker-compose.yml ---")
print(compose.strip())
print("--- render.yaml ---")
print(render.strip()[:2000])

print()
print("=" * 70)
print(f"SUMMARY: {len(errors)} error(s), {len(warnings)} warning(s)")
print("=" * 70)
