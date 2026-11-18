import os, json, urllib.request, time
from pathlib import Path

os.chdir(r"C:\Users\ADMIN\Desktop\major major project clg final\BountyAI_v3_Project\bountyai\server")
for line in Path(".env").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())
key = os.environ.get("OPENROUTER_API_KEY", "")

code = """
from flask import request
import sqlite3, os
def login():
    u = request.form["username"]
    q = "SELECT * FROM users WHERE username='" + u + "'"
    r = sqlite3.connect("app.db").execute(q).fetchone()
    if r:
        return {"token": os.popen("echo " + u).read()}
    return {"error": "unauthorized"}
"""

prompt = (
    "Analyze this code for security vulnerabilities. Return ONLY valid JSON, no markdown.\n\n"
    "Code:\n" + code + "\n\n"
    '{"reasoning": "short analysis", '
    '"nodes": [{"id":"n1","type":"Input","label":"Name","x":10,"y":20}], '
    '"links": [{"from":"n1","to":"n2"}], '
    '"entities": [{"type":"URL","val":"x"}]}\n'
    "5-8 nodes. Node types: Attacker, Input, Server, Database, Vulnerability, Output, Trust Boundary, Process"
)

for model in ["minimax/minimax-m3:free", "google/gemma-4-26b-a4b-it:free",
              "z-ai/glm-5.2:free", "thinkingmachines/inkling:free",
              "inclusionai/ling-3.0-flash-fin:free", "openrouter/free"]:
    t0 = time.time()
    payload = json.dumps({"model": model, "max_tokens": 700, "temperature": 0.3,
                          "messages": [{"role": "user", "content": prompt}]}).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions", data=payload,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key,
                 "HTTP-Referer": "http://localhost:5000", "X-Title": "BountyAI"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            res = json.loads(r.read().decode())
        el = time.time() - t0
        if "error" in res:
            print(f"{el:5.1f}s  ERR  {model}: {res['error'].get('message','')[:70]}")
            continue
        c = res["choices"][0]["message"]["content"]
        ok = "OK " if c.strip().startswith("{") or "```json" in c else "BAD"
        print(f"{el:5.1f}s  {ok} {model}  len={len(c)}")
    except urllib.error.HTTPError as e:
        print(f"{time.time()-t0:5.1f}s  HTTP{e.code} {model}")
    except Exception as e:
        print(f"{time.time()-t0:5.1f}s  TO  {model}: {str(e)[:60]}")
