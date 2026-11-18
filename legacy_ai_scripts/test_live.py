import urllib.request, json, urllib.error

BASE = "https://bountyai.onrender.com"

def req(path, data=None, token=None, method=None, timeout=90):
    headers = {"Content-Type": "application/json"}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.Request(BASE + path, data=body, headers=headers,
                               method=method or ("POST" if data is not None else "GET"))
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return 0, str(e)

st, body = req("/api/auth/login", {"username": "admin", "password": "admin123"})
print("LOGIN:", st)
try:
    tok = json.loads(body).get("token")
except Exception:
    tok = None
print("token:", (tok or body)[:80])

if tok:
    code = """
from flask import request
import sqlite3, os
def login():
    u = request.form["username"]
    p = request.form["password"]
    q = "SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'"
    r = sqlite3.connect("app.db").execute(q).fetchone()
    if r:
        return {"token": os.popen("echo " + u).read()}
    return {"error": "unauthorized"}
"""
    st, body = req("/api/analyze/visual-flow", {"content": code}, tok, timeout=90)
    print("\nVISUAL-FLOW:", st)
    try:
        d = json.loads(body)
        print("reasoning:", str(d.get("reasoning"))[:300])
        print("nodes:", len(d.get("nodes", [])), "links:", len(d.get("links", [])), "entities:", len(d.get("entities", [])))
        for n in d.get("nodes", [])[:12]:
            print("  -", n.get("type"), "|", n.get("label"))
    except Exception:
        print("RAW:", body[:1200])
