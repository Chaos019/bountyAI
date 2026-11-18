import re

with open(r"c:\Users\ADMIN\Desktop\major major project clg final\BountyAI_v3_Project\bountyai\frontend\index.html", "r", encoding="utf-8", errors="ignore") as f:
    text = f.read()

print("File size:", len(text))
matches = [m.start() for m in re.finditer(r"function loadDash", text)]
print("loadDash matches:", matches)

for m in re.finditer(r"function \w+\(", text):
    fname = m.group(0)
    if any(k in fname for k in ["go", "loadDash", "checkHealth", "api"]):
        print(f"Line {text[:m.start()].count('\n') + 1}: {fname}")
