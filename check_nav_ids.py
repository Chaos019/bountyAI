import re

with open(r"c:\Users\ADMIN\Desktop\major major project clg final\BountyAI_v3_Project\bountyai\frontend\index.html", "r", encoding="utf-8", errors="ignore") as f:
    text = f.read()

calls = set(re.findall(r"go\(['\"](\w+)['\"]\)", text))
print("All go('...') calls found in index.html:", sorted(list(calls)))

# Check all panel IDs in index.html
panels = set(re.findall(r'id=["\']panel-(\w+)["\']', text))
print("All panel-XX IDs found in index.html:", sorted(list(panels)))

# Check all tab IDs in index.html
tabs = set(re.findall(r'id=["\']tab-(\w+)["\']', text))
print("All tab-XX IDs found in index.html:", sorted(list(tabs)))
