import pathlib, re

html = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"
text = html.read_text(encoding="utf-8", errors="ignore")

# Find all div tags with panel class or panel- id
pattern = r'<div[^>]*id=["\']panel-([^"\']+)["\'][^>]*>'
matches = list(re.finditer(pattern, text))

print(f"Total panel divs found: {len(matches)}")
for m in matches:
    full_tag = m.group(0)
    panel_id = m.group(1)
    print(f"Panel ID: {panel_id:12s} | Full tag: {full_tag}")
