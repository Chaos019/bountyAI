import pathlib, re

html = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"
text = html.read_text(encoding="utf-8", errors="ignore")

lines = text.splitlines()

print("=== SEARCHING FOR ALL PANEL DIVS ===")
for i, line in enumerate(lines):
    if 'id="panel-' in line or "id='panel-" in line or 'class="panel' in line:
        print(f"Line {i+1}: {line.strip()[:100]}")

print("\n=== SEARCHING FOR ALL NAV TABS ===")
for i, line in enumerate(lines):
    if 'class="ntab' in line or "go(" in line:
        if 'button' in line or 'onclick' in line:
            print(f"Line {i+1}: {line.strip()[:100]}")
