import pathlib, re

html = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"
text = html.read_text(encoding="utf-8", errors="ignore")

# Find all panels
panels = re.findall(r'id="(panel-[^"]+)"', text)
tabs = re.findall(r'id="(tab-[^"]+)"', text)
clicks = re.findall(r'onclick="go\(\'([^\']+)\'\)"', text)

print("=== PANELS FOUND IN DOM ===")
for p in sorted(set(panels)):
    print(f"  - {p}")

print("\n=== TABS FOUND IN DOM ===")
for t in sorted(set(tabs)):
    print(f"  - {t}")

print("\n=== CLICK HANDLERS ===")
for c in sorted(set(clicks)):
    print(f"  - go('{c}')")

# Check syntax / script tags
print("\n=== SCRIPT TAG COUNT ===")
print("  <script> count:", text.count("<script>"))
print("  </script> count:", text.count("</script>"))
