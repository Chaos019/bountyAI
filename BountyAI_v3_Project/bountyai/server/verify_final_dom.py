import pathlib, re
from html.parser import HTMLParser

html_path = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"
content = html_path.read_text(encoding="utf-8", errors="ignore")

class DOMChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.panels = []
        self.tabs = []
        self.buttons = []
        self.ids = set()
        self.duplicates = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        el_id = attr_dict.get('id')
        if el_id:
            if el_id in self.ids:
                self.duplicates.append(el_id)
            self.ids.add(el_id)
            if el_id.startswith('panel-'):
                self.panels.append(el_id)
            if el_id.startswith('tab-'):
                self.tabs.append(el_id)
        
        onclick = attr_dict.get('onclick')
        if onclick and 'go(' in onclick:
            self.buttons.append((tag, el_id, onclick))

parser = DOMChecker()
parser.feed(content)

print("=== DOM VERIFICATION REPORT ===")
print(f"Total Unique IDs: {len(parser.ids)}")
print(f"Duplicate IDs: {parser.duplicates}")

print("\n=== PANELS FOUND ===")
for p in parser.panels:
    print(f"  ✓ {p}")

print("\n=== TABS FOUND ===")
for t in parser.tabs:
    print(f"  ✓ {t}")

print("\n=== BUTTON ONCLICK HANDLERS ===")
for b in parser.buttons:
    print(f"  ✓ <{b[0]} id='{b[1]}'> -> {b[2]}")
