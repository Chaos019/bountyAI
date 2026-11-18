"""
fix_html.py - Fixes the corrupted LOG PAYOUT section in index.html
Run once: python fix_html.py
"""
import pathlib, re, sys

html_file = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"

if not html_file.exists():
    print(f"[ERROR] Not found: {html_file}")
    sys.exit(1)

content = html_file.read_text(encoding="utf-8", errors="replace")

# The corrupted chunk: JS code got embedded into the HTML text content
# We use a regex to find from "LOG PAYOUT</div>" up to "Benchmark:"
# and replace with clean HTML

clean_block = '''      <div style="font-size:12px;color:var(--t2);margin-bottom:14px">When a finding gets accepted and paid, log it here to track your real earnings.</div>
      <div id="pf-select-wrap">
        <div class="fg"><label>Finding ID</label><input id="pf-finding-id" type="number" min="1" placeholder="e.g. 3"></div>
        <div class="fg"><label>Finding Title (optional)</label><input id="pf-title" type="text" placeholder="e.g. XSS in /api/users"></div>
        <button class="btn blime bsm" style="margin-top:6px" onclick="openPayoutModal(document.getElementById('pf-finding-id').value, document.getElementById('pf-title').value)">&#x1F4B0; Log Payout for This Finding</button>
      </div>'''

# Pattern: match everything between LOG PAYOUT</div> and the Benchmark div
pattern = r"(LOG PAYOUT</div>)(.*?)(<div style=\"margin-top:14px)"
replacement = r"\1\n" + clean_block + r"\n      \3"

new_content, count = re.subn(pattern, replacement, content, count=1, flags=re.DOTALL)

if count == 0:
    print("[WARN] Corrupted block not found by regex — checking manually...")
    # Fallback: look for the exact corruption marker
    if "log it herfunction go" in content:
        new_content = content.replace(
            content[content.find("When a finding"):content.find("Benchmark:")],
            clean_block[content.find("When a"):].split("Benchmark:")[0] + "\n      "
        )
        # More targeted approach
        start = content.find("log it herfunction go")
        end = content.find("💰 Log Payout", start)
        if start != -1 and end != -1:
            # Find the full corrupted region
            line_start = content.rfind("\n", 0, start) + 1
            # Find end of button line
            btn_end = content.find("\n", end) + 1
            corrupted = content[line_start:btn_end]
            new_content = content.replace(corrupted,
                '      <div style="font-size:12px;color:var(--t2);margin-bottom:14px">When a finding gets accepted and paid, log it here to track your real earnings.</div>\n'
                '      <div id="pf-select-wrap">\n'
                '        <div class="fg"><label>Finding ID</label><input id="pf-finding-id" type="number" min="1" placeholder="e.g. 3"></div>\n'
                '        <div class="fg"><label>Finding Title (optional)</label><input id="pf-title" type="text" placeholder="e.g. XSS in /api/users"></div>\n'
                "        <button class=\"btn blime bsm\" style=\"margin-top:6px\" onclick=\"openPayoutModal(document.getElementById('pf-finding-id').value, document.getElementById('pf-title').value)\">&#x1F4B0; Log Payout for This Finding</button>\n"
                '      </div>\n'
            )
            print(f"[OK] Fallback fix applied")
        else:
            print("[ERROR] Could not locate corruption. File unchanged.")
            sys.exit(1)
    else:
        print("[OK] No corruption found — file looks clean already!")
        sys.exit(0)
else:
    print(f"[OK] Fixed {count} corrupted block(s)")

html_file.write_text(new_content, encoding="utf-8")
print(f"[OK] Saved: {html_file}")
print("[DONE] Reload http://localhost:5000 in your browser")
