"""
FIX_NOW.py - Direct Line Repair for index.html
"""
import pathlib

HTML = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"

if HTML.exists():
    raw = HTML.read_bytes()
    text = raw.decode("utf-8", errors="ignore")
    modified = False

    if "log it herfunction go" in text or "function go(id)" in text[1000:1500]:
        pout_idx = text.find("LOG PAYOUT")
        cai_idx = text.find("CAI paper reports AI costs", pout_idx if pout_idx != -1 else 0)
        if pout_idx != -1 and cai_idx != -1:
            div_start = text.find("<div", pout_idx)
            div_end = text.rfind("<div", pout_idx, cai_idx)
            if div_start != -1 and div_end != -1:
                clean_block = (
                    '<div style="font-size:12px;color:var(--t2);margin-bottom:14px">When a finding gets accepted and paid, log it here to track your real earnings.</div>\r\n'
                    '      <div id="pf-select-wrap">\r\n'
                    '        <div class="fg"><label>Finding ID</label><input id="pf-finding-id" type="number" min="1" placeholder="e.g. 3"></div>\r\n'
                    '        <div class="fg"><label>Finding Title (optional)</label><input id="pf-title" type="text" placeholder="e.g. XSS in /api/users"></div>\r\n'
                    '        <button class="btn blime bsm" style="margin-top:6px" onclick="openPayoutModal(document.getElementById(\'pf-finding-id\').value, document.getElementById(\'pf-title\').value)">💰 Log Payout for This Finding</button>\r\n'
                    '      </div>\r\n'
                    '      '
                )
                text = text[:div_start] + clean_block + text[div_end:]
                modified = True

    if text.count('id="panel-learn"') > 1:
        first = text.find('id="panel-learn"')
        p_start = text.rfind('<div id="panel-learn"', 0, first + 20)
        p_end = text.find('</div></div>', p_start)
        if p_start != -1 and p_end != -1:
            text = text[:p_start] + text[p_end + 12:]
            modified = True

    if modified:
        HTML.write_bytes(text.encode("utf-8"))
        print("[SUCCESS] Fixed frontend/index.html")
    else:
        print("[INFO] frontend/index.html is already clean")
