import pathlib

HTML = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"
if HTML.exists():
    text = HTML.read_text(encoding="utf-8", errors="ignore")
    
    # 1. Clean Log Payout button if it got contaminated
    bad_btn = """<button class="btn blime bsm" style="margin-top:6px" onclick="try {"""
    if bad_btn in text:
        s = text.find(bad_btn)
        e = text.find("</button>", s) + 9
        clean_btn = '<button class="btn blime bsm" style="margin-top:6px" onclick="openPayoutModal(document.getElementById(\'pf-finding-id\').value, document.getElementById(\'pf-title\').value)">💰 Log Payout for This Finding</button>'
        text = text[:s] + clean_btn + text[e:]

    HTML.write_text(text, encoding="utf-8")
    print("Cleaned index.html")
