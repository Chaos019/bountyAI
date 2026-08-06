import pathlib, re

HTML = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"
text = HTML.read_text(encoding="utf-8", errors="ignore")

# Find second occurrence of panel-arcade
p1 = text.find('id="panel-arcade"')
if p1 != -1:
    p2 = text.find('id="panel-arcade"', p1 + 20)
    if p2 != -1:
        # Find the end of this duplicate panel block (</div></div>)
        end_p2 = text.find('</div></div>', p2)
        if end_p2 != -1:
            start_comment = text.rfind('<!--', 0, p2)
            if start_comment != -1 and start_comment > p1:
                text = text[:start_comment] + text[end_p2 + 12:]
            else:
                text = text[:p2 - 5] + text[end_p2 + 12:]

HTML.write_text(text, encoding="utf-8")
print("Removed duplicate panel-arcade")
