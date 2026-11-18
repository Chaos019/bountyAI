import pathlib

HTML = pathlib.Path(__file__).parent.parent / "frontend" / "index.html"
text = HTML.read_text(encoding="utf-8", errors="ignore")

roi_start = text.find('<!-- ══════════════════════════ ROI DASHBOARD')
toast_start = text.find('<div id="toast"')

clean_roi = """<!-- ══════════════════════════ ROI DASHBOARD ══════════════════════════ -->
<div id="panel-roi" class="panel"><div class="pg">
  <div class="hero" style="margin-bottom:20px">
    <div>
      <div class="htitle" style="font-size:24px">💰 ROI <em>& Earnings Tracker</em></div>
      <div class="hsub">Real data from your actual scans and accepted findings. CAI research: AI is 156× cheaper than human pentesters. All numbers below are calculated from your real activity.</div>
    </div>
  </div>

  <div class="g3" style="margin-bottom:20px">
    <div class="card cp" style="text-align:center">
      <div style="font-size:9px;color:var(--t3);font-family:'IBM Plex Mono',monospace;letter-spacing:1.5px">EST. TIME SAVED</div>
      <div style="font-size:28px;font-weight:900;color:var(--lime);margin:6px 0" id="roi-time-saved">0 hrs</div>
      <div style="font-size:11px;color:var(--t3)">vs. manual recon time</div>
    </div>
    <div class="card cp" style="text-align:center">
      <div style="font-size:9px;color:var(--t3);font-family:'IBM Plex Mono',monospace;letter-spacing:1.5px">EST. COST SAVED</div>
      <div style="font-size:28px;font-weight:900;color:var(--cyan);margin:6px 0" id="roi-cost-saved">$0</div>
      <div style="font-size:11px;color:var(--t3)">based on $150/hr consultant rate</div>
    </div>
    <div class="card cp" style="text-align:center">
      <div style="font-size:9px;color:var(--t3);font-family:'IBM Plex Mono',monospace;letter-spacing:1.5px">TOTAL SCANS</div>
      <div style="font-size:28px;font-weight:900;color:var(--txt);margin:6px 0" id="roi-scans-count">0</div>
      <div style="font-size:11px;color:var(--t3)">automated scans completed</div>
    </div>
  </div>

  <!-- Performance Benchmark Table -->
  <div class="sl">Performance Benchmark by Category (CAI Paper — Table 2)</div>
  <div class="card" style="margin-bottom:20px">
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="border-bottom:1px solid var(--ln)">
        <td style="padding:10px 14px;color:var(--t3);font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:1px">CATEGORY</td>
        <td style="padding:10px 14px;color:var(--t3);font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:1px">AI TIME</td>
        <td style="padding:10px 14px;color:var(--t3);font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:1px">HUMAN TIME</td>
        <td style="padding:10px 14px;color:var(--t3);font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:1px">SPEED RATIO</td>
        <td style="padding:10px 14px;color:var(--t3);font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:1px">COST RATIO</td>
      </tr></thead>
      <tbody id="benchmark-table"></tbody>
    </table>
  </div>

  <!-- Security Posture -->
  <div class="sl">Security Posture Score (Live — from your findings)</div>
  <div class="g2">
    <div class="card cp" style="text-align:center">
      <div style="font-size:11px;color:var(--t3);margin-bottom:8px;font-family:'IBM Plex Mono',monospace;letter-spacing:1px">CURRENT POSTURE</div>
      <div class="posture-grade posture-N" id="roi-posture-grade" style="font-size:48px;font-weight:900;margin:8px auto">—</div>
      <div style="display:flex;flex-direction:column;gap:6px;margin-top:12px;text-align:left">
        <div class="qblock"><span>Total Findings</span><span style="color:var(--lime)" id="roi-findings2">0</span></div>
        <div class="qblock"><span>Critical Open</span><span style="color:var(--red)" id="roi-crit-open">0</span></div>
        <div class="qblock"><span>Acceptance Rate</span><span style="color:var(--cyan)" id="roi-acc-rate2">0%</span></div>
      </div>
    </div>
    <div class="card cp">
      <div style="font-size:11px;color:var(--t3);margin-bottom:12px;font-family:'IBM Plex Mono',monospace;letter-spacing:1px">LOG PAYOUT</div>
      <div style="font-size:12px;color:var(--t2);margin-bottom:14px">When a finding gets accepted and paid, log it here to track your real earnings.</div>
      <div id="pf-select-wrap">
        <div class="fg"><label>Finding ID</label><input id="pf-finding-id" type="number" min="1" placeholder="e.g. 3"></div>
        <div class="fg"><label>Finding Title (optional)</label><input id="pf-title" type="text" placeholder="e.g. XSS in /api/users"></div>
        <button class="btn blime bsm" style="margin-top:6px" onclick="openPayoutModal(document.getElementById('pf-finding-id').value, document.getElementById('pf-title').value)">💰 Log Payout for This Finding</button>
      </div>
      <div style="margin-top:14px;background:var(--bg3);padding:10px;border-radius:4px;font-size:11px;color:var(--t2)">
        📊 Benchmark: CAI paper reports AI costs avg $109 for work that costs humans $17,218. Speed ratio: 11× faster overall.
      </div>
    </div>
  </div>
</div></div>

"""

if roi_start != -1 and toast_start != -1:
    text = text[:roi_start] + clean_roi + text[toast_start:]
    HTML.write_text(text, encoding="utf-8")
    print("Rebuilt panel-roi cleanly!")
else:
    print(f"Error: roi_start={roi_start}, toast_start={toast_start}")
