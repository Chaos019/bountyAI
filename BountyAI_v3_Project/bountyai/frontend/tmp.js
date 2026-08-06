

var TABS=['dash','prog','recon','log','report','learn'];
var pfilt='',allFindings=[],selFid=0,lastMd='';
var SN={C:'CRITICAL',H:'HIGH',M:'MEDIUM',L:'LOW'};
var SC={C:'var(--red)',H:'var(--orange)',M:'var(--yellow)',L:'var(--lime)'};

function go(id){
  for(var i=0;i<TABS.length;i++){document.getElementById('panel-'+TABS[i]).classList.remove('on');document.querySelectorAll('.ntab')[i].classList.remove('on');}
  document.getElementById('panel-'+id).classList.add('on');
  document.querySelectorAll('.ntab')[TABS.indexOf(id)].classList.add('on');
  window.scrollTo(0,0);
  if(id==='dash')loadDash();
  if(id==='prog')loadProgs();
  if(id==='log'||id==='report')loadFindings();
}

function showToast(msg,t){
  t=t||'ok';
  var el=document.getElementById('toast');
  el.textContent=(t==='ok'?'\u2713 ':t==='err'?'\u2717 ':'\u2139 ')+msg;
  el.className='toast '+t;el.style.display='flex';
  clearTimeout(el._tid);el._tid=setTimeout(function(){el.style.display='none';},3200);
}

function api(method,path,body){
  var opts={method:method,headers:{'Content-Type':'application/json'}};
  if(body)opts.body=JSON.stringify(body);
  return fetch('/api'+path,opts).then(function(r){
    if(!r.ok)return r.json().then(function(e){throw new Error(e.error||r.statusText);});
    return r.json();
  });
}

function checkHealth(){
  api('GET','/health').then(function(h){
    var dot=document.getElementById('apd'),lbl=document.getElementById('albl');
    if(h.ai_enabled){dot.style.background='#28c840';lbl.textContent='CLAUDE AI ON';lbl.style.color='var(--lime)';}
    else{dot.style.background='var(--yellow)';lbl.textContent='TEMPLATE MODE';lbl.style.color='var(--yellow)';}
    var agents=[
      {n:'Agent 1 - Idea Parser',c:'var(--lime)',on:true},
      {n:'Agent 2 - Recon (crt.sh live)',c:'var(--cyan)',on:true},
      {n:'Agent 3 - AI Synthesis (Claude)',c:'var(--blue)',on:h.ai_enabled},
      {n:'Agent 4 - CVSS Scorer',c:'var(--orange)',on:true}
    ];
    var pip=document.getElementById('pipeline');
    if(pip)pip.innerHTML=agents.map(function(a){
      return '<div class="pit"><div class="pdot" style="background:'+(a.on?a.c:'var(--t3)')+(a.on?';animation:blink 2s infinite':'')+'">'
        +'</div><div class="pn">'+a.n+'</div><div class="ps" style="color:'+(a.on?a.c:'var(--t3)')+'">'+
        (a.on?'ACTIVE':'NO KEY')+'</div></div>';
    }).join('');
  }).catch(function(){
    var lbl=document.getElementById('albl');if(lbl)lbl.textContent='SERVER OFF';
    var dot=document.getElementById('apd');if(dot)dot.style.background='var(--red)';
  });
}

function loadDash(){
  Promise.all([api('GET','/stats'),api('GET','/findings'),api('GET','/programs')]).then(function(res){
    var st=res[0],fr=res[1],pr=res[2];
    var earn=st.total_earned>0?'Rs'+Math.round(st.total_earned/1000)+'K':'Rs0';
    var set=function(id,v){var e=document.getElementById(id);if(e)e.textContent=v;};
    set('kv-total',st.total_findings);set('ks-total',(st.by_severity.C||0)+' critical');
    set('kv-earn',earn);set('ks-earn',(st.by_status.accepted||0)+' accepted');
    set('kv-crit',st.by_severity.C||0);set('kv-rate',(st.acceptance_rate||0)+'%');
    set('ks-rate',(st.by_status.accepted||0)+' of '+st.total_findings);
    set('h-earn',earn);set('h-total',st.total_findings);set('h-crit',st.by_severity.C||0);
    var PICO={R:{bg:'rgba(72,150,255,.12)',c:'var(--blue)'},P:{bg:'rgba(255,201,68,.1)',c:'var(--yellow)'},
      F:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},Z:{bg:'rgba(255,63,98,.1)',c:'var(--red)'},
      S:{bg:'rgba(255,128,64,.1)',c:'var(--orange)'},C:{bg:'rgba(53,232,196,.1)',c:'var(--cyan)'},
      M:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},G:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},
      A:{bg:'rgba(72,150,255,.12)',c:'var(--blue)'},E:{bg:'rgba(53,232,196,.1)',c:'var(--cyan)'},
      U:{bg:'rgba(255,128,64,.1)',c:'var(--orange)'},V:{bg:'rgba(255,63,98,.1)',c:'var(--red)'},
      T:{bg:'rgba(72,150,255,.12)',c:'var(--blue)'},H:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},
      B:{bg:'rgba(255,201,68,.1)',c:'var(--yellow)'},I:{bg:'rgba(53,232,196,.1)',c:'var(--cyan)'}};
    var fl=(fr.findings||[]).slice(0,6);
    var df=document.getElementById('dash-findings');
    if(df)df.innerHTML=!fl.length
      ?'<div style="padding:22px;text-align:center;color:var(--t3)">No findings yet</div>'
      :fl.map(function(f){return '<div class="arow"><div class="adot" style="background:'+(SC[f.severity]||'var(--t3)')+'"></div>'
        +'<div class="ainf"><div class="at">'+f.vuln_type+' - '+(f.program_name||f.target_domain||'unknown')+'</div>'
        +'<div class="au">'+(f.affected_url||'')+'</div></div>'
        +'<span class="sv sv'+f.severity+'">'+(SN[f.severity]||f.severity)+'</span>'
        +(f.payout_amount>0?'<div class="apay">Rs'+Math.round(f.payout_amount/1000)+'K</div>':'')
        +'<span class="sts st'+(f.status==='accepted'?'acc':f.status==='submitted'?'pen':'dft')+'">'+(f.status||'DRAFT').toUpperCase()+'</span>'
        +'</div>';}).join('');
    var ps=(pr.programs||[]).slice(0,6);
    var dp=document.getElementById('dash-progs');
    if(dp)dp.innerHTML=ps.map(function(p){var k=p.name[0];var ico=PICO[k]||{bg:'var(--bg3)',c:'var(--txt)'};
      return '<div class="pmini"><div class="pico" style="background:'+ico.bg+';color:'+ico.c+'">'+k+'</div>'
        +'<div><div class="pname">'+p.name+'</div><div class="pplat">'+p.platform+'</div></div>'
        +'<div class="ppay">'+(p.payout_critical||'').split('-').pop()+' max</div></div>';}).join('');
  }).catch(function(e){console.error('dash error',e);});
}

var cachedProgs=[];
function loadProgs(){
  api('GET','/programs').then(function(r){cachedProgs=r.programs||[];renderProgs();}).catch(function(){});
}
function setF(el,v){document.querySelectorAll('.fchip').forEach(function(c){c.classList.remove('on');});el.classList.add('on');pfilt=v;renderProgs();}
function renderProgs(){
  var q=(document.getElementById('pq')?document.getElementById('pq').value:'').toLowerCase();
  var fl=cachedProgs.filter(function(p){return(!q||p.name.toLowerCase().indexOf(q)>=0)&&(!pfilt||p.cat===pfilt||p.category===pfilt||(pfilt==='beginner'&&p.beginner_friendly));});
  var PICO={R:{bg:'rgba(72,150,255,.12)',c:'var(--blue)'},P:{bg:'rgba(255,201,68,.1)',c:'var(--yellow)'},
    F:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},Z:{bg:'rgba(255,63,98,.1)',c:'var(--red)'},
    S:{bg:'rgba(255,128,64,.1)',c:'var(--orange)'},C:{bg:'rgba(53,232,196,.1)',c:'var(--cyan)'},
    M:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},G:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},
    A:{bg:'rgba(72,150,255,.12)',c:'var(--blue)'},E:{bg:'rgba(53,232,196,.1)',c:'var(--cyan)'},
    U:{bg:'rgba(255,128,64,.1)',c:'var(--orange)'},V:{bg:'rgba(255,63,98,.1)',c:'var(--red)'},
    T:{bg:'rgba(72,150,255,.12)',c:'var(--blue)'},H:{bg:'rgba(180,240,66,.1)',c:'var(--lime)'},
    B:{bg:'rgba(255,201,68,.1)',c:'var(--yellow)'},I:{bg:'rgba(53,232,196,.1)',c:'var(--cyan)'}};
  var pg=document.getElementById('pgrid');if(!pg)return;
  if(!fl.length){pg.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--t3)">No programs match</div>';return;}
  pg.innerHTML=fl.map(function(p){
    var k=p.name[0];var ico=PICO[k]||{bg:'var(--bg3)',c:'var(--txt)'};
    var si=(p.scope_in||[]).map(function(s){return '<div class="scrow in"><span>&#10003;</span>'+s+'</div>';}).join('');
    var so=(p.scope_out||[]).slice(0,2).map(function(s){return '<div class="scrow out"><span>&#10007;</span>'+s+'</div>';}).join('');
    return '<div class="pcard" onclick="pickP(this)">'
      +'<div class="pctop"><div class="pchead">'
      +'<div class="pcico" style="background:'+ico.bg+';color:'+ico.c+'">'+k+'</div>'
      +'<div><div class="pcname">'+p.name+'</div><div class="pcplat">'+p.platform+'</div></div>'
      +(p.beginner_friendly?'<span class="sv svL" style="margin-left:auto">BEGINNER</span>':'<span class="sv" style="margin-left:auto;background:var(--bd);color:var(--blue);border:1px solid rgba(72,150,255,.25)">'+(p.category||'').toUpperCase()+'</span>')
      +'</div>'
      +'<div class="paygrid">'
      +'<div class="payc"><div class="payt">CRITICAL</div><div class="paya" style="color:var(--red)">'+(p.payout_critical||'-')+'</div></div>'
      +'<div class="payc"><div class="payt">HIGH</div><div class="paya" style="color:var(--orange)">'+(p.payout_high||'-')+'</div></div>'
      +'<div class="payc"><div class="payt">MEDIUM</div><div class="paya" style="color:var(--yellow)">'+(p.payout_medium||'-')+'</div></div>'
      +'<div class="payc"><div class="payt">LOW</div><div class="paya" style="color:var(--lime)">'+(p.payout_low||'-')+'</div></div>'
      +'</div></div>'
      +'<div class="scwrap">'+si+so+'</div>'
      +'<div class="pcfoot"><div class="resp">Avg '+(p.response_days||5)+'-day response</div>'
      +'<button class="btn blime bsm" onclick="event.stopPropagation();rjump(\''+p.domain+'\')">Recon</button>'
      +'</div></div>';}).join('');
}
function pickP(el){document.querySelectorAll('.pcard').forEach(function(c){c.classList.remove('sel');});el.classList.add('sel');}
function rjump(d){document.getElementById('ri').value=d;go('recon');setTimeout(doRecon,400);}

function doRecon(){
  var domain=document.getElementById('ri').value.trim().replace(/https?:\/\//,'').split('/')[0];
  if(!domain){showToast('Enter a domain first','err');return;}
  var term=document.getElementById('termout'),btn=document.getElementById('rbtn');
  term.innerHTML='';document.getElementById('rout').style.display='none';
  btn.textContent='Scanning...';btn.disabled=true;
  var pre=['<span class="tp">bountyai@recon:~$ </span><span style="color:var(--txt)">recon --target '+domain+' --full</span>',
    '<span class="td">[*] Initializing pipeline...</span>',
    '<span class="ts">[+] Target: '+domain+'</span>',
    '<span class="td">[*] Querying crt.sh (LIVE)...</span>',
    '<span class="td">[*] Fingerprinting tech stack...</span>',
    '<span class="td">[*] Querying NVD CVE database...</span>',
    '<span class="td">[*] Running AI suggestion engine...</span>'];
  var i=0;
  function nl(){if(i<pre.length){var el=document.createElement('div');el.innerHTML=pre[i++];term.appendChild(el);term.scrollTop=term.scrollHeight;setTimeout(nl,170+Math.random()*130);}
    else{api('POST','/recon',{domain:domain}).then(function(r){
      [('<span class="tr">[+] '+(r.subdomains||[]).length+' subdomains ('+(r.data_source||'mixed')+')</span>'),
       ('<span class="tr">[+] '+(r.tech_stack||[]).length+' technologies</span>'),
       ((r.cves_found||[]).length>0?'<span class="tw2">[!] '+r.cves_found.length+' CVE(s) found</span>':'<span class="ts">[+] No critical CVEs</span>'),
       ('<span class="ts">[+] Done in '+(r.scan_duration||0)+'s</span>')
      ].forEach(function(l){var el=document.createElement('div');el.innerHTML=l;term.appendChild(el);});
      term.scrollTop=term.scrollHeight;showReconOut(r);
    }).catch(function(e){var el=document.createElement('div');el.innerHTML='<span class="te">[X] '+e.message+'</span>';term.appendChild(el);showToast('Recon failed','err');btn.textContent='Run Recon';btn.disabled=false;});}
  }
  nl();
}
function showReconOut(r){
  document.getElementById('rout').style.display='block';
  document.getElementById('rsubs').innerHTML=(r.subdomains||[]).map(function(s){return '<span class="subtag">'+s+'</span>';}).join('')||'<span style="color:var(--t3)">None</span>';
  document.getElementById('rtech').innerHTML=(r.tech_stack||[]).map(function(t){return '<span class="techtag">'+(t.name||t)+(t.version?' '+t.version:'')+'</span>';}).join('')||'<span style="color:var(--t3)">Unknown</span>';
  document.getElementById('rcves').innerHTML=!(r.cves_found||[]).length?'<div style="color:var(--lime);font-size:11px">No critical CVEs detected</div>':r.cves_found.map(function(c){return '<div class="cverow"><div class="cveid">'+c.id+'</div><span class="sv sv'+(c.severity||'M')+'">'+(SN[c.severity]||'MEDIUM')+'</span><div style="font-size:10.5px;color:var(--t2);flex:1">'+c.description+'</div></div>';}).join('');
  document.getElementById('rvulns').innerHTML=(r.vuln_suggestions||[]).map(function(v){return '<div class="vc '+(v.severity||'M')+'"><div class="vch"><span class="sv sv'+(v.severity||'M')+'">'+(SN[v.severity]||'MEDIUM')+'</span><div class="vct">'+v.title+'</div></div><div class="vcd">'+v.description+'</div><div class="vcp">'+v.payload+'</div></div>';}).join('');
  document.getElementById('rbtn').textContent='Run Recon';document.getElementById('rbtn').disabled=false;
}
function clrRecon(){document.getElementById('termout').innerHTML='<div><span class="tp">bountyai@recon:~$ </span><span class="td">Cleared.</span></div>';document.getElementById('rout').style.display='none';document.getElementById('ri').value='';}

function recalc(){
  var m={C:[9.1,'var(--red)','91%','CRITICAL - RCE possible'],H:[7.6,'var(--orange)','76%','HIGH - Account takeover possible'],M:[5.3,'var(--yellow)','53%','MEDIUM - Limited exposure'],L:[2.1,'var(--lime)','21%','LOW - Minor issue']};
  var s=document.getElementById('fvs').value;var row=m[s]||m.M;
  document.getElementById('cvssnum').textContent=row[0];document.getElementById('cvssnum').style.color=row[1];
  document.getElementById('cvssfill').style.width=row[2];document.getElementById('cvssfill').style.background=row[1];
  document.getElementById('cvsslab').textContent=row[3];
}
function fkUp(){document.getElementById('uplbl').textContent='screenshot_exploit.png (328KB) attached';}
function clrForm(){['fvu','fvdesc','fvsteps','fvimpact','fvp','fvd'].forEach(function(id){var e=document.getElementById(id);if(e)e.value='';});}
function fillSample(){
  document.getElementById('fvt').value='Cross-Site Scripting (XSS)';
  document.getElementById('fvs').value='H';
  document.getElementById('fvp').value='Razorpay';
  document.getElementById('fvd').value='razorpay.com';
  document.getElementById('fvu').value='https://merchant.razorpay.com/profile/edit';
  document.getElementById('fvdesc').value='The profile name field stores unsanitized HTML. Script tags execute in every visitor browser when the merchant profile is loaded.';
  document.getElementById('fvsteps').value='1. Login to merchant.razorpay.com\n2. Navigate to Profile and Edit Name\n3. Enter XSS payload\n4. Save and visit the public profile URL\n5. JavaScript fires in visitor browser';
  document.getElementById('fvimpact').value='Session hijacking and full account takeover for any user viewing the profile.';
  recalc();showToast('Sample XSS finding loaded');
}
function saveFinding(){
  var sev=document.getElementById('fvs').value;
  var desc=document.getElementById('fvdesc').value;
  var steps=document.getElementById('fvsteps').value;
  if(!desc||!steps){showToast('Description and Steps required','err');return;}
  api('POST','/findings',{vuln_type:document.getElementById('fvt').value,severity:sev,program_name:document.getElementById('fvp').value,target_domain:document.getElementById('fvd').value,affected_url:document.getElementById('fvu').value,description:desc,steps_to_reproduce:steps,impact:document.getElementById('fvimpact').value}).then(function(r){showToast('Saved! CVSS '+r.cvss.score+' '+r.cvss.severity);loadFindings();}).catch(function(e){showToast('Error: '+e.message,'err');});
}
function loadFindings(){
  api('GET','/findings').then(function(r){allFindings=r.findings||[];renderSaved();renderRFL();}).catch(function(){});
}
function renderSaved(){
  var fc=document.getElementById('fc');if(fc)fc.textContent=allFindings.length?'('+allFindings.length+')':'';
  var sl=document.getElementById('slist');if(!sl)return;
  if(!allFindings.length){sl.innerHTML='<div style="color:var(--t3);font-size:12px;text-align:center;padding:20px">No findings yet</div>';return;}
  sl.innerHTML=allFindings.slice(0,10).map(function(f,i){return '<div class="fscard '+f.severity+'" onclick="loadF('+i+')">'
    +'<div class="fstop"><span class="sv sv'+f.severity+'">'+(SN[f.severity]||f.severity)+'</span>'
    +'<div style="font-family:\'IBM Plex Mono\',monospace;font-size:9px;color:var(--t3);margin-left:auto">'+(f.target_domain||'')+'</div></div>'
    +'<div class="fsn">'+f.vuln_type+'</div>'
    +'<div class="fsu">'+(f.affected_url||'').substring(0,52)+'</div>'
    +'<div class="fsbot"><div class="fsc">CVSS '+(f.cvss_score||'-')+' - '+ago(f.created_at)+'</div>'
    +'<div style="display:flex;gap:5px">'
    +'<button class="btn blime bxs" onclick="event.stopPropagation();goRep('+f.id+')">Report</button>'
    +'<button class="btn bred bxs" onclick="event.stopPropagation();delF('+f.id+')">X</button>'
    +'</div></div></div>';}).join('');
}
function renderRFL(){
  var rfl=document.getElementById('rfl');if(!rfl)return;
  rfl.innerHTML=!allFindings.length?'<div style="color:var(--t3);font-size:11.5px">No findings yet</div>':allFindings.slice(0,6).map(function(f){return '<div class="rsf'+(selFid===f.id?' on':'')+'" id="rsf-'+f.id+'" onclick="selR('+f.id+')">'+'<div class="rsfn">'+f.vuln_type+'</div>'+'<div class="rsfs" style="color:'+(SC[f.severity]||'var(--txt)')+'">'+(SN[f.severity]||f.severity)+' - CVSS '+(f.cvss_score||'-')+' - '+(f.target_domain||'')+'</div></div>';}).join('');
}
function loadF(i){var f=allFindings[i];if(!f)return;document.getElementById('fvt').value=f.vuln_type||'';document.getElementById('fvs').value=f.severity||'M';document.getElementById('fvp').value=f.program_name||'';document.getElementById('fvd').value=f.target_domain||'';document.getElementById('fvu').value=f.affected_url||'';document.getElementById('fvdesc').value=f.description||'';document.getElementById('fvsteps').value=f.steps_to_reproduce||'';document.getElementById('fvimpact').value=f.impact||'';recalc();}
function delF(id){if(!confirm('Delete?'))return;api('DELETE','/findings/'+id).then(function(){showToast('Deleted');loadFindings();}).catch(function(e){showToast('Error: '+e.message,'err');});}
function goRep(id){selFid=id;go('report');setTimeout(trigGen,500);}
function selR(id){selFid=id;document.querySelectorAll('.rsf').forEach(function(e){e.classList.remove('on');});var el=document.getElementById('rsf-'+id);if(el)el.classList.add('on');}

function trigGen(){
  if(!selFid){showToast('Select a finding first','err');return;}
  document.getElementById('genov').style.display='flex';
  var steps=['Analyzing vulnerability...','Mapping CWE and OWASP...','Calculating CVSS...','Generating description...','Writing steps...','Crafting remediation...','Formatting report...'];
  var i=0;var iv=setInterval(function(){if(i<steps.length)document.getElementById('genstep').textContent=steps[i++];},420);
  api('POST','/reports/generate',{finding_id:selFid}).then(function(r){
    clearInterval(iv);document.getElementById('genov').style.display='none';
    document.getElementById('repcontent').innerHTML=md2html(r.report_markdown||'');
    document.getElementById('q1').textContent=Math.round((r.quality_score||0)*10)+'%';
    document.getElementById('q2').textContent=Math.round((r.quality_score||0)*9.5)+'%';
    document.getElementById('q3').textContent=(r.quality_score||0)+'/10';
    lastMd=r.report_markdown||'';
    showToast('Report generated - Quality '+(r.quality_score||0)+'/10');
  }).catch(function(e){clearInterval(iv);document.getElementById('genov').style.display='none';showToast('Error: '+e.message,'err');});
}

function md2html(md){
  return md
    .replace(/^### (.+)$/gm,'<h3>$1</h3>')
    .replace(/^## (.+)$/gm,'<h2>$1</h2>')
    .replace(/^# (.+)$/gm,'<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2" target="_blank">$1</a>')
    .replace(/\x60\x60\x60[\w]*\n?([\s\S]*?)\x60\x60\x60/gm,'<pre>$1</pre>')
    .replace(/\x60([^\x60]+)\x60/g,'<code>$1</code>')
    .replace(/^\|(.+)\|$/gm,function(m,r){return '<tr>'+r.split('|').map(function(c){return '<td>'+c.trim()+'</td>';}).join('')+'</tr>';})
    .replace(/(<tr>[\s\S]*?<\/tr>)+/g,function(s){return '<table>'+s+'</table>';})
    .replace(/^[-*] (.+)$/gm,'<li>$1</li>')
    .replace(/^\d+\. (.+)$/gm,'<li>$1</li>')
    .replace(/(<li>[\s\S]*?<\/li>)+/g,function(s){return '<ul>'+s+'</ul>';})
    .replace(/^---$/gm,'<hr style="border-color:var(--ln);margin:12px 0">')
    .replace(/\n\n+/g,'</p><p>')
    .replace(/^(?!<[htupil])(.+)$/gm,'<p>$1</p>');
}

function cpRep(){var t=lastMd||document.getElementById('repcontent').innerText;if(navigator.clipboard)navigator.clipboard.writeText(t).catch(function(){});showToast('Report copied');}
function dlRep(){var t=lastMd||document.getElementById('repcontent').innerText;var b=new Blob([t],{type:'text/plain'});var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='BountyAI_Report.md';a.click();showToast('Downloaded');}

function ago(ts){if(!ts)return 'just now';var d=new Date(ts),n=new Date(),s=Math.floor((n-d)/1000);if(s<60)return 'just now';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}

checkHealth();loadDash();setInterval(checkHealth,30000);

// ── LEARNING ──────────────────────────────────────────────────
var allResources=[], resCatFilter='all';
function loadResources(){
  api('GET','/learning').then(function(r){
    allResources=r.resources||[];
    var src=document.getElementById('res-src');
    if(src)src.textContent='Source: '+(r.source==='cache'?'cached (refreshes every 6h)':'live — GitHub API + curated')+' · '+allResources.length+' resources';
    renderResources();
  }).catch(function(e){
    var g=document.getElementById('res-grid');
    if(g)g.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--red)">Failed to load: '+e.message+'</div>';
  });
}
function filterRes(cat){
  resCatFilter=cat;
  document.querySelectorAll('[id^="rf-"]').forEach(function(b){b.className='btn bdim bsm';b.style.borderColor='';});
  var el=document.getElementById('rf-'+cat);
  if(el){el.className='btn bghost bsm';el.style.borderColor='rgba(180,240,66,.4)';}
  renderResources();
}
function refreshResources(){
  var g=document.getElementById('res-grid');if(g)g.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--t3)">Refreshing from GitHub...</div>';
  allResources=[];loadResources();
}
function renderResources(){
  var fl=resCatFilter==='all'?allResources:allResources.filter(function(r){return r.category===resCatFilter;});
  var g=document.getElementById('res-grid');if(!g)return;
  if(!fl.length){g.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--t3)">No resources in this category</div>';return;}
  var catColors={labs:'var(--lime)',tools:'var(--cyan)',reference:'var(--blue)',writeups:'var(--orange)',courses:'var(--yellow)'};
  var srcIcons={portswigger:'&#127947;',hackthebox:'&#127919;',github:'&#128013;',owasp:'&#128274;',hackerone:'&#9876;',bugcrowd:'&#128030;'};
  g.innerHTML=fl.map(function(r){
    var tags=[];
    try{tags=typeof r.tags==='string'?JSON.parse(r.tags||'[]'):r.tags||[];}catch(e){}
    var cc=catColors[r.category]||'var(--t2)';
    var ico=srcIcons[r.source]||'&#128196;';
    var stars=r.stars>0?'<span style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--yellow)">&#11088; '+fmtStars(r.stars)+'</span>':'';
    return '<div class="card cp" style="cursor:pointer;transition:border-color .2s;border-top:2px solid '+cc+'" onclick="window.open(''+r.url+'','_blank')">'
      +'<div style="display:flex;align-items:center;gap:7px;margin-bottom:8px">'
      +'<span style="font-size:18px">'+ico+'</span>'
      +'<div style="flex:1"><div style="font-size:12.5px;font-weight:700">'+r.title+'</div>'
      +'<div style="font-family:'IBM Plex Mono',monospace;font-size:8.5px;color:var(--t3);text-transform:uppercase;letter-spacing:.5px">'+r.source+'</div></div>'
      +stars+'</div>'
      +'<div style="font-size:11px;color:var(--t2);line-height:1.6;margin-bottom:8px">'+(r.description||'')+'</div>'
      +'<div style="display:flex;flex-wrap:wrap;gap:4px">'
      +tags.slice(0,4).map(function(t){return '<span style="font-size:9px;font-weight:600;padding:2px 7px;border-radius:2px;background:var(--bd);border:1px solid rgba(72,150,255,.18);color:var(--blue)">'+t+'</span>';}).join('')
      +'</div></div>';
  }).join('');
}
function fmtStars(n){return n>=1000?(n/1000).toFixed(1)+'k':n;}

// ── HACKERONE SYNC ────────────────────────────────────────────
function syncH1(){
  var btn=document.getElementById('syncbtn');
  if(btn){btn.textContent='Syncing...';btn.disabled=true;}
  api('POST','/programs/sync').then(function(r){
    showToast('Real-world scan complete: '+r.synced+' real programs added');
    loadProgs();
    if(btn){btn.innerHTML='&#8635; Global Live Sync';btn.disabled=false;}
  }).catch(function(e){
    showToast('Sync: '+e.message,'inf');
    if(btn){btn.innerHTML='&#8635; Global Live Sync';btn.disabled=false;}
  });
}
function syncPacks(){
  api('POST','/resources/sync').then(function(r){
    showToast('Synced '+r.resources.length+' essential resource packs (Wordlists, Nuclei, Payloads)');
    allResources = r.resources.concat(allResources);
    renderResources();
  }).catch(function(e){
    showToast('Sync Failed: '+e.message,'inf');
  });
}

// Patch go() to load resources on learn tab
var _go=go;
go=function(id){
  _go(id);
  if(id==='learn'){if(!allResources.length)loadResources();}
};

checkHealth();loadDash();setInterval(checkHealth,30000);

