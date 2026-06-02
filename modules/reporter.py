"""
ADScan v2.0 — reporter.py
"""
import os, math
from datetime import datetime
from collections import Counter

_SEV = {
    "CRITICAL": ("critical","#da3633","🔴"),
    "HIGH":     ("high",    "#f0883e","🟠"),
    "MEDIUM":   ("medium",  "#e3b341","🟡"),
    "LOW":      ("low",     "#3fb950","🟢"),
    "INFO":     ("info",    "#58a6ff","🔵"),
}
_EP_COLOR = {
    "Any authenticated user":        "#f0883e",
    "Low-privileged domain user":    "#e3b341",
    "Local administrator":           "#f0883e",
    "Domain Admin":                  "#da3633",
    "Anonymous / unauthenticated":   "#da3633",
    "External attacker (no creds)":  "#da3633",
}
_GRADE = {
    "A": ("#3fb950","Excellent"),
    "B": ("#58a6ff","Good"),
    "C": ("#e3b341","Fair"),
    "D": ("#f0883e","Poor"),
    "F": ("#da3633","Critical Risk"),
}

CHECKS_TABLE = [
    (1,"AS-REP Roasting","Kerberos","LDAP → userAccountControl (0x400000)","Low-privileged domain user","HIGH"),
    (2,"Kerberoasting — SPN Accounts","Kerberos","LDAP → servicePrincipalName","Low-privileged domain user","HIGH"),
    (3,"Unconstrained Kerberos Delegation","Kerberos","LDAP → userAccountControl (0x080000)","Local administrator","CRITICAL"),
    (4,"Constrained Delegation Misconfiguration","Kerberos","LDAP → msDS-AllowedToDelegateTo","Local administrator","HIGH"),
    (5,"krbtgt Password Age — Golden Ticket Risk","Kerberos","LDAP → krbtgt → pwdLastSet","Domain Admin","CRITICAL"),
    (6,"Minimum Password Length < 14","Password Policy","LDAP → domainDNS → minPwdLength","External attacker (no creds)","HIGH"),
    (7,"Password Complexity Disabled","Password Policy","LDAP → domainDNS → pwdProperties (bit 1)","External attacker (no creds)","HIGH"),
    (8,"Insufficient Password History","Password Policy","LDAP → domainDNS → pwdHistoryLength","Any authenticated user","MEDIUM"),
    (9,"Account Lockout Not Configured","Password Policy","LDAP → domainDNS → lockoutThreshold = 0","External attacker (no creds)","HIGH"),
    (10,"Lockout Observation Window Too Short","Password Policy","LDAP → domainDNS → lockoutObservationWindow","External attacker (no creds)","MEDIUM"),
    (11,"Lockout Duration Too Short","Password Policy","LDAP → domainDNS → lockoutDuration","External attacker (no creds)","MEDIUM"),
    (12,"Maximum Password Age Unlimited","Password Policy","LDAP → domainDNS → maxPwdAge","Any authenticated user","MEDIUM"),
    (13,"Fine-Grained Password Policy Missing","Password Policy","LDAP → msDS-PasswordSettingsContainer","Domain Admin","LOW"),
    (14,"Excessive Domain Admins (>5)","Privileged Accounts","LDAP → Domain Admins → member count","Low-privileged domain user","HIGH"),
    (15,"Default Administrator Active & Not Renamed","Privileged Accounts","LDAP → user Administrator → enabled","External attacker (no creds)","MEDIUM"),
    (16,"Disabled Accounts in Privileged Groups","Privileged Accounts","LDAP → privileged groups + UAC cross-check","Domain Admin","MEDIUM"),
    (17,"Guest Account Enabled","Privileged Accounts","LDAP → user Guest → userAccountControl","Anonymous / unauthenticated","HIGH"),
    (18,"Schema Admins Group Non-Empty","Privileged Accounts","LDAP → Schema Admins → member count","Domain Admin","MEDIUM"),
    (19,"Enterprise Admins Group Non-Empty","Privileged Accounts","LDAP → Enterprise Admins → member count","Domain Admin","MEDIUM"),
    (20,"Admin Accounts Without Description","Privileged Accounts","LDAP → users with admin in name → description","Domain Admin","LOW"),
    (21,"Service Accounts in Privileged Groups","Service Accounts","LDAP → privileged groups + svc_ cross-check","Local administrator","HIGH"),
    (22,"Undocumented Service Accounts","Service Accounts","LDAP → svc_ accounts → description = empty","Low-privileged domain user","MEDIUM"),
    (23,"Service Accounts — Password Never Expires","Service Accounts","LDAP → svc_ accounts → UAC (0x10000)","Low-privileged domain user","MEDIUM"),
    (24,"Shared / Generic Service Accounts","Service Accounts","LDAP → accounts with shared/common/generic","Low-privileged domain user","MEDIUM"),
    (25,"Stale Accounts — Inactive 90+ Days","Account Hygiene","LDAP → user accounts → lastLogon (>90 days)","Low-privileged domain user","MEDIUM"),
    (26,"Password Never Expires — User Accounts","Account Hygiene","LDAP → user accounts → UAC (DONT_EXPIRE_PASSWORD)","Low-privileged domain user","MEDIUM"),
    (27,"Credentials in Account Description Field","Account Hygiene","LDAP → description (keyword: pass/pwd/secret)","Low-privileged domain user","HIGH"),
    (28,"High Failed Login Count (>=5)","Account Hygiene","LDAP → user accounts → badPwdCount >= 5","External attacker (no creds)","MEDIUM"),
    (29,"Accounts That Have Never Logged On","Account Hygiene","LDAP → user accounts → lastLogon = 0","Low-privileged domain user","LOW"),
    (30,"krbtgt Password Never Changed","Account Hygiene","LDAP → krbtgt → pwdLastSet = 0","Domain Admin","CRITICAL"),
    (31,"Passwords Older Than 180 Days","Account Hygiene","LDAP → user accounts → pwdLastSet (>180 days)","Low-privileged domain user","MEDIUM"),
    (32,"Weak Kerberos Encryption (RC4/DES)","Account Hygiene","LDAP → UAC (DONT_REQ_PREAUTH flag)","Low-privileged domain user","MEDIUM"),
    (33,"End-of-Life Operating Systems","System Security","LDAP → computer → operatingSystem (EOL match)","External attacker (no creds)","HIGH"),
    (34,"Unknown Patch Status","System Security","LDAP → computer → operatingSystemVersion (empty)","Local administrator","LOW"),
    (35,"WinRM Enabled on Domain Controller","System Security","nmap → port 5985/5986 on DC IP","Low-privileged domain user","MEDIUM"),
    (36,"SMBv1 Risk on Legacy Systems","System Security","nmap → port 445 + LDAP → EOL computers","External attacker (no creds)","HIGH"),
    (37,"Anonymous LDAP Bind Possible","System Security","LDAP → anonymous bind attempt","Anonymous / unauthenticated","HIGH"),
    (38,"Excessive Number of GPOs (>20)","Group Policy","LDAP → groupPolicyContainer count","Domain Admin","LOW"),
    (39,"Empty / Unused GPOs","Group Policy","LDAP → groupPolicyContainer → no linked OUs","Domain Admin","LOW"),
    (40,"Bidirectional Domain Trusts","Domain Config","LDAP → trustedDomain → trustDirection = 3","Domain Admin","MEDIUM"),
    (41,"Domain Functional Level Below 2016","Domain Config","LDAP → domainDNS → msDS-Behavior-Version","Domain Admin","MEDIUM"),
    (42,"AD Recycle Bin Not Enabled","Domain Config","LDAP → Optional Features → Recycle Bin","Domain Admin","LOW"),
    (43,"Protected Users Group Empty","Domain Config","LDAP → Protected Users group → member count = 0","Domain Admin","MEDIUM"),
    (44,"Anonymous LDAP Enumeration Possible","Domain Config","LDAP → anonymous query on base DN","Anonymous / unauthenticated","HIGH"),
    (45,"Shadow Admin Accounts Detected","Privileged Accounts","LDAP → adminCount=1 attribute cross-check","Low-privileged domain user","MEDIUM"),
    (46,"Reversible Encryption Enabled","Account Hygiene","LDAP → UAC (ADS_UF_ENCRYPTED_TEXT_PASSWORD)","Low-privileged domain user","HIGH"),
    (47,"DC Running End-of-Life OS","System Security","LDAP → DC computer objects → operatingSystem","External attacker (no creds)","CRITICAL"),
    (48,"DC Not Owned by Domain Admins","Domain Config","LDAP → DC objects → nTSecurityDescriptor","Domain Admin","HIGH"),
    (49,"High Password Spray Attack Risk","Password Policy","LDAP → lockoutThreshold=0 + minPwdLength<8","External attacker (no creds)","HIGH"),
    (50,"Nested Groups in Privileged Groups","Privileged Accounts","LDAP → privileged groups → group objects nested","Low-privileged domain user","MEDIUM"),
]

def build_report(meta, net, ad, findings, summary, out_dir):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"adscan_report_{ts}.html")
    with open(path,"w",encoding="utf-8") as f:
        f.write(_render(meta,net,ad,findings,summary))
    return path

def _badge(sev):
    cls,_,icon = _SEV.get(sev,("low","#3fb950","🟢"))
    return f'<span class="badge {cls}">{icon} {sev}</span>'

def _ep_badge(ep):
    if not ep: return ""
    color = _EP_COLOR.get(ep,"#8b949e")
    return f'<span class="ep-badge" style="border-color:{color};color:{color}">⚡ {ep}</span>'

def _stat(label,val,color="var(--accent)"):
    return (f'<div class="scard"><div class="snum" style="color:{color}">{val}</div>'
            f'<div class="slbl">{label}</div></div>')


def _charts(findings):
    """Pie chart (interactive) + Bar chart side by side"""
    if not findings:
        return '<p style="color:var(--t2)">No findings to chart.</p>'

    # ── Pie data ──────────────────────────────────────────────────────
    cats   = Counter(f.get("category","Other") for f in findings)
    total  = sum(cats.values())
    items  = sorted(cats.items(), key=lambda x: -x[1])
    colors = ["#da3633","#f0883e","#e3b341","#3fb950","#58a6ff","#8957e5","#db6d28","#1f6feb"]

    cx, cy, r_outer, r_inner = 130, 130, 110, 55
    angle   = -90.0
    slices  = ""
    legend  = ""

    for i,(cat,cnt) in enumerate(items):
        color  = colors[i % len(colors)]
        pct    = cnt / total
        pct_lbl= f"{pct*100:.0f}%"
        sweep  = pct * 360
        # Tam daire sorununu önle
        if sweep >= 359.9:
            sweep = 359.9
        x1 = cx + r_outer * math.cos(math.radians(angle))
        y1 = cy + r_outer * math.sin(math.radians(angle))
        mid_angle = angle + sweep/2
        angle += sweep
        x2 = cx + r_outer * math.cos(math.radians(angle))
        y2 = cy + r_outer * math.sin(math.radians(angle))
        large = 1 if sweep > 180 else 0

        # Label position (outside middle of slice)
        lx = cx + (r_outer + 18) * math.cos(math.radians(mid_angle))
        ly = cy + (r_outer + 18) * math.sin(math.radians(mid_angle))

        slices += f"""
<path class="pie-slice" d="M{cx},{cy} L{x1:.2f},{y1:.2f} A{r_outer},{r_outer} 0 {large},1 {x2:.2f},{y2:.2f} Z"
  fill="{color}" stroke="#0d1117" stroke-width="2"
  data-cat="{cat}" data-cnt="{cnt}" data-pct="{pct_lbl}"
  onmouseenter="pieHover(this,true,event)" onmouseleave="pieHover(this,false,event)">
</path>"""

        legend += f"""<div class="pie-leg">
  <span class="pie-dot" style="background:{color}"></span>
  <span class="pie-name">{cat}</span>
  <span class="pie-num">{cnt}</span>
  <span class="pie-pct" style="color:{color}">{pct_lbl}</span>
</div>"""

    # ── Bar chart data ─────────────────────────────────────────────────
    sev_data = [
        ("CRITICAL", summary_sev("CRITICAL", findings), "#da3633"),
        ("HIGH",     summary_sev("HIGH",     findings), "#f0883e"),
        ("MEDIUM",   summary_sev("MEDIUM",   findings), "#e3b341"),
        ("LOW",      summary_sev("LOW",      findings), "#3fb950"),
    ]
    max_val = max((v for _,v,_ in sev_data), default=1) or 1
    bars    = ""
    for sev, val, color in sev_data:
        pct = (val / max_val) * 100 if val else 0
        bars += f"""
<div class="bar-row">
  <div class="bar-label">{sev}</div>
  <div class="bar-track">
    <div class="bar-fill" style="width:{pct}%;background:{color}">
      <span class="bar-val">{val}</span>
    </div>
  </div>
</div>"""

    return f"""
<div class="charts-wrap">

  <!-- Pie Chart -->
  <div class="chart-box">
    <div class="chart-title">Findings by Category</div>
    <div class="pie-container">
      <svg id="pie-svg" viewBox="0 0 260 260" width="240" height="240" style="overflow:visible">
        {slices}
        <!-- Donut hole -->
        <circle cx="{cx}" cy="{cy}" r="{r_inner}" fill="var(--bg2)" pointer-events="none"/>
        <!-- Center text -->
        <text id="pie-center-num" x="{cx}" y="{cy-8}" text-anchor="middle"
              fill="var(--t)" font-size="22" font-weight="800">{total}</text>
        <text id="pie-center-lbl" x="{cx}" y="{cy+12}" text-anchor="middle"
              fill="var(--t2)" font-size="11">findings</text>

      </svg>
      <div class="pie-legend">{legend}</div>
    </div>
  </div>

  <!-- Bar Chart -->
  <div class="chart-box">
    <div class="chart-title">Findings by Severity</div>
    <div class="bar-chart">{bars}</div>
  </div>

</div>

<script>
function pieHover(el, enter, evt) {{
  const tt   = document.getElementById('pie-tt');
  const cNum = document.getElementById('pie-center-num');
  const cLbl = document.getElementById('pie-center-lbl');

  if (enter) {{
    const cat  = el.getAttribute('data-cat');
    const cnt  = el.getAttribute('data-cnt');
    const pct  = el.getAttribute('data-pct');
    const fill = el.getAttribute('fill');

    // Pop slice
    el.style.transform = 'scale(1.07)';
    el.style.transformOrigin = '130px 130px';
    el.style.filter = 'drop-shadow(0 0 10px ' + fill + 'aa)';

    // Center text
    cNum.textContent = pct;
    cNum.setAttribute('fill', fill);
    cLbl.textContent = cat;

    // HTML tooltip
    document.getElementById('pie-tt-cat').textContent = cat;
    document.getElementById('pie-tt-cat').style.color = fill;
    document.getElementById('pie-tt-cnt').textContent = 'Findings: ' + cnt;
    document.getElementById('pie-tt-pct').textContent = 'Share: ' + pct;
    tt.style.display = 'block';
  }} else {{
    el.style.transform = '';
    el.style.filter    = '';
    tt.style.display   = 'none';
    cNum.textContent   = '{total}';
    cNum.setAttribute('fill','var(--t)');
    cLbl.textContent   = 'findings';
  }}
}}

document.addEventListener('mousemove', function(e) {{
  const tt = document.getElementById('pie-tt');
  if (tt.style.display === 'block') {{
    tt.style.left = (e.clientX + 16) + 'px';
    tt.style.top  = (e.clientY - 10) + 'px';
  }}
}});
</script>"""


def summary_sev(sev, findings):
    return sum(1 for f in findings if f.get("severity") == sev)


def _executive_summary(meta, findings, summary):
    sc    = summary.get("SCORE",0)
    grade = summary.get("GRADE","F")
    gc,gl = _GRADE.get(grade,("#da3633","Critical Risk"))
    pct   = sc
    fill  = "#da3633" if sc<40 else "#e3b341" if sc<70 else "#3fb950"
    crit  = summary.get("CRITICAL",0)
    high  = summary.get("HIGH",0)
    med   = summary.get("MEDIUM",0)
    low   = summary.get("LOW",0)
    total = summary.get("TOTAL",0)
    chk   = summary.get("CHECKS",0)
    scope = meta.get("scope","Full scan — all 50 controls executed")
    chk_count = summary.get("CHECKS",0)
    if "Full scan" in scope:
        scope_short = f"Full Scan — {chk_count}/50 Controls"
    elif "Group scan" in scope:
        grp = scope.split(chr(34))[1] if chr(34) in scope else "group"
        scope_short = f"Group Scan: {grp} — {chk_count} Controls"
    else:
        scope_short = f"Custom Scan — {chk_count} Controls"

    order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    top3  = ""
    for f in srt[:3]:
        cls,_,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        top3 += f"""<div class="es-finding">
          <span class="badge {cls}" style="flex-shrink:0">{icon} {f['severity']}</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">{f['title']}</div>
            <div style="color:var(--t2);font-size:.82rem;margin-top:.1rem">{f['desc'].split(chr(10))[0]}</div>
          </div></div>"""

    if crit>0:
        eval_txt=(f"Assessment of <strong style='color:#58a6ff'>{meta.get('domain','')}</strong> "
                  f"identified <strong style='color:#da3633'>{crit} critical</strong> and "
                  f"<strong style='color:#f0883e'>{high} high</strong> severity findings. "
                  f"Immediate remediation is strongly recommended.")
    elif high>0:
        eval_txt=(f"Assessment of <strong style='color:#58a6ff'>{meta.get('domain','')}</strong> "
                  f"identified <strong style='color:#f0883e'>{high} high</strong> severity findings.")
    else:
        eval_txt=(f"Assessment completed with {total} findings across {chk} checks.")

    return f"""
<section id="executive-summary">
  <h2>📋 Executive Summary</h2>
  <div class="es-box">
    <div class="es-score-col">
      <div class="scope-badge">🔍 {scope_short}</div>
      <div class="es-circle" style="border-color:{gc}">
        <div class="es-num" style="color:{gc}">{sc}</div>
        <div class="es-den">/100</div>
      </div>
      <div class="es-grade" style="color:{gc}">Grade: {grade}</div>
      <div class="es-glbl" style="color:{gc}">{gl}</div>
      <div class="es-slider">
        <div class="es-sl-labels">
          <span style="color:#da3633">F</span><span style="color:#f0883e">D</span>
          <span style="color:#e3b341">C</span><span style="color:#58a6ff">B</span>
          <span style="color:#3fb950">A</span>
        </div>
        <div class="es-sl-track">
          <div class="es-sl-fill" style="width:{pct}%"></div>
          <div class="es-sl-thumb" style="left:calc({pct}% - 10px);background:{fill}"></div>
        </div>
        <div class="es-sl-mm"><span>0</span><span style="color:{gc};font-weight:700">{sc}</span><span>100</span></div>
      </div>
      <div class="es-counts">
        <div class="es-cnt" style="border-color:#da3633"><span style="color:#da3633;font-size:1.4rem;font-weight:800">{crit}</span><span>Critical</span></div>
        <div class="es-cnt" style="border-color:#f0883e"><span style="color:#f0883e;font-size:1.4rem;font-weight:800">{high}</span><span>High</span></div>
        <div class="es-cnt" style="border-color:#e3b341"><span style="color:#e3b341;font-size:1.4rem;font-weight:800">{med}</span><span>Medium</span></div>
        <div class="es-cnt" style="border-color:#3fb950"><span style="color:#3fb950;font-size:1.4rem;font-weight:800">{low}</span><span>Low</span></div>
      </div>
    </div>
    <div class="es-info-col">
      <div class="es-meta-grid">
        <div><div class="es-lbl">Target Domain</div><div class="es-val">{meta.get('domain','')}</div></div>
        <div><div class="es-lbl">Domain Controller</div><div class="es-val">{meta.get('dc','')}</div></div>
        <div><div class="es-lbl">Scan Date</div><div class="es-val">{meta.get('tarih','')}</div></div>
        <div><div class="es-lbl">Scan Duration</div><div class="es-val">{meta.get('sure','')}</div></div>
        <div><div class="es-lbl">Total Findings</div><div class="es-val">{total}</div></div>
        <div><div class="es-lbl">Checks Run</div><div class="es-val">{chk} / 50</div></div>
        <div><div class="es-lbl">Analyst</div><div class="es-val">{meta.get('user','')}</div></div>
        <div><div class="es-lbl">Tool</div><div class="es-val">ADScan v2.0</div></div>
        <div style="grid-column:1/-1">
          <div class="es-lbl">Scan Scope</div>
          <div class="es-val" style="color:#58a6ff;font-weight:600">{scope}</div>
        </div>
      </div>
      <div style="margin-top:1rem">
        <div class="es-lbl">OVERALL ASSESSMENT</div>
        <p style="color:var(--t2);font-size:.88rem;line-height:1.6;margin-top:.35rem">{eval_txt}</p>
      </div>
      <div style="margin-top:1rem">
        <div class="es-lbl" style="margin-bottom:.5rem">TOP PRIORITY FINDINGS</div>
        {top3 or '<p style="color:var(--t2);font-size:.85rem">No critical findings.</p>'}
      </div>
    </div>
  </div>
</section>"""


def _findings_html(findings):
    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    out   = ""
    for f in srt:
        cls,color,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        aff  = "".join(f"<li>{a}</li>" for a in f["affected"][:25])
        if len(f["affected"])>25: aff+=f"<li><em>...and {len(f['affected'])-25} more</em></li>"
        ep   = _ep_badge(f.get("exploitable_by",""))
        fi   = f.get("found_in","")
        out += f"""
<div class="finding {cls}" id="{f['id']}">
  <div class="fh" onclick="tog(this)">
    <div class="fhl"><code class="fid">{f['id']}</code><span class="ftitle">{f['title']}</span></div>
    <div class="fhr">{_badge(f['severity'])}<span class="fcat">{f.get('category','')}</span><span class="chev">▼</span></div>
  </div>
  <div class="fb">
    <div class="fsec"><div class="flab">📋 Description</div><p>{f['desc'].replace(chr(10),'<br>')}</p></div>
    <div class="fsec"><div class="flab">⚡ Exploitable By</div><div style="margin-top:.35rem">{ep or '<span style="color:var(--t2)">N/A</span>'}</div></div>
    <div class="fsec"><div class="flab">📍 Found In</div><p style="font-family:monospace;font-size:.85rem;color:#79c0ff">{fi or '—'}</p></div>
    <div class="fsec"><div class="flab">🎯 Affected ({len(f['affected'])})</div><ul class="aff">{aff}</ul></div>
    <div class="fsec fix"><div class="flab">🛠 Remediation</div><p>{f['fix'].replace(chr(10),'<br>')}</p></div>
  </div>
</div>"""
    return out or '<p class="empty">No findings detected.</p>'


def _remediation_summary(findings):
    order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    rows  = ""
    for i,f in enumerate(srt,1):
        cls,_,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        rows += f"""<div class="rem-item">
  <div class="rem-header">
    <span class="rem-num">#{i}</span>
    <span class="rem-title">{f['title']}</span>
    <span class="badge {cls}" style="flex-shrink:0">{icon} {f['severity']}</span>
  </div>
  <div class="rem-fix">{f['fix'].replace(chr(10),'<br>')}</div>
</div>"""
    return rows or '<p class="empty">No remediation items.</p>'


def _findings_overview(findings):
    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    rows  = ""
    for f in srt:
        cls,_,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        rows += f"""<tr>
  <td><code>{f['id']}</code></td>
  <td>{f['title']}</td>
  <td><span class="badge {cls}">{icon} {f['severity']}</span></td>
  <td><span class="fcat">{f.get('category','')}</span></td>
  <td style="text-align:center">{len(f.get('affected',[]))}</td>
  <td><a href="#{f['id']}" onclick="scrollToFinding('{f['id']}')" style="color:var(--accent);font-size:.82rem">View →</a></td>
</tr>"""
    return rows or "<tr><td colspan=6 style='color:var(--t2)'>No findings.</td></tr>"


def _checks_table_html(findings):
    found_ids = {f.get("check_id") for f in findings}
    rows = ""
    for cid,title,cat,found_in,ep,sev in CHECKS_TABLE:
        cls,_,icon = _SEV.get(sev,("low","#3fb950","🟢"))
        ep_color   = _EP_COLOR.get(ep,"#8b949e")
        if cid in found_ids:
            status  = '<span class="tag crit">⚠ FOUND</span>'
            row_cls = ' class="check-found"'
        else:
            status  = '<span class="tag ok">✓ PASS</span>'
            row_cls = ""
        rows += f"""<tr{row_cls}>
  <td><code>AD-{cid:03d}</code></td><td>{title}</td>
  <td><span class="fcat">{cat}</span></td>
  <td><span class="badge {cls}">{icon} {sev}</span></td>
  <td style="font-size:.78rem;color:{ep_color}">⚡ {ep}</td>
  <td style="font-family:monospace;font-size:.75rem;color:var(--t2)">{found_in}</td>
  <td>{status}</td>
</tr>"""
    return rows


def _tbl_users(users):
    rows=""
    for u in users[:60]:
        tg=""
        if u.get("pwd_never"):  tg+='<span class="tag warn">Pwd∞</span>'
        if u.get("no_preauth"): tg+='<span class="tag crit">AS-REP</span>'
        if u.get("delegation"): tg+='<span class="tag crit">Delegation</span>'
        st='<span class="tag ok">Active</span>' if u.get("enabled") else '<span class="tag off">Disabled</span>'
        rows+=(f"<tr><td><code>{u['username']}</code></td><td>{st}</td>"
               f"<td>{u.get('department','')}</td><td>{u.get('title','')}</td><td>{tg}</td></tr>")
    return rows or "<tr><td colspan=5>—</td></tr>"

def _tbl_comp(comps):
    rows=""
    for c in comps:
        eol='<span class="tag crit">EOL</span>' if c.get("eol") else ""
        rows+=(f"<tr><td><code>{c['name']}</code></td><td>{c['os']} {eol}</td><td>{c.get('dns','')}</td></tr>")
    return rows or "<tr><td colspan=3>—</td></tr>"

def _tbl_spn(spns):
    rows=""
    for s in spns:
        st='<span class="tag ok">Active</span>' if s.get("enabled") else '<span class="tag off">Disabled</span>'
        lst="<br>".join(f"<code>{x}</code>" for x in s.get("spns",[]))
        rows+=(f"<tr><td><code>{s['username']}</code></td><td>{st}</td><td>{lst}</td></tr>")
    return rows or "<tr><td colspan=3>—</td></tr>"

def _tbl_asrep(users):
    rows=""
    for u in users:
        rows+=(f"<tr><td><code>{u['username']}</code></td>"
               f"<td>{u.get('dept','')}</td>"
               f"<td>{', '.join(u.get('member_of',[])[:3])}</td></tr>")
    return rows or "<tr><td colspan=3>Not detected</td></tr>"

def _tbl_group(groups):
    priv={"Domain Admins","Enterprise Admins","Schema Admins","Administrators",
          "Backup Operators","Account Operators","Protected Users","Group Policy Creator Owners"}
    rows=""
    for g in groups:
        hl=' class="priv"' if g["name"] in priv else ""
        rows+=(f"<tr{hl}><td><code>{g['name']}</code></td>"
               f"<td>{g['count']}</td><td>{g.get('description','')[:80]}</td></tr>")
    return rows or "<tr><td colspan=3>—</td></tr>"

def _pol_rows(pol):
    checks=[
        ("min_len",    "Min. Password Length", lambda v: int(v or 0)<14),
        ("history",    "Password History",      lambda v: int(v or 0)<24),
        ("complexity", "Complexity",            lambda v: "disabled" in str(v).lower() or "disi" in str(v).lower()),
        ("lockout_thr","Lockout Threshold",     lambda v: str(v).strip() in("0","?","")),
        ("max_age",    "Max. Password Age",     lambda v: "unlimited" in str(v).lower()),
    ]
    rows=""
    for key,label,is_bad in checks:
        val=pol.get(key,"?")
        try:    bad=is_bad(val)
        except: bad=False
        cls=' class="bad"' if bad else ""
        rows+=f"<tr><td><b>{label}</b></td><td{cls}>{val}{' ⚠' if bad else ''}</td></tr>"
    return rows


def _render(meta,net,ad,findings,summary):
    sc      = summary.get("SCORE",0)
    grade   = summary.get("GRADE","F")
    gc,gl   = _GRADE.get(grade,("#da3633","Critical Risk"))
    u_cnt   = len(ad.get("users",[]))
    g_cnt   = len(ad.get("groups",[]))
    c_cnt   = len(ad.get("computers",[]))
    spn_cnt = len(ad.get("spns",[]))
    ar_cnt  = len(ad.get("asrep_users",[]))
    gpo_cnt = len(ad.get("gpos",[]))
    ports   = net.get("ports",[])
    svc     = net.get("services",{})
    ph      = "".join(f'<span class="pt">{p} <small>{svc.get(p,"")}</small></span>' for p in sorted(ports)) or "—"

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ADScan Report — {meta.get('domain','')}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#30363d;--t:#e6edf3;--t2:#8b949e;--brd:#30363d;--accent:#58a6ff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--t);line-height:1.6;font-size:15px}}
code{{font-family:monospace;font-size:.85em;color:#79c0ff}}
h2{{font-size:1.05rem;font-weight:600;border-left:3px solid var(--accent);padding-left:.7rem;margin-bottom:1rem}}
section{{margin-bottom:2.5rem}}
header{{background:#161b22;border-bottom:2px solid #da3633;padding:1.5rem 2.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}}
.hl h1{{font-size:1.6rem;color:#f85149;font-weight:800}}
.hl h1 span{{color:var(--t2);font-size:1rem;font-weight:400;margin-left:.5rem}}
.hl p{{color:var(--t2);font-size:.82rem;margin-top:.2rem}}
.hr .domain{{font-size:1rem;font-weight:600;color:var(--accent)}}
.hr .dt{{font-size:.8rem;color:var(--t2);margin-top:.2rem}}
.wrap{{max-width:1400px;margin:0 auto;padding:2rem 2.5rem}}

/* ES */
.es-box{{background:var(--bg2);border:1px solid var(--brd);border-radius:12px;padding:1.5rem;display:flex;gap:2rem;flex-wrap:wrap}}
.es-score-col{{display:flex;flex-direction:column;align-items:center;gap:.9rem;min-width:200px}}
.es-circle{{width:100px;height:100px;border-radius:50%;border:4px solid;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 auto}}
.es-num{{font-size:1.8rem;font-weight:800;line-height:1}}
.es-den{{font-size:.8rem;color:var(--t2)}}
.es-grade{{font-size:1.5rem;font-weight:800}}
.es-glbl{{font-size:.8rem;font-weight:600}}
.scope-badge{{background:rgba(88,166,255,.12);border:1px solid #58a6ff;color:#58a6ff;border-radius:6px;padding:.3rem .7rem;font-size:.78rem;font-weight:700;text-align:center;white-space:nowrap}}
.es-slider{{width:190px}}
.es-sl-labels{{display:flex;justify-content:space-between;font-size:.75rem;font-weight:700;margin-bottom:.3rem}}
.es-sl-track{{position:relative;height:8px;background:var(--bg4);border-radius:4px}}
.es-sl-fill{{height:100%;border-radius:4px;background:linear-gradient(90deg,#da3633 0%,#e3b341 50%,#3fb950 100%)}}
.es-sl-thumb{{position:absolute;top:-6px;width:20px;height:20px;border-radius:50%;box-shadow:0 0 6px rgba(0,0,0,.6)}}
.es-sl-mm{{display:flex;justify-content:space-between;font-size:.72rem;color:var(--t2);margin-top:.35rem}}
.es-counts{{display:grid;grid-template-columns:1fr 1fr;gap:.45rem;width:100%}}
.es-cnt{{background:var(--bg3);border:1px solid;border-radius:8px;padding:.45rem;text-align:center;display:flex;flex-direction:column;align-items:center;gap:.1rem}}
.es-cnt span:last-child{{font-size:.72rem;color:var(--t2)}}
.es-info-col{{flex:1;min-width:280px}}
.es-meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:.35rem .75rem}}
.es-lbl{{font-size:.72rem;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;font-weight:600}}
.es-val{{font-size:.88rem;color:var(--t);font-weight:500;margin-top:.1rem}}
.es-finding{{display:flex;align-items:flex-start;gap:.75rem;padding:.55rem 0;border-bottom:1px solid var(--brd)}}
.es-finding:last-child{{border-bottom:none}}

/* Charts */
.charts-wrap{{display:flex;gap:1.5rem;flex-wrap:wrap}}
.chart-box{{background:var(--bg2);border:1px solid var(--brd);border-radius:12px;padding:1.5rem;flex:1;min-width:280px}}
.chart-title{{font-size:.9rem;font-weight:600;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;margin-bottom:1rem}}
.pie-container{{display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap}}
.pie-slice{{cursor:pointer;transition:transform .15s,filter .15s}}
.pie-legend{{display:flex;flex-direction:column;gap:.5rem}}
.pie-leg{{display:flex;align-items:center;gap:.6rem;font-size:.88rem}}
.pie-dot{{width:11px;height:11px;border-radius:50%;flex-shrink:0}}
.pie-name{{flex:1;color:var(--t)}}
.pie-num{{font-weight:700;color:var(--t);min-width:20px;text-align:right}}
.pie-pct{{font-size:.78rem;min-width:36px;text-align:right}}

/* Bar chart */
.bar-chart{{display:flex;flex-direction:column;gap:.85rem;padding-top:.25rem}}
.bar-row{{display:flex;align-items:center;gap:.75rem}}
.bar-label{{font-size:.78rem;font-weight:700;width:70px;text-align:right;color:var(--t2)}}
.bar-track{{flex:1;background:var(--bg4);border-radius:4px;height:28px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;display:flex;align-items:center;
           justify-content:flex-end;padding-right:.5rem;
           transition:width .6s ease;min-width:28px}}
.bar-val{{font-size:.82rem;font-weight:700;color:#fff}}

/* Stats */
.scards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:.7rem}}
.scard{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;padding:.9rem;text-align:center}}
.snum{{font-size:2rem;font-weight:800;line-height:1}}
.slbl{{color:var(--t2);font-size:.73rem;margin-top:.3rem}}
.dcbox{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;padding:1.25rem;display:flex;flex-wrap:wrap;gap:1.5rem}}
.dcip{{font-size:1.2rem;font-weight:700;color:var(--accent)}}
.dclbl{{color:var(--t2);font-size:.8rem;margin-bottom:.3rem}}
.pt{{display:inline-block;background:var(--bg3);border:1px solid var(--brd);border-radius:5px;padding:.15rem .5rem;margin:.2rem;font-size:.78rem}}
.polcard{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;overflow:hidden}}
.polcard table{{width:100%}}
.polcard td{{padding:.55rem 1rem;border-top:1px solid var(--brd);font-size:.9rem}}
.polcard tr:first-child td{{border-top:none}}
.bad{{color:#f85149;font-weight:600}}

/* Findings */
.finding{{border-radius:10px;margin-bottom:.65rem;border:1px solid var(--brd);overflow:hidden}}
.finding.critical{{border-left:4px solid #da3633}}
.finding.high{{border-left:4px solid #f0883e}}
.finding.medium{{border-left:4px solid #e3b341}}
.finding.low{{border-left:4px solid #3fb950}}
.fh{{display:flex;justify-content:space-between;align-items:center;padding:.8rem 1.2rem;cursor:pointer;background:var(--bg2)}}
.fh:hover{{background:var(--bg3)}}
.fhl{{display:flex;align-items:center;gap:.6rem;flex:1;min-width:0}}
.fhr{{display:flex;align-items:center;gap:.5rem;flex-shrink:0}}
.fid{{color:var(--t2);font-size:.78rem;flex-shrink:0}}
.ftitle{{font-weight:600;font-size:.95rem}}
.fcat{{font-size:.72rem;color:var(--t2);background:var(--bg4);padding:.1rem .4rem;border-radius:4px;white-space:nowrap}}
.chev{{color:var(--t2);transition:transform .2s}}
.finding.open .chev{{transform:rotate(180deg)}}
.fb{{display:none;padding:1rem 1.2rem 1.2rem;background:var(--bg2);border-top:1px solid var(--brd)}}
.finding.open .fb{{display:block}}
.fsec{{margin-top:.9rem}}
.flab{{font-size:.8rem;color:var(--t2);font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.35rem}}
.fsec p{{color:var(--t2);font-size:.9rem}}
.aff{{margin:.35rem 0 0 1.2rem;color:var(--t2);font-size:.85rem;font-family:monospace}}
.fix{{background:rgba(63,185,80,.07);border:1px solid rgba(63,185,80,.2);border-radius:6px;padding:.85rem}}
.fix p{{color:#7ee787!important}}
.ep-badge{{display:inline-flex;align-items:center;gap:.25rem;padding:.2rem .7rem;border-radius:5px;border:1px solid;font-size:.78rem;font-weight:600;vertical-align:middle;line-height:1.4}}
.badge{{display:inline-flex;align-items:center;gap:.2rem;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:700;vertical-align:middle;white-space:nowrap}}
.badge.critical{{background:#3d1212;color:#ff7b72;font-size:.75rem}}
.badge.high{{background:#3d2200;color:#ffa657;border-left:3px solid #f0883e}}
.badge.medium{{background:#3d3000;color:#e3b341}}
.badge.low{{background:#0d4429;color:#7ee787;border-left:3px solid #3fb950}}
.badge.info{{background:#1e3a5f;color:#93c5fd}}
.tag{{display:inline-flex;align-items:center;gap:.2rem;padding:.12rem .5rem;border-radius:4px;font-size:.74rem;font-weight:600;margin:.1rem;vertical-align:middle;line-height:1.4}}
.tag.ok{{background:#0d4429;color:#3fb950}}
.tag.off{{background:#1c2128;color:#6e7681}}
.tag.warn{{background:#3d2b00;color:#e3b341}}
.tag.crit{{background:#3d1212;color:#f85149}}

/* Remediation */
.rem-item{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;margin-bottom:.75rem;overflow:hidden}}
.rem-header{{display:flex;align-items:center;gap:.75rem;padding:.85rem 1.2rem;background:var(--bg3)}}
.rem-num{{color:var(--t2);font-size:.82rem;font-weight:700;flex-shrink:0}}
.rem-title{{flex:1;font-weight:600;font-size:.95rem}}
.rem-fix{{padding:.85rem 1.2rem;color:#7ee787;font-size:.88rem;background:rgba(63,185,80,.06);border-top:1px solid var(--brd)}}

/* Tabs */
.tabs{{display:flex;border-bottom:1px solid var(--brd);margin-bottom:1rem;overflow-x:auto}}
.tab{{padding:.5rem 1rem;cursor:pointer;font-size:.88rem;color:var(--t2);border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap}}
.tab.on{{color:var(--accent);border-bottom-color:var(--accent)}}
.tab-p{{display:none}}
.tab-p.on{{display:block}}
.tw{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:.88rem}}
th{{background:var(--bg3);padding:.6rem .75rem;text-align:left;font-size:.76rem;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;vertical-align:middle}}
td{{padding:.5rem .75rem;border-top:1px solid var(--brd);vertical-align:middle}}
tr:hover td{{background:rgba(255,255,255,.015)}}
tr.priv td{{background:rgba(218,54,51,.06)}}
tr.check-found td{{background:rgba(218,54,51,.04)}}
.empty{{color:var(--t2);font-style:italic;padding:.5rem}}
.checks-filter{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
.cf-btn{{background:var(--bg3);border:1px solid var(--brd);color:var(--t2);padding:.3rem .75rem;border-radius:5px;cursor:pointer;font-size:.8rem}}
.cf-btn.on{{background:var(--accent);color:#000;border-color:var(--accent)}}
.pdf-btn{{text-align:center;margin:1.5rem 0}}
.pdf-btn button{{background:#1f6feb;color:#fff;border:none;padding:.7rem 2rem;border-radius:8px;font-size:.95rem;cursor:pointer;font-family:inherit}}
footer{{text-align:center;padding:1.5rem;color:var(--t2);font-size:.8rem;border-top:1px solid var(--brd)}}

/* PRINT WHITE THEME */
@media print{{
  :root{{--bg:#fff;--bg2:#f8f9fa;--bg3:#e9ecef;--bg4:#dee2e6;--t:#212529;--t2:#6c757d;--brd:#dee2e6;--accent:#0d6efd}}
  body{{background:#fff;color:#212529;font-size:13px}}
  header{{background:#fff;border-bottom:2px solid #dc3545}}
  .hl h1{{color:#dc3545}}
  .pdf-btn,.tabs,.checks-filter{{display:none!important}}
  .fb,.tab-p{{display:block!important}}
  .finding{{break-inside:avoid}}
  .fh{{background:#f8f9fa}}
  .badge.critical{{background:#f8d7da;color:#842029}}
  .badge.high{{background:#fff3cd;color:#664d03}}
  .badge.medium{{background:#fff3cd;color:#664d03}}
  .badge.low{{background:#d1e7dd;color:#0a3622}}
  .tag.ok{{background:#d1e7dd;color:#0a3622}}
  .tag.crit{{background:#f8d7da;color:#842029}}
  .tag.warn{{background:#fff3cd;color:#664d03}}
  .fix{{background:#d1e7dd;border-color:#a3cfbb}}
  .fix p{{color:#0a3622!important}}
  .rem-fix{{color:#0a3622;background:#d1e7dd}}
  .bar-val{{color:#212529}}
  code{{color:#0d6efd}}
  tr.check-found td{{background:#f8d7da}}
  tr.priv td{{background:#f8d7da}}
  .bad{{color:#dc3545}}
  h2{{color:#212529;border-left-color:#0d6efd}}
  section{{page-break-inside:avoid}}
}}
</style></head><body>

<header>
  <div class="hl">
    <h1>ADScan <span>Active Directory Security Analyzer</span></h1>
    <p>Active Directory Security Assessment Report</p>
  </div>
  <div class="hr">
    <div class="domain">{meta.get('domain','')}</div>
    <div class="dt">{meta.get('tarih','')}</div>
  </div>
</header>

<div class="wrap">

{_executive_summary(meta, findings, summary)}

<section>
  <h2>📊 Inventory Overview</h2>
  <div class="scards">
    <div class="scard"><div class="snum" style="color:{gc}">{sc}<span style="font-size:.9rem">/100</span></div><div class="slbl">Score · <strong style="color:{gc}">{grade}</strong></div></div>
    {_stat("Critical",    summary.get("CRITICAL",0),"#da3633")}
    {_stat("High",        summary.get("HIGH",0),    "#f0883e")}
    {_stat("Medium",      summary.get("MEDIUM",0),  "#e3b341")}
    {_stat("Low",         summary.get("LOW",0),     "#3fb950")}
    {_stat("Users",       u_cnt)}
    {_stat("Groups",      g_cnt)}
    {_stat("Computers",   c_cnt)}
    {_stat("GPOs",        gpo_cnt)}
    {_stat("SPN Accounts",spn_cnt,"#f0883e" if spn_cnt else "var(--accent)")}
    {_stat("AS-REP Vuln", ar_cnt, "#da3633" if ar_cnt  else "var(--accent)")}
  </div>
</section>

<section>
  <h2>📊 Risk Distribution</h2>
  {_charts(findings)}
</section>

<section>
  <h2>🖥 Domain Controller</h2>
  <div class="dcbox">
    <div><div class="dclbl">IP Address</div><div class="dcip">{meta.get('dc','')}</div></div>
    <div><div class="dclbl">Domain</div><div style="font-weight:600">{meta.get('domain','')}</div></div>
    <div><div class="dclbl">Open Ports</div><div>{ph}</div></div>
  </div>
</section>

<section>
  <h2>🔐 Password Policy</h2>
  <div class="polcard"><table><tbody>{_pol_rows(ad.get('password_policy',{}))}</tbody></table></div>
</section>

<section>
  <h2>⚠ Security Findings ({summary.get('TOTAL',0)})</h2>
  {_findings_html(findings)}
</section>

<section>
  <h2>📋 Findings Overview</h2>
  <div class="tw" style="background:var(--bg2);border:1px solid var(--brd);border-radius:10px;overflow:hidden">
    <table>
      <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Category</th><th>Affected</th><th>Detail</th></tr></thead>
      <tbody>{_findings_overview(findings)}</tbody>
    </table>
  </div>
</section>

<section>
  <h2>🛠 Remediation Summary</h2>
  <p style="color:var(--t2);font-size:.85rem;margin-bottom:1rem">All remediation steps in priority order. Address Critical and High findings first.</p>
  {_remediation_summary(findings)}
</section>

<section>
  <h2>📁 Inventory</h2>
  <div style="background:var(--bg2);border:1px solid var(--brd);border-radius:10px;padding:1.25rem">
    <div class="tabs">
      <div class="tab on" onclick="tab(this,'tu')">Users ({u_cnt})</div>
      <div class="tab"    onclick="tab(this,'tc')">Computers ({c_cnt})</div>
      <div class="tab"    onclick="tab(this,'ts')">SPN / Kerberoasting ({spn_cnt})</div>
      <div class="tab"    onclick="tab(this,'ta')">AS-REP Vulnerable ({ar_cnt})</div>
      <div class="tab"    onclick="tab(this,'tg')">Groups ({g_cnt})</div>
    </div>
    <div id="tu" class="tab-p on"><div class="tw"><table>
      <thead><tr><th>Username</th><th>Status</th><th>Department</th><th>Title</th><th>Risk Flags</th></tr></thead>
      <tbody>{_tbl_users(ad.get('users',[]))}</tbody></table></div></div>
    <div id="tc" class="tab-p"><div class="tw"><table>
      <thead><tr><th>Computer</th><th>Operating System</th><th>DNS</th></tr></thead>
      <tbody>{_tbl_comp(ad.get('computers',[]))}</tbody></table></div></div>
    <div id="ts" class="tab-p"><div class="tw">
      <p style="color:var(--t2);font-size:.85rem;margin-bottom:.75rem">TGS tickets can be requested and cracked offline.</p>
      <table><thead><tr><th>Account</th><th>Status</th><th>SPN Records</th></tr></thead>
      <tbody>{_tbl_spn(ad.get('spns',[]))}</tbody></table></div></div>
    <div id="ta" class="tab-p"><div class="tw">
      <p style="color:var(--t2);font-size:.85rem;margin-bottom:.75rem">AS-REP hash can be captured and cracked offline without credentials.</p>
      <table><thead><tr><th>Account</th><th>Department</th><th>Group Memberships</th></tr></thead>
      <tbody>{_tbl_asrep(ad.get('asrep_users',[]))}</tbody></table></div></div>
    <div id="tg" class="tab-p"><div class="tw">
      <p style="color:var(--t2);font-size:.85rem;margin-bottom:.75rem">Red rows: privileged groups.</p>
      <table><thead><tr><th>Group</th><th>Members</th><th>Description</th></tr></thead>
      <tbody>{_tbl_group(ad.get('groups',[]))}</tbody></table></div></div>
  </div>
</section>

<section>
  <h2>🔍 Security Checks Reference — All 50 Controls</h2>
  <p style="color:var(--t2);font-size:.85rem;margin-bottom:1rem">
    <span style="color:#da3633;font-weight:600">Red rows</span> = findings detected in this scan.
  </p>
  <div class="checks-filter">
    <button class="cf-btn on" onclick="filterChecks(this,'all')">All (50)</button>
    <button class="cf-btn" onclick="filterChecks(this,'kerberos')">Kerberos</button>
    <button class="cf-btn" onclick="filterChecks(this,'password')">Password Policy</button>
    <button class="cf-btn" onclick="filterChecks(this,'privileged')">Privileged Accounts</button>
    <button class="cf-btn" onclick="filterChecks(this,'service')">Service Accounts</button>
    <button class="cf-btn" onclick="filterChecks(this,'hygiene')">Account Hygiene</button>
    <button class="cf-btn" onclick="filterChecks(this,'system')">System Security</button>
    <button class="cf-btn" onclick="filterChecks(this,'domain')">Domain Config</button>
  </div>
  <div class="tw" style="background:var(--bg2);border:1px solid var(--brd);border-radius:10px;overflow:hidden">
    <table id="checks-tbl">
      <thead><tr><th>ID</th><th>Control</th><th>Category</th><th>Severity</th><th>Exploitable By</th><th>Detection Source</th><th>Status</th></tr></thead>
      <tbody>{_checks_table_html(findings)}</tbody>
    </table>
  </div>
</section>

</div>

<div class="pdf-btn">
  <button onclick="window.print()">🖨 Save as PDF / Print</button>
</div>

<!-- Pie Tooltip -->
<div id="pie-tt" style="
  position:fixed;display:none;z-index:9999;
  background:#21262d;border:1px solid #58a6ff;border-radius:8px;
  padding:.6rem .9rem;pointer-events:none;
  box-shadow:0 4px 20px rgba(0,0,0,.6);min-width:140px">
  <div id="pie-tt-cat" style="font-weight:700;font-size:.9rem;margin-bottom:.25rem"></div>
  <div id="pie-tt-cnt" style="color:#8b949e;font-size:.82rem"></div>
  <div id="pie-tt-pct" style="color:#8b949e;font-size:.82rem"></div>
</div>

<footer>ADScan v2.0 — Active Directory Security Analyzer &nbsp;|&nbsp; Kali Linux &nbsp;|&nbsp; {meta.get('tarih','')}</footer>

<script>
function tog(h){{h.closest('.finding').classList.toggle('open')}}
function tab(el,id){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  document.querySelectorAll('.tab-p').forEach(p=>p.classList.remove('on'));
  el.classList.add('on');document.getElementById(id).classList.add('on');
}}
function filterChecks(btn,cat){{
  document.querySelectorAll('.cf-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('#checks-tbl tbody tr').forEach(r=>{{
    if(cat==='all'){{r.style.display='';return;}}
    const c=r.cells[2]?.textContent?.toLowerCase()||'';
    r.style.display=c.includes(cat)?'':'none';
  }});
}}
function scrollToFinding(id){{
  const el=document.getElementById(id);
  if(el){{el.classList.add('open');el.scrollIntoView({{behavior:'smooth',block:'start'}});}}
}}
document.querySelectorAll('.finding').forEach((f,i)=>{{if(i<2)f.classList.add('open')}});
</script>
</body></html>"""
