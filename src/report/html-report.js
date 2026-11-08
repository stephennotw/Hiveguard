'use strict';

/**
 * Generate a self-contained interactive HTML report from scan results.
 */
function generateReport(result) {
  const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const isSafeUrl = (u) => /^https?:\/\//i.test(String(u || ''));
  // JSON embedded in <script> must not contain "</script>" or raw U+2028/2029
  const scriptJson = (v) => JSON.stringify(v).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  const meta = result.meta;
  const ti = result.threat_intel;
  const summary = result.summary;
  const findings = result.findings || [];
  const packages = result.packages || [];
  const threatMatches = result.threat_matches || [];
  const catalogs = result.catalogs || [];
  const ecosystems = result.ecosystems || {};
  const aiSignalCount = (ecosystems.mcp_configs?.total_servers || 0) + (ecosystems.ai_models?.total || 0)
    + (ecosystems.ai_usage?.providers?.length || 0) + (ecosystems.ai_usage?.sdks?.length || 0);
  const hygieneFlagged = (ecosystems.lifecycle_scripts?.total_findings || 0) + (ecosystems.git_hooks?.suspicious || 0) + (ecosystems.ai_instructions?.suspicious || 0) + (ecosystems.persistence?.findings || []).length;

  // Build searchable package array for client-side
  const searchPkgs = packages.map((p, i) => ({
    id: i, eco: p.ecosystem, name: p.name, ver: p.version,
    proj: p.project || '', src: p.source || '', conf: p.confidence || 'high',
    dn: p.displayName || '', res: p.resolved || '', user: p.user || '',
    threat: threatMatches.some(m => m.name === p.name && m.version === p.version && m.ecosystem === p.ecosystem),
  }));

  // Source tier + freshness
  const tiSource = ti.source || 'none';
  const isLive = tiSource.includes('live');
  const isBaseline = tiSource.includes('baseline');
  const hasCustom = tiSource.includes('custom');
  const syncDot = tiSource === 'none' ? 'never' : isLive ? 'fresh' : isBaseline ? 'stale' : 'fresh';
  const sourceLabel = isLive ? '🟢 Live' : isBaseline ? '🟡 Baseline (bundled)' : tiSource === 'none' ? '🔴 None' : '🟢 Custom';
  const customLabel = hasCustom ? ` + ${ti.custom_catalogs || 0} custom` : '';

  let html = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HiveGuard Report — ${esc(meta.hostname)}</title>
<style>
:root{--bg:#0a0b10;--surface:#12141d;--surface2:#1a1d2b;--surface3:#222538;--border:#2a2d42;--text:#e1e4ed;--text-dim:#7a7e95;--text-muted:#555872;--accent:#6c5ce7;--accent-light:#a29bfe;--green:#00b894;--green-light:#55efc4;--blue:#74b9ff;--orange:#fdcb6e;--red:#ff6b6b;--critical:#ff4757;--critical-bg:rgba(255,71,87,0.1);--high:#ff6b6b;--medium:#fdcb6e;--low:#74b9ff}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
.app{display:flex;min-height:100vh}
.sidebar{width:260px;background:var(--surface);border-right:1px solid var(--border);position:fixed;top:0;left:0;bottom:0;overflow-y:auto;z-index:100}
.sidebar-header{padding:1.25rem;border-bottom:1px solid var(--border)}
.sidebar-header h1{font-size:1rem;color:#fff;display:flex;align-items:center;gap:.5rem}
.sidebar-header .meta{font-size:.7rem;color:var(--text-dim);margin-top:.25rem}
.sidebar-nav{padding:.5rem 0}
.nav-item{display:flex;align-items:center;gap:.5rem;padding:.6rem 1.25rem;font-size:.82rem;color:var(--text-dim);cursor:pointer;transition:all .15s;border-left:3px solid transparent}
.nav-item:hover{background:var(--surface2);color:var(--text)}
.nav-item.active{background:var(--surface2);color:var(--accent-light);border-left-color:var(--accent)}
.nav-item .badge{margin-left:auto;background:var(--surface3);color:var(--text-dim);padding:.1rem .5rem;border-radius:10px;font-size:.7rem}
.nav-item .badge.critical{background:var(--critical-bg);color:var(--critical)}
.nav-item .badge.threat{background:var(--critical-bg);color:var(--critical);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
.main{margin-left:260px;flex:1;padding:1.5rem 2rem}
.stats-row{display:flex;gap:.75rem;margin-bottom:1.5rem;flex-wrap:wrap}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;min-width:130px;flex:1}
.stat .num{font-size:1.6rem;font-weight:700;color:var(--accent-light)}
.stat .lbl{font-size:.7rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.04em}
.stat.danger .num{color:var(--critical)}.stat.warn .num{color:var(--orange)}.stat.ok .num{color:var(--green)}
.panel{display:none}.panel.active{display:block}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:1.25rem;overflow:hidden}
.card-header{padding:.85rem 1.25rem;background:var(--surface2);border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none}
.card-header h3{font-size:.95rem;color:#fff}
.card-body{padding:1rem 1.25rem;max-height:500px;overflow-y:auto}.card-body.collapsed{display:none}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:.45rem .6rem;color:var(--text-dim);font-weight:600;font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface);z-index:1}
td{padding:.35rem .6rem;border-bottom:1px solid rgba(42,45,66,.5);font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:.78rem}
tr{cursor:pointer;transition:background .1s}tr:hover{background:rgba(108,92,231,.06)}
tr.threat-row{background:var(--critical-bg)}tr.threat-row:hover{background:rgba(255,71,87,.15)}tr.threat-row td{color:var(--critical)}
.sev{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.68rem;font-weight:700;text-transform:uppercase}
.sev-critical{background:var(--critical-bg);color:var(--critical)}.sev-high{background:rgba(255,107,107,.12);color:var(--high)}.sev-medium{background:rgba(253,203,110,.12);color:var(--medium)}.sev-low{background:rgba(116,185,255,.12);color:var(--low)}.sev-info{background:rgba(116,185,255,.06);color:var(--text-dim)}
.global-search{position:relative;margin-bottom:1.5rem}
.global-search input{width:100%;padding:.8rem 1rem .8rem 2.5rem;background:var(--surface);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:.9rem;outline:none;transition:border-color .2s}
.global-search input:focus{border-color:var(--accent)}.global-search input::placeholder{color:var(--text-muted)}
.global-search .icon{position:absolute;left:.85rem;top:50%;transform:translateY(-50%);color:var(--text-muted);font-size:1rem}
.search-results-count{position:absolute;right:.85rem;top:50%;transform:translateY(-50%);font-size:.75rem;color:var(--text-dim)}
.search-filters{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap}
.filter-chip{padding:.3rem .75rem;border-radius:20px;font-size:.75rem;cursor:pointer;border:1px solid var(--border);background:var(--surface);color:var(--text-dim);transition:all .15s}
.filter-chip:hover,.filter-chip.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.filter-chip.threat-filter{border-color:var(--critical);color:var(--critical)}.filter-chip.threat-filter.active{background:var(--critical);color:#fff}
.export-bar{display:flex;gap:.5rem;margin-bottom:1.5rem}
.export-btn{padding:.45rem .9rem;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text-dim);font-size:.78rem;cursor:pointer;transition:all .15s}
.export-btn:hover{background:var(--accent);color:#fff;border-color:var(--accent)}
.modal-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);z-index:1000;backdrop-filter:blur(4px)}
.modal-overlay.show{display:flex;align-items:center;justify-content:center}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;width:700px;max-width:90vw;max-height:80vh;overflow-y:auto}
.modal-header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.modal-header h2{font-size:1.1rem;color:#fff}
.modal-close{background:none;border:none;color:var(--text-dim);font-size:1.5rem;cursor:pointer;padding:.25rem}.modal-close:hover{color:#fff}
.modal-body{padding:1.25rem 1.5rem}
.detail-grid{display:grid;grid-template-columns:140px 1fr;gap:.5rem 1rem;font-size:.85rem}
.detail-grid .label{color:var(--text-dim);font-weight:600}.detail-grid .value{color:var(--text);word-break:break-all;font-family:monospace;font-size:.8rem}
.detail-grid .value a{color:var(--blue);text-decoration:none}.detail-grid .value a:hover{text-decoration:underline}
.threat-banner{background:var(--critical-bg);border:1px solid rgba(255,71,87,.3);border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem}
.threat-banner h4{color:var(--critical);font-size:.9rem;margin-bottom:.25rem}.threat-banner p{font-size:.8rem;color:var(--text-dim)}
.critical-alert{background:linear-gradient(135deg,rgba(255,71,87,.15),rgba(255,71,87,.05));border:2px solid var(--critical);border-radius:14px;padding:1.5rem;margin-bottom:1.5rem;position:relative;overflow:hidden}
.critical-alert::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,var(--critical),var(--orange),var(--critical));animation:alertPulse 2s infinite}
@keyframes alertPulse{0%,100%{opacity:1}50%{opacity:.5}}
.critical-alert h2{color:var(--critical);font-size:1.2rem;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem}
.critical-alert .alert-count{font-size:2.5rem;font-weight:900;color:var(--critical);line-height:1}
.alert-match{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.25);border-radius:10px;padding:.85rem 1rem;margin-top:.75rem}
.alert-match .pkg-name{font-size:1rem;font-weight:700;color:#fff;font-family:monospace}
.alert-match .attack-name{color:var(--critical);font-weight:700;font-size:.9rem;margin-top:.25rem}
.alert-match .attack-meta{font-size:.78rem;color:var(--text-dim);margin-top:.2rem}
.alert-match .ioc-row{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.4rem}
.alert-match .ioc-tag{background:rgba(253,203,110,.12);color:var(--orange);padding:.15rem .5rem;border-radius:4px;font-size:.68rem;font-family:monospace}
.sync-status{display:flex;align-items:center;gap:.5rem;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:.5rem .85rem;font-size:.75rem;color:var(--text-dim);margin-bottom:1rem}
.sync-dot{width:8px;height:8px;border-radius:50%}.sync-dot.fresh{background:var(--green)}.sync-dot.stale{background:var(--orange)}.sync-dot.never{background:var(--red)}
.clean-banner{background:linear-gradient(135deg,rgba(0,184,148,.1),rgba(0,184,148,.03));border:1px solid rgba(0,184,148,.3);border-radius:14px;padding:1.5rem;margin-bottom:1.5rem}
.clean-banner h2{color:var(--green);font-size:1.1rem;margin-bottom:.25rem}.clean-banner p{color:var(--text-dim);font-size:.85rem}
.campaign-card{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;margin-bottom:.75rem}
.campaign-card h4{color:var(--orange);font-size:.9rem;margin-bottom:.25rem}
.campaign-card .campaign-meta{font-size:.75rem;color:var(--text-dim)}
.match-status{margin-top:.5rem;font-size:.8rem}.match-clean{color:var(--green)}.match-hit{color:var(--critical);font-weight:700}
.mcp-entry{background:var(--surface2);border-radius:8px;padding:.65rem 1rem;margin-bottom:.4rem}
.mcp-entry .name{font-weight:600;color:var(--green-light);font-size:.85rem}
.mcp-entry .meta{font-size:.72rem;color:var(--text-dim);font-family:monospace}
.mcp-entry .env-warn{color:var(--orange);font-size:.72rem}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#000}}
</style></head><body><div class="app">`;

  // ── SIDEBAR ──
  const critCount = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  html += `<div class="sidebar"><div class="sidebar-header">
    <h1>🐝 HiveGuard</h1>
    <div class="meta">${esc(meta.hostname)} · ${(meta.users_scanned || []).length > 0 ? esc((meta.users_scanned || []).join(', ')) : esc(meta.username)} · ${new Date(meta.scan_time).toLocaleDateString()}</div>
  </div><div class="sidebar-nav">
    <div class="nav-item active" onclick="showPanel('overview')">📊 Overview</div>
    <div class="nav-item" onclick="showPanel('search')">🔍 All Packages<span class="badge">${packages.length.toLocaleString()}</span></div>
    <div class="nav-item" onclick="showPanel('threats')">🛡️ Threat Intel${threatMatches.length > 0 ? `<span class="badge threat">${threatMatches.length}</span>` : '<span class="badge">0</span>'}</div>
    <div class="nav-item" onclick="showPanel('findings')">⚠️ Findings<span class="badge${critCount > 0 ? ' critical' : ''}">${findings.length}</span></div>
    <div class="nav-item" onclick="showPanel('npm')">📦 npm<span class="badge">${summary.ecosystems.npm_projects} projects</span></div>
    <div class="nav-item" onclick="showPanel('pypi')">🐍 Python<span class="badge">${summary.ecosystems.pypi_packages}</span></div>
    <div class="nav-item" onclick="showPanel('go')">🔷 Go<span class="badge">${summary.ecosystems.go_projects} projects</span></div>
    <div class="nav-item" onclick="showPanel('extensions')">🔌 Extensions<span class="badge">${summary.ecosystems.editor_extensions + summary.ecosystems.browser_extensions}</span></div>
    <div class="nav-item" onclick="showPanel('mcp')">🔗 MCP<span class="badge">${summary.ecosystems.mcp_servers}</span></div>
    <div class="nav-item" onclick="showPanel('ai')">🤖 AI on this machine<span class="badge">${aiSignalCount}</span></div>
    <div class="nav-item" onclick="showPanel('hygiene')">🪝 Scripts, Hooks &amp; AI<span class="badge${hygieneFlagged > 0 ? ' critical' : ''}">${hygieneFlagged}</span></div>
  </div></div>`;

  html += `<div class="main">`;

  // ── OVERVIEW ──
  html += `<div class="panel active" id="panel-overview">
  <h2 style="color:#fff;margin-bottom:1rem">Endpoint Inventory Overview</h2>
  <div class="sync-status"><span class="sync-dot ${syncDot}"></span>
    <span>Threat Intel: <strong>${sourceLabel}</strong>${customLabel} · ${ti.catalogs_loaded} catalogs · ${ti.total_known_bad_versions} known-bad versions${isBaseline ? ' · <span style="color:var(--orange)">Bundled snapshot — run online for latest</span>' : ''}</span>
  </div>`;

  // Critical alert or clean banner
  if (threatMatches.length > 0) {
    html += `<div class="critical-alert"><div style="display:flex;align-items:center;gap:1.25rem;margin-bottom:.5rem">
      <div class="alert-count">${threatMatches.length}</div><div>
      <h2>🚨 SUPPLY CHAIN COMPROMISE DETECTED</h2>
      <div style="color:var(--text-dim);font-size:.82rem">${threatMatches.length} package${threatMatches.length > 1 ? 's' : ''} match known-compromised releases.</div>
    </div></div>`;
    // Group by attack
    const byAttack = {};
    for (const m of threatMatches) {
      for (const t of (m.threats || [])) {
        const key = t.attackType || t.catalog;
        if (!byAttack[key]) byAttack[key] = { attack: t.attackType, catalog: t.catalog, source: t.source, indicators: t.indicators || {}, pkgs: [] };
        byAttack[key].pkgs.push(m);
      }
    }
    for (const [, info] of Object.entries(byAttack)) {
      html += `<div class="alert-match"><div class="attack-name">🎯 ${esc(info.attack)}</div>
        <div class="attack-meta">Catalog: ${esc(info.catalog)}${isSafeUrl(info.source) ? ` · <a href="${esc(info.source)}" target="_blank" rel="noopener noreferrer" style="color:var(--blue)">Source →</a>` : info.source ? ` · Source: ${esc(info.source)}` : ''}</div>`;
      for (const p of info.pkgs) {
        html += `<div class="pkg-name" style="margin-top:.3rem">📦 ${esc(p.name)}@${esc(p.version)} <span style="font-size:.75rem;color:var(--text-dim);font-weight:400">in ${esc(p.project)} (${esc(p.ecosystem)})</span></div>`;
      }
      const iocs = Object.entries(info.indicators).filter(([k]) => !k.startsWith('_'));
      if (iocs.length > 0) {
        html += `<div class="ioc-row" style="margin-top:.5rem">`;
        for (const [k, v] of iocs) html += `<span class="ioc-tag">${esc(k)}: ${esc(String(v))}</span>`;
        html += `</div>`;
      }
      html += `</div>`;
    }
    html += `</div>`;
  } else {
    html += `<div class="clean-banner"><h2>✅ No Supply Chain Compromises Detected</h2>
      <p>All ${packages.length.toLocaleString()} packages checked against ${ti.total_known_bad_versions} known-compromised versions. No matches.</p></div>`;
  }

  // Stats row
  html += `<div class="stats-row">
    <div class="stat${threatMatches.length > 0 ? ' danger' : ' ok'}"><div class="num">${threatMatches.length}</div><div class="lbl">Threat Matches</div></div>
    <div class="stat${critCount > 0 ? ' danger' : ' warn'}"><div class="num">${findings.length}</div><div class="lbl">Findings</div></div>
    <div class="stat"><div class="num">${packages.length.toLocaleString()}</div><div class="lbl">Components</div></div>
    <div class="stat"><div class="num">${summary.ecosystems.npm_projects}</div><div class="lbl">npm Projects</div></div>
    <div class="stat"><div class="num">${summary.ecosystems.pypi_packages}</div><div class="lbl">Python Pkgs</div></div>
    <div class="stat"><div class="num">${summary.ecosystems.go_projects}</div><div class="lbl">Go Projects</div></div>
    <div class="stat"><div class="num">${summary.ecosystems.editor_extensions}</div><div class="lbl">IDE Ext</div></div>
    <div class="stat"><div class="num">${summary.ecosystems.browser_extensions}</div><div class="lbl">Browser Ext</div></div>
    <div class="stat"><div class="num">${summary.ecosystems.mcp_servers}</div><div class="lbl">MCP Servers</div></div>
  </div>`;

  // Metadata
  html += `<div class="stats-row"><div class="stat" style="flex:3"><div class="lbl" style="margin-bottom:.5rem">Scan Metadata</div>
    <div style="font-size:.8rem;color:var(--text-dim)">
      <strong>Host:</strong> ${esc(meta.hostname)} | <strong>OS:</strong> ${esc(meta.platform)}/${esc(meta.arch)} |
      <strong>User:</strong> ${esc(meta.username)} | <strong>Users Scanned:</strong> ${esc((meta.users_scanned || []).join(', ') || 'n/a')} | <strong>Node:</strong> ${esc(meta.nodeVersion)} |
      <strong>Scan:</strong> ${esc(meta.scan_time)} | <strong>Duration:</strong> ${meta.elapsed_seconds}s |
      <strong>Catalogs:</strong> ${ti.catalogs_loaded} | <strong>Intel Source:</strong> ${esc(ti.source || 'none')}${ti.custom_catalogs ? ` (${ti.custom_catalogs} custom)` : ''}
    </div></div></div>`;

  // Top findings
  if (findings.length > 0) {
    html += `<div class="card"><div class="card-header"><h3>Top Findings</h3><span class="badge" style="background:var(--critical-bg);color:var(--critical)">${findings.length}</span></div><div class="card-body" style="max-height:300px">`;
    for (const f of findings.slice(0, 12)) {
      const pkgLabel = f.package && f.package !== 'secrets-hygiene' && !f.package.startsWith('env_') && !f.package.startsWith('git_') && !f.package.startsWith('ssh_') ? `<strong>${esc(f.package)}${f.version ? '@' + esc(f.version) : ''}</strong> — ` : '';
      const loc = f.project ? `<span style="font-size:.72rem;color:var(--text-muted)"> ← ${esc(f.project)}</span>` : f.path ? `<span style="font-size:.72rem;color:var(--text-muted)"> ← ${esc(f.path)}</span>` : '';
      html += `<div style="margin-bottom:.5rem;font-size:.82rem"><span class="sev sev-${f.severity}">${f.severity}</span> <span class="sev sev-low" style="font-size:.6rem">${esc(f.ecosystem || '')}</span> ${pkgLabel}${esc(f.text)}${f.cve ? ` <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" style="color:var(--blue);font-size:.72rem">${esc(f.cve)}</a>` : ''}${loc}</div>`;
    }
    if (findings.length > 12) html += `<div style="color:var(--text-dim);font-size:.8rem">+${findings.length - 12} more — see Findings panel</div>`;
    html += `</div></div>`;
  }
  html += `</div>`;

  // ── SEARCH PANEL ──
  const ecoFilterCounts = {};
  for (const p of searchPkgs) { ecoFilterCounts[p.eco] = (ecoFilterCounts[p.eco] || 0) + 1; }

  html += `<div class="panel" id="panel-search">
  <h2 style="color:#fff;margin-bottom:1rem">🔍 All Packages</h2>
  <div class="export-bar">
    <button class="export-btn" onclick="exportCSV()">📥 CSV</button>
    <button class="export-btn" onclick="exportJSON()">📥 JSON</button>
    <button class="export-btn" onclick="window.print()">🖨️ Print</button>
  </div>
  <div class="global-search"><span class="icon">🔍</span>
    <input type="text" id="globalSearch" placeholder="Search packages... (Ctrl+K)" oninput="globalFilter()">
    <span class="search-results-count" id="searchCount">${packages.length.toLocaleString()}</span>
  </div>
  <div class="search-filters">
    <span class="filter-chip active" onclick="setEcoFilter(this,'all')">All</span>`;
  for (const [eco, count] of Object.entries(ecoFilterCounts).sort((a, b) => b[1] - a[1])) {
    html += `<span class="filter-chip" onclick="setEcoFilter(this,'${esc(eco)}')">${esc(eco)} (${count})</span>`;
  }
  html += `<span class="filter-chip threat-filter" onclick="setEcoFilter(this,'threats')">⚠ Threats Only</span></div>`;
  html += `<div style="max-height:calc(100vh - 280px);overflow-y:auto"><table>
    <thead><tr><th>Eco</th><th>Package</th><th>Version</th><th>User</th><th>Project</th><th>Status</th></tr></thead>
    <tbody id="searchTableBody">`;
  for (const p of searchPkgs) {
    const cls = p.threat ? ' class="threat-row"' : '';
    const badge = p.threat ? '<span class="sev sev-critical">⚠</span>' : '<span style="color:var(--green)">✓</span>';
    html += `<tr${cls} onclick="showDetail(${p.id})" data-eco="${esc(p.eco)}" data-s="${esc((p.name + ' ' + p.ver + ' ' + p.eco + ' ' + p.proj + ' ' + p.dn + ' ' + (p.user || '')).toLowerCase())}">`;
    html += `<td><span class="sev sev-low" style="font-size:.62rem">${esc(p.eco)}</span></td>`;
    html += `<td>${esc(p.name)}</td><td>${esc(p.ver)}</td><td style="font-size:.72rem;color:var(--accent-light)">${esc(p.user || '')}</td><td style="font-size:.72rem;color:var(--text-dim)">${esc(p.proj)}</td><td>${badge}</td></tr>`;
  }
  html += `</tbody></table></div></div>`;

  // ── THREATS PANEL ──
  html += `<div class="panel" id="panel-threats">
  <h2 style="color:#fff;margin-bottom:.5rem">🛡️ Threat Intelligence</h2>
  <p style="color:var(--text-dim);font-size:.82rem;margin-bottom:1.5rem">${ti.catalogs_loaded} catalogs, ${ti.total_known_bad_versions} known-compromised versions indexed.</p>`;
  const sourceRows = Object.entries(ti.sources || {});
  if (sourceRows.length > 0) {
    const labels = { bumblebee: 'Bumblebee live feed', osv: 'OSV.dev (OpenSSF)', ghsa: 'GitHub Advisory DB' };
    html += `<p style="font-size:.78rem;margin:-1rem 0 1.5rem">${sourceRows.map(([k, v]) => {
      const bad = v.status === 'failed' || v.status === 'partial';
      return `<span style="color:${bad ? 'var(--critical)' : 'var(--text-dim)'}">${esc(labels[k] || k)}: ${esc(v.status)}${v.error ? ` (${esc(v.error)})` : ''}</span>`;
    }).join(' · ')}</p>`;
  }

  if (threatMatches.length > 0) {
    html += `<div style="background:var(--critical-bg);border:1px solid rgba(255,71,87,.3);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem">
      <h3 style="color:var(--critical)">🚨 ${threatMatches.length} MATCH${threatMatches.length > 1 ? 'ES' : ''}</h3>`;
    for (const m of threatMatches) {
      const t = (m.threats || [])[0] || {};
      html += `<div style="margin:.5rem 0;font-size:.85rem"><span class="sev sev-critical">CRITICAL</span> <strong>${esc(m.name)}@${esc(m.version)}</strong> — ${esc(t.attackType || '')} — <em>${esc(m.project)}</em></div>`;
    }
    html += `</div>`;
  } else {
    html += `<div class="clean-banner"><h2>✅ No Matches</h2><p>None of ${packages.length.toLocaleString()} packages match known-compromised versions.</p></div>`;
  }

  for (const cat of catalogs) {
    html += `<div class="campaign-card"><h4>${esc(cat.file)}</h4>
      <div class="campaign-meta">${cat.entries} packages · ${esc(cat.campaignName)}</div>
      <div style="font-size:.75rem;color:var(--text-dim);margin-top:.25rem">${esc((cat.comment || '').slice(0, 250))}</div></div>`;
  }
  html += `</div>`;

  // ── FINDINGS PANEL ──
  html += `<div class="panel" id="panel-findings">
  <h2 style="color:#fff;margin-bottom:1rem">⚠️ Findings</h2>`;
  if ((result.ioc_search || []).length > 0) {
    html += `<div class="card"><div class="card-header"><h3>🔎 Indicator search</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${result.ioc_search.filter(r => r.found).length} of ${result.ioc_search.length} found</span></div><div class="card-body"><table><thead><tr><th>Indicator</th><th>Kind</th><th>Result</th></tr></thead><tbody>`;
    for (const r of result.ioc_search) {
      html += `<tr><td><code>${esc(r.ioc)}</code></td><td style="font-size:.72rem">${esc(r.kind)}</td><td style="font-size:.72rem">${r.found ? `<span class="sev sev-critical">found</span><div style="color:var(--text-dim);word-break:break-all">${r.locations.slice(0, 20).map(esc).join('<br>')}</div>` : r.error ? esc(r.error) : 'not found'}</td></tr>`;
    }
    html += `</tbody></table></div></div>`;
  }
  for (const f of findings) {
    const borderColor = f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'orange' : 'blue';
    const pkgLabel = f.package && f.package !== 'secrets-hygiene' && !f.package.startsWith('env_') && !f.package.startsWith('git_') && !f.package.startsWith('ssh_') ? `<strong>${esc(f.package)}${f.version ? '@' + esc(f.version) : ''}</strong> — ` : '';
    const loc = f.project ? `<br><span style="font-size:.72rem;color:var(--text-muted)">📁 Found in: <code>${esc(f.project)}</code></span>` : f.path ? `<br><span style="font-size:.72rem;color:var(--text-muted)">📁 Location: <code>${esc(f.path)}</code></span>` : '';
    html += `<div style="margin-bottom:.6rem;font-size:.85rem;padding:.6rem .75rem;background:var(--surface);border-radius:8px;border-left:3px solid var(--${borderColor})">
      <span class="sev sev-${f.severity}">${f.severity}</span> <span class="sev sev-low" style="font-size:.6rem">${esc(f.ecosystem || '')}</span>
      ${f.user ? `<span style="font-size:.68rem;color:var(--accent-light);margin-right:.3rem">[${esc(f.user)}]</span>` : ''}${pkgLabel}${esc(f.text)}
      ${f.cve ? `<br><a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" style="color:var(--blue);font-size:.72rem">${esc(f.cve)}</a>` : ''}${loc}
    </div>`;
  }
  html += `</div>`;

  // ── NPM PANEL ──
  html += `<div class="panel" id="panel-npm"><h2 style="color:#fff;margin-bottom:1rem">📦 npm</h2>`;
  for (const proj of (ecosystems.npm?.projects || [])) {
    html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
      <h3>${esc(proj.project)}${proj.user ? ` <span style="font-size:.7rem;color:var(--accent-light);font-weight:400">[${esc(proj.user)}]</span>` : ''}</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${proj.lockfile_type ? `${esc(proj.lockfile_type)} · ` : ''}${proj.total_dependencies} deps</span>
    </div><div class="card-body collapsed">
      <input type="text" style="width:100%;padding:.4rem .6rem;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.8rem;margin-bottom:.5rem;outline:none" placeholder="Filter..." oninput="filterTable(this)">
      <table><thead><tr><th>Package</th><th>Version</th></tr></thead><tbody>`;
    for (const d of (proj.dependencies || []).slice(0, 500)) {
      html += `<tr><td>${esc(d.name)}</td><td>${esc(d.version)}</td></tr>`;
    }
    if ((proj.dependencies || []).length > 500) html += `<tr><td colspan="2" style="color:var(--text-dim)">...and ${proj.dependencies.length - 500} more</td></tr>`;
    html += `</tbody></table></div></div>`;
  }
  html += `</div>`;

  // ── PYPI PANEL ──
  html += `<div class="panel" id="panel-pypi"><h2 style="color:#fff;margin-bottom:1rem">🐍 Python</h2>
    <table><thead><tr><th>Package</th><th>Version</th><th>User</th><th>Source</th></tr></thead><tbody>`;
  for (const p of (ecosystems.pypi?.packages || [])) {
    html += `<tr><td>${esc(p.name)}</td><td>${esc(p.version)}</td><td style="font-size:.72rem;color:var(--accent-light)">${esc(p.user || '')}</td><td style="font-size:.72rem;color:var(--text-dim)">${esc(p.source_type || '')}</td></tr>`;
  }
  html += `</tbody></table></div>`;

  // ── GO PANEL ──
  html += `<div class="panel" id="panel-go"><h2 style="color:#fff;margin-bottom:1rem">🔷 Go</h2>`;
  for (const proj of (ecosystems.go?.projects || [])) {
    html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
      <h3>${esc(proj.project)}${proj.user ? ` <span style="font-size:.7rem;color:var(--accent-light);font-weight:400">[${esc(proj.user)}]</span>` : ''}</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${proj.total_dependencies} deps</span>
    </div><div class="card-body collapsed"><table><thead><tr><th>Module</th><th>Version</th></tr></thead><tbody>`;
    for (const d of (proj.dependencies || []).slice(0, 300)) {
      html += `<tr><td>${esc(d.name)}</td><td>${esc(d.version)}</td></tr>`;
    }
    html += `</tbody></table></div></div>`;
  }
  if ((ecosystems.go?.projects || []).length === 0) html += `<p style="color:var(--text-dim)">No Go projects found.</p>`;
  html += `</div>`;

  // ── EXTENSIONS PANEL ──
  html += `<div class="panel" id="panel-extensions"><h2 style="color:#fff;margin-bottom:1rem">🔌 Extensions</h2>`;
  for (const [editor, exts] of Object.entries(ecosystems.editor_extensions?.editors || {})) {
    html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
      <h3>${esc(editor)}</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${exts.length}</span>
    </div><div class="card-body"><table><thead><tr><th>Publisher</th><th>Extension</th><th>Version</th><th>User</th></tr></thead><tbody>`;
    for (const e of exts) {
      const notes = [];
      if (e.hidden_unicode_run) notes.push(`<span class="sev sev-critical">hidden code</span> invisible-Unicode run of ${e.hidden_unicode_run}`);
      if ((e.extension_pack || []).length) notes.push(`pack: ${e.extension_pack.map(esc).join(', ')}`);
      if ((e.extension_dependencies || []).length) notes.push(`depends on: ${e.extension_dependencies.map(esc).join(', ')}`);
      html += `<tr><td>${esc(e.publisher)}</td><td>${esc(e.displayName)}${notes.length ? `<div style="font-size:.65rem;color:var(--text-dim)">${notes.join('<br>')}</div>` : ''}</td><td>${esc(e.version)}</td><td style="font-size:.72rem;color:var(--accent-light)">${esc(e.user || '')}</td></tr>`;
    }
    html += `</tbody></table></div></div>`;
  }
  for (const [browser, exts] of Object.entries(ecosystems.browser_extensions?.browsers || {})) {
    html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
      <h3>${esc(browser)}</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${exts.length}</span>
    </div><div class="card-body"><table><thead><tr><th>Name</th><th>Version</th><th>User</th><th>Permissions</th></tr></thead><tbody>`;
    for (const e of exts) {
      const name = e.name.startsWith('__MSG_') ? `(${e.extension_id.slice(0, 16)}...)` : e.name;
      html += `<tr><td>${esc(name)}</td><td>${esc(e.version)}</td><td style="font-size:.72rem;color:var(--accent-light)">${esc(e.user || '')}</td><td style="font-size:.65rem;color:var(--text-dim)">${(e.permissions || []).slice(0, 8).map(esc).join(', ')}</td></tr>`;
    }
    html += `</tbody></table></div></div>`;
  }
  html += `</div>`;

  // ── MCP PANEL ──
  html += `<div class="panel" id="panel-mcp"><h2 style="color:#fff;margin-bottom:1rem">🔗 MCP Configs</h2>`;
  const allMcp = ecosystems.mcp_configs?.configs || [];
  // Configured servers: one card per config file.
  for (const cfg of allMcp.filter(c => c.state !== 'available')) {
    html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
      <h3>${esc(cfg.app || cfg.config_name)}${cfg.user ? ` <span style="font-size:.7rem;color:var(--accent-light);font-weight:400">[${esc(cfg.user)}]</span>` : ''}</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${cfg.server_count} servers</span>
    </div><div class="card-body">`;
    for (const srv of (cfg.servers || [])) {
      html += `<div class="mcp-entry"><div class="name">${esc(srv.name)}${srv.disabled ? ' <span style="font-size:.7rem;color:var(--text-dim)">(disabled)</span>' : ''}</div>
        <div class="meta">transport: ${esc(srv.transport)} | cmd: ${esc(srv.command || srv.url || 'n/a')}${srv.package ? ` | package: ${esc(srv.package)}@${esc(srv.package_version || 'unpinned')}` : ''}</div>`;
      if (srv.unpinned && srv.active !== false) html += `<div class="env-warn">⚠ unpinned: runs whatever version of ${esc(srv.package)} was published last</div>`;
      if (srv.env_keys?.length > 0) html += `<div class="env-warn">⚠ env: ${srv.env_keys.map(esc).join(', ')}</div>`;
      html += `</div>`;
    }
    html += `</div></div>`;
  }
  // Catalog entries (connector/plugin caches): one collapsed card per tool.
  const mcpCatalogs = new Map();
  for (const cfg of allMcp.filter(c => c.state === 'available')) {
    const key = `${cfg.app || cfg.config_name}\u0000${cfg.user || ''}`;
    if (!mcpCatalogs.has(key)) mcpCatalogs.set(key, { app: cfg.app || cfg.config_name, user: cfg.user, rows: [] });
    for (const srv of (cfg.servers || [])) mcpCatalogs.get(key).rows.push({ srv, dir: cfg.relative_dir || '' });
  }
  for (const { app, user, rows } of mcpCatalogs.values()) {
    html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
      <h3>${esc(app)} <span style="font-size:.7rem;color:var(--text-dim);font-weight:400">— catalog: available, not configured</span>${user ? ` <span style="font-size:.7rem;color:var(--accent-light);font-weight:400">[${esc(user)}]</span>` : ''}</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${rows.length} available</span>
    </div><div class="card-body collapsed"><table><thead><tr><th>Server</th><th>Would run</th><th>Catalog folder</th></tr></thead><tbody>`;
    for (const { srv, dir } of rows) {
      html += `<tr><td>${esc(srv.name)}</td><td style="font-size:.72rem">${srv.package ? `${esc(srv.package)}@${esc(srv.package_version || 'unpinned')}` : esc(srv.command || srv.url || '')}</td><td style="font-size:.7rem;color:var(--text-dim)">${esc(dir)}</td></tr>`;
    }
    html += `</tbody></table></div></div>`;
  }
  html += `</div>`;

  // ── AI ON THIS MACHINE PANEL ──
  {
    const fmtBytes = (n) => n >= 1073741824 ? `${(n / 1073741824).toFixed(1)} GB` : `${Math.round((n || 0) / 1048576)} MB`;
    const card = (title, badge, body) => `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')"><h3>${title}</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${badge}</span></div><div class="card-body">${body}</div></div>`;
    const empty = (t) => `<p style="color:var(--text-dim);font-size:.8rem">${t}</p>`;
    const table = (head, rows) => `<table><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
    const mcpCfgs = (ecosystems.mcp_configs?.configs || []).filter(c => c.servers.some(s => s.active !== false));
    const mcpInactive = (ecosystems.mcp_configs?.available_servers || 0) + (ecosystems.mcp_configs?.disabled_servers || 0);
    const models = ecosystems.ai_models || {};
    const usage = ecosystems.ai_usage || {};
    const editors = ecosystems.editor_extensions?.discovered_editors || [];
    const compromised = new Set(threatMatches.map(m => `${String(m.ecosystem).toLowerCase()}:${m.name}@${m.version}`));

    html += `<div class="panel" id="panel-ai"><h2 style="color:#fff;margin-bottom:.5rem">🤖 AI on this machine</h2>
      <p style="color:var(--text-dim);font-size:.82rem;margin-bottom:1.5rem">Found by structure (MCP configs, model file formats, credential formats, SDKs), not by product name, so tools HiveGuard has never heard of still show up under their folder name.</p>`;

    const knownApps = ecosystems.ai_apps?.apps || [];
    html += card('📦 Known AI apps', `${new Set(knownApps.map(a => a.id)).size} apps`, knownApps.length === 0 ? empty('None of the AI apps on HiveGuard\'s short list were found (tools without a known footprint are still found by the signals below).')
      : table(['App', 'Kind', 'User', 'Found at'], knownApps.map(a => `<tr><td>${esc(a.name)}</td><td>${esc(a.kind)}</td><td>${esc(a.user)}</td><td style="font-size:.7rem;word-break:break-all">${a.evidence.map(esc).join('<br>')}</td></tr>`)));

    html += card('🔗 MCP servers', `${ecosystems.mcp_configs?.total_servers || 0} servers in ${mcpCfgs.length} configs`, mcpCfgs.length === 0 ? empty('No MCP servers configured.')
      : table(['App', 'Server', 'Runs', 'Notes'], mcpCfgs.flatMap(c => c.servers.filter(s => s.active !== false).map(s => `<tr><td>${esc(c.app || c.config_name)}</td><td>${esc(s.name)}${s.project ? `<div style="font-size:.65rem;color:var(--text-dim)">${esc(s.project)}</div>` : ''}</td><td style="font-size:.72rem">${s.package ? `${esc(s.package)}@${esc(s.package_version || 'unpinned')}` : esc(s.command || s.url || '')}</td><td style="font-size:.7rem">${[compromised.has(`${s.package_ecosystem}:${s.package}@${s.package_version}`) ? '<span class="sev sev-critical">known malicious</span>' : '', s.unpinned ? '<span class="sev sev-medium">unpinned</span>' : '', s.has_credentials ? 'credentials in env' : '', s.wrapped_by ? `via ${esc(s.wrapped_by)}` : ''].filter(Boolean).join(' ') || '—'}</td></tr>`))));

    if (mcpInactive > 0) html += `<p style="color:var(--text-dim);font-size:.75rem;margin:-.5rem 0 1rem">Not counted: ${ecosystems.mcp_configs.available_servers || 0} servers listed in catalogs/caches (available, not configured) and ${ecosystems.mcp_configs.disabled_servers || 0} disabled. All are listed in the MCP panel.</p>`;

    html += card('🧠 Local models', `${models.total || 0} models, ${fmtBytes(models.total_size)}${models.pickle_count ? `, ${models.pickle_count} pickle-format` : ''}`, (models.models || []).length === 0 ? empty('No local model files found.')
      : '<p style="color:var(--text-dim);font-size:.75rem;margin-bottom:.5rem">Pickle-format models (PyTorch .pt/.ckpt/.bin) can run code when loaded; prefer safetensors or GGUF from untrusted sources.</p>'
        + table(['Store', 'Model', 'Format', 'Size'], models.models.map(m => `<tr><td>${esc(m.store || '—')}</td><td style="font-size:.72rem;word-break:break-all">${esc(m.name || m.path)}</td><td>${esc(m.format)}${m.pickle ? ' <span class="sev sev-low">pickle</span>' : ''}${m.content_not_read ? ' <span style="font-size:.65rem;color:var(--text-dim)">(cloud, not read)</span>' : ''}</td><td>${fmtBytes(m.size)}</td></tr>`)));

    html += card('🔑 AI provider credentials', `${(usage.providers || []).length} found`, (usage.providers || []).length === 0 ? empty('No plaintext AI provider credentials found.')
      : '<p style="color:var(--text-dim);font-size:.75rem;margin-bottom:.5rem">Key values are never read into the report; only where a key appears.</p>'
        + table(['Provider', 'Where', 'Detected by', 'File'], usage.providers.map(p => `<tr><td>${esc(p.provider)}</td><td>${esc(p.source)}</td><td>${esc(p.variable || 'key format')}</td><td style="font-size:.72rem;word-break:break-all">${esc(p.path)}</td></tr>`)));

    html += card('📚 AI SDKs in dependencies', `${(usage.sdks || []).length} SDKs`, (usage.sdks || []).length === 0 ? empty('No AI SDKs in the dependency inventory.')
      : table(['Ecosystem', 'SDK', 'Versions', 'Projects'], usage.sdks.map(s => `<tr><td>${esc(s.ecosystem)}</td><td>${esc(s.name)}</td><td style="font-size:.72rem">${s.versions.map(esc).join(', ')}</td><td>${s.projects}</td></tr>`)));

    html += card('🧩 Editors found by structure', `${editors.length}`, editors.length === 0 ? empty('No additional VS Code-family editors beyond the known ones.')
      : `<p style="font-size:.8rem">${editors.map(esc).join(', ')} — their extensions are listed in the Extensions panel.</p>`);
    html += `</div>`;
  }

  // ── SCRIPTS, HOOKS & AI PANEL ──
  const sevTag = (sev) => `<span class="sev sev-${esc(sev)}">${esc(sev)}</span>`;
  const codeCell = (t) => `<code style="font-size:.68rem;word-break:break-all;color:var(--text-dim)">${esc(t)}</code>`;
  html += `<div class="panel" id="panel-hygiene"><h2 style="color:#fff;margin-bottom:.5rem">🪝 Install Scripts, Git Hooks, AI Files &amp; Autostart</h2>
    <p style="color:var(--text-dim);font-size:.82rem;margin-bottom:1.5rem">Code that runs automatically: npm install hooks and binding.gyp commands, git hooks, instruction/config files read by AI coding assistants, and programs set to start on login. Excerpts are attacker-controlled text.</p>`;

  const lc = ecosystems.lifecycle_scripts || {};
  html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
    <h3>📜 npm install scripts</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${lc.total_findings || 0} flagged / ${lc.packages_scanned || 0} packages</span>
  </div><div class="card-body">`;
  if ((lc.findings || []).length === 0) html += `<p style="color:var(--text-dim);font-size:.8rem">No suspicious install scripts.</p>`;
  else {
    html += `<table><thead><tr><th>Severity</th><th>Package</th><th>Hook</th><th>Triggers</th><th>Script</th></tr></thead><tbody>`;
    for (const f of lc.findings) {
      html += `<tr><td>${sevTag(f.severity)}</td><td>${esc(f.package)}<div style="font-size:.65rem;color:var(--text-dim)">${esc(f.path)}</div></td><td>${esc(f.hook || (f.dependency ? (f.dependency === 'resolved' ? 'installed from URL' : `dependency ${f.dependency}`) : ''))}</td><td style="font-size:.7rem">${(f.triggers || []).map(esc).join(', ')}${(f.script_files || []).length ? `<div style="color:var(--text-dim)">via ${f.script_files.map(esc).join(', ')}</div>` : ''}</td><td>${codeCell(f.script || f.url || '')}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `</div></div>`;

  const gh = ecosystems.git_hooks || {};
  html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
    <h3>🪝 Git hooks</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${gh.suspicious || 0} suspicious / ${gh.hooks_found || 0} hooks in ${gh.repos_scanned || 0} repos</span>
  </div><div class="card-body">`;
  if ((gh.findings || []).length === 0) html += `<p style="color:var(--text-dim);font-size:.8rem">No custom git hooks found.</p>`;
  else {
    html += `<table><thead><tr><th>Severity</th><th>Hook</th><th>Repository</th><th>Source</th><th>Triggers</th></tr></thead><tbody>`;
    for (const f of gh.findings) {
      html += `<tr><td>${sevTag(f.severity)}</td><td>${esc(f.hook)}</td><td style="font-size:.72rem">${esc(f.repo)}</td><td style="font-size:.72rem">${esc(f.origin || '')}</td><td style="font-size:.7rem">${(f.triggers || []).map(esc).join(', ') || '—'}${f.symlink_target ? `<div style="color:var(--text-dim)">→ ${esc(f.symlink_target)}</div>` : ''}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `</div></div>`;

  const ai = ecosystems.ai_instructions || {};
  const aiFlags = new Map((ai.findings || []).map(f => [f.path, f]));
  html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
    <h3>🤖 AI assistant files</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${ai.suspicious || 0} flagged / ${ai.files_found || 0} files</span>
  </div><div class="card-body">`;
  if ((ai.inventory || []).length === 0) html += `<p style="color:var(--text-dim);font-size:.8rem">No AI assistant instruction or config files found.</p>`;
  else {
    html += `<table><thead><tr><th>Severity</th><th>Tool</th><th>File</th><th>Details</th></tr></thead><tbody>`;
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3 };
    const rows = [...ai.inventory].sort((a, b) => (sevRank[(aiFlags.get(a.path) || {}).severity] ?? 9) - (sevRank[(aiFlags.get(b.path) || {}).severity] ?? 9));
    for (const item of rows) {
      const f = aiFlags.get(item.path);
      const details = [];
      if (f) details.push((f.triggers || []).map(esc).join(', '));
      for (const h of (item.hooks || [])) details.push(`hook ${esc(h.event)}: ${codeCell(h.command)}`);
      for (const t of (item.autorun_tasks || [])) details.push(`runs on folder open: ${codeCell(t.command)}`);
      if (item.symlink_target) details.push(`→ ${esc(item.symlink_target)}`);
      html += `<tr><td>${f ? sevTag(f.severity) : '<span style="color:var(--text-dim);font-size:.7rem">—</span>'}</td><td>${esc(item.tool)}</td><td style="font-size:.72rem;word-break:break-all">${esc(item.path)}</td><td style="font-size:.7rem">${details.join('<br>') || '—'}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `</div></div>`;

  const ps = ecosystems.persistence || {};
  const psFindings = ps.findings || [];
  const psFlags = new Map(psFindings.filter(f => f.type === 'suspicious_autostart').map(f => [f.path, f]));
  html += `<div class="card"><div class="card-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
    <h3>🚀 Autostart &amp; persistence</h3><span class="badge" style="background:var(--surface3);color:var(--text-dim)">${psFindings.length} flagged / ${ps.total || 0} entries</span>
  </div><div class="card-body">`;
  for (const f of psFindings.filter(x => x.type === 'known_ioc_file')) {
    html += `<p style="font-size:.8rem">${sevTag(f.severity)} Known persistence file present: <code>${esc(f.path)}</code> <span style="color:var(--text-dim)">(${esc(f.ioc)})</span></p>`;
  }
  if ((ps.entries || []).length === 0) html += `<p style="color:var(--text-dim);font-size:.8rem">No autostart entries found (LaunchAgents, XDG autostart, systemd user units, Startup folder${(ps.unreadable || []).length ? '; scheduled tasks need an elevated scan' : ''}).</p>`;
  else {
    html += `<table><thead><tr><th>Severity</th><th>Kind</th><th>Entry</th><th>Command</th></tr></thead><tbody>`;
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    const rows = [...ps.entries].sort((a, b) => (rank[(psFlags.get(a.path) || {}).severity] ?? 9) - (rank[(psFlags.get(b.path) || {}).severity] ?? 9));
    for (const e of rows) {
      const f = psFlags.get(e.path);
      html += `<tr><td>${f ? sevTag(f.severity) : '<span style="color:var(--text-dim);font-size:.7rem">—</span>'}</td><td style="font-size:.72rem">${esc(e.kind)}</td><td style="font-size:.72rem;word-break:break-all">${esc(e.name)}${e.user ? ` <span style="color:var(--accent-light)">[${esc(e.user)}]</span>` : ''}${f ? `<div style="color:var(--text-dim)">${(f.triggers || []).map(esc).join(', ')}</div>` : ''}</td><td>${e.command ? codeCell(e.command) : '<span style="color:var(--text-dim);font-size:.7rem">not readable</span>'}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `</div></div></div>`;

  // ── MODAL ──
  html += `<div class="modal-overlay" id="modalOverlay" onclick="if(event.target===this)closeModal()">
    <div class="modal"><div class="modal-header"><h2 id="modalTitle">Details</h2><button class="modal-close" onclick="closeModal()">×</button></div>
    <div class="modal-body" id="modalBody"></div></div></div>`;

  // Footer
  html += `<div style="text-align:center;color:var(--text-muted);font-size:.7rem;margin-top:2rem;padding:1rem">
    HiveGuard v${esc(meta.version || '')} · ${esc(meta.scan_time)} · ${ti.catalogs_loaded} threat catalogs · Read-only scan
  </div></div></div>`;

  // ── JAVASCRIPT ──
  html += `<script>
const P=${scriptJson(searchPkgs)};
let ecoF='all';
function showPanel(n){document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.nav-item').forEach(i=>i.classList.remove('active'));const el=document.getElementById('panel-'+n);if(el)el.classList.add('active');document.querySelectorAll('.nav-item').forEach(i=>{const labels={overview:'📊',search:'🔍',threats:'🛡️',findings:'⚠️',npm:'📦',pypi:'🐍',go:'🔷',extensions:'🔌',mcp:'🔗',hygiene:'🪝',ai:'🤖'};if(i.textContent.includes(labels[n]))i.classList.add('active')})}
function globalFilter(){const q=document.getElementById('globalSearch').value.toLowerCase();const rows=document.querySelectorAll('#searchTableBody tr');let c=0;rows.forEach(r=>{const s=r.dataset.s;const e=r.dataset.eco;const t=r.classList.contains('threat-row');let em=ecoF==='all'||e===ecoF||(ecoF==='threats'&&t);let tm=!q||s.includes(q);const show=em&&tm;r.style.display=show?'':'none';if(show)c++});document.getElementById('searchCount').textContent=c.toLocaleString()}
function setEcoFilter(el,e){document.querySelectorAll('.filter-chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');ecoF=e;globalFilter()}
function filterTable(input){const f=input.value.toLowerCase();const t=input.parentElement.querySelector('table');if(!t)return;t.querySelectorAll('tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(f)?'':'none'})}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function showDetail(id){const p=P[id];if(!p)return;document.getElementById('modalTitle').textContent=p.name+'@'+p.ver;let b='';
if(p.threat){b+='<div class="threat-banner" style="border-width:2px"><h4 style="font-size:1rem">🚨 SUPPLY CHAIN COMPROMISE</h4><p>This package+version is listed as compromised in threat intel catalogs.</p></div>'}
b+='<div class="detail-grid">';b+='<div class="label">Ecosystem</div><div class="value">'+esc(p.eco)+'</div>';
b+='<div class="label">Package</div><div class="value">'+esc(p.name)+'</div>';
if(p.dn)b+='<div class="label">Display Name</div><div class="value">'+esc(p.dn)+'</div>';
b+='<div class="label">Version</div><div class="value">'+esc(p.ver)+'</div>';
if(p.user)b+='<div class="label">User</div><div class="value">'+esc(p.user)+'</div>';
b+='<div class="label">Project</div><div class="value">'+esc(p.proj)+'</div>';
b+='<div class="label">Source</div><div class="value">'+esc(p.src)+'</div>';
if(p.res)b+='<div class="label">Resolved</div><div class="value">'+(/^https?:\\/\\//i.test(p.res)?'<a href="'+esc(p.res)+'" target="_blank" rel="noopener noreferrer">'+esc(p.res)+'</a>':esc(p.res))+'</div>';
b+='<div class="label">Status</div><div class="value">'+(p.threat?'<span class="sev sev-critical">COMPROMISED</span>':'<span style="color:var(--green)">✅ Clean</span>')+'</div>';
b+='</div>';
const same=P.filter(x=>x.name===p.name&&x.id!==p.id);
if(same.length>0){b+='<div style="margin-top:1rem"><strong style="font-size:.8rem;color:var(--text-dim)">Also in:</strong><div style="display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.3rem">';
for(const s of same)b+='<span style="background:var(--surface3);padding:.2rem .5rem;border-radius:4px;font-size:.72rem;color:var(--text-dim)">'+esc(s.proj)+' v'+esc(s.ver)+'</span>';
b+='</div></div>'}
document.getElementById('modalBody').innerHTML=b;document.getElementById('modalOverlay').classList.add('show')}
function closeModal(){document.getElementById('modalOverlay').classList.remove('show')}
function exportCSV(){let c='Ecosystem,Package,Version,User,Project,Source,Threat\\n';document.querySelectorAll('#searchTableBody tr').forEach(r=>{if(r.style.display==='none')return;const id=parseInt(r.getAttribute('onclick').match(/\\d+/)[0]);const p=P[id];c+=[p.eco,'"'+p.name+'"',p.ver,'"'+(p.user||'')+'"','"'+p.proj+'"','"'+p.src+'"',p.threat].join(',')+'\\n'});const b=new Blob([c],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='hiveguard-${esc(meta.hostname)}.csv';a.click()}
function exportJSON(){const v=[];document.querySelectorAll('#searchTableBody tr').forEach(r=>{if(r.style.display==='none')return;const id=parseInt(r.getAttribute('onclick').match(/\\d+/)[0]);v.push(P[id])});const b=new Blob([JSON.stringify(v,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='hiveguard-${esc(meta.hostname)}.json';a.click()}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();if((e.ctrlKey||e.metaKey)&&e.key==='k'){e.preventDefault();showPanel('search');document.getElementById('globalSearch').focus()}});
</script></body></html>`;

  return html;
}

module.exports = { generateReport };
