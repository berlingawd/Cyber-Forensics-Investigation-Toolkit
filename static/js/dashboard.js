/* ============================================================
   Cyber Forensics Toolkit — Dashboard JavaScript
   All tabs use onclick switchTab() — NO Bootstrap JS tabs
   ============================================================ */

"use strict";

// Shorthand selector
const $ = id => document.getElementById(id);

/* ── Tab Switcher ─────────────────────────────────────────
   Called by onclick on every tab button.
   Hides all panes, removes .active from all buttons,
   then shows the requested pane and marks its button active.
──────────────────────────────────────────────────────────── */
function switchTab(tabId) {
  document.querySelectorAll(".cf-tab-pane").forEach(p => p.style.display = "none");
  document.querySelectorAll(".cf-tab-btn").forEach(b => b.classList.remove("active"));

  const pane = $(tabId);
  if (pane) pane.style.display = "block";

  const btn = document.querySelector(`.cf-tab-btn[data-tab="${tabId}"]`);
  if (btn) btn.classList.add("active");
}

/* ── Utility ─────────────────────────────────────────────── */
function setLoading(elId, msg) {
  const el = $(elId);
  if (el) el.textContent = msg || "Loading…";
}

function apiPost(url, body) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(r => r.json());
}

function getFileName() {
  const v = ($("evidenceFileName") || {}).value;
  return (v || "").trim();
}

function getCaseId() {
  const sel = $("caseSelect");
  return sel ? sel.value : "";
}

/* ── Evidence table row click ────────────────────────────── */
function setupEvidenceRows() {
  document.querySelectorAll(".evidence-row").forEach(row => {
    row.addEventListener("click", () => {
      const fn = row.dataset.filename || "";
      if ($("evidenceFileName")) $("evidenceFileName").value = fn;
      document.querySelectorAll(".evidence-row").forEach(r => r.style.background = "");
      row.style.background = "rgba(34,197,94,.08)";
    });
  });
}

/* ── Case selector ───────────────────────────────────────── */
function setupCaseSelector() {
  const sel = $("caseSelect");
  if (!sel) return;
  sel.addEventListener("change", () => {
    const cid = sel.value;
    if (cid) window.location.href = `/dashboard?case_id=${encodeURIComponent(cid)}`;
  });
}

/* ── New Case modal ──────────────────────────────────────── */
function setupNewCase() {
  const btn = $("btnNewCase");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const name = prompt("Case name:");
    if (!name) return;
    const inv  = prompt("Investigator name:") || "Investigator";
    apiPost("/api/cases", { case_name: name, investigator_name: inv })
      .then(d => {
        if (d.success) window.location.href = `/dashboard?case_id=${encodeURIComponent(d.case_id)}`;
        else alert("Error: " + (d.error || "Unknown error"));
      })
      .catch(() => alert("Network error creating case."));
  });
}

/* ── Log Analyzer ────────────────────────────────────────── */
function runAnalyzeLog() {
  const fn = getFileName();
  if (!fn) { alert("Enter or click an evidence file name first."); return; }
  switchTab("tabLog");
  setLoading("analysisResult", "Analyzing log file…");
  apiPost("/api/analyze_log", { file_name: fn })
    .then(d => {
      if (!d.success) { $("analysisResult").textContent = "Error: " + d.error; return; }
      const r = d.result;
      if (r.error) { $("analysisResult").textContent = "Error: " + r.error; return; }
      let out = "=== LOG ANALYSIS RESULTS ===\n\n";
      out += `Suspicious IPs found: ${r.suspicious_ips.length}\n`;
      out += `Brute force IPs:      ${r.brute_force_detected.length}\n\n`;
      if (r.suspicious_ips.length) {
        out += "--- Suspicious IPs ---\n";
        r.suspicious_ips.slice(0, 30).forEach(ip => {
          out += `  ${ip.suspicious_ip}  |  ${ip.number_of_attempts} attempts  |  ${ip.event_type}\n`;
        });
      }
      if (r.failed_logins.length) {
        out += `\n--- Recent Events (first 20 of ${r.failed_logins.length}) ---\n`;
        r.failed_logins.slice(0, 20).forEach(e => {
          out += `  [${e.timestamp || "—"}]  ${e.event}  from  ${e.ip}\n`;
        });
      }
      $("analysisResult").textContent = out;
    })
    .catch(e => { $("analysisResult").textContent = "Network error: " + e.message; });
}

/* ── Timeline ────────────────────────────────────────────── */
function runTimeline() {
  const fn = getFileName();
  if (!fn) { alert("Enter or click an evidence file name first."); return; }
  const cid = getCaseId();
  apiPost("/api/timeline", { file_name: fn, case_id: cid })
    .then(d => {
      if (!d.success) { alert("Error: " + d.error); return; }
      const tl = $("timelineList");
      if (!tl) return;
      tl.innerHTML = "";
      if (!d.timeline.length) {
        tl.innerHTML = '<p class="cf-muted mb-0">No timestamped events found in this file.</p>';
        return;
      }
      d.timeline.forEach(ev => {
        const div = document.createElement("div");
        div.className = "cf-timeline-item";
        div.innerHTML = `<strong>${ev.time_str}</strong> — ${ev.event}`;
        tl.appendChild(div);
      });
    })
    .catch(e => alert("Network error: " + e.message));
}

/* ── PCAP Analyzer ───────────────────────────────────────── */
function runAnalyzePcap() {
  const fn = getFileName();
  if (!fn) { alert("Enter or click an evidence file name first."); return; }
  switchTab("tabPcap");
  setLoading("pcapResult", "Analyzing PCAP file…");
  apiPost("/api/analyze_pcap", { file_name: fn })
    .then(d => {
      if (!d.success) { $("pcapResult").textContent = "Error: " + d.error; return; }
      const r = d.result;
      if (r.error) { $("pcapResult").textContent = "Error: " + r.error; return; }
      let out = "=== PCAP ANALYSIS RESULTS ===\n\n";
      out += `Connections:      ${r.connections.length}\n`;
      out += `DNS Queries:      ${r.dns_queries.length}\n`;
      out += `Suspicious IPs:   ${r.suspicious_ips.length}\n`;
      out += `Unusual Ports:    ${r.unusual_ports.length}\n\n`;
      if (r.suspicious_ips.length) {
        out += "--- Suspicious IPs ---\n";
        r.suspicious_ips.forEach(ip => { out += `  ${ip}\n`; });
      }
      if (r.dns_queries.length) {
        out += "\n--- DNS Queries (first 20) ---\n";
        r.dns_queries.slice(0, 20).forEach(q => { out += `  ${q}\n`; });
      }
      if (r.unusual_ports.length) {
        out += "\n--- Unusual Ports ---\n";
        r.unusual_ports.forEach(p => { out += `  ${p.ip}  port ${p.port}  (${p.protocol})\n`; });
      }
      if (r.connections.length) {
        out += `\n--- Connections (first 20 of ${r.connections.length}) ---\n`;
        r.connections.slice(0, 20).forEach(c => {
          out += `  ${c.source_ip}:${c.source_port} → ${c.destination_ip}:${c.destination_port}  [${c.protocol}]\n`;
        });
      }
      $("pcapResult").textContent = out;
    })
    .catch(e => { $("pcapResult").textContent = "Network error: " + e.message; });
}

/* ── Malware Scanner ─────────────────────────────────────── */
function runScanMalware() {
  const fn = getFileName();
  if (!fn) { alert("Enter or click an evidence file name first."); return; }
  switchTab("tabMalware");
  setLoading("malwareResult", "Scanning for malware indicators…");
  apiPost("/api/scan_malware", { file_name: fn })
    .then(d => {
      if (!d.success) { $("malwareResult").textContent = "Error: " + d.error; return; }
      const r = d.result;
      let out = "=== MALWARE SCAN RESULTS ===\n\n";
      out += `File:         ${r.file_name}\n`;
      out += `Suspicious:   ${r.is_suspicious ? "⚠️  YES" : "✅  NO"}\n`;
      out += `SHA-256:      ${r.sha256 || "—"}\n\n`;
      out += "--- Findings ---\n";
      (r.reasons || []).forEach(reason => { out += `  • ${reason}\n`; });
      $("malwareResult").textContent = out;
    })
    .catch(e => { $("malwareResult").textContent = "Network error: " + e.message; });
}

/* ── Metadata Extractor ──────────────────────────────────── */
function renderMetadata(r) {
  const el = $("metadataResult");
  if (!el) return;

  let html = `<div style="color:#d8b4fe;font-weight:700;margin-bottom:.6rem;">
    📄 ${r.file_type_label || "File"}</div>`;

  if (r.error) {
    el.innerHTML = html + `<span style="color:#f87171;">Error: ${r.error}</span>`;
    return;
  }

  // File info section
  if (r.file_info && Object.keys(r.file_info).length) {
    html += `<div style="color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.3rem;">FILE SYSTEM INFO</div>`;
    html += `<table style="width:100%;border-collapse:collapse;margin-bottom:1rem;">`;
    for (const [k, v] of Object.entries(r.file_info)) {
      html += `<tr>
        <td style="color:#94a3b8;padding:.18rem .6rem .18rem 0;width:140px;font-size:.8rem;">${k.replace(/_/g," ")}</td>
        <td style="color:#e2e8f0;font-size:.8rem;">${v}</td>
      </tr>`;
    }
    html += `</table>`;
  }

  // Type-specific metadata
  if (r.type_metadata && Object.keys(r.type_metadata).length) {
    html += `<div style="color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.3rem;">EXTRACTED METADATA</div>`;

    const renderObject = (obj, indent) => {
      let s = "";
      for (const [k, v] of Object.entries(obj)) {
        if (v === null || v === undefined) continue;
        if (typeof v === "object" && !Array.isArray(v)) {
          s += `<tr><td colspan="2" style="color:#d8b4fe;padding:.25rem .6rem .1rem 0;font-weight:600;font-size:.8rem;">${k}</td></tr>`;
          s += renderObject(v, indent + 1);
        } else {
          const val = Array.isArray(v) ? v.join(", ") : String(v);
          const truncated = val.length > 200 ? val.slice(0,200) + "…" : val;
          s += `<tr>
            <td style="color:#94a3b8;padding:.18rem .6rem .18rem ${indent*12}px;width:180px;font-size:.8rem;vertical-align:top;">${k}</td>
            <td style="color:#e2e8f0;font-size:.8rem;word-break:break-all;">${truncated}</td>
          </tr>`;
        }
      }
      return s;
    };

    html += `<table style="width:100%;border-collapse:collapse;">`;
    html += renderObject(r.type_metadata, 0);
    html += `</table>`;
  }

  el.innerHTML = html;
}

function runExtractMetadata() {
  const fn = getFileName();
  if (!fn) { alert("Enter or click an evidence file name first."); return; }
  switchTab("tabMetadata");
  $("metadataResult").innerHTML = '<span style="color:#94a3b8;">Extracting metadata…</span>';
  apiPost("/api/extract_metadata", { file_name: fn })
    .then(d => {
      if (!d.success) {
        $("metadataResult").innerHTML = `<span style="color:#f87171;">Error: ${d.error}</span>`;
        return;
      }
      renderMetadata(d.result);
    })
    .catch(e => {
      $("metadataResult").innerHTML = `<span style="color:#f87171;">Network error: ${e.message}</span>`;
    });
}

/* ── Email Phishing Detector ─────────────────────────────── */
function renderEmailPhishing(r) {
  const el = $("emailResult");
  if (!el) return;

  if (r.error) {
    el.innerHTML = `<span style="color:#f87171;">Error: ${r.error}</span>`;
    return;
  }

  const riskColors = { Low:"#86efac", Medium:"#fde68a", High:"#fb923c", Critical:"#f87171" };
  const riskColor  = riskColors[r.risk_level] || "#f1f5f9";

  let html = `
    <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;flex-wrap:wrap;">
      <div style="font-size:2rem;font-weight:800;color:${riskColor};">${r.risk_score}/100</div>
      <div>
        <div style="color:${riskColor};font-weight:700;font-size:1.1rem;">${r.risk_level} Risk</div>
        <div style="color:#94a3b8;font-size:.82rem;">${r.summary}</div>
      </div>
    </div>`;

  // Email headers
  if (r.email_headers) {
    html += `<div style="color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.3rem;">EMAIL HEADERS</div>`;
    html += `<table style="width:100%;border-collapse:collapse;margin-bottom:.8rem;">`;
    for (const [k, v] of Object.entries(r.email_headers)) {
      if (v && v !== "—") {
        html += `<tr>
          <td style="color:#94a3b8;padding:.15rem .5rem .15rem 0;width:140px;font-size:.78rem;">${k}</td>
          <td style="color:#e2e8f0;font-size:.78rem;word-break:break-all;">${v}</td>
        </tr>`;
      }
    }
    html += `</table>`;
  }

  // Header checks (findings)
  if (r.header_checks && r.header_checks.length) {
    html += `<div style="color:#f87171;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.3rem;">⚠ HEADER ISSUES</div>`;
    r.header_checks.forEach(c => {
      html += `<div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:.5rem .75rem;margin-bottom:.4rem;">
        <div style="color:#fca5a5;font-weight:600;font-size:.82rem;">${c.check} (+${c.risk_score} pts)</div>
        <div style="color:#e2e8f0;font-size:.78rem;margin-top:.15rem;">${c.finding}</div>
      </div>`;
    });
  }

  // Auth results
  if (r.auth_results) {
    const a = r.auth_results;
    const col = s => s === "pass" ? "#86efac" : s === "not found" ? "#94a3b8" : "#f87171";
    html += `<div style="color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin:.6rem 0 .3rem;">EMAIL AUTHENTICATION</div>
    <div style="display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.8rem;">
      <span style="background:rgba(2,6,23,.5);border:1px solid rgba(51,65,85,.8);border-radius:6px;padding:.25rem .6rem;font-size:.82rem;">
        SPF <strong style="color:${col(a.spf)};">${a.spf}</strong>
      </span>
      <span style="background:rgba(2,6,23,.5);border:1px solid rgba(51,65,85,.8);border-radius:6px;padding:.25rem .6rem;font-size:.82rem;">
        DKIM <strong style="color:${col(a.dkim)};">${a.dkim}</strong>
      </span>
      <span style="background:rgba(2,6,23,.5);border:1px solid rgba(51,65,85,.8);border-radius:6px;padding:.25rem .6rem;font-size:.82rem;">
        DMARC <strong style="color:${col(a.dmarc)};">${a.dmarc}</strong>
      </span>
    </div>`;
  }

  // URLs
  if (r.url_analysis) {
    const u = r.url_analysis;
    html += `<div style="color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.3rem;">URL ANALYSIS</div>
    <div style="color:#e2e8f0;font-size:.82rem;margin-bottom:.4rem;">Total URLs: ${u.total_urls}</div>`;
    if (u.ip_based_urls.length) {
      html += `<div style="color:#fb923c;font-size:.78rem;margin-bottom:.2rem;">IP-Based URLs (${u.ip_based_urls.length}):</div>`;
      u.ip_based_urls.forEach(url => {
        html += `<div style="color:#fdba74;font-size:.75rem;padding:.1rem 0;word-break:break-all;">  ${url}</div>`;
      });
    }
    if (u.shortener_urls.length) {
      html += `<div style="color:#fb923c;font-size:.78rem;margin-top:.3rem;margin-bottom:.2rem;">Shortener URLs (${u.shortener_urls.length}):</div>`;
      u.shortener_urls.forEach(url => {
        html += `<div style="color:#fdba74;font-size:.75rem;word-break:break-all;">  ${url}</div>`;
      });
    }
  }

  // Keywords
  if (r.keyword_analysis && r.keyword_analysis.match_count > 0) {
    html += `<div style="color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin:.6rem 0 .3rem;">PHISHING KEYWORDS (${r.keyword_analysis.match_count})</div>`;
    r.keyword_analysis.keyword_matches.forEach(kw => {
      html += `<span style="background:rgba(251,146,60,.12);border:1px solid rgba(251,146,60,.3);color:#fed7aa;border-radius:4px;padding:.15rem .4rem;font-size:.75rem;margin:.1rem;display:inline-block;">${kw}</span>`;
    });
  }

  // Attachments
  if (r.attachments && r.attachments.total_attachments > 0) {
    html += `<div style="color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin:.6rem 0 .3rem;">ATTACHMENTS (${r.attachments.total_attachments})</div>`;
    r.attachments.attachments.forEach(att => {
      const bad = att.is_dangerous;
      html += `<div style="background:${bad ? "rgba(239,68,68,.08)" : "rgba(2,6,23,.3)"};border:1px solid ${bad ? "rgba(239,68,68,.3)" : "rgba(51,65,85,.6)"};border-radius:6px;padding:.35rem .6rem;margin-bottom:.3rem;font-size:.8rem;">
        ${bad ? "🚨" : "📎"} <strong>${att.filename}</strong>
        <span style="color:#94a3b8;margin-left:.5rem;">${att.mime_type}</span>
        ${bad ? '<span style="color:#f87171;margin-left:.5rem;font-weight:600;">DANGEROUS</span>' : ""}
      </div>`;
    });
  }

  el.innerHTML = html;
}

function runAnalyzeEmail() {
  const fn = getFileName();
  if (!fn) { alert("Enter or click an evidence file name first."); return; }
  switchTab("tabEmail");
  $("emailResult").innerHTML = '<span style="color:#94a3b8;">Analyzing email for phishing indicators…</span>';
  apiPost("/api/analyze_email", { file_name: fn })
    .then(d => {
      if (!d.success) {
        $("emailResult").innerHTML = `<span style="color:#f87171;">Error: ${d.error}</span>`;
        return;
      }
      renderEmailPhishing(d.result);
    })
    .catch(e => {
      $("emailResult").innerHTML = `<span style="color:#f87171;">Network error: ${e.message}</span>`;
    });
}

/* ── PDF Report Generator ────────────────────────────────── */
function setupReportGenerator() {
  const btn = $("btnGenerateReport");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const cid = getCaseId();
    if (!cid) { alert("Select a case first."); return; }
    const conclusion = ($("reportConclusion") || {}).value || "";
    const status = $("reportStatus");
    if (status) status.innerHTML = '<span class="spinner-border spinner-border-sm text-success me-2"></span>Generating PDF…';
    btn.disabled = true;

    apiPost("/api/generate_report", { case_id: cid, conclusion })
      .then(d => {
        btn.disabled = false;
        if (!d.success) {
          if (status) status.innerHTML = `<span class="text-danger">Error: ${d.error}</span>`;
          return;
        }
        const url = `/reports/${encodeURIComponent(d.report_file)}`;
        if (status) status.innerHTML = `<a href="${url}" target="_blank" class="btn btn-cf-ghost btn-sm">
          <i class="bi bi-file-pdf"></i> Open PDF Report
        </a>`;
      })
      .catch(e => {
        btn.disabled = false;
        if (status) status.innerHTML = `<span class="text-danger">Network error: ${e.message}</span>`;
      });
  });
}

/* ── Init ─────────────────────────────────────────────────── */
function init() {
  setupEvidenceRows();
  setupCaseSelector();
  setupNewCase();
  setupReportGenerator();

  // Wire analysis buttons
  const wire = (id, fn) => { const el = $(id); if (el) el.addEventListener("click", fn); };
  wire("btnAnalyzeLog",      runAnalyzeLog);
  wire("btnTimeline",        runTimeline);
  wire("btnAnalyzePcap",     runAnalyzePcap);
  wire("btnScanMalware",     runScanMalware);
  wire("btnExtractMetadata", runExtractMetadata);
  wire("btnAnalyzeEmail",    runAnalyzeEmail);
}

document.addEventListener("DOMContentLoaded", init);
