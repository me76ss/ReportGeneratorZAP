#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenStack OWASP ZAP Enterprise Security Dashboard Generator v03
──────────────────────────────────────────────────────────────
Aggregates multiple OWASP ZAP HTML reports (ZAP 2.17.0 structure) and
produces a bilingual (Persian/English) executive dashboard with inline
SVG charts, a service/risk matrix and a fully filterable alerts table.

Parser notes (real ZAP table.results structure):
  Every alert is its own <table class="results"> block:
    <tr>
      <th class="risk-3"><a id="40018"></a><div>High</div></th>
      <th>Alert Title</th>
    </tr>
    <tr><td class="indent1"><a href="http://host:port/...">URL</a></td></tr>
    <tr><td class="indent2">Method</td><td>GET</td></tr>
    <tr><td class="indent2">Parameter</td><td>param</td></tr>
    ...
  The parser splits on ALL such table blocks (not just the first one).

Usage:
  python zap_dashboard_generator_v03.py report1.html report2.html -o dashboard.html
"""

import argparse
import os
import re
import sys
from datetime import datetime
from html import escape, unescape
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ── OpenStack service port mapping ──────────────────────────────────────────
SERVICE_PORTS = {
    "5000":  ("Keystone",  "Identity"),
    "8774":  ("Nova",      "Compute"),
    "9696":  ("Neutron",   "Network"),
    "8780":  ("Placement", "Placement"),
    "9292":  ("Glance",    "Image"),
    "8776":  ("Cinder",    "Block Storage"),
    "15868": ("Masakari",  "Instance HA"),
    "9311":  ("Barbican",  "Key Manager"),
    "8004":  ("Heat",      "Orchestration"),
    "9998":  ("Skyline",   "Dashboard"),
    "8000":  ("Heat-CFN",  "CloudFormation"),
}

RISK_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
RISK_CLASS_NUMBER = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}

RISK_FA = {
    "High": "بحرانی",
    "Medium": "متوسط",
    "Low": "کم‌اهمیت",
    "Informational": "اطلاعاتی",
}

RISK_CSS = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "informational",
}


def _risk_from_text(text):
    t = (text or "").lower()
    if "high" in t:
        return "High"
    if "medium" in t or "متوسط" in t:
        return "Medium"
    if "low" in t:
        return "Low"
    return "Informational"


def normalize_risk(risk_class_number, raw_text):
    """Resolve risk from th class risk-X first, then from the div text."""
    risk = RISK_CLASS_NUMBER.get(str(risk_class_number))
    if risk:
        return risk
    return _risk_from_text(raw_text)


def detect_service(url_str):
    """Return (service_name, service_type, port) inferred from a URL."""
    try:
        parsed = urlparse(url_str)
        port = parsed.port
        if port and str(port) in SERVICE_PORTS:
            name, stype = SERVICE_PORTS[str(port)]
            return name, stype, int(port)
    except Exception:
        pass
    # Fallback 1: explicit :port anywhere in the URL string
    m = re.search(r":(\d{2,5})(?:[/:?#]|$)", url_str or "")
    if m and m.group(1) in SERVICE_PORTS:
        name, stype = SERVICE_PORTS[m.group(1)]
        return name, stype, int(m.group(1))
    # Fallback 2: service name embedded in the URL
    lower = (url_str or "").lower()
    for p, (n, st) in SERVICE_PORTS.items():
        if n.lower() in lower:
            return n, st, int(p)
    return "Unknown", "N/A", 0


# ── Parsing: BeautifulSoup path ─────────────────────────────────────────────
def _parse_bs4(html_text):
    alerts = []
    # soup = BeautifulSoup(html_text, "html.parser")
    soup = BeautifulSoup(html_text, "lxml")
    # for table in soup.find_all("table", class_=re.compile(r"\bresults\b")):
    for table in soup.find_all("table", class_=lambda c: c and "results" in c):
        rows = table.find_all("tr")
        if not rows:
            continue
        header = rows[0]
        ths = header.find_all("th")
        if not ths:
            continue
        risk_th = ths[0]
        a_tag = risk_th.find("a", id=True)
        plugin_id = a_tag["id"].strip() if a_tag else "0"
        risk_div = risk_th.find("div")
        raw_risk = risk_div.get_text(" ", strip=True) if risk_div else risk_th.get_text(" ", strip=True)
        risk_classes = " ".join(risk_th.get("class") or [])
        rm = re.search(r"risk-([0-9])", risk_classes)
        risk = normalize_risk(rm.group(1) if rm else None, raw_risk)
        title = unescape(ths[1].get_text(" ", strip=True)) if len(ths) > 1 else "Unknown Alert"
        title = re.sub(r"\s+", " ", title).strip()

        instances = []
        current = None
        # for tr in rows[1:]:
        #     tds = tr.find_all("td")
        #     if not tds:
        #         continue
        #     first = tds[0]
        #     cls = set(first.get("class") or [])
        #     if "indent1" in cls:
        #         a = first.find("a", href=True)
        #         url = unescape(a["href"]).strip() if a else unescape(first.get_text(" ", strip=True)).strip()
        for row in rows[1:]:
            cells = row.find_all("td")
            if not cells:
                continue
            first = cells[0]
            if "indent1" in first.get("class", []):
                label = first.get_text(strip=True)
                if label == "URL" and len(cells) > 1:
                    a = cells[1].find("a", href=True)
                    url = a["href"] if a else cells[1].get_text(strip=True)
                else:
                    url = first.get_text(strip=True)
                # ادامه منطق فعلی برای Method/Parameter تغییر نمی‌کند
                if not url:
                    current = None
                    continue
                current = {"url": url, "method": "GET", "parameter": "-"}
                instances.append(current)
            # elif "indent2" in cls and current is not None:
            #     label = first.get_text(" ", strip=True).lower()
            #     value = unescape(tds[1].get_text(" ", strip=True)).strip() if len(tds) > 1 else ""
            elif "indent2" in (first.get("class") or []) and current is not None:
                label = first.get_text(" ", strip=True).lower()
                value = unescape(cells[1].get_text(" ", strip=True)).strip() if len(cells) > 1 else ""
                if label == "method" and value:
                    current["method"] = value.upper()
                elif label == "parameter":
                    current["parameter"] = value or "-"
        if instances:
            alerts.append({
                "plugin_id": plugin_id,
                "risk": risk,
                "name": title,
                "instances": instances,
            })
    return alerts


# ── Parsing: regex fallback path ────────────────────────────────────────────
def _strip_tags(fragment):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment or "")).strip()


def _parse_regex(html_text):
    alerts = []
    tables = re.split(r'(?i)<table[^>]*\bclass="[^"]*results[^"]*"[^>]*>', html_text)
    for chunk in tables[1:]:
        end = chunk.lower().find("</table>")
        if end != -1:
            chunk = chunk[:end]
        m = re.search(
            r'(?is)<tr[^>]*>\s*<th[^>]*class="risk-([0-9])"[^>]*>(.*?)</th>\s*<th[^>]*>(.*?)</th>',
            chunk,
        )
        if not m:
            continue
        risk_num, risk_inner, title_html = m.groups()
        pid_m = re.search(r'(?i)<a\s+id="(\d+)"', risk_inner)
        plugin_id = pid_m.group(1) if pid_m else "0"
        risk = normalize_risk(risk_num, _strip_tags(risk_inner))
        title = unescape(_strip_tags(title_html)) or "Unknown Alert"

        instances = []
        segments = re.split(r'(?i)<td\s+class="indent1"[^>]*>', chunk)
        for seg in segments[1:]:
            url_m = re.search(r'(?is)<a\s+href="([^"]+)"', seg)
            if url_m:
                url = unescape(url_m.group(1)).strip()
            else:
                td_end = seg.lower().find("</td>")
                url = unescape(_strip_tags(seg[:td_end])) if td_end != -1 else ""
            if not url:
                continue
            method, parameter = "GET", "-"
            mm = re.search(
                r'(?is)<td\s+class="indent2"[^>]*>\s*Method\s*</td>\s*<td[^>]*>(.*?)</td>', seg
            )
            if mm and _strip_tags(mm.group(1)):
                method = _strip_tags(mm.group(1)).upper()
            pm = re.search(
                r'(?is)<td\s+class="indent2"[^>]*>\s*Parameter\s*</td>\s*<td[^>]*>(.*?)</td>', seg
            )
            if pm:
                parameter = _strip_tags(pm.group(1)) or "-"
            instances.append({"url": url, "method": method, "parameter": parameter})
        if instances:
            alerts.append({
                "plugin_id": plugin_id,
                "risk": risk,
                "name": title,
                "instances": instances,
            })
    return alerts


def parse_zap_html(file_path):
    """
    Extract alerts from a single ZAP HTML report using table.results structure.
    Returns a list of dicts:
      {'plugin_id': str, 'risk': str, 'name': str,
       'instances': [{'url': str, 'method': str, 'parameter': str}, ...]}
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        html_text = f.read()
    if HAS_BS4:
        try:
            return _parse_bs4(html_text)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"   ⚠ BeautifulSoup failed ({exc}); falling back to regex.",
                  file=sys.stderr)
    return _parse_regex(html_text)


def aggregate_alerts(file_paths):
    """
    Parse multiple ZAP HTML files, print per-file summaries and merge alerts.
    Deduplication key: (plugin_id, url, parameter).
    Returns (all_alerts, scanned_sites) where scanned_sites is a set of
    (host, port) tuples.
    """
    all_alerts_raw = []
    scanned_sites = set()

    for fp in file_paths:
        if not os.path.isfile(fp):
            print(f"⚠️  File not found, skipped: {fp}", file=sys.stderr)
            continue
        alerts = parse_zap_html(fp)
        all_alerts_raw.extend(alerts)
        instance_total = sum(len(a["instances"]) for a in alerts)
        print(f"\n📄 {fp}  →  {len(alerts)} alert type(s), "
              f"{instance_total} instance(s)")
        if alerts:
            print("   " + "─" * 72)
            for a in sorted(alerts, key=lambda x: -RISK_ORDER.get(x["risk"], 0)):
                print(f"   [{a['risk']:<13}] {a['name']:<55} "
                      f"{len(a['instances']):>3} instance(s)")
            print("   " + "─" * 72)
        for alert in alerts:
            for inst in alert["instances"]:
                try:
                    parsed = urlparse(inst["url"])
                    if parsed.hostname:
                        port = parsed.port or (443 if parsed.scheme == "https" else 80)
                        scanned_sites.add((parsed.hostname, port))
                except Exception:
                    pass

    # Deduplicate by (plugin_id, url, parameter)
    merged = {}
    for alert in all_alerts_raw:
        pid = alert["plugin_id"]
        for inst in alert["instances"]:
            key = (pid, inst["url"], inst["parameter"])
            if key not in merged:
                merged[key] = {
                    "plugin_id": pid,
                    "risk": alert["risk"],
                    "name": alert["name"],
                    "url": inst["url"],
                    "method": inst["method"],
                    "parameter": inst["parameter"],
                }
    all_alerts = list(merged.values())
    all_alerts.sort(key=lambda x: (-RISK_ORDER.get(x["risk"], 0), x["name"], x["url"]))
    return all_alerts, scanned_sites


def compute_stats(all_alerts):
    """Return (risk_counts, service_stats, type_counts)."""
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    service_stats = {}
    type_counts = {}

    for alert in all_alerts:
        risk = alert["risk"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        svc_name, svc_type, port = detect_service(alert["url"])
        if svc_name not in service_stats:
            service_stats[svc_name] = {
                "service_type": svc_type, "port": port,
                "high": 0, "medium": 0, "low": 0, "informational": 0,
                "total": 0,
            }
        service_stats[svc_name][risk.lower()] += 1
        service_stats[svc_name]["total"] += 1
        type_counts[alert["name"]] = type_counts.get(alert["name"], 0) + 1

    return risk_counts, service_stats, type_counts


# ── HTML generation ─────────────────────────────────────────────────────────
CSS = """
:root {
  --bg: #0f172a;
  --bg-soft: #111827;
  --panel: #1e1b4b;
  --panel-solid: #1e293b;
  --line: rgba(148, 163, 184, 0.16);
  --text: #e2e8f0;
  --text-strong: #f1f5f9;
  --muted: #94a3b8;
  --muted-2: #64748b;
  --grad: linear-gradient(135deg, #4f46e5, #7c3aed 50%, #2563eb);
  --cyan: #22d3ee;
  --pink: #f472b6;
  --high: #fb7185;
  --medium: #fbbf24;
  --low: #38bdf8;
  --info: #94a3b8;
  --success: #34d399;
  --focus: #22d3ee;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Vazirmatn', 'Inter', Tahoma, sans-serif;
  background:
    radial-gradient(circle at 15% 0%, #312e81, transparent 32%),
    radial-gradient(circle at 95% 18%, #1e3a8a, transparent 40%),
    var(--bg);
  color: var(--text);
  line-height: 1.7;
  padding: 2rem 1.25rem;
  min-height: 100vh;
}
.wrap { max-width: 1440px; margin: 0 auto; }
h1 {
  font-size: clamp(1.6rem, 3.5vw, 2.5rem);
  font-weight: 700;
  background: var(--grad);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}
.hero {
  background: linear-gradient(145deg, #312e81cc, #1e1b4bcc, #1d4ed855);
  border: 1px solid var(--line);
  border-radius: 24px;
  padding: 2.5rem;
  margin-bottom: 2rem;
  position: relative;
  overflow: hidden;
  backdrop-filter: blur(14px);
}
.hero::after {
  content: '';
  position: absolute;
  width: 400px; height: 400px;
  border-radius: 50%;
  background: radial-gradient(circle, #4f46e588, transparent 70%);
  top: -160px; inset-inline-end: -160px;
  pointer-events: none;
  filter: blur(80px);
}
.kpis {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 1.2rem;
  margin-bottom: 2rem;
}
@media (max-width: 1100px) { .kpis { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 680px)  { .kpis { grid-template-columns: repeat(2, 1fr); } }
.card {
  background: linear-gradient(145deg, #1e1b4be0, #111827cc);
  border: 1px solid var(--line);
  border-radius: 20px;
  padding: 1.5rem;
  backdrop-filter: blur(14px);
}
.kpi-card { text-align: center; }
.kpi-card .label { font-size: 0.9rem; color: var(--muted); margin-bottom: 0.4rem; }
.kpi-card .value { font-size: 2.3rem; font-weight: 700; line-height: 1.2; }
.kpi-card.high  .value { color: var(--high); }
.kpi-card.med   .value { color: var(--medium); }
.kpi-card.low   .value { color: var(--low); }
.kpi-card.info  .value { color: var(--info); }
.kpi-card.clean .value { color: var(--success); }
.charts { display: grid; grid-template-columns: 1fr 1.6fr; gap: 1.5rem; margin-bottom: 2rem; }
@media (max-width: 950px) { .charts { grid-template-columns: 1fr; } }
.chart-title { font-size: 1.15rem; font-weight: 600; margin-bottom: 1rem; color: #cbd5e1; }
.donut-wrap { display: flex; flex-direction: column; align-items: center; }
svg.donut { max-width: 210px; width: 100%; display: block; }
.donut .track { fill: none; stroke: #1e293b; stroke-width: 24; }
.donut .slice {
  fill: none;
  stroke-width: 24;
  stroke-linecap: butt;
  transition: stroke-dashoffset 1s ease;
}
.donut .slice.high     { stroke: var(--high); }
.donut .slice.medium   { stroke: var(--medium); }
.donut .slice.low      { stroke: var(--low); }
.donut-center-num { fill: #f1f5f9; font-size: 2.1rem; font-weight: 700; text-anchor: middle; }
.donut-center-cap { fill: var(--muted); font-size: 0.72rem; text-anchor: middle; }
.legend { display: flex; flex-direction: column; gap: 0.5rem; margin-top: 1.1rem; }
.swatch { display: flex; align-items: center; gap: 0.6rem; font-size: 0.95rem; color: #cbd5e1; }
.swatch-color { width: 16px; height: 16px; border-radius: 5px; flex: none; }
.swatch-color.high     { background: var(--high); }
.swatch-color.medium   { background: var(--medium); }
.swatch-color.low      { background: var(--low); }
.swatch-color.info     { background: var(--info); }
.bar.mixed { fill: #a78bfa; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 900px; }
thead th {
  background: linear-gradient(135deg, #1e293b, #334155);
  padding: 0.9rem 1rem;
  text-align: right;
  font-weight: 600;
  color: #e2e8f0;
  border-bottom: 2px solid var(--line);
  white-space: nowrap;
}
tbody td {
  padding: 0.85rem 1rem;
  color: #cbd5e1;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
tbody tr { transition: background 0.2s; }
tbody tr:hover { background: rgba(79, 70, 229, 0.12); }
.port-code {
  display: inline-block;
  background: #0f172a;
  color: var(--cyan);
  padding: 0.25rem 0.6rem;
  border-radius: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  border: 1px solid var(--line);
}
.status-pill {
  display: inline-block;
  padding: 0.35rem 0.85rem;
  border-radius: 999px;
  font-size: 0.85rem;
  font-weight: 600;
  white-space: nowrap;
}
.status-high { background: rgba(251, 113, 133, 0.16); color: var(--high); }
.status-med  { background: rgba(251, 191, 36, 0.16);  color: var(--medium); }
.status-low  { background: rgba(56, 189, 248, 0.16);  color: var(--low); }
.status-clean{ background: rgba(52, 211, 153, 0.16);  color: var(--success); }
.risk-badge {
  display: inline-block;
  padding: 0.25rem 0.65rem;
  border-radius: 8px;
  font-size: 0.83rem;
  font-weight: 600;
  white-space: nowrap;
}
.risk-badge.high          { background: rgba(251, 113, 133, 0.18); color: var(--high); }
.risk-badge.medium        { background: rgba(251, 191, 36, 0.18);  color: var(--medium); }
.risk-badge.low           { background: rgba(56, 189, 248, 0.18);  color: var(--low); }
.risk-badge.informational { background: rgba(148, 163, 184, 0.18); color: #cbd5e1; }
.method-tag {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 6px;
  font-size: 0.78rem;
  font-weight: 600;
  background: #0f172a;
  color: var(--cyan);
  font-family: 'JetBrains Mono', monospace;
  border: 1px solid var(--line);
}
code {
  background: #0f172a;
  color: var(--pink);
  padding: 0.15rem 0.45rem;
  border-radius: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  word-break: break-all;
}
.alert-url {
  color: #a5b4fc;
  text-decoration: none;
  font-size: 0.9rem;
  word-break: break-all;
  direction: ltr;
  unicode-bidi: embed;
  display: inline-block;
}
.alert-url:hover { color: var(--cyan); text-decoration: underline; }
.filters { margin-bottom: 1.2rem; display: flex; gap: 0.8rem; flex-wrap: wrap; align-items: center; }
.filters input[type="search"], .filters select {
  padding: 0.7rem 1rem;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: #0f172a;
  color: var(--text);
  font-family: inherit;
  font-size: 0.95rem;
}
.filters input[type="search"] { flex: 1 1 260px; min-width: 200px; }
.filters input:focus, .filters select:focus {
  outline: 2px solid var(--focus);
  outline-offset: 1px;
  border-color: var(--focus);
}
.risk-btn {
  padding: 0.55rem 1rem;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: #0f172a;
  color: #cbd5e1;
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}


.bar-svg { width: 100%; display: block; }
.axis-label {
    font-size: 13px;
    font-family: 'Vazirmatn', sans-serif;
    fill: #94a3b8;
    font-weight: 500;
}
.bar-value {
    font-size: 12px;
    font-family: 'Vazirmatn', sans-serif;
    fill: #cbd5e1;
    font-weight: 600;
}
.gridline {
    stroke: rgba(255,255,255,0.06);
    stroke-width: 1;
}
.bar { opacity: 0.9; transition: opacity 0.15s; }
.bar:hover { opacity: 1; }
.bar.high   { fill: #ef4444; }
.bar.medium { fill: #f59e0b; }
.bar.low    { fill: #3b82f6; }
.bar.none   { fill: #6b7280; }




.risk-btn:hover { border-color: #64748b; }
.risk-btn.active { color: #fff; }
.risk-btn.active[data-risk="all"]            { background: #4f46e5; border-color: #4f46e5; }
.risk-btn.active[data-risk="High"]           { background: #be123c; border-color: #be123c; }
.risk-btn.active[data-risk="Medium"]         { background: #b45309; border-color: #b45309; }
.risk-btn.active[data-risk="Low"]            { background: #0369a1; border-color: #0369a1; }
.risk-btn.active[data-risk="Informational"]  { background: #475569; border-color: #475569; }
.counter { color: var(--muted); font-size: 0.9rem; }
.empty-row td { text-align: center; color: var(--muted-2); padding: 2rem; }
footer { text-align: center; color: var(--muted-2); font-size: 0.85rem; margin-top: 2.5rem; }
a:focus-visible, button:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
  border-radius: 8px;
}
@media print {
  body { background: #fff; color: #000; }
  .card, .hero { border: 1px solid #ddd; background: #fff; }
  .filters { display: none; }
}
"""

JS = """
(function () {
  'use strict';
  var searchInput = document.getElementById('searchInput');
  var serviceSelect = document.getElementById('serviceSelect');
  var riskButtons = document.querySelectorAll('.risk-btn');
  var rows = document.querySelectorAll('#alertsTable tbody tr[data-row]');
  var counter = document.getElementById('visibleCount');
  var activeRisk = 'all';

  function rowVisible(row) {
    var q = (searchInput.value || '').toLowerCase().trim();
    var svc = serviceSelect.value;
    var text = row.getAttribute('data-search') || '';
    var svcVal = row.getAttribute('data-service') || '';
    var risk = row.getAttribute('data-risk') || '';
    var okText = !q || text.indexOf(q) !== -1;
    var okSvc = svc === 'all' || svcVal === svc;
    var okRisk = activeRisk === 'all' || risk === activeRisk;
    return okText && okSvc && okRisk;
  }

  function applyFilters() {
    var visible = 0;
    rows.forEach(function (row) {
      var show = rowVisible(row);
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    if (counter) counter.textContent = visible;
    var emptyRow = document.getElementById('emptyRow');
    if (emptyRow) emptyRow.style.display = visible === 0 ? '' : 'none';
  }

  searchInput.addEventListener('input', applyFilters);
  serviceSelect.addEventListener('change', applyFilters);
  riskButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      riskButtons.forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      activeRisk = btn.getAttribute('data-risk');
      applyFilters();
    });
  });
  applyFilters();
})();
"""


def build_html_dashboard(all_alerts, scanned_sites, output_path, report_count=0):
    """Generate the full self-contained RTL Persian dark-theme dashboard."""
    risk_counts, service_stats, type_counts = compute_stats(all_alerts)

    total_alerts = len(all_alerts)
    high_count = risk_counts["High"]
    medium_count = risk_counts["Medium"]
    low_count = risk_counts["Low"]
    info_count = risk_counts["Informational"]

    service_list = sorted(
        service_stats.items(),
        key=lambda x: (-x[1]["high"], -x[1]["medium"], -x[1]["low"], -x[1]["total"]),
    )

    now = datetime.now()
    date_fa = now.strftime("%Y/%m/%d")
    date_en = now.strftime("%Y-%m-%d %H:%M")

    # ── Donut chart data (Informational excluded from donut, counted in KPI) ──
    donut_total = high_count + medium_count + low_count
    donut_segments = [
        ("high", high_count, RISK_FA["High"]),
        ("medium", medium_count, RISK_FA["Medium"]),
        ("low", low_count, RISK_FA["Low"]),
    ]
    donut_segments = [s for s in donut_segments if s[1] > 0]
    donut_svg_parts = [
        '<circle class="track" cx="100" cy="100" r="72" pathLength="100"></circle>'
    ]
    if donut_total > 0 and donut_segments:
        offset = 0.0
        for cls, count, _fa in donut_segments:
            seg_len = (count / donut_total) * 100.0
            donut_svg_parts.append(
                f'<circle class="slice {cls}" cx="100" cy="100" r="72" '
                f'pathLength="100" stroke-dasharray="{seg_len:.2f} {100 - seg_len:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}"></circle>'
            )
            offset += seg_len
    donut_center_label = "کل هشدارها" if donut_total == 0 else "بدون اطلاعاتی"
    donut_aria = (f"توزیع شدت: {high_count} بحرانی، {medium_count} متوسط، "
                  f"{low_count} کم‌اهمیت (و {info_count} اطلاعاتی)")

    # ── Horizontal bar chart: per-service alert counts, top 10 ──
    ##############################################################################3
    # bar_services = service_list[:10]
    # bar_max = max([s[1]["total"] for s in bar_services], default=1)
    # row_h = 26
    # label_w = 120
    # value_w = 46
    # chart_w = 640
    # bar_area_w = chart_w - label_w - value_w
    # chart_h = 18 + max(len(bar_services), 1) * row_h + 8
    # ── Horizontal bar chart: per-service alert counts, top 10 ──
    ##########################################################################
    bar_services = service_list[:10]
    bar_max = max([s[1]["total"] for s in bar_services], default=1)
    row_h = 34                   # از 26 به 34 — فاصله بین barها بیشتر
    label_w = 100                # از 120 به 150 — جا برای نام کامل
    value_w = 46
    chart_w = 680                # کمی عریض‌تر
    bar_area_w = chart_w - label_w - value_w
    chart_h = 24 + max(len(bar_services), 1) * row_h + 12
    #############################################################################
    bar_svg_parts = [
        f'<svg class="bar-svg" viewBox="0 0 {chart_w} {chart_h}" role="img" '
        f'aria-label="تعداد هشدار به تفکیک سرویس">'
    ]
    for i in range(5):
        x = label_w + (bar_area_w / 5.0) * i
        bar_svg_parts.append(
            f'<line class="gridline" x1="{x:.1f}" y1="4" x2="{x:.1f}" y2="{chart_h - 8}"></line>'
        )
    if not bar_services:
        bar_svg_parts.append(
            f'<text class="axis-label" x="{chart_w / 2}" y="{chart_h / 2}" text-anchor="middle">داده‌ای موجود نیست</text>'
        )
    ###############################################################################################################
    # for idx, (svc_name, stats) in enumerate(bar_services):
    #     y = 10 + idx * row_h
    #     w = max((stats["total"] / bar_max) * bar_area_w, 3)
    #     risk_cls = ("high" if stats["high"] > 0
    #                 else "medium" if stats["medium"] > 0
    #                 else "low" if stats["low"] > 0
    #                 else "none")
    #     bar_svg_parts.append(
    #         f'<text class="axis-label" x="{label_w - 8}" y="{y + 14}" text-anchor="end">{escape(svc_name)}</text>'
    #     )
    #     bar_svg_parts.append(
    #         f'<rect class="bar {risk_cls}" x="{label_w}" y="{y}" width="{w:.1f}" '
    #         f'height="{row_h - 10}" rx="5">'
    #         f'<title>{escape(svc_name)}: {stats["total"]} هشدار</title></rect>'
    #     )
    #     bar_svg_parts.append(
    #         f'<text class="bar-value" x="{label_w + w + 6:.1f}" y="{y + 14}">{stats["total"]}</text>'
    #     )
        #############################################################################################
    for idx, (svc_name, stats) in enumerate(bar_services):
        y = 14 + idx * row_h
        w = max((stats["total"] / bar_max) * bar_area_w, 4)
        risk_cls = ("high" if stats["high"] > 0
                    else "medium" if stats["medium"] > 0
                    else "low" if stats["low"] > 0
                    else "none")
        #########################################################################################
        # bar_svg_parts.append(
        #     f'<text class="axis-label" x="{label_w - 10}" y="{y + 16}" '
        #     f'text-anchor="end" dominant-baseline="middle">{escape(svc_name)}</text>'
        # )
        bar_svg_parts.append(
        f'<text class="axis-label" x="{label_w - 65}" y="{y + 16}" '  # ←← از -10 به -5
        f'text-anchor="end" dominant-baseline="middle">{escape(svc_name)}</text>'
        )
        #########################################################################################
        bar_svg_parts.append(
            f'<rect class="bar {risk_cls}" x="{label_w}" y="{y + 4}" width="{w:.1f}" '
            f'height="{row_h - 12}" rx="4">'
            f'<title>{escape(svc_name)}: {stats["total"]} هشدار</title></rect>'
        )
        bar_svg_parts.append(
            f'<text class="bar-value" x="{label_w + w + 12:.1f}" y="{y + 16}" '
            f'dominant-baseline="middle">{stats["total"]}</text>'
        )
        ########################################################################################################
    bar_svg_parts.append("</svg>")

    # ── Service/risk matrix table rows ──
    matrix_rows = []
    for svc_name, stats in service_list:
        port = stats["port"] if stats["port"] else "N/A"
        h, m, l = stats["high"], stats["medium"], stats["low"]
        if h > 0:
            status = '<span class="status-pill status-high">⚠ نیازمند اقدام فوری</span>'
        elif m > 0:
            status = '<span class="status-pill status-med">نیازمند بررسی</span>'
        elif l > 0:
            status = '<span class="status-pill status-low">قابل قبول</span>'
        else:
            status = '<span class="status-pill status-clean">✓ پاک</span>'
        matrix_rows.append(
            "<tr>"
            f"<td><strong>{escape(svc_name)}</strong><br>"
            f"<small style='color:var(--muted)'>{escape(stats['service_type'])}</small></td>"
            f"<td><span class='port-code'>{escape(str(port))}</span></td>"
            f"<td style='color:var(--high);font-weight:600'>{h}</td>"
            f"<td style='color:var(--medium);font-weight:600'>{m}</td>"
            f"<td style='color:var(--low);font-weight:600'>{l}</td>"
            f"<td>{stats['informational']}</td>"
            f"<td><strong>{stats['total']}</strong></td>"
            f"<td>{status}</td>"
            "</tr>"
        )

    # ── Service dropdown options ──
    service_options = ['<option value="all">همه سرویس‌ها</option>']
    for svc_name, _stats in service_list:
        service_options.append(
            f'<option value="{escape(svc_name)}">{escape(svc_name)}</option>'
        )

    # ── Alerts table rows ──
    alert_rows = []
    for a in all_alerts:
        svc_name, svc_type, port = detect_service(a["url"])
        param_html = escape(a["parameter"]) if a["parameter"] and a["parameter"] != "-" else "—"
        search_blob = escape(f"{a['url']} {a['name']} {a['parameter']} {a['method']}".lower(), quote=True)
        alert_rows.append(
            "<tr data-row "
            f"data-risk=\"{a['risk']}\" "
            f"data-service=\"{escape(svc_name)}\" "
            f"data-search=\"{search_blob}\">"
            f"<td><span class='risk-badge {RISK_CSS[a['risk']]}'>{RISK_FA[a['risk']]}</span></td>"
            f"<td><strong>{escape(a['name'])}</strong><br>"
            f"<small style='color:var(--muted-2)'>Plugin ID: {escape(a['plugin_id'])}</small></td>"
            f"<td>{escape(svc_name)}</td>"
            f"<td><span class='method-tag'>{escape(a['method'])}</span></td>"
            f"<td>{param_html}</td>"
            f"<td><a class='alert-url' href='{escape(a['url'], quote=True)}' target='_blank' rel='noopener noreferrer'>"
            f"{escape(a['url'])}</a></td>"
            "</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>نمای مدیریتی امنیت سرویس‌های OpenStack — گزارش OWASP ZAP</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&family=Inter:wght@400;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

<div class="hero">
<h1>🔒 نمای مدیریتی امنیت سرویس‌های OpenStack</h1>
<p style="font-size:1.05rem; margin-top:0.5rem;">گزارش تجمیعی OWASP ZAP — تحلیل آسیب‌پذیری‌های زیرساخت ابری</p>
<p style="margin-top:0.4rem; color:var(--muted-2); font-size:0.9rem;">
📅 تاریخ تولید: {date_fa} ({date_en}) &nbsp;|&nbsp; 📁 تعداد گزارش‌های ورودی: {report_count} &nbsp;|&nbsp; 🌐 سرویس‌های اسکن‌شده: {len(scanned_sites)}</p>
</div>

<div class="kpis">
<div class="card kpi-card high">
<div class="label">🔴 بحرانی (High)</div>
<div class="value">{high_count}</div>
</div>
<div class="card kpi-card med">
<div class="label">🟡 متوسط (Medium)</div>
<div class="value">{medium_count}</div>
</div>
<div class="card kpi-card low">
<div class="label">🔵 کم‌اهمیت (Low)</div>
<div class="value">{low_count}</div>
</div>
<div class="card kpi-card info">
<div class="label">⚪ اطلاعاتی (Informational)</div>
<div class="value">{info_count}</div>
</div>
<div class="card kpi-card clean">
<div class="label">✅ سرویس‌های اسکن‌شده</div>
<div class="value">{len(scanned_sites)}</div>
</div>
</div>

<div class="charts">
<div class="card donut-wrap">
<div class="chart-title" style="align-self:flex-start;">📊 توزیع شدت هشدارها</div>
<svg class="donut" viewBox="0 0 200 200" role="img" aria-label="{donut_aria}">
{chr(10).join(donut_svg_parts)}
<text class="donut-center-num" x="100" y="97">{donut_total}</text>
<text class="donut-center-cap" x="100" y="122">{donut_center_label}</text>
</svg>
<div class="legend">
<div class="swatch"><div class="swatch-color high"></div><span>بحرانی: {high_count}</span></div>
<div class="swatch"><div class="swatch-color medium"></div><span>متوسط: {medium_count}</span></div>
<div class="swatch"><div class="swatch-color low"></div><span>کم‌اهمیت: {low_count}</span></div>
<div class="swatch"><div class="swatch-color info"></div><span>اطلاعاتی: {info_count} (خارج از نمودار)</span></div>
</div>
</div>

<div class="card">
<div class="chart-title">📈 تعداد هشدار به تفکیک سرویس (۱۰ سرویس برتر)</div>
{chr(10).join(bar_svg_parts)}
</div>
</div>

<div class="card">
<h2 class="chart-title">🗂 ماتریس سرویس و ریسک</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>سرویس</th><th>پورت</th><th>بحرانی</th><th>متوسط</th><th>کم‌اهمیت</th><th>اطلاعاتی</th><th>کل</th><th>وضعیت</th>
</tr>
</thead>
<tbody>
{chr(10).join(matrix_rows) if matrix_rows else '<tr><td colspan="8" style="text-align:center;color:var(--muted)">داده‌ای موجود نیست</td></tr>'}
</tbody>
</table>
</div>
</div>

<div class="card">
<h2 class="chart-title">🔎 فهرست کامل هشدارها (<span id="visibleCount">{total_alerts}</span> مورد)</h2>
<div class="filters">
<input type="search" id="searchInput" placeholder="جستجو بر اساس URL، عنوان هشدار یا پارامتر…" aria-label="جستجوی هشدارها">
<select id="serviceSelect" aria-label="فیلتر سرویس">
{chr(10).join(service_options)}
</select>
<div role="group" aria-label="فیلتر شدت">
<button class="risk-btn active" data-risk="all">همه</button>
<button class="risk-btn" data-risk="High">بحرانی</button>
<button class="risk-btn" data-risk="Medium">متوسط</button>
<button class="risk-btn" data-risk="Low">کم‌اهمیت</button>
<button class="risk-btn" data-risk="Informational">اطلاعاتی</button>
</div>
</div>
<div class="table-wrap">
<table id="alertsTable">
<thead>
<tr>
<th>شدت</th><th>عنوان هشدار</th><th>سرویس</th><th>متد</th><th>پارامتر</th><th>آدرس (URL)</th>
</tr>
</thead>
<tbody>
{chr(10).join(alert_rows)}
<tr id="emptyRow" class="empty-row" style="display:none"><td colspan="6">هیچ هشداری مطابق فیلترها یافت نشد</td></tr>
</tbody>
</table>
</div>
</div>

<footer>
داشبورد امنیتی OpenStack — تولیدشده توسط zap_dashboard_generator_v03.py | داده‌ها از گزارش‌های OWASP ZAP استخراج شده‌اند
</footer>
</div>
<script>{JS}</script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return len(html)


# ── CLI ──────────────────────────────────────────────────────────────────────
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a Persian RTL dark-theme OpenStack security "
                    "dashboard from one or more OWASP ZAP HTML reports.",
    )
    parser.add_argument("reports", nargs="+", help="ZAP HTML report file(s)")
    parser.add_argument("-o", "--output", default="zap_dashboard.html",
                        help="output HTML path (default: zap_dashboard.html)")
    args = parser.parse_args(argv)

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   OpenStack ZAP Security Dashboard Generator v03             ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"Parser engine: {'BeautifulSoup4' if HAS_BS4 else 'regex fallback'}")

    all_alerts, scanned_sites = aggregate_alerts(args.reports)

    print("\n" + "═" * 78)
    print(f"✅ TOTAL UNIQUE ALERTS (deduplicated by plugin_id + url + parameter): "
          f"{len(all_alerts)}")
    print("═" * 78)

    report_count = len([p for p in args.reports if os.path.isfile(p)])
    print(f"[DEBUG] sites={len(scanned_sites)}, alerts={len(all_alerts)}")
    bytes_written = build_html_dashboard(all_alerts, scanned_sites, args.output, report_count)
    print(f"✅ Dashboard written: {os.path.abspath(args.output)} "
          f"({bytes_written:,} bytes)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
