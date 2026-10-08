"""
Odineyes - Report Builder
Generates HTML, JSON, and CSV reports from scan results.
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any

from odineyes.utils.logger import setup_logger
logger = setup_logger()


class ReportBuilder:
    """Generates formatted security reports from scan results."""
    
    def __init__(self, results: Dict[str, Any], compliance_frameworks: List[str] = None):
        self.results = results
        self.compliance_frameworks = compliance_frameworks or []
    
    def generate(self, fmt: str, output_path: str) -> str:
        """Generate a report in the specified format."""
        if fmt == "json":
            return self._generate_json(output_path)
        elif fmt == "html":
            return self._generate_html(output_path)
        elif fmt == "csv":
            return self._generate_csv(output_path)
        else:
            raise ValueError(f"Unsupported format: {fmt}")
    
    def _generate_json(self, output_path: str) -> str:
        """Generate JSON report."""
        path = f"{output_path}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)
        return path
    
    def _generate_csv(self, output_path: str) -> str:
        """Generate CSV report of findings."""
        path = f"{output_path}.csv"
        findings = self.results.get("findings", [])
        
        fieldnames = [
            "check_id", "name", "provider", "category", "severity",
            "status", "resource_id", "resource_type", "region",
            "message", "risk_score", "remediation", "timestamp"
        ]
        
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                row = {k: finding.get(k, "") for k in fieldnames}
                writer.writerow(row)
        return path
    
    def _generate_html(self, output_path: str) -> str:
        """Generate rich interactive HTML report."""
        path = f"{output_path}.html"
        findings = self.results.get("findings", [])
        meta = self.results.get("scan_metadata", {})
        summary = self.results.get("summary", {})
        risk_score = self.results.get("risk_score", 0)
        risk_level = self.results.get("risk_level", "UNKNOWN")
        
        # Count by severity
        sev_counts = summary.get("by_severity", {})
        by_provider = summary.get("by_provider", {})
        by_category = summary.get("by_category", {})
        
        failed_findings = [f for f in findings if f.get("status") != "pass"]
        passed_findings = [f for f in findings if f.get("status") == "pass"]
        
        # Sort by severity order
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        failed_findings.sort(key=lambda x: sev_order.get(x.get("severity", "low"), 5))
        
        scan_date = meta.get("start_time", datetime.now().isoformat())[:19].replace("T", " ")
        providers_str = ", ".join(p.upper() for p in meta.get("providers", ["AWS"]))
        
        # Build findings rows HTML
        rows_html = ""
        for f in failed_findings:
            sev = f.get("severity", "low").lower()
            sev_class = {"critical": "sev-critical", "high": "sev-high", 
                        "medium": "sev-medium", "low": "sev-low"}.get(sev, "sev-low")
            compliance_html = ""
            if f.get("compliance_mappings"):
                for fw, ctrls in f["compliance_mappings"].items():
                    compliance_html += f'<span class="tag tag-{fw.lower()}">{fw}: {", ".join(ctrls)}</span>'
            
            simulated = f.get("metadata", {}).get("simulated", False)
            sim_badge = '<span class="sim-badge">SIMULATED</span>' if simulated else ""
            
            remediation = (f.get("remediation") or "")[:200]
            
            rows_html += f"""
            <tr class="finding-row" data-severity="{sev}" data-provider="{f.get('provider', '')}" data-category="{f.get('category', '')}">
                <td><span class="check-id">{f.get('check_id', '')}</span></td>
                <td class="{sev_class}"><strong>{sev.upper()}</strong></td>
                <td>{f.get('provider', '').upper()}</td>
                <td><span class="category-badge">{f.get('category', '')}</span></td>
                <td class="resource-cell" title="{f.get('resource_id', '')}">{(f.get('resource_id') or '')[:45]}</td>
                <td class="message-cell">{f.get('message', '')}{sim_badge}</td>
                <td><span class="risk-score">{f.get('risk_score', 'N/A')}</span></td>
                <td class="remediation-cell" title="{remediation}">{remediation[:80]}{'...' if len(remediation) > 80 else ''}</td>
                <td class="compliance-cell">{compliance_html}</td>
            </tr>"""
        
        # Category chart data
        cat_labels = json.dumps(list(by_category.keys()))
        cat_values = json.dumps(list(by_category.values()))
        provider_labels = json.dumps(list(by_provider.keys()))
        provider_values = json.dumps(list(by_provider.values()))
        
        risk_color = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#16a34a", "MINIMAL": "#15803d"
        }.get(risk_level, "#6b7280")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Odineyes Security Report — {scan_date}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0a0f1a;
    --surface: #111827;
    --surface2: #1a2234;
    --border: #1e2d45;
    --text: #e2e8f0;
    --text-dim: #64748b;
    --accent: #3b82f6;
    --accent2: #06b6d4;
    --critical: #dc2626;
    --high: #ea580c;
    --medium: #d97706;
    --low: #16a34a;
    --pass: #059669;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    font-size: 14px;
  }}
  
  /* Header */
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
  }}
  .header-left h1 {{
    font-size: 28px;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(90deg, #60a5fa, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }}
  .header-left p {{ color: var(--text-dim); margin-top: 4px; font-size: 13px; }}
  .header-right {{ text-align: right; }}
  .scan-badge {{
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    border: 1px solid;
    margin-bottom: 6px;
  }}
  
  .main {{ padding: 32px 40px; max-width: 1600px; margin: 0 auto; }}
  
  /* Score Cards */
  .score-grid {{
    display: grid;
    grid-template-columns: 260px 1fr;
    gap: 20px;
    margin-bottom: 28px;
  }}
  .risk-card {{
    background: var(--surface);
    border: 2px solid {risk_color};
    border-radius: 16px;
    padding: 28px;
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
  }}
  .risk-gauge {{
    width: 140px;
    height: 140px;
    border-radius: 50%;
    background: conic-gradient({risk_color} 0% {risk_score}%, var(--surface2) {risk_score}% 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
  }}
  .risk-gauge::after {{
    content: '';
    position: absolute;
    width: 110px;
    height: 110px;
    border-radius: 50%;
    background: var(--surface);
  }}
  .risk-number {{
    position: relative;
    z-index: 1;
    font-size: 34px;
    font-weight: 900;
    color: {risk_color};
    line-height: 1;
  }}
  .risk-label {{ font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }}
  .risk-level-text {{ font-size: 22px; font-weight: 800; color: {risk_color}; }}
  
  .stat-cards {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    align-content: start;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 16px;
    text-align: center;
    transition: transform 0.2s;
  }}
  .stat-card:hover {{ transform: translateY(-2px); }}
  .stat-card .value {{ font-size: 32px; font-weight: 800; line-height: 1.1; }}
  .stat-card .label {{ font-size: 11px; color: var(--text-dim); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .stat-critical .value {{ color: var(--critical); }}
  .stat-high .value {{ color: var(--high); }}
  .stat-medium .value {{ color: var(--medium); }}
  .stat-low .value {{ color: var(--low); }}
  .stat-pass .value {{ color: var(--pass); }}
  
  /* Charts row */
  .charts-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 20px;
    margin-bottom: 28px;
  }}
  .chart-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
  }}
  .chart-card h3 {{
    font-size: 13px;
    font-weight: 600;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 16px;
  }}
  .chart-wrap {{ height: 200px; }}
  
  /* Filters */
  .filters-bar {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }}
  .filter-label {{ color: var(--text-dim); font-size: 12px; }}
  .filter-btn {{
    padding: 5px 14px;
    border-radius: 20px;
    border: 1px solid var(--border);
    background: var(--surface2);
    color: var(--text);
    cursor: pointer;
    font-size: 12px;
    transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{ border-color: var(--accent); color: var(--accent); background: #1e3a5f; }}
  .search-input {{
    padding: 6px 14px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--surface2);
    color: var(--text);
    font-size: 13px;
    width: 220px;
    margin-left: auto;
  }}
  .search-input:focus {{ outline: none; border-color: var(--accent); }}
  
  /* Findings Table */
  .findings-section {{ margin-bottom: 32px; }}
  .section-title {{
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .count-badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: var(--accent);
    color: white;
    font-size: 12px;
    font-weight: 700;
  }}
  
  .findings-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  .findings-table thead th {{
    background: var(--surface2);
    padding: 10px 12px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 10;
  }}
  .findings-table tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
  }}
  .findings-table tbody tr:hover {{ background: var(--surface2); }}
  .findings-table td {{ padding: 10px 12px; vertical-align: middle; }}
  
  .check-id {{ 
    font-family: 'Courier New', monospace; 
    font-size: 11px;
    color: var(--accent2);
    background: rgba(6,182,212,0.1);
    padding: 2px 6px;
    border-radius: 4px;
  }}
  .sev-critical {{ color: var(--critical); }}
  .sev-high {{ color: var(--high); }}
  .sev-medium {{ color: var(--medium); }}
  .sev-low {{ color: var(--low); }}
  
  .category-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    background: rgba(59,130,246,0.15);
    color: #93c5fd;
    text-transform: capitalize;
  }}
  .risk-score {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 13px;
    background: rgba(239,68,68,0.1);
    color: #fca5a5;
  }}
  .resource-cell {{ 
    font-family: monospace;
    font-size: 11px;
    color: var(--text-dim);
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  .message-cell {{ max-width: 280px; }}
  .remediation-cell {{ 
    color: var(--text-dim); 
    font-size: 12px;
    max-width: 200px;
  }}
  .compliance-cell {{ max-width: 180px; }}
  
  .tag {{ 
    display: inline-block; 
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    margin: 1px;
  }}
  .tag-cis {{ background: rgba(59,130,246,0.2); color: #93c5fd; }}
  .tag-soc2 {{ background: rgba(139,92,246,0.2); color: #c4b5fd; }}
  .tag-hipaa {{ background: rgba(236,72,153,0.2); color: #f9a8d4; }}
  .tag-pci-dss {{ background: rgba(245,158,11,0.2); color: #fcd34d; }}
  .tag-nist {{ background: rgba(16,185,129,0.2); color: #6ee7b7; }}
  
  .sim-badge {{
    display: inline-block;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 9px;
    font-weight: 700;
    background: rgba(245,158,11,0.2);
    color: #fcd34d;
    text-transform: uppercase;
    margin-left: 6px;
    letter-spacing: 0.5px;
  }}
  
  .table-wrap {{
    overflow-x: auto;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: var(--surface);
  }}
  
  .no-findings {{
    text-align: center;
    padding: 40px;
    color: var(--text-dim);
  }}
  
  /* Compliance section */
  .compliance-section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 28px;
  }}
  
  /* Footer */
  .footer {{
    border-top: 1px solid var(--border);
    padding: 20px 40px;
    color: var(--text-dim);
    font-size: 12px;
    display: flex;
    justify-content: space-between;
  }}
  
  .hidden {{ display: none !important; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>🛡 Odineyes Security Report</h1>
    <p>Multicloud GRC & Security Posture Assessment  •  {scan_date}  •  Providers: {providers_str}</p>
  </div>
  <div class="header-right">
    <div class="scan-badge" style="color:{risk_color};border-color:{risk_color};">Risk: {risk_level}</div>
    <div style="color:var(--text-dim);font-size:12px;">Scan ID: {meta.get('scan_id', 'N/A')}</div>
    <div style="color:var(--text-dim);font-size:12px;">Duration: {meta.get('duration_seconds', 0):.1f}s</div>
  </div>
</div>

<div class="main">

<!-- Risk Score + Stats -->
<div class="score-grid">
  <div class="risk-card">
    <div class="risk-gauge">
      <div class="risk-number">{risk_score}</div>
    </div>
    <div class="risk-level-text">{risk_level}</div>
    <div class="risk-label">Overall Risk Score / 100</div>
  </div>
  <div class="stat-cards">
    <div class="stat-card stat-critical">
      <div class="value">{sev_counts.get('critical', 0)}</div>
      <div class="label">Critical</div>
    </div>
    <div class="stat-card stat-high">
      <div class="value">{sev_counts.get('high', 0)}</div>
      <div class="label">High</div>
    </div>
    <div class="stat-card stat-medium">
      <div class="value">{sev_counts.get('medium', 0)}</div>
      <div class="label">Medium</div>
    </div>
    <div class="stat-card stat-low">
      <div class="value">{sev_counts.get('low', 0)}</div>
      <div class="label">Low</div>
    </div>
    <div class="stat-card stat-pass">
      <div class="value">{summary.get('passed', 0)}</div>
      <div class="label">Passed</div>
    </div>
    <div class="stat-card" style="grid-column:1/-1; padding:16px; display:flex; align-items:center; gap:20px; justify-content:center;">
      <div style="font-size:13px;color:var(--text-dim);">Total Checks: <strong style="color:var(--text)">{summary.get('total_checks', 0)}</strong></div>
      <div style="font-size:13px;color:var(--text-dim);">Pass Rate: <strong style="color:{'var(--pass)' if summary.get('pass_rate',0)>=80 else 'var(--medium)'}">{summary.get('pass_rate', 0):.1f}%</strong></div>
      <div style="font-size:13px;color:var(--text-dim);">Frameworks: <strong style="color:var(--text)">{', '.join(self.compliance_frameworks) if self.compliance_frameworks else 'None'}</strong></div>
      <div style="font-size:13px;color:var(--text-dim);">Regions: <strong style="color:var(--text)">{', '.join(meta.get('regions', []) or ['global'])[:40]}</strong></div>
    </div>
  </div>
</div>

<!-- Charts -->
<div class="charts-grid">
  <div class="chart-card">
    <h3>Findings by Severity</h3>
    <div class="chart-wrap"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="chart-card">
    <h3>Findings by Category</h3>
    <div class="chart-wrap"><canvas id="catChart"></canvas></div>
  </div>
  <div class="chart-card">
    <h3>Findings by Provider</h3>
    <div class="chart-wrap"><canvas id="provChart"></canvas></div>
  </div>
</div>

<!-- Findings Table -->
<div class="findings-section">
  <div class="section-title">
    ⚠ Security Findings
    <span class="count-badge">{len(failed_findings)}</span>
  </div>
  
  <div class="filters-bar">
    <span class="filter-label">Filter:</span>
    <button class="filter-btn active" onclick="filterSeverity('all', this)">All</button>
    <button class="filter-btn" onclick="filterSeverity('critical', this)" style="border-color:var(--critical);color:var(--critical)">Critical ({sev_counts.get('critical',0)})</button>
    <button class="filter-btn" onclick="filterSeverity('high', this)" style="border-color:var(--high);color:var(--high)">High ({sev_counts.get('high',0)})</button>
    <button class="filter-btn" onclick="filterSeverity('medium', this)" style="border-color:var(--medium);color:var(--medium)">Medium ({sev_counts.get('medium',0)})</button>
    <button class="filter-btn" onclick="filterSeverity('low', this)">Low ({sev_counts.get('low',0)})</button>
    <input type="text" class="search-input" placeholder="🔍 Search findings..." oninput="searchFindings(this.value)">
  </div>
  
  <div class="table-wrap">
    <table class="findings-table">
      <thead>
        <tr>
          <th>Check ID</th>
          <th>Severity</th>
          <th>Provider</th>
          <th>Category</th>
          <th>Resource</th>
          <th>Finding</th>
          <th>Risk</th>
          <th>Remediation</th>
          <th>Compliance</th>
        </tr>
      </thead>
      <tbody id="findingsBody">
        {rows_html if rows_html else '<tr><td colspan="9" class="no-findings">✅ No failed findings — excellent security posture!</td></tr>'}
      </tbody>
    </table>
  </div>
</div>

</div>

<div class="footer">
  <div>Generated by <strong>Odineyes v2.0</strong> — Multicloud GRC Security Platform</div>
  <div>Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
</div>

<script>
// Charts
const chartDefaults = {{
  plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }},
  responsive: true,
  maintainAspectRatio: false,
}};

new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{{ 
      data: [{sev_counts.get('critical',0)}, {sev_counts.get('high',0)}, {sev_counts.get('medium',0)}, {sev_counts.get('low',0)}],
      backgroundColor: ['#dc2626','#ea580c','#d97706','#16a34a'],
      borderColor: '#111827',
      borderWidth: 3,
    }}]
  }},
  options: {{...chartDefaults, cutout: '65%'}}
}});

new Chart(document.getElementById('catChart'), {{
  type: 'bar',
  data: {{
    labels: {cat_labels},
    datasets: [{{
      data: {cat_values},
      backgroundColor: '#3b82f6',
      borderRadius: 4,
    }}]
  }},
  options: {{
    ...chartDefaults,
    scales: {{
      x: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#1e2d45' }} }},
      y: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#1e2d45' }}, beginAtZero: true }},
    }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});

new Chart(document.getElementById('provChart'), {{
  type: 'pie',
  data: {{
    labels: {provider_labels},
    datasets: [{{
      data: {provider_values},
      backgroundColor: ['#f59e0b','#3b82f6','#10b981','#8b5cf6'],
      borderColor: '#111827',
      borderWidth: 3,
    }}]
  }},
  options: chartDefaults
}});

// Filtering
function filterSeverity(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-row').forEach(row => {{
    row.classList.toggle('hidden', sev !== 'all' && row.dataset.severity !== sev);
  }});
}}

function searchFindings(query) {{
  const q = query.toLowerCase();
  document.querySelectorAll('.finding-row').forEach(row => {{
    row.classList.toggle('hidden', q.length > 0 && !row.textContent.toLowerCase().includes(q));
  }});
}}
</script>
</body>
</html>"""
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path
