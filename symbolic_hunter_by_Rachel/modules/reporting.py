# modules/reporting.py
# Drop-in reporting module for SymbolicHunter with pandas + matplotlib charts
from __future__ import annotations

import json
import os
import base64
from io import BytesIO
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd
import matplotlib.pyplot as plt


class ReportGenerator:
    """
    Build a rich HTML report from SymbolicHunter analysis results.
    - Summaries using pandas
    - Charts with matplotlib embedded as base64 images
    """

    def __init__(self, results: Dict[str, Any], outdir: str, title: str = "SymbolicHunter Report"):
        self.results = results or {}
        self.outdir = outdir
        self.title = title
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        os.makedirs(self.outdir, exist_ok=True)

    # ---------------------------
    # Public API
    # ---------------------------
    def write_all(self, html_name: str = "report.html", json_name: str = "report.json") -> str:
        """
        Write JSON + HTML report. Returns HTML path.
        """
        json_path = os.path.join(self.outdir, json_name)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)

        charts_b64 = self._generate_charts()
        html = self._render_html(charts_b64)

        html_path = os.path.join(self.outdir, html_name)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        return html_path


# ----------------------------------------------------------------------
# Helper functions (not part of the class public API)
# ----------------------------------------------------------------------
    def _render_html(self, charts_b64: Dict[str, str]) -> str:
        # Embed charts
        charts_html = ""
        for name, img_b64 in charts_b64.items():
            charts_html += f"""
            <section style="margin: 28px 0;">
              <h3 style="margin-bottom:10px;">{name}</h3>
              <img alt="{name}" src="data:image/png;base64,{img_b64}"
                   style="max-width:100%;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.12);"/>
            </section>
            """

        # Overview panels
        meta_items = []
        for k in ("binary_name", "binary_size", "architecture", "hashes"):
            v = self.results.get(k)
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                v = json.dumps(v, indent=2)
            meta_items.append(f"<div class='kv'><span>{k}</span><code>{self._escape(str(v))}</code></div>")
        meta_html = "\n".join(meta_items) or "<em>No basic metadata provided.</em>"

        # Raw dump
        raw_json = self._escape(json.dumps(self.results, indent=2))

        # Minimal CSS
        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{self._escape(self.title)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
  :root {{
    --bg:#0f1221; --card:#161a2b; --text:#e7ecff; --muted:#a6aed3; --accent:#6aa5ff;
    --ok:#5bd691; --warn:#ffd166; --bad:#ff6b6b;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, 'Helvetica Neue', Arial, 'Apple Color Emoji', 'Segoe UI Emoji';
    margin:0; padding:32px; color:var(--text); background: radial-gradient(1200px 800px at 10% -10%, #1c2250 0, #0f1221 50%, #0f1221 100%);
  }}
  .container {{
    max-width:1100px; margin:0 auto; background:var(--card); border-radius:18px; padding:28px 28px 36px; 
    box-shadow: 0 10px 40px rgba(0,0,0,.35), inset 0 0 0 1px rgba(255,255,255,.05);
  }}
  h1 {{ font-size:28px; margin:0 0 6px; }}
  .sub {{ color:var(--muted); margin-bottom:8px; }}
  hr {{ border:none; border-top:1px solid rgba(255,255,255,.08); margin:22px 0; }}
  section h2 {{ font-size:20px; margin:0 0 12px; }}
  pre {{
    background:#0d1020; color:#d7ddff; border:1px solid rgba(255,255,255,.08); border-radius:12px; 
    padding:16px; overflow:auto; font-size:13px; line-height:1.4;
  }}
  .grid {{
    display:grid; grid-template-columns: repeat(12, 1fr); gap:16px;
  }}
  .card {{
    grid-column: span 12; background: linear-gradient(180deg, rgba(255,255,255,.02), rgba(255,255,255,.01));
    border: 1px solid rgba(255,255,255,.08); border-radius:14px; padding:18px;
  }}
  .kv {{ display:flex; align-items:baseline; gap:10px; margin:6px 0; }}
  .kv span {{ width:140px; color:var(--muted); font-size:13px; }}
  .pill {{ display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; background:#10142a; border:1px solid rgba(255,255,255,.08); color:#c7d0ff; }}
  @media (min-width: 800px) {{
    .col-6 {{ grid-column: span 6; }}
  }}
</style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{self._escape(self.title)}</h1>
      <div class="sub">Generated: {self._escape(self.timestamp)}</div>
      <div class="sub">Output directory: <span class="pill">{self._escape(self.outdir)}</span></div>
    </header>

    <hr/>

    <section class="grid">
      <div class="card col-6">
        <h2>Overview</h2>
        {meta_html}
      </div>

      <div class="card col-6">
        <h2>High-Level Stats</h2>
        {self._stats_table()}
      </div>
    </section>

    <section class="card" style="margin-top:12px;">
      <h2>Visualizations</h2>
      {charts_html or "<em>No chartable data found.</em>"}
    </section>

    <section class="card" style="margin-top:12px;">
      <h2>Raw Analysis JSON</h2>
      <pre>{raw_json}</pre>
    </section>
  </div>
</body>
</html>"""

    def _stats_table(self) -> str:
        stats = self.results.get("statistics") or {}
        if not isinstance(stats, dict) or not stats:
            return "<em>No statistics provided.</em>"
        # Render a simple key/value list
        rows = []
        for k, v in stats.items():
            rows.append(f"<div class='kv'><span>{self._escape(str(k))}</span><code>{self._escape(str(v))}</code></div>")
        return "\n".join(rows)

    def _escape(self, s: str) -> str:
        return (
            s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;")
        )

    # --------------------------------------------------
    # Chart generation
    # --------------------------------------------------
    def _generate_charts(self) -> Dict[str, str]:
        """
        Build base64-encoded PNG charts keyed by name.
        We try multiple common sections in self.results and only draw if present.
        """
        charts: Dict[str, str] = {}

        # 1) Vulnerability counts per type (dict: type -> list/entries)
        vulns = self.results.get("vulnerabilities")
        if isinstance(vulns, dict) and vulns:
            # normalize to counts
            rows = [{"Type": k, "Count": len(v if isinstance(v, list) else [v])} for k, v in vulns.items()]
            df = pd.DataFrame(rows)
            if not df.empty:
                fig, ax = plt.subplots()
                df.plot(kind="bar", x="Type", y="Count", ax=ax, legend=False)
                ax.set_title("Vulnerability Counts")
                ax.set_ylabel("Count")
                charts["Vulnerabilities"] = self._fig_to_b64(fig)

        # 2) Execution statistics (dict of numeric)
        stats = self.results.get("statistics")
        if isinstance(stats, dict) and stats:
            # keep only numeric
            items = [(k, v) for k, v in stats.items() if isinstance(v, (int, float))]
            if items:
                df = pd.DataFrame(items, columns=["Metric", "Value"])
                fig, ax = plt.subplots()
                df.plot(kind="barh", x="Metric", y="Value", ax=ax, legend=False)
                ax.set_title("Execution Statistics")
                charts["Execution Statistics"] = self._fig_to_b64(fig)

        # 3) Section entropy histogram (list of numbers or list of {entropy: x})
        ent = self.results.get("entropy") or self._extract_entropies()
        if isinstance(ent, list) and ent:
            nums = []
            for e in ent:
                if isinstance(e, (int, float)):
                    nums.append(float(e))
                elif isinstance(e, dict) and "entropy" in e and isinstance(e["entropy"], (int, float)):
                    nums.append(float(e["entropy"]))
            if nums:
                fig, ax = plt.subplots()
                pd.Series(nums).plot(kind="hist", bins=20, ax=ax)
                ax.set_title("Entropy Distribution")
                ax.set_xlabel("Entropy")
                charts["Entropy Histogram"] = self._fig_to_b64(fig)

        # 4) API/capability categories pie (e.g., {"process_injection": 5, "persistence": 2, ...})
        caps = self.results.get("capability_counts") or self._infer_capability_counts()
        if isinstance(caps, dict) and caps:
            rows = [(k, v) for k, v in caps.items() if isinstance(v, (int, float)) and v > 0]
            if rows:
                df = pd.DataFrame(rows, columns=["Capability", "Count"])
                fig, ax = plt.subplots()
                df.set_index("Capability")["Count"].plot(kind="pie", autopct="%1.0f%%", ax=ax)
                ax.set_ylabel("")  # hide y label
                ax.set_title("Capabilities Breakdown")
                charts["Capabilities Pie"] = self._fig_to_b64(fig)

        plt.close("all")
        return charts

    def _fig_to_b64(self, fig) -> str:
        buf = BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format="png", dpi=140)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")

    # Heuristics to pull usable data if field names vary across runs
    def _extract_entropies(self) -> List[float]:
        """
        Try to find entropy-like numbers from common result fields:
        e.g., results["sections"] -> [{name, entropy, size}, ...]
        """
        secs = self.results.get("sections")
        out: List[float] = []
        if isinstance(secs, list):
            for s in secs:
                if isinstance(s, dict) and isinstance(s.get("entropy"), (int, float)):
                    out.append(float(s["entropy"]))
        return out

    def _infer_capability_counts(self) -> Dict[str, int]:
        """
        If no explicit capability_counts provided, infer from 'vulnerabilities' keys.
        """
        caps: Dict[str, int] = {}
        vulns = self.results.get("vulnerabilities")
        if isinstance(vulns, dict):
            for k, v in vulns.items():
                caps[str(k)] = len(v if isinstance(v, list) else [v])
        return caps


# ----------------------------------------------------------------------
# Simple functional wrapper used by callers
# ----------------------------------------------------------------------
def generate_report(results: Dict[str, Any], outdir: str, title: str = "SymbolicHunter Report") -> str:
    """
    Convenience function to write report HTML + JSON.
    Returns the path to the HTML file.
    """
    rg = ReportGenerator(results=results, outdir=outdir, title=title)
    return rg.write_all()

