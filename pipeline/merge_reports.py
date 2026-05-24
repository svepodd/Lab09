#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = ROOT / "pipeline" / "artifacts"
OUTPUT_HTML = ROOT / "pipeline" / "unified-report.html"

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5,
}


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
        print(f"[!] Не удалось прочитать {path}: {e}", file=sys.stderr)
        return None


def _norm_severity(s: str | None) -> str:
    if not s:
        return "UNKNOWN"
    s = s.upper()
    return {
        "ERROR": "HIGH", "WARNING": "MEDIUM", "INFORMATIONAL": "INFO",
        "INFORMATION": "INFO", "MODERATE": "MEDIUM",
    }.get(s, s)


def parse_semgrep(path: Path) -> list[dict]:
    data = _load_json(path)
    if not data:
        return []
    out = []
    for r in data.get("results", []):
        out.append({
            "tool": "Semgrep (SAST)",
            "id": r.get("check_id", ""),
            "severity": _norm_severity(r.get("extra", {}).get("severity")),
            "title": r.get("extra", {}).get("message", "").strip().split("\n")[0],
            "location": f'{r.get("path", "")}:{r.get("start", {}).get("line", "?")}',
            "description": r.get("extra", {}).get("message", "").strip(),
        })
    return out


def parse_checkov(path: Path) -> list[dict]:
    data = _load_json(path)
    if not data:
        return []
    blocks = data if isinstance(data, list) else [data]
    out = []
    for block in blocks:
        results = block.get("results", {}) if isinstance(block, dict) else {}
        for fc in results.get("failed_checks", []):
            out.append({
                "tool": "Checkov (SAST/IaC)",
                "id": fc.get("check_id", ""),
                "severity": _norm_severity(fc.get("severity")) or "MEDIUM",
                "title": fc.get("check_name", ""),
                "location": f'{fc.get("file_path", "")}:{fc.get("file_line_range", ["?"])[0]}',
                "description": fc.get("guideline", "") or fc.get("check_name", ""),
            })
    return out


def parse_dependency_check(path: Path) -> list[dict]:
    data = _load_json(path)
    if not data:
        return []
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            cvss = (v.get("cvssv3", {}).get("baseScore")
                    or v.get("cvssv2", {}).get("score") or 0)
            if cvss >= 9:
                sev = "CRITICAL"
            elif cvss >= 7:
                sev = "HIGH"
            elif cvss >= 4:
                sev = "MEDIUM"
            elif cvss > 0:
                sev = "LOW"
            else:
                sev = _norm_severity(v.get("severity"))
            out.append({
                "tool": "OWASP Dependency-Check (SCA)",
                "id": v.get("name", ""),
                "severity": sev,
                "title": f'{dep.get("fileName", "")} → {v.get("name", "")}',
                "location": dep.get("filePath", "") or dep.get("fileName", ""),
                "description": (v.get("description") or "").strip(),
            })
    return out


def parse_trivy(path: Path) -> list[dict]:
    data = _load_json(path)
    if not data:
        return []
    out = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            out.append({
                "tool": "Trivy (Image scan)",
                "id": vuln.get("VulnerabilityID", ""),
                "severity": _norm_severity(vuln.get("Severity")),
                "title": f'{vuln.get("PkgName", "")} {vuln.get("InstalledVersion", "")} → {vuln.get("VulnerabilityID", "")}',
                "location": target,
                "description": (vuln.get("Title") or vuln.get("Description") or "").strip(),
            })
    return out


def parse_zap(path: Path) -> list[dict]:
    data = _load_json(path)
    if not data:
        return []
    out = []
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            sev = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}.get(
                str(alert.get("riskcode", "0")), "INFO")
            out.append({
                "tool": "OWASP ZAP (DAST)",
                "id": alert.get("pluginid", ""),
                "severity": sev,
                "title": alert.get("name", ""),
                "location": site.get("@name", ""),
                "description": (alert.get("desc") or "").strip(),
            })
    return out


def collect_findings() -> list[dict]:
    findings: list[dict] = []
    for p in ARTIFACTS_DIR.rglob("semgrep-report.json"):
        findings.extend(parse_semgrep(p))
    for p in ARTIFACTS_DIR.rglob("checkov-*-report.json"):
        findings.extend(parse_checkov(p))
    for p in ARTIFACTS_DIR.rglob("dependency-check-report.json"):
        findings.extend(parse_dependency_check(p))
    for p in ARTIFACTS_DIR.rglob("trivy-report.json"):
        findings.extend(parse_trivy(p))
    for p in ARTIFACTS_DIR.rglob("zap-report.json"):
        findings.extend(parse_zap(p))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["tool"]))
    return findings


HTML_TEMPLATE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>DevSecOps Unified Report — lab09</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         margin: 2rem; background: #fafafa; color: #222; }
  h1 { border-bottom: 3px solid #2c3e50; padding-bottom: .5rem; }
  .meta { color: #666; margin-bottom: 1.5rem; }
  .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .card { background: white; padding: 1rem 1.5rem; border-radius: 6px;
          box-shadow: 0 1px 3px rgba(0,0,0,.1); min-width: 130px; }
  .card .num { font-size: 2rem; font-weight: bold; }
  .card.crit .num { color: #c0392b; }
  .card.high .num { color: #e67e22; }
  .card.med  .num { color: #d4ac0d; }
  .card.low  .num { color: #3498db; }
  .card.info .num { color: #95a5a6; }
  table { width: 100%; border-collapse: collapse; background: white;
          box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  th { background: #2c3e50; color: white; text-align: left; padding: .6rem .8rem; }
  td { padding: .6rem .8rem; border-bottom: 1px solid #eee; vertical-align: top; }
  tr:hover { background: #f5f5f5; }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 4px;
         color: white; font-size: .85rem; font-weight: bold; }
  .sev.CRITICAL { background: #c0392b; }
  .sev.HIGH { background: #e67e22; }
  .sev.MEDIUM { background: #d4ac0d; }
  .sev.LOW { background: #3498db; }
  .sev.INFO { background: #95a5a6; }
  .sev.UNKNOWN { background: #7f8c8d; }
  code { background: #eee; padding: 1px 4px; border-radius: 3px; font-size: .85rem; }
  .desc { color: #555; max-width: 600px; }
  .empty { text-align: center; padding: 3rem; color: #999; }
</style>
</head>
<body>
  <h1>DevSecOps Unified Report — lab09</h1>
  <div class="meta">Сгенерировано: {{ generated_at }} · Всего находок: {{ findings|length }}</div>
  <div class="summary">
    <div class="card crit"><div class="num">{{ counts.CRITICAL }}</div><div>Critical</div></div>
    <div class="card high"><div class="num">{{ counts.HIGH }}</div><div>High</div></div>
    <div class="card med"><div class="num">{{ counts.MEDIUM }}</div><div>Medium</div></div>
    <div class="card low"><div class="num">{{ counts.LOW }}</div><div>Low</div></div>
    <div class="card info"><div class="num">{{ counts.INFO }}</div><div>Info</div></div>
  </div>
  <h2>По инструментам</h2>
  <table>
    <thead><tr><th>Инструмент</th><th>Находок</th></tr></thead>
    <tbody>
    {% for tool, cnt in by_tool.items() %}<tr><td>{{ tool }}</td><td>{{ cnt }}</td></tr>{% endfor %}
    </tbody>
  </table>
  <h2 style="margin-top:2rem;">Все находки</h2>
  {% if findings %}
  <table>
    <thead><tr><th>Sev</th><th>Tool</th><th>ID</th><th>Title</th><th>Location</th><th>Description</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td><span class="sev {{ f.severity }}">{{ f.severity }}</span></td>
        <td>{{ f.tool }}</td>
        <td><code>{{ f.id }}</code></td>
        <td>{{ f.title }}</td>
        <td><code>{{ f.location }}</code></td>
        <td class="desc">{{ f.description[:300] }}{% if f.description|length > 300 %}…{% endif %}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">Находок не обнаружено (или артефакты не скачаны).</div>
  {% endif %}
</body>
</html>
"""


def main() -> int:
    if not ARTIFACTS_DIR.exists():
        print(f"[!] Директория артефактов не найдена: {ARTIFACTS_DIR}", file=sys.stderr)
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    findings = collect_findings()
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    by_tool: dict[str, int] = {}
    for f in findings:
        by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1

    html = Template(HTML_TEMPLATE).render(
        findings=findings, counts=counts, by_tool=by_tool,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    OUTPUT_HTML.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_HTML.write_text(html, encoding="utf-8")

    print(f"[+] Unified report сохранён: {OUTPUT_HTML}")
    print(f"[i] Всего находок: {len(findings)}")
    for sev, n in counts.items():
        if n:
            print(f"    {sev}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
