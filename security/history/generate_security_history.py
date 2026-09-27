#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

Finding = Dict[str, Any]

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "BLOCKER": 5,
    "HIGH": 4,
    "MAJOR": 4,
    "MEDIUM": 3,
    "MINOR": 2,
    "LOW": 1,
    "INFO": 0,
    "INFORMATIONAL": 0,
    "UNKNOWN": -1,
    "N/A": -1,
}

ZAP_RISK_TO_SEVERITY = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
}


def load_json(path: Path) -> Tuple[Optional[Any], str]:
    if not path.exists():
        return None, f"No existe: {path}"
    if path.stat().st_size == 0:
        return None, f"Archivo vacío: {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except Exception as exc:
        return None, f"No se pudo leer JSON {path}: {exc}"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def sha_id(*parts: Any) -> str:
    return hashlib.sha256(
        "|".join(str(p or "") for p in parts).encode("utf-8", errors="ignore")
    ).hexdigest()[:16]


def norm_severity(value: Any) -> str:
    if value is None:
        return "UNKNOWN"

    text = str(value).strip().upper()

    if text in ("WARN", "WARNING"):
        return "MEDIUM"

    for key in ("CRITICAL", "BLOCKER", "HIGH", "MAJOR", "MEDIUM", "MINOR", "LOW", "INFO"):
        if key in text:
            return {
                "MAJOR": "HIGH",
                "MINOR": "LOW",
            }.get(key, key)

    return text or "UNKNOWN"


def sev_rank(finding: Finding) -> int:
    return SEVERITY_ORDER.get(norm_severity(finding.get("severity")), -1)


def phase_rank(finding: Finding) -> int:
    phase_order = {
        "SAST": 0,
        "SCA": 1,
        "DAST": 2,
    }
    return phase_order.get(str(finding.get("phase", "")).upper(), 9)


def clean_text(value: Any, max_len: int = 220) -> str:
    """Convierte evidencia y mensajes de herramientas a texto plano para el HTML.

    Algunos reportes, especialmente OWASP ZAP, entregan la descripción con
    etiquetas HTML como <p>, <br> o entidades escapadas. Para que la columna
    Evidencia sea legible, primero se decodifican entidades HTML y luego se
    eliminan las etiquetas, dejando solo texto.
    """
    text = html.unescape(str(value or ""))
    text = re.sub(r"(?i)<\s*(br|/p|/li|/div|/section)\s*/?>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = " ".join(text.replace("\n", " ").replace("\r", " ").split())

    return text[: max_len - 3] + "..." if len(text) > max_len else text


def build_finding(
    *,
    phase: str,
    tool: str,
    rule_id: str,
    title: str,
    severity: str,
    location: str,
    source_report: str,
    evidence: str = "",
    url: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Finding:
    title_c = clean_text(title, 260)
    location_c = clean_text(location, 260)
    rule_c = clean_text(rule_id, 160)

    return {
        "fingerprint": sha_id(phase, tool, rule_c, location_c, title_c),
        "phase": phase,
        "tool": tool,
        "rule_id": rule_c,
        "title": title_c,
        "severity": norm_severity(severity),
        "location": location_c,
        "source_report": source_report,
        "evidence": clean_text(evidence, 500),
        "url": url or "",
        "extra": extra or {},
    }


def parse_sonar(path: Path):
    data, message = load_json(path)
    warnings = []

    if data is None:
        return [], [message]

    if isinstance(data, dict) and data.get("errors"):
        warnings.append(f"SonarCloud devolvió errores: {data.get('errors')}")

    issues = data.get("issues") if isinstance(data, dict) else []

    if not isinstance(issues, list):
        return [], ["El JSON de SonarCloud no contiene una lista válida en 'issues'."]

    findings = []

    for issue in issues:
        if not isinstance(issue, dict):
            continue

        component = issue.get("component") or issue.get("project") or ""
        line = issue.get("line") or (issue.get("textRange") or {}).get("startLine") or ""

        findings.append(
            build_finding(
                phase="SAST",
                tool="SonarCloud",
                rule_id=str(
                    issue.get("rule")
                    or issue.get("cleanCodeAttribute")
                    or issue.get("key")
                    or "SONAR-ISSUE"
                ),
                title=str(issue.get("message") or issue.get("rule") or "SonarCloud issue"),
                severity=str(issue.get("severity") or issue.get("impactSeverity") or "UNKNOWN"),
                location=f"{component}:{line}" if line else str(component),
                source_report=str(path),
                evidence=(
                    f"issue_key={issue.get('key', '')}; "
                    f"type={issue.get('type', '')}; "
                    f"status={issue.get('status') or issue.get('issueStatus', '')}"
                ),
                extra={
                    "issue_key": issue.get("key", ""),
                    "type": issue.get("type", ""),
                    "status": issue.get("status") or issue.get("issueStatus") or "",
                },
            )
        )

    return findings, warnings


def parse_trivy(path: Path, label: str):
    data, message = load_json(path)

    if data is None:
        return [], [message]

    results = data.get("Results") if isinstance(data, dict) else []

    if not isinstance(results, list):
        return [], [f"El JSON de Trivy no contiene una lista válida en 'Results': {path}"]

    findings = []

    for result in results:
        if not isinstance(result, dict):
            continue

        target = result.get("Target", "")
        result_class = result.get("Class", "")
        result_type = result.get("Type", "")

        for vuln in result.get("Vulnerabilities") or []:
            vulnerability_id = vuln.get("VulnerabilityID") or "TRIVY-VULN"
            package = vuln.get("PkgName") or ""
            installed = vuln.get("InstalledVersion") or ""
            fixed = vuln.get("FixedVersion") or ""

            findings.append(
                build_finding(
                    phase="SCA",
                    tool=f"Trivy ({label})",
                    rule_id=str(vulnerability_id),
                    title=str(vuln.get("Title") or vuln.get("Description") or vulnerability_id),
                    severity=str(vuln.get("Severity") or "UNKNOWN"),
                    location=f"{target} | package={package} | installed={installed}",
                    source_report=str(path),
                    evidence=f"fixed_version={fixed}; class={result_class}; type={result_type}; scan={label}",
                    url=str(vuln.get("PrimaryURL") or ""),
                    extra={
                        "package": package,
                        "installed_version": installed,
                        "fixed_version": fixed,
                        "target": target,
                        "scan": label,
                    },
                )
            )

        for secret in result.get("Secrets") or []:
            rule = secret.get("RuleID") or secret.get("Category") or "TRIVY-SECRET"
            line = secret.get("StartLine") or secret.get("EndLine") or ""

            findings.append(
                build_finding(
                    phase="SCA",
                    tool=f"Trivy Secret ({label})",
                    rule_id=str(rule),
                    title=str(secret.get("Title") or secret.get("Match") or "Secret detected by Trivy"),
                    severity=str(secret.get("Severity") or "HIGH"),
                    location=f"{target}:{line}" if line else str(target),
                    source_report=str(path),
                    evidence=f"category={secret.get('Category', '')}; scan={label}",
                    extra={
                        "target": target,
                        "scan": label,
                    },
                )
            )

    return findings, []


def parse_dependency_check(path: Path):
    data, message = load_json(path)

    if data is None:
        return [], [message]

    dependencies = data.get("dependencies") if isinstance(data, dict) else []

    if not isinstance(dependencies, list):
        return [], ["El JSON de OWASP Dependency-Check no contiene una lista válida en 'dependencies'."]

    findings = []

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue

        file_path = dependency.get("filePath") or dependency.get("fileName") or ""
        package = (
            dependency.get("packages", [{}])[0].get("id", "")
            if isinstance(dependency.get("packages"), list) and dependency.get("packages")
            else ""
        )

        for vuln in dependency.get("vulnerabilities") or []:
            findings.append(
                build_finding(
                    phase="SCA",
                    tool="OWASP Dependency-Check",
                    rule_id=str(vuln.get("name") or vuln.get("source") or "ODC-VULN"),
                    title=str(vuln.get("description") or vuln.get("name") or "Dependency-Check vulnerability"),
                    severity=str(vuln.get("severity") or "UNKNOWN"),
                    location=f"{file_path} | package={package}",
                    source_report=str(path),
                    evidence=(
                        f"cvssv3={(vuln.get('cvssv3') or {}).get('baseScore', '')}; "
                        f"cvssv2={(vuln.get('cvssv2') or {}).get('score', '')}"
                    ),
                    extra={
                        "dependency": file_path,
                        "package": package,
                    },
                )
            )

    return findings, []


def parse_zap(path: Path):
    data, message = load_json(path)

    if data is None:
        return [], [message]

    sites = data.get("site") if isinstance(data, dict) else []

    if isinstance(sites, dict):
        sites = [sites]

    if not isinstance(sites, list):
        return [], ["El JSON de OWASP ZAP no contiene una lista válida en 'site'."]

    findings = []

    for site in sites:
        host = site.get("@host") or site.get("@name") or site.get("name") or "ZAP target"

        for alert in site.get("alerts") or []:
            plugin_id = alert.get("pluginid") or alert.get("pluginId") or alert.get("alertRef") or "ZAP-ALERT"
            riskcode = str(alert.get("riskcode") if alert.get("riskcode") is not None else "")

            instances = alert.get("instances") or []
            first_instance = {}

            if isinstance(instances, list) and instances and isinstance(instances[0], dict):
                first_instance = instances[0]

            findings.append(
                build_finding(
                    phase="DAST",
                    tool="OWASP ZAP",
                    rule_id=str(plugin_id),
                    title=str(alert.get("alert") or alert.get("name") or "ZAP alert"),
                    severity=str(ZAP_RISK_TO_SEVERITY.get(riskcode, alert.get("riskdesc") or "UNKNOWN")),
                    location=str(first_instance.get("uri") or first_instance.get("url") or host),
                    source_report=str(path),
                    evidence=str(alert.get("desc") or alert.get("solution") or alert.get("evidence") or ""),
                    extra={
                        "riskcode": riskcode,
                        "confidence": alert.get("confidence", ""),
                        "instance_count": len(instances) if isinstance(instances, list) else 0,
                    },
                )
            )

    return findings, []


def normalize_all(args):
    all_findings = []
    warnings = []

    parsers = [
        (parse_sonar, Path(args.sonar)),
        (lambda p: parse_trivy(p, "filesystem"), Path(args.trivy_fs)),
        (lambda p: parse_trivy(p, "image"), Path(args.trivy_image)),
        (parse_dependency_check, Path(args.dependency_check)),
        (parse_zap, Path(args.zap)),
    ]

    for parser, path in parsers:
        findings, parser_warnings = parser(path)
        all_findings.extend(findings)
        warnings.extend(parser_warnings)

    unique = {
        finding["fingerprint"]: finding
        for finding in all_findings
    }

    return sorted(
        unique.values(),
        key=lambda finding: (
            phase_rank(finding),
            finding.get("tool", ""),
            -sev_rank(finding),
            finding.get("title", ""),
        ),
    ), warnings


def load_previous(path: Path):
    data, _ = load_json(path)

    if data is None:
        return []

    findings = (data.get("findings") if isinstance(data, dict) else data) or []

    return [
        finding
        for finding in findings
        if isinstance(finding, dict) and finding.get("fingerprint")
    ]


def compare(previous, current):
    previous_by_id = {
        finding["fingerprint"]: finding
        for finding in previous
    }

    current_by_id = {
        finding["fingerprint"]: finding
        for finding in current
    }

    rows = []

    for finding_id, finding in current_by_id.items():
        row = dict(finding)
        row["tracking_status"] = "Persistente" if finding_id in previous_by_id else "Nuevo"
        rows.append(row)

    for finding_id, finding in previous_by_id.items():
        if finding_id not in current_by_id:
            row = dict(finding)
            row["tracking_status"] = "Corregido"
            rows.append(row)

    tracking_order = {
        "Nuevo": 0,
        "Persistente": 1,
        "Corregido": 2,
    }

    rows.sort(
        key=lambda finding: (
            tracking_order.get(finding.get("tracking_status", ""), 9),
            phase_rank(finding),
            finding.get("tool", ""),
            -sev_rank(finding),
            finding.get("title", ""),
        )
    )

    summary = {
        "current_total": len(current),
        "previous_total": len(previous),
        "new_count": sum(row.get("tracking_status") == "Nuevo" for row in rows),
        "persistent_count": sum(row.get("tracking_status") == "Persistente" for row in rows),
        "fixed_count": sum(row.get("tracking_status") == "Corregido" for row in rows),
        "sast_current": sum(row.get("phase") == "SAST" for row in current),
        "sca_current": sum(row.get("phase") == "SCA" for row in current),
        "dast_current": sum(row.get("phase") == "DAST" for row in current),
    }

    return rows, summary


def severity_badge(severity):
    normalized = norm_severity(severity)

    css = {
        "CRITICAL": "critical",
        "BLOCKER": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "INFORMATIONAL": "info",
    }.get(normalized, "unknown")

    return f'<span class="badge {css}">{html.escape(normalized)}</span>'


def status_badge(status):
    css = {
        "Nuevo": "new",
        "Persistente": "persistent",
        "Corregido": "fixed",
    }.get(status, "unknown")

    return f'<span class="status {css}">{html.escape(status)}</span>'


def generate_html(rows, summary, warnings):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    repo = os.getenv("GITHUB_REPOSITORY", "local")
    run_id = os.getenv("GITHUB_RUN_ID", "local")
    ref = os.getenv("GITHUB_REF_NAME", "local")
    event = os.getenv("GITHUB_EVENT_NAME", "local")

    def card(label, value, css=""):
        return (
            f'<div class="card {css}">'
            f'<div class="value">{html.escape(str(value))}</div>'
            f'<div class="label">{html.escape(label)}</div>'
            f'</div>'
        )

    warning_html = ""
    if warnings:
        warning_items = "".join(
            f"<li>{html.escape(warning)}</li>"
            for warning in warnings
        )
        warning_html = (
            "<section class='warnings'>"
            "<h2>Advertencias de lectura</h2>"
            f"<ul>{warning_items}</ul>"
            "</section>"
        )

    headers = [
        "Seguimiento",
        "Fase",
        "Herramienta",
        "Severidad",
        "Regla / CVE",
        "Hallazgo",
        "Ubicación",
        "Evidencia",
    ]

    def table_cell(label: str, value: str) -> str:
        return f'<td data-label="{html.escape(label)}">{value}</td>'

    def select_options(values: List[str], phase_order: bool = False) -> str:
        if phase_order:
            order = {"SAST": 0, "SCA": 1, "DAST": 2}
            values = sorted(values, key=lambda value: (order.get(value, 9), value))
        else:
            values = sorted(values)

        return "".join(
            f'<option value="{html.escape(value, quote=True)}">{html.escape(value)}</option>'
            for value in values
        )

    status_values = [
        status
        for status in ("Nuevo", "Persistente", "Corregido")
        if any(row.get("tracking_status") == status for row in rows)
    ]
    phase_values = sorted({str(row.get("phase", "")) for row in rows if row.get("phase")})
    tool_values = sorted({str(row.get("tool", "")) for row in rows if row.get("tool")})

    filter_controls = (
        '\n    <div class="filters" aria-label="Filtros del historial de hallazgos">\n'
        '      <div class="filter-grid">\n'
        '        <label class="filter-control" for="filter-status">\n'
        '          <span>Estado de seguimiento</span>\n'
        '          <select id="filter-status" data-filter="status">\n'
        '            <option value="">Todos</option>\n'
        f'            {select_options(status_values)}\n'
        '          </select>\n'
        '        </label>\n\n'
        '        <label class="filter-control" for="filter-phase">\n'
        '          <span>Fase</span>\n'
        '          <select id="filter-phase" data-filter="phase">\n'
        '            <option value="">Todas</option>\n'
        f'            {select_options(phase_values, phase_order=True)}\n'
        '          </select>\n'
        '        </label>\n\n'
        '        <label class="filter-control" for="filter-tool">\n'
        '          <span>Herramienta</span>\n'
        '          <select id="filter-tool" data-filter="tool">\n'
        '            <option value="">Todas</option>\n'
        f'            {select_options(tool_values)}\n'
        '          </select>\n'
        '        </label>\n\n'
        '        <button type="button" id="clear-filters" class="clear-filters">Limpiar filtros</button>\n'
        '      </div>\n'
        '      <p id="filter-summary" class="filter-summary">Mostrando todos los hallazgos.</p>\n'
        '    </div>\n'
    )

    table_rows = []

    for item in rows:
        title = html.escape(item.get("title", ""))
        url = item.get("url") or ""
        tracking_status = str(item.get("tracking_status", ""))
        phase = str(item.get("phase", ""))
        tool = str(item.get("tool", ""))

        if url:
            title = f'<a href="{html.escape(url)}">{title}</a>'

        table_rows.append(
            (
                '<tr '
                f'data-status="{html.escape(tracking_status, quote=True)}" '
                f'data-phase="{html.escape(phase, quote=True)}" '
                f'data-tool="{html.escape(tool, quote=True)}">'
            )
            + table_cell("Seguimiento", status_badge(tracking_status))
            + table_cell("Fase", html.escape(phase))
            + table_cell("Herramienta", html.escape(tool))
            + table_cell("Severidad", severity_badge(item.get("severity", "")))
            + table_cell("Regla / CVE", html.escape(item.get("rule_id", "")))
            + table_cell("Hallazgo", title)
            + table_cell("Ubicación", html.escape(item.get("location", "")))
            + table_cell("Evidencia", html.escape(item.get("evidence", "")))
            + "</tr>"
        )

    if not table_rows:
        table_rows.append(
            '<tr><td colspan="8">No se encontraron hallazgos en los reportes disponibles.</td></tr>'
        )

    table_headers = "".join(
        f"<th>{html.escape(header)}</th>"
        for header in headers
    )

    filter_script = """
  <script>
    (function () {
      const statusFilter = document.getElementById("filter-status");
      const phaseFilter = document.getElementById("filter-phase");
      const toolFilter = document.getElementById("filter-tool");
      const clearButton = document.getElementById("clear-filters");
      const summary = document.getElementById("filter-summary");
      const rows = Array.from(document.querySelectorAll("tbody tr[data-status]"));

      function applyFilters() {
        const selectedStatus = statusFilter.value;
        const selectedPhase = phaseFilter.value;
        const selectedTool = toolFilter.value;
        let visible = 0;

        rows.forEach(function (row) {
          const matchStatus = !selectedStatus || row.dataset.status === selectedStatus;
          const matchPhase = !selectedPhase || row.dataset.phase === selectedPhase;
          const matchTool = !selectedTool || row.dataset.tool === selectedTool;
          const shouldShow = matchStatus && matchPhase && matchTool;

          row.style.display = shouldShow ? "" : "none";
          if (shouldShow) {
            visible += 1;
          }
        });

        if (summary) {
          summary.textContent = "Mostrando " + visible + " de " + rows.length + " hallazgos.";
        }
      }

      [statusFilter, phaseFilter, toolFilter].forEach(function (filter) {
        if (filter) {
          filter.addEventListener("change", applyFilters);
        }
      });

      if (clearButton) {
        clearButton.addEventListener("click", function () {
          statusFilter.value = "";
          phaseFilter.value = "";
          toolFilter.value = "";
          applyFilters();
        });
      }

      applyFilters();
    })();
  </script>
    """

    css = """
      :root {
        --bg: #f8fafc;
        --text: #1f2937;
        --muted: #6b7280;
        --border: #e5e7eb;
        --header: #111827;
        --card: #ffffff;
      }

      * {
        box-sizing: border-box;
      }

      body {
        font-family: Arial, Helvetica, sans-serif;
        margin: 24px;
        color: var(--text);
        background: var(--bg);
      }

      header {
        background: var(--header);
        color: white;
        padding: 22px;
        border-radius: 12px;
      }

      h1 {
        margin: 0 0 8px;
        font-size: 26px;
      }

      h2 {
        margin-top: 0;
      }

      .subtitle {
        margin: 0;
        color: #d1d5db;
      }

      .meta {
        margin-top: 14px;
        font-size: 13px;
        color: #e5e7eb;
        line-height: 1.8;
      }

      .meta-label {
        color: #f9fafb;
        font-weight: 700;
      }

      header code {
        background: rgba(255, 255, 255, .16);
        color: #ffffff;
        padding: 2px 6px;
        border-radius: 4px;
        overflow-wrap: anywhere;
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
        gap: 12px;
        margin: 20px 0;
      }

      .card {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, .04);
      }

      .card .value {
        font-size: 28px;
        font-weight: bold;
      }

      .card .label {
        color: var(--muted);
        font-size: 13px;
        margin-top: 4px;
      }

      .new-card .value {
        color: #1d4ed8;
      }

      .persistent-card .value {
        color: #b45309;
      }

      .fixed-card .value {
        color: #047857;
      }

      section {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 18px;
        margin-top: 18px;
      }

      .filters {
        margin: 16px 0 18px;
        padding: 14px;
        background: #f9fafb;
        border: 1px solid var(--border);
        border-radius: 12px;
      }

      .filter-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(160px, 1fr)) auto;
        gap: 12px;
        align-items: end;
      }

      .filter-control {
        display: grid;
        gap: 6px;
        font-size: 12px;
        font-weight: 700;
        color: #374151;
      }

      .filter-control select {
        width: 100%;
        min-height: 38px;
        padding: 8px 10px;
        border: 1px solid #d1d5db;
        border-radius: 8px;
        background: #ffffff;
        color: var(--text);
        font-size: 13px;
      }

      .clear-filters {
        min-height: 38px;
        padding: 8px 12px;
        border: 1px solid #d1d5db;
        border-radius: 8px;
        background: #ffffff;
        color: #374151;
        font-weight: 700;
        cursor: pointer;
      }

      .clear-filters:hover {
        background: #f3f4f6;
      }

      .filter-summary {
        margin: 10px 0 0;
        color: var(--muted);
        font-size: 13px;
      }

      .table-wrap {
        width: 100%;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        border: 1px solid var(--border);
        border-radius: 12px;
      }

      table {
        width: 100%;
        min-width: 980px;
        border-collapse: collapse;
        font-size: 13px;
        background: white;
      }

      th,
      td {
        border-bottom: 1px solid var(--border);
        padding: 9px 8px;
        text-align: left;
        vertical-align: top;
      }

      th {
        background: #f3f4f6;
        font-size: 12px;
        text-transform: uppercase;
        color: #374151;
      }

      td {
        overflow-wrap: anywhere;
        word-break: break-word;
      }

      th:nth-child(2),
      td[data-label="Fase"] {
        white-space: nowrap;
        min-width: 72px;
        width: 72px;
        text-align: center;
        word-break: normal;
        overflow-wrap: normal;
      }

      tr:last-child td {
        border-bottom: 0;
      }

      .badge,
      .status {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 999px;
        font-weight: bold;
        font-size: 11px;
        white-space: nowrap;
      }

      .critical {
        background: #7f1d1d;
        color: white;
      }

      .high {
        background: #fee2e2;
        color: #991b1b;
      }

      .medium {
        background: #fef3c7;
        color: #92400e;
      }

      .low {
        background: #dbeafe;
        color: #1e40af;
      }

      .info {
        background: #e0f2fe;
        color: #0369a1;
      }

      .unknown {
        background: #e5e7eb;
        color: #374151;
      }

      .new {
        background: #dbeafe;
        color: #1d4ed8;
      }

      .persistent {
        background: #fef3c7;
        color: #92400e;
      }

      .fixed {
        background: #dcfce7;
        color: #166534;
      }

      .warnings {
        border-color: #fde68a;
        background: #fffbeb;
      }

      code {
        background: #f3f4f6;
        padding: 2px 5px;
        border-radius: 4px;
      }

      a {
        color: #2563eb;
      }

      @media (max-width: 768px) {
        body {
          margin: 12px;
        }

        header {
          padding: 18px;
          border-radius: 10px;
        }

        h1 {
          font-size: 22px;
        }

        .subtitle,
        .meta {
          font-size: 12px;
        }

        .grid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 10px;
        }

        .filter-grid {
          grid-template-columns: 1fr;
        }

        .clear-filters {
          width: 100%;
        }

        .card {
          padding: 14px;
        }

        .card .value {
          font-size: 24px;
        }

        section {
          padding: 14px;
        }

        .table-wrap {
          border: 0;
          overflow-x: visible;
        }

        table {
          min-width: 0;
        }

        table,
        thead,
        tbody,
        th,
        td,
        tr {
          display: block;
          width: 100%;
        }

        thead {
          display: none;
        }

        tr {
          border: 1px solid var(--border);
          border-radius: 12px;
          margin-bottom: 12px;
          padding: 10px 12px;
          background: #ffffff;
          box-shadow: 0 1px 2px rgba(0, 0, 0, .03);
        }

        td {
          border-bottom: 0;
          display: grid;
          grid-template-columns: 130px minmax(0, 1fr);
          gap: 8px;
          padding: 7px 0;
          align-items: start;
        }

        td::before {
          content: attr(data-label);
          font-weight: 700;
          color: var(--muted);
        }
      }

      @media (max-width: 480px) {
        body {
          margin: 8px;
        }

        .grid {
          grid-template-columns: 1fr;
        }

        td {
          grid-template-columns: 1fr;
          gap: 4px;
        }

        td::before {
          font-size: 12px;
        }
      }
    """

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Historial de hallazgos de seguridad</title>
  <style>{css}</style>
</head>
<body>
  <header>
    <h1>Historial de hallazgos de seguridad</h1>
    <p class="subtitle">Seguimiento entre ejecuciones del pipeline DevSecOps: SAST, SCA y DAST.</p>
    <div class="meta">
      <span class="meta-label">Repositorio:</span> <code>{html.escape(repo)}</code> ·
      <span class="meta-label">Rama/PR:</span> <code>{html.escape(ref)}</code> ·
      <span class="meta-label">Evento:</span> <code>{html.escape(event)}</code> ·
      <span class="meta-label">Run:</span> <code>{html.escape(run_id)}</code> ·
      <span class="meta-label">Generado:</span> {generated_at}
    </div>
  </header>

  <div class="grid">
    {card("Hallazgos actuales", summary.get("current_total", 0))}
    {card("Hallazgos anteriores", summary.get("previous_total", 0))}
    {card("Nuevos", summary.get("new_count", 0), "new-card")}
    {card("Persistentes", summary.get("persistent_count", 0), "persistent-card")}
    {card("Corregidos", summary.get("fixed_count", 0), "fixed-card")}
    {card("SAST actuales", summary.get("sast_current", 0))}
    {card("SCA actuales", summary.get("sca_current", 0))}
    {card("DAST actuales", summary.get("dast_current", 0))}
  </div>

  {warning_html}

  <section>
    <h2>Detalle de seguimiento</h2>
    <p>
      La clasificación se realiza comparando el snapshot anterior contra los hallazgos actuales.
      Si el hallazgo estaba antes y ya no aparece, se marca como <b>Corregido</b>.
      Si aparece en ambas ejecuciones, se marca como <b>Persistente</b>.
      Si aparece por primera vez, se marca como <b>Nuevo</b>.
    </p>

    {filter_controls}

    <div class="table-wrap">
      <table>
        <thead>
          <tr>{table_headers}</tr>
        </thead>
        <tbody>
          {"".join(table_rows)}
        </tbody>
      </table>
    </div>
  </section>

  {filter_script}
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--sonar", default="security/evidence/sonar/sonar-issues.json")
    parser.add_argument("--trivy-fs", default="security/evidence/trivy/trivy-report.json")
    parser.add_argument("--trivy-image", default="security/evidence/trivy/trivy-image-report.json")
    parser.add_argument("--dependency-check", default="security/evidence/dependency-check/dependency-check-report.json")
    parser.add_argument("--zap", default="security/evidence/zap/zap-report.json")
    parser.add_argument("--previous", default=".security-history-cache/previous-findings.json")
    parser.add_argument("--current", default="security/evidence/history/current-findings.json")
    parser.add_argument("--history-json", default="security/evidence/history/security-history.json")
    parser.add_argument("--history-html", default="security/evidence/history/security-history.html")
    parser.add_argument("--summary-env", default="security/evidence/history/summary.env")
    parser.add_argument("--state-out", default=".security-history-cache/previous-findings.json")

    args = parser.parse_args()

    current_findings, warnings = normalize_all(args)
    previous_findings = load_previous(Path(args.previous))
    rows, summary = compare(previous_findings, current_findings)

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": os.getenv("GITHUB_REPOSITORY", "local"),
        "run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "event_name": os.getenv("GITHUB_EVENT_NAME", "local"),
        "ref_name": os.getenv("GITHUB_REF_NAME", "local"),
        "warnings": warnings,
    }

    write_json(
        Path(args.current),
        {
            "metadata": metadata,
            "findings": current_findings,
        },
    )

    write_json(
        Path(args.history_json),
        {
            "metadata": metadata,
            "summary": summary,
            "findings": rows,
        },
    )

    Path(args.history_html).parent.mkdir(parents=True, exist_ok=True)
    Path(args.history_html).write_text(
        generate_html(rows, summary, warnings),
        encoding="utf-8",
    )

    Path(args.summary_env).parent.mkdir(parents=True, exist_ok=True)
    Path(args.summary_env).write_text(
        "\n".join(f"{key}={value}" for key, value in summary.items()) + "\n",
        encoding="utf-8",
    )

    write_json(
        Path(args.state_out),
        {
            "metadata": metadata,
            "findings": current_findings,
        },
    )

    print("Security history generated")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"- {warning}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())