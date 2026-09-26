#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, html, json, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
Finding = Dict[str, Any]
SEVERITY_ORDER = {"CRITICAL":5,"BLOCKER":5,"HIGH":4,"MAJOR":4,"MEDIUM":3,"MINOR":2,"LOW":1,"INFO":0,"INFORMATIONAL":0,"UNKNOWN":-1,"N/A":-1}
ZAP_RISK_TO_SEVERITY = {"3":"HIGH","2":"MEDIUM","1":"LOW","0":"INFO"}

def load_json(path: Path) -> Tuple[Optional[Any], str]:
    if not path.exists(): return None, f"No existe: {path}"
    if path.stat().st_size == 0: return None, f"Archivo vacío: {path}"
    try: return json.loads(path.read_text(encoding="utf-8")), "ok"
    except Exception as exc: return None, f"No se pudo leer JSON {path}: {exc}"

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def sha_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p or "") for p in parts).encode("utf-8", errors="ignore")).hexdigest()[:16]

def norm_severity(value: Any) -> str:
    if value is None: return "UNKNOWN"
    text = str(value).strip().upper()
    if text in ("WARN","WARNING"): return "MEDIUM"
    for k in ("CRITICAL","BLOCKER","HIGH","MAJOR","MEDIUM","MINOR","LOW","INFO"):
        if k in text: return {"MAJOR":"HIGH","MINOR":"LOW"}.get(k,k)
    return text or "UNKNOWN"

def sev_rank(f: Finding) -> int: return SEVERITY_ORDER.get(norm_severity(f.get("severity")), -1)

def clean_text(value: Any, max_len: int = 220) -> str:
    text = " ".join(str(value or "").replace("\n"," ").replace("\r"," ").split())
    return text[:max_len-3] + "..." if len(text) > max_len else text

def build_finding(*, phase: str, tool: str, rule_id: str, title: str, severity: str, location: str, source_report: str, evidence: str="", url: str="", extra: Optional[Dict[str,Any]]=None) -> Finding:
    title_c, location_c, rule_c = clean_text(title,260), clean_text(location,260), clean_text(rule_id,160)
    return {"fingerprint": sha_id(phase, tool, rule_c, location_c, title_c), "phase": phase, "tool": tool, "rule_id": rule_c, "title": title_c, "severity": norm_severity(severity), "location": location_c, "source_report": source_report, "evidence": clean_text(evidence,500), "url": url or "", "extra": extra or {}}

def parse_sonar(path: Path):
    data,msg=load_json(path); warnings=[]
    if data is None: return [], [msg]
    if isinstance(data,dict) and data.get("errors"): warnings.append(f"SonarCloud devolvió errores: {data.get('errors')}")
    issues = data.get("issues") if isinstance(data,dict) else []
    if not isinstance(issues,list): return [], ["El JSON de SonarCloud no contiene una lista válida en 'issues'."]
    out=[]
    for issue in issues:
        if not isinstance(issue,dict): continue
        component=issue.get("component") or issue.get("project") or ""
        line=issue.get("line") or (issue.get("textRange") or {}).get("startLine") or ""
        out.append(build_finding(phase="SAST", tool="SonarCloud", rule_id=str(issue.get("rule") or issue.get("cleanCodeAttribute") or issue.get("key") or "SONAR-ISSUE"), title=str(issue.get("message") or issue.get("rule") or "SonarCloud issue"), severity=str(issue.get("severity") or issue.get("impactSeverity") or "UNKNOWN"), location=f"{component}:{line}" if line else str(component), source_report=str(path), evidence=f"issue_key={issue.get('key','')}; type={issue.get('type','')}; status={issue.get('status') or issue.get('issueStatus','')}", extra={"issue_key": issue.get("key", ""), "type": issue.get("type", ""), "status": issue.get("status") or issue.get("issueStatus") or ""}))
    return out,warnings

def parse_trivy(path: Path, label: str):
    data,msg=load_json(path)
    if data is None: return [], [msg]
    results=data.get("Results") if isinstance(data,dict) else []
    if not isinstance(results,list): return [], [f"El JSON de Trivy no contiene una lista válida en 'Results': {path}"]
    out=[]
    for result in results:
        if not isinstance(result,dict): continue
        target=result.get("Target",""); rclass=result.get("Class",""); rtype=result.get("Type","")
        for vuln in result.get("Vulnerabilities") or []:
            vid=vuln.get("VulnerabilityID") or "TRIVY-VULN"; pkg=vuln.get("PkgName") or ""; installed=vuln.get("InstalledVersion") or ""; fixed=vuln.get("FixedVersion") or ""
            out.append(build_finding(phase="SCA", tool=f"Trivy ({label})", rule_id=str(vid), title=str(vuln.get("Title") or vuln.get("Description") or vid), severity=str(vuln.get("Severity") or "UNKNOWN"), location=f"{target} | package={pkg} | installed={installed}", source_report=str(path), evidence=f"fixed_version={fixed}; class={rclass}; type={rtype}; scan={label}", url=str(vuln.get("PrimaryURL") or ""), extra={"package":pkg,"installed_version":installed,"fixed_version":fixed,"target":target,"scan":label}))
        for secret in result.get("Secrets") or []:
            rule=secret.get("RuleID") or secret.get("Category") or "TRIVY-SECRET"; line=secret.get("StartLine") or secret.get("EndLine") or ""
            out.append(build_finding(phase="SCA", tool=f"Trivy Secret ({label})", rule_id=str(rule), title=str(secret.get("Title") or secret.get("Match") or "Secret detected by Trivy"), severity=str(secret.get("Severity") or "HIGH"), location=f"{target}:{line}" if line else str(target), source_report=str(path), evidence=f"category={secret.get('Category','')}; scan={label}", extra={"target":target,"scan":label}))
    return out,[]

def parse_dependency_check(path: Path):
    data,msg=load_json(path)
    if data is None: return [], [msg]
    deps=data.get("dependencies") if isinstance(data,dict) else []
    if not isinstance(deps,list): return [], ["El JSON de OWASP Dependency-Check no contiene una lista válida en 'dependencies'."]
    out=[]
    for dep in deps:
        if not isinstance(dep,dict): continue
        file_path=dep.get("filePath") or dep.get("fileName") or ""
        package=dep.get("packages", [{}])[0].get("id", "") if isinstance(dep.get("packages"), list) and dep.get("packages") else ""
        for vuln in dep.get("vulnerabilities") or []:
            out.append(build_finding(phase="SCA", tool="OWASP Dependency-Check", rule_id=str(vuln.get("name") or vuln.get("source") or "ODC-VULN"), title=str(vuln.get("description") or vuln.get("name") or "Dependency-Check vulnerability"), severity=str(vuln.get("severity") or "UNKNOWN"), location=f"{file_path} | package={package}", source_report=str(path), evidence=f"cvssv3={(vuln.get('cvssv3') or {}).get('baseScore','')}; cvssv2={(vuln.get('cvssv2') or {}).get('score','')}", extra={"dependency":file_path,"package":package}))
    return out,[]

def parse_zap(path: Path):
    data,msg=load_json(path)
    if data is None: return [], [msg]
    sites=data.get("site") if isinstance(data,dict) else []
    if isinstance(sites,dict): sites=[sites]
    if not isinstance(sites,list): return [], ["El JSON de OWASP ZAP no contiene una lista válida en 'site'."]
    out=[]
    for site in sites:
        host=site.get("@host") or site.get("@name") or site.get("name") or "ZAP target"
        for alert in site.get("alerts") or []:
            pid=alert.get("pluginid") or alert.get("pluginId") or alert.get("alertRef") or "ZAP-ALERT"; riskcode=str(alert.get("riskcode") if alert.get("riskcode") is not None else "")
            inst=alert.get("instances") or []; first={}
            if isinstance(inst,list) and inst and isinstance(inst[0],dict): first=inst[0]
            out.append(build_finding(phase="DAST", tool="OWASP ZAP", rule_id=str(pid), title=str(alert.get("alert") or alert.get("name") or "ZAP alert"), severity=str(ZAP_RISK_TO_SEVERITY.get(riskcode, alert.get("riskdesc") or "UNKNOWN")), location=str(first.get("uri") or first.get("url") or host), source_report=str(path), evidence=str(alert.get("desc") or alert.get("solution") or alert.get("evidence") or ""), extra={"riskcode":riskcode,"confidence":alert.get("confidence",""),"instance_count":len(inst) if isinstance(inst,list) else 0}))
    return out,[]

def normalize_all(args):
    allf=[]; warnings=[]
    for parser,path in [(parse_sonar,Path(args.sonar)),(lambda p: parse_trivy(p,"filesystem"),Path(args.trivy_fs)),(lambda p: parse_trivy(p,"image"),Path(args.trivy_image)),(parse_dependency_check,Path(args.dependency_check)),(parse_zap,Path(args.zap))]:
        f,w=parser(path); allf.extend(f); warnings.extend(w)
    unique={f["fingerprint"]:f for f in allf}
    return sorted(unique.values(), key=lambda f:(f.get("phase",""),f.get("tool",""),-sev_rank(f),f.get("title",""))), warnings

def load_previous(path: Path):
    data,_=load_json(path)
    if data is None: return []
    findings=(data.get("findings") if isinstance(data,dict) else data) or []
    return [f for f in findings if isinstance(f,dict) and f.get("fingerprint")]

def compare(prev,curr):
    p={f["fingerprint"]:f for f in prev}; c={f["fingerprint"]:f for f in curr}; rows=[]
    for fid,f in c.items():
        row=dict(f); row["tracking_status"]="Persistente" if fid in p else "Nuevo"; rows.append(row)
    for fid,f in p.items():
        if fid not in c:
            row=dict(f); row["tracking_status"]="Corregido"; rows.append(row)
    order={"Nuevo":0,"Persistente":1,"Corregido":2}
    rows.sort(key=lambda f:(order.get(f.get("tracking_status",""),9),f.get("phase",""),f.get("tool",""),-sev_rank(f),f.get("title","")))
    return rows,{"current_total":len(curr),"previous_total":len(prev),"new_count":sum(r.get("tracking_status")=="Nuevo" for r in rows),"persistent_count":sum(r.get("tracking_status")=="Persistente" for r in rows),"fixed_count":sum(r.get("tracking_status")=="Corregido" for r in rows),"sast_current":sum(r.get("phase")=="SAST" for r in curr),"sca_current":sum(r.get("phase")=="SCA" for r in curr),"dast_current":sum(r.get("phase")=="DAST" for r in curr)}

def severity_badge(sev):
    s=norm_severity(sev); css={"CRITICAL":"critical","BLOCKER":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"info","INFORMATIONAL":"info"}.get(s,"unknown"); return f'<span class="badge {css}">{html.escape(s)}</span>'
def status_badge(st):
    css={"Nuevo":"new","Persistente":"persistent","Corregido":"fixed"}.get(st,"unknown"); return f'<span class="status {css}">{html.escape(st)}</span>'

def generate_html(rows, summary, warnings):
    generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"); repo=os.getenv("GITHUB_REPOSITORY","local"); run_id=os.getenv("GITHUB_RUN_ID","local"); ref=os.getenv("GITHUB_REF_NAME","local"); event=os.getenv("GITHUB_EVENT_NAME","local")
    def card(label,value,css=""): return f'<div class="card {css}"><div class="value">{html.escape(str(value))}</div><div class="label">{html.escape(label)}</div></div>'
    warning_html = f"<section class='warnings'><h2>Advertencias de lectura</h2><ul>{''.join(f'<li>{html.escape(w)}</li>' for w in warnings)}</ul></section>" if warnings else ""
    trs=[]
    for it in rows:
        title=html.escape(it.get("title","")); url=it.get("url") or ""
        if url: title=f'<a href="{html.escape(url)}">{title}</a>'
        trs.append("<tr>"+f"<td>{status_badge(it.get('tracking_status',''))}</td><td>{html.escape(it.get('phase',''))}</td><td>{html.escape(it.get('tool',''))}</td><td>{severity_badge(it.get('severity',''))}</td><td>{html.escape(it.get('rule_id',''))}</td><td>{title}</td><td>{html.escape(it.get('location',''))}</td><td>{html.escape(it.get('evidence',''))}</td>"+"</tr>")
    if not trs: trs.append('<tr><td colspan="8">No se encontraron hallazgos en los reportes disponibles.</td></tr>')
    return f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Historial de hallazgos de seguridad</title><style>body{{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#1f2937;background:#f8fafc}}header{{background:#111827;color:white;padding:22px;border-radius:12px}}h1{{margin:0 0 8px;font-size:26px}}.subtitle{{margin:0;color:#d1d5db}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}}.card{{background:white;border:1px solid #e5e7eb;border-radius:12px;padding:16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}}.card .value{{font-size:28px;font-weight:bold}}.card .label{{color:#6b7280;font-size:13px;margin-top:4px}}.new-card .value{{color:#1d4ed8}}.persistent-card .value{{color:#b45309}}.fixed-card .value{{color:#047857}}section{{background:white;border:1px solid #e5e7eb;border-radius:12px;padding:18px;margin-top:18px}}table{{width:100%;border-collapse:collapse;font-size:13px;background:white}}th,td{{border-bottom:1px solid #e5e7eb;padding:9px 8px;text-align:left;vertical-align:top}}th{{background:#f3f4f6;font-size:12px;text-transform:uppercase;color:#374151}}.badge,.status{{display:inline-block;padding:3px 8px;border-radius:999px;font-weight:bold;font-size:11px;white-space:nowrap}}.critical{{background:#7f1d1d;color:white}}.high{{background:#fee2e2;color:#991b1b}}.medium{{background:#fef3c7;color:#92400e}}.low{{background:#dbeafe;color:#1e40af}}.info{{background:#e0f2fe;color:#0369a1}}.unknown{{background:#e5e7eb;color:#374151}}.new{{background:#dbeafe;color:#1d4ed8}}.persistent{{background:#fef3c7;color:#92400e}}.fixed{{background:#dcfce7;color:#166534}}.meta{{margin-top:14px;font-size:13px;color:#6b7280}}.warnings{{border-color:#fde68a;background:#fffbeb}}code{{background:#f3f4f6;padding:2px 5px;border-radius:4px}}a{{color:#2563eb}}</style></head><body><header><h1>Historial de hallazgos de seguridad</h1><p class="subtitle">Seguimiento entre ejecuciones del pipeline DevSecOps: SAST, SCA y DAST.</p><div class="meta">Repositorio: <code>{html.escape(repo)}</code> · Rama/PR: <code>{html.escape(ref)}</code> · Evento: <code>{html.escape(event)}</code> · Run: <code>{html.escape(run_id)}</code> · Generado: {generated_at}</div></header><div class="grid">{card('Hallazgos actuales', summary.get('current_total',0))}{card('Hallazgos anteriores', summary.get('previous_total',0))}{card('Nuevos', summary.get('new_count',0),'new-card')}{card('Persistentes', summary.get('persistent_count',0),'persistent-card')}{card('Corregidos', summary.get('fixed_count',0),'fixed-card')}{card('SAST actuales', summary.get('sast_current',0))}{card('SCA actuales', summary.get('sca_current',0))}{card('DAST actuales', summary.get('dast_current',0))}</div>{warning_html}<section><h2>Detalle de seguimiento</h2><p>La clasificación se realiza comparando el snapshot anterior contra los hallazgos actuales. Si el hallazgo estaba antes y ya no aparece, se marca como <b>Corregido</b>. Si aparece en ambas ejecuciones, se marca como <b>Persistente</b>. Si aparece por primera vez, se marca como <b>Nuevo</b>.</p><table><thead><tr><th>Seguimiento</th><th>Fase</th><th>Herramienta</th><th>Severidad</th><th>Regla / CVE</th><th>Hallazgo</th><th>Ubicación</th><th>Evidencia</th></tr></thead><tbody>{''.join(trs)}</tbody></table></section></body></html>'''

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--sonar",default="security/evidence/sonar/sonar-issues.json"); ap.add_argument("--trivy-fs",default="security/evidence/trivy/trivy-report.json"); ap.add_argument("--trivy-image",default="security/evidence/trivy/trivy-image-report.json"); ap.add_argument("--dependency-check",default="security/evidence/dependency-check/dependency-check-report.json"); ap.add_argument("--zap",default="security/evidence/zap/zap-report.json"); ap.add_argument("--previous",default=".security-history-cache/previous-findings.json"); ap.add_argument("--current",default="security/evidence/history/current-findings.json"); ap.add_argument("--history-json",default="security/evidence/history/security-history.json"); ap.add_argument("--history-html",default="security/evidence/history/security-history.html"); ap.add_argument("--summary-env",default="security/evidence/history/summary.env"); ap.add_argument("--state-out",default=".security-history-cache/previous-findings.json"); args=ap.parse_args()
    curr,warnings=normalize_all(args); prev=load_previous(Path(args.previous)); rows,summary=compare(prev,curr)
    metadata={"generated_at":datetime.now(timezone.utc).isoformat(),"repository":os.getenv("GITHUB_REPOSITORY","local"),"run_id":os.getenv("GITHUB_RUN_ID","local"),"event_name":os.getenv("GITHUB_EVENT_NAME","local"),"ref_name":os.getenv("GITHUB_REF_NAME","local"),"warnings":warnings}
    write_json(Path(args.current), {"metadata":metadata,"findings":curr}); write_json(Path(args.history_json), {"metadata":metadata,"summary":summary,"findings":rows}); Path(args.history_html).parent.mkdir(parents=True,exist_ok=True); Path(args.history_html).write_text(generate_html(rows,summary,warnings),encoding="utf-8"); Path(args.summary_env).parent.mkdir(parents=True,exist_ok=True); Path(args.summary_env).write_text("\n".join(f"{k}={v}" for k,v in summary.items())+"\n",encoding="utf-8"); write_json(Path(args.state_out), {"metadata":metadata,"findings":curr})
    print("Security history generated"); print(json.dumps(summary,ensure_ascii=False,indent=2));
    if warnings:
        print("Warnings:"); [print(f"- {w}") for w in warnings]
    return 0
if __name__ == "__main__": raise SystemExit(main())
