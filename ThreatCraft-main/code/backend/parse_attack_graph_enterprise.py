#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import argparse
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from graphviz import Digraph



IMPACT_ORDER = {
    "Negligible": 0,
    "Low": 1,
    "Moderate": 2,
    "Major": 3,
    "Severe": 4,
}

IMPACT_BY_SCORE = {0: "Negligible", 1: "Low", 2: "Moderate", 3: "Major", 4: "Severe"}

FEASIBILITY_ORDER = {
    "very low": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "very high": 4,
}
FEASIBILITY_BY_SCORE = {v: k.title() for k, v in FEASIBILITY_ORDER.items()}


def _read_json(path_like) -> dict | list:
    with open(path_like, "r", encoding="utf-8") as f:
        return json.load(f)


def _safe_text(v) -> str:
    if v is None:
        return "-"
    return escape(str(v))


def _eng_name(s: str) -> str:
    if not s:
        return s or ""
    import re as _ren
    if _ren.search('[\uAC00-\uD7A3]', s):
        m = _ren.search(r'\(([^)]+)\)', s)
        if m:
            return m.group(1).strip()
        return _ren.sub('[\uAC00-\uD7A3]+', '', s).strip()
    return s


def _load_target_asset_record(asset_map_path: str, target_asset_name: str) -> dict:
    data = _read_json(asset_map_path)
    if isinstance(data, dict):
        for item in data.get("assets", []):
            if item.get("asset_name") == target_asset_name:
                return item
    return {"asset_name": target_asset_name, "threats": []}


def _load_impact_record(impact_map_path: str, target_asset_name: str) -> dict:
    data = _read_json(impact_map_path)
    if isinstance(data, list):
        for item in data:
            if item.get("asset_name") == target_asset_name:
                return item
    elif isinstance(data, dict):
        if target_asset_name in data:
            return data[target_asset_name]
        for item in data.get("assets", []):
            if item.get("asset_name") == target_asset_name:
                return item
    return {
        "asset_name": target_asset_name,
        "safety": "Negligible",
        "financial": "Negligible",
        "operational": "Negligible",
        "privacy": "Negligible",
        "score": 0,
    }

def _load_feasibility_index(attack_vector_path: str) -> Dict[str, dict]:
    data = _read_json(attack_vector_path)
    idx: Dict[str, dict] = {}
    if isinstance(data, list):
        for item in data:
            tid = item.get("id") or item.get("threat_id")
            if tid:
                idx[tid] = item
    elif isinstance(data, dict):
        for item in data.get("threats", []):
            tid = item.get("id") or item.get("threat_id")
            if tid:
                idx[tid] = item
    return idx


def _load_threat_index(threat_cti_path: str) -> Dict[str, dict]:
    data = _read_json(threat_cti_path)
    if isinstance(data, dict) and "threat_index" in data:
        return data.get("threat_index", {})
    if isinstance(data, list):
        return {item.get("id"): item for item in data if item.get("id")}
    return {}


def _severity_label_from_impact(impact_record: dict) -> str:
    labels = []
    for key in ("safety", "financial", "operational", "privacy"):
        val = str(impact_record.get(key, "") or "").strip().title()
        if val in IMPACT_ORDER:
            labels.append(val)
    if labels:
        return max(labels, key=lambda x: IMPACT_ORDER.get(x, 0))
    score = impact_record.get("score")
    try:
        score = int(score)
    except Exception:
        score = 0
    score = max(0, min(4, score))
    return IMPACT_BY_SCORE.get(score, "Negligible")


def _calc_cal_label(impact_label: str, mode: str) -> str:
    vector = (mode or "").strip().lower()
    if vector == "remote":
        vector = "network"
    cal_matrix = {
        "Severe": {"physical": "CAL2", "local": "CAL3", "adjacent": "CAL4", "network": "CAL4"},
        "Major": {"physical": "CAL1", "local": "CAL2", "adjacent": "CAL3", "network": "CAL4"},
        "Moderate": {"physical": "CAL1", "local": "CAL1", "adjacent": "CAL2", "network": "CAL3"},
        "Low": {"physical": "CAL1", "local": "CAL1", "adjacent": "CAL1", "network": "CAL2"},
        "Negligible": {"physical": "---", "local": "---", "adjacent": "---", "network": "---"},
    }
    return cal_matrix.get(impact_label, cal_matrix["Negligible"]).get(vector, "---")


def _normalize_feasibility_label(raw: Optional[str], mode: str) -> str:
    txt = str(raw or "").strip().lower().replace("_", " ")
    if txt in FEASIBILITY_ORDER:
        return txt.title()
    fallback = {
        "remote": "High",
        "adjacent": "Medium",
        "local": "Medium",
        "physical": "Low",
    }
    return fallback.get((mode or "").strip().lower(), "Medium")


def _calc_risk_level(impact_label: str, feasibility_label: str) -> str:
    impact_score = IMPACT_ORDER.get(impact_label, 0)
    feasibility_score = FEASIBILITY_ORDER.get(str(feasibility_label).strip().lower(), 2)
    if impact_score == 0:
        return "Low"
    score = impact_score + feasibility_score
    if score >= 7:
        return "Critical"
    if score >= 5:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"

def _max_impact_label(labels: List[str]) -> str:
    valid = [str(x).strip().title() for x in (labels or []) if str(x).strip()]
    if not valid:
        return "Negligible"
    return max(valid, key=lambda x: IMPACT_ORDER.get(x, 0))


def _risk_treatment_for_level(risk_level: str) -> str:
    mapping = {
        "Critical": "Reduce (mandatory) and define cybersecurity goals immediately",
        "High": "Reduce and define cybersecurity goals",
        "Medium": "Reduce if feasible, otherwise retain with explicit rationale",
        "Low": "Retain with documented rationale and monitoring assumption",
    }
    return mapping.get(risk_level, "Retain with documented rationale")


def _collect_unique_threat_ids(data: dict) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for node in data.get("nodes", []):
        tid = node.get("threat_id")
        if tid and tid not in seen:
            seen.add(tid)
            ordered.append(tid)
    return ordered


def _collect_observed_tactics(data: dict) -> Dict[str, str]:
    tactic_map: Dict[str, List[str]] = {}
    for node in data.get("nodes", []):
        tid = node.get("threat_id")
        tactic = str(node.get("tactic") or "").strip()
        if not tid or not tactic:
            continue
        bucket = tactic_map.setdefault(tid, [])
        if tactic not in bucket:
            bucket.append(tactic)
    return {tid: ", ".join(vals) for tid, vals in tactic_map.items()}

def _build_path_descriptions(data: dict) -> List[List[dict]]:
    node_index = {n.get("node_id"): n for n in data.get("nodes", [])}
    rendered = []
    for idx, path in enumerate(data.get("paths", []), start=1):
        row = []
        for nid in path:
            n = node_index.get(nid, {})
            row.append({
                "asset_name": n.get("asset_name", "?"),
                "threat_name": _eng_name(n.get("threat_name") or n.get("threat_id") or "?"),
                "phase": n.get("phase", "?"),
                "tactic": n.get("tactic", "?"),
            })
        rendered.append(row)
    return rendered

def _build_path_descriptions_for_path_with_risk(data: dict) -> List[List[dict]]:
    node_index = {n.get("node_id"): n for n in data.get("nodes", [])}
    rendered = []
    for idx, path in enumerate(data.get("paths", []), start=1):
        row = []
        for nid in path["path"]:
            n = node_index.get(nid, {})
            row.append({
                "asset_name": n.get("asset_name", "?"),
                "threat_name": _eng_name(n.get("threat_name") or n.get("threat_id") or "?"),
                "phase": n.get("phase", "?"),
                "tactic": n.get("tactic", "?"),
            })
        row = {"row": row, "risk": path["risk"]}
        rendered.append(row)
    return rendered



def _format_path(path_rows: List[dict]) -> str:
    chunks = []
    for step in path_rows:
        chunks.append(
            f"{_safe_text(step.get('asset_name'))} | {_safe_text(step.get('phase'))} | {_safe_text(_eng_name(step.get('threat_name') or ''))}"
        )
    return " &rarr; ".join(chunks)

def _format_path_fixed(path_rows: List[dict]) -> str:
    chunks = []
    for step in path_rows:
        color = ""
        if step.get('phase') == "Out":
            color = "color:red;"
        elif step.get('phase') == "Through":
            color = "color:orange;"
        elif step.get('phase') == "In":
            color = "color:green;"
        chunks.append(
            f"{_safe_text(step.get('asset_name'))} (via <span style=\"{color}\"> {_safe_text(_eng_name(step.get('threat_name') or ''))}</span>)"
        )
    return " &rarr; ".join(chunks)

OUT_TACTICS = {
    "impact",
    "collection",
    "exfiltration",
}


def _split_tactics(tactic_text: str) -> List[str]:
    if not tactic_text:
        return []
    return [t.strip() for t in str(tactic_text).split(',') if t.strip()]


def _is_out_tactic(tactic_text: str) -> bool:
    tactics = _split_tactics(tactic_text)
    return any(t.lower() in OUT_TACTICS for t in tactics)


def _make_damage_scenario_text(target_asset_name: str, mode: str, threat_name: str, impact_label: str) -> str:
    return (
        f"This technique can directly cause damage to {target_asset_name} via {mode} access by enabling "
        f"{threat_name}, resulting in {impact_label.lower()} impact on the target asset."
    )


def _make_threat_scenario_text(target_asset_name: str, mode: str, threat_name: str, impact_label: str) -> str:
    return (
        f"This technique can be used as a threat scenario against {target_asset_name} via {mode} access and "
        f"can contribute to a subsequent damage scenario that leads to {impact_label.lower()} impact."
    )


def _find_browser_executable() -> Optional[str]:
    candidates = [
        'msedge', 'microsoft-edge', 'chrome', 'google-chrome', 'chromium', 'chromium-browser', 'brave',
    ]
    for name in candidates:
        found = shutil.which(name)
        if found:
            return found

    common_windows = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    ]
    for p in common_windows:
        if os.path.exists(p):
            return p
    return None


def _convert_html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from weasyprint import HTML  # type: ignore
        HTML(filename=str(html_path), base_url=str(html_path.parent)).write_pdf(str(pdf_path))
        print(f"[OK] PDF report generated via WeasyPrint: {pdf_path}")
        return True
    except Exception:
        pass

    wk = shutil.which('wkhtmltopdf')
    if wk:
        try:
            subprocess.run(
                [wk, '--enable-local-file-access', str(html_path), str(pdf_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            print(f"[OK] PDF report generated via wkhtmltopdf: {pdf_path}")
            return True
        except Exception:
            pass

    browser = _find_browser_executable()
    if browser:
        try:
            html_uri = html_path.as_uri()
            subprocess.run(
                [
                    browser,
                    '--headless',
                    '--disable-gpu',
                    '--allow-file-access-from-files',
                    f'--print-to-pdf={str(pdf_path)}',
                    html_uri,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            print(f"[OK] PDF report generated via headless browser: {pdf_path}")
            return True
        except Exception:
            pass

    print(
        '[WARN] HTML-to-PDF conversion skipped. Install weasyprint, wkhtmltopdf, or a Chromium-based browser to enable automatic PDF export.',
        file=sys.stderr,
    )
    return False

def _stencil_to_cy_type(stencil_type: str) -> str:
    if stencil_type == "StencilEllipse":
        return "process"
    if stencil_type == "StencilParallelLines":
        return "datastore"
    return "external"


def _phase_color(phase: Optional[str]) -> str:
    if phase == "Out":
        return "#ef4444"   
    if phase == "Through":
        return "#f59e0b"   
    if phase == "In":
        return "#22c55e"   
    if phase == "Entry":
        return "#9ca3af"   
    return "#cbd5e1"      


def _phase_priority(phase: Optional[str]) -> int:
    order = {
        "Entry": 0,
        "In": 1,
        "Through": 2,
        "Out": 3,
    }
    return order.get(phase or "", -1)


def _build_asset_detail_text(asset_name: str, threats: List[dict]) -> str:
    lines = [f"DFD Element: {asset_name}", "", "Applicable Threats:"]

    if not threats:
        lines.append("- None")
        return "\n".join(lines)

    seen = set()
    for th in threats:
        threat_id = str(th.get("threat_id") or "-").strip()
        threat_name = str(th.get("threat_name") or threat_id or "-").strip()
        phase = str(th.get("phase") or "-").strip()

        key = (threat_id, threat_name, phase)
        if key in seen:
            continue
        seen.add(key)

        lines.append(f"- [{threat_id}] {threat_name} (Phase: {phase})")

    return "\n".join(lines)


def _build_cytoscape_fallback_model(attack_graph_result: dict) -> dict:
    attack_nodes = attack_graph_result.get("nodes", []) or []
    attack_edges = attack_graph_result.get("edges", []) or []

    asset_info: Dict[str, dict] = {}
    asset_threat_map: Dict[str, List[dict]] = defaultdict(list)

    for n in attack_nodes:
        guid = n.get("asset_guid") or n.get("asset_name") or n.get("node_id")
        if not guid:
            continue
        phase = n.get("phase") or ""
        prev_phase = asset_info.get(guid, {}).get("phase", "")
        if guid not in asset_info or _phase_priority(phase) > _phase_priority(prev_phase):
            asset_info[guid] = {
                "id": guid,
                "label": n.get("asset_name") or str(guid),
                "type": _stencil_to_cy_type(n.get("stencil_type") or ""),
                "phase": phase,
            }
        asset_threat_map[guid].append({
            "threat_id": n.get("threat_id"),
            "threat_name": n.get("threat_name"),
            "phase": phase,
            "tactic": n.get("tactic"),
        })

    phase_buckets: Dict[str, List[str]] = {"Entry": [], "In": [], "Through": [], "Out": [], "": []}
    for guid, info in asset_info.items():
        phase_buckets.setdefault(info.get("phase") or "", []).append(guid)

    x_by_phase = {"Entry": 0, "In": 240, "Through": 520, "Out": 800, "": 1040}
    cy_nodes = []
    for phase, guids in phase_buckets.items():
        for idx, guid in enumerate(guids):
            info = asset_info[guid]
            cy_nodes.append({
                "data": {
                    "id": guid,
                    "label": info.get("label") or str(guid),
                    "type": info.get("type") or "external",
                    "phase": phase,
                    "highlighted": "yes" if phase else "no",
                    "borderColor": _phase_color(phase),
                    "desc": _build_asset_detail_text(
                        info.get("label") or str(guid),
                        asset_threat_map.get(guid, []),
                    ),
                },
                "position": {
                    "x": x_by_phase.get(phase, 1040),
                    "y": idx * 115,
                },
            })

    node_id_to_asset_guid = {
        n.get("node_id"): (n.get("asset_guid") or n.get("asset_name") or n.get("node_id"))
        for n in attack_nodes
    }

    seen_edges: Set[Tuple[str, str, str]] = set()
    cy_edges = []
    for idx, e in enumerate(attack_edges):
        src = node_id_to_asset_guid.get(e.get("from"))
        dst = node_id_to_asset_guid.get(e.get("to"))
        if not src or not dst or src == dst:
            continue
        label = e.get("dfd_flow_label") or ""
        key = (src, dst, label)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        phase = asset_info.get(src, {}).get("phase") or "Through"
        cy_edges.append({
            "data": {
                "id": f"fallback_edge_{idx}",
                "source": src,
                "target": dst,
                "label": label,
                "phase": phase,
                "highlighted": "yes",
                "borderColor": _phase_color(phase),
                "desc": json.dumps({
                    "source": asset_info.get(src, {}).get("label", src),
                    "target": asset_info.get(dst, {}).get("label", dst),
                    "label": label,
                    "phase": phase,
                }, ensure_ascii=False, indent=2),
            }
        })

    return {"nodes": cy_nodes, "edges": cy_edges}


def _build_cytoscape_dfd_model(tm7_path: Path, attack_graph_result: dict) -> dict:
    nodes_by_guid, flows, _ = parse_tm7(tm7_path)

    attack_nodes = attack_graph_result.get("nodes", [])
    attack_edges = attack_graph_result.get("edges", [])

    asset_phase_map: Dict[str, str] = {}
    asset_threat_map: Dict[str, List[dict]] = defaultdict(list)

    for n in attack_nodes:
        asset_guid = n.get("asset_guid")
        phase = n.get("phase")
        if not asset_guid:
            continue

        prev = asset_phase_map.get(asset_guid)
        if prev is None or _phase_priority(phase) > _phase_priority(prev):
            asset_phase_map[asset_guid] = phase

        asset_threat_map[asset_guid].append({
            "threat_id": n.get("threat_id"),
            "threat_name": n.get("threat_name"),
            "phase": phase,
            "tactic": n.get("tactic"),
        })

    flow_phase_map: Dict[str, str] = {}
    for e in attack_edges:
        fg = e.get("dfd_flow_guid")
        if not fg:
            continue

        src_phase = None
        src_node_id = e.get("from")
        for n in attack_nodes:
            if n.get("node_id") == src_node_id:
                src_phase = n.get("phase")
                break

        prev = flow_phase_map.get(fg)
        if prev is None or _phase_priority(src_phase) > _phase_priority(prev):
            flow_phase_map[fg] = src_phase or "Through"

    cy_nodes = []
    for guid, n in nodes_by_guid.items():
        phase = asset_phase_map.get(guid)
        cy_nodes.append({
            "data": {
                "id": guid,
                "label": n.name,
                "type": _stencil_to_cy_type(n.stencil_type),
                "stencil_type": n.stencil_type,
                "phase": phase or "",
                "highlighted": "yes" if guid in asset_phase_map else "no",
                "borderColor": _phase_color(phase),
                "desc": _build_asset_detail_text(
                    n.name,
                    asset_threat_map.get(guid, []),
                ),
            },
            "position": {
                "x": float(n.left) + float(n.width) / 2.0,
                "y": float(n.top) + float(n.height) / 2.0,
            },
        })

    valid_node_ids = {str(guid) for guid in nodes_by_guid.keys()}

    cy_edges = []
    skipped_edges = 0
    for f in flows:
        src = str(f.source_guid or "")
        dst = str(f.target_guid or "")
        if src not in valid_node_ids or dst not in valid_node_ids:
            skipped_edges += 1
            continue

        phase = flow_phase_map.get(f.guid)
        cy_edges.append({
            "data": {
                "id": f.guid,
                "source": src,
                "target": dst,
                "label": f.label or "",
                "phase": phase or "",
                "highlighted": "yes" if f.guid in flow_phase_map else "no",
                "borderColor": _phase_color(phase),
                "desc": json.dumps({
                    "guid": f.guid,
                    "label": f.label,
                    "source_guid": src,
                    "target_guid": dst,
                    "phase": phase or "-",
                    "skipped_invalid_tm7_edges": skipped_edges,
                }, ensure_ascii=False, indent=2),
            }
        })

    return {
        "nodes": cy_nodes,
        "edges": cy_edges,
        "skipped_invalid_tm7_edges": skipped_edges,
    }


def _render_enterprise_level_review_html(enterprise_review_data: Optional[dict]) -> str:
    if not enterprise_review_data:
        return "<div class='card'><p style='color:#6b7280'>No enterprise-level AI review available. Provide an AI analysis JSON to enable this section.</p></div>"

    vr = enterprise_review_data.get("enterprise_level_review", enterprise_review_data)
    overall_summary = _safe_text(vr.get("overall_summary") or "-")
    overall_validity = _safe_text(vr.get("overall_validity") or "-")
    overall_confidence = _safe_text(vr.get("overall_confidence") or "-")
    highest_risk = _safe_text(vr.get("highest_risk_path_id") or "-")
    weaknesses = vr.get("systemic_weaknesses") or []
    common_patterns = _safe_text(vr.get("common_attack_patterns") or "-")
    path_reviews = vr.get("path_reviews") or []

    weakness_html = "".join(f"<li style='font-size:12px'>{escape(str(w))}</li>" for w in weaknesses) if weaknesses else "<li>-</li>"

    path_html = ""
    for pr in path_reviews:
        pid = _safe_text(pr.get("path_id") or "-")
        seq = _safe_text(pr.get("phase_sequence") or "-")
        narrative = _safe_text(pr.get("narrative") or pr.get("narrative_en") or pr.get("narrative_ko") or "-")
        entry_assessment = _safe_text(pr.get("entry_point_assessment") or "-")
        attack_obj = _safe_text(pr.get("attack_objective") or "-")
        confidence = _safe_text(pr.get("confidence") or "-")
        recs = pr.get("recommendations") or []
        equipment = pr.get("required_equipment") or []
        critical_assets = ", ".join(pr.get("critical_assets") or [])
        key_threats = ", ".join(pr.get("key_threat_ids") or [])
        dominant_tactics = ", ".join(pr.get("dominant_tactics") or [])
        risk_score = pr.get("risk_score") or 0

        recs_html = "".join(f"<li style='font-size:11px'>{escape(str(r))}</li>" for r in recs)
        eq_html = "".join(f"<li style='font-size:11px'><span style='background:#1e3a8a;color:white;padding:1px 6px;border-radius:3px;font-size:9px;margin-right:4px'>EQ</span>{escape(str(e))}</li>" for e in equipment) if equipment else ""

        path_html += f"""
        <div class='card avoid-break' style='margin-bottom:14px;border-left:5px solid #1e40af'>
            <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;margin-bottom:8px'>
                <span style='font-size:14px;font-weight:bold;color:#1e40af'>{pid}</span>
                <div style='display:flex;gap:8px;flex-wrap:wrap'>
                    <span style='background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:4px;font-size:10px'>Confidence: {confidence}</span>
                    <span style='background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:4px;font-size:10px'>Risk Score: {risk_score}</span>
                </div>
            </div>
            <p style='font-size:11px;color:#6b7280;margin:0 0 6px 0'><b>Phase Sequence:</b> {seq}</p>
            <p style='font-size:11px;color:#6b7280;margin:0 0 6px 0'><b>Attack Objective:</b> {attack_obj}</p>
            <div style='background:#f8fafc;border-radius:6px;padding:10px;margin-bottom:8px'>
                <p style='font-size:12px;font-weight:bold;color:#374151;margin:0 0 4px 0'>Attack Path Narrative</p>
                <p style='font-size:12px;color:#374151;margin:0;line-height:1.7'>{narrative}</p>
            </div>
            <div style='background:#f0fdf4;border-radius:6px;padding:8px;margin-bottom:6px'>
                <p style='font-size:11px;font-weight:bold;color:#166534;margin:0 0 3px 0'>Entry Point Assessment</p>
                <p style='font-size:11px;color:#374151;margin:0'>{entry_assessment}</p>
            </div>
            <div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:#6b7280;margin-bottom:6px'>
                <div><b>Critical Assets:</b> {escape(critical_assets) if critical_assets else "-"}</div>
                <div><b>Key Threats:</b> {escape(key_threats) if key_threats else "-"}</div>
                <div><b>Dominant Tactics:</b> {escape(dominant_tactics) if dominant_tactics else "-"}</div>
            </div>
            {f"<div style='margin-bottom:6px'><p style='font-size:11px;font-weight:bold;color:#374151;margin:0 0 2px 0'>Recommendations</p><ul style='margin:0;padding-left:16px'>{recs_html}</ul></div>" if recs_html else ""}
            {f"<div style='background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:8px'><p style='font-size:11px;font-weight:bold;color:#1e40af;margin:0 0 4px 0'>Required Attack Equipment</p><ul style='margin:0;padding-left:16px'>{eq_html}</ul></div>" if eq_html else ""}
        </div>
        """

    return f"""
    <div class='card' style='margin-bottom:14px'>
        <div style='display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:10px;font-size:11px'>
            <div style='background:#f0fdf4;border-radius:6px;padding:8px;text-align:center'>
                <div style='color:#6b7280'>Confidence</div>
                <div style='font-weight:bold;color:#166534'>{overall_confidence}</div>
            </div>
            <div style='background:#fef2f2;border-radius:6px;padding:8px;text-align:center'>
                <div style='color:#6b7280'>Highest Risk Path</div>
                <div style='font-weight:bold;color:#dc2626'>{highest_risk}</div>
            </div>
        </div>
        <div style='background:#f8fafc;border-radius:6px;padding:12px;margin-bottom:10px'>
            <p style='font-size:13px;font-weight:bold;color:#374151;margin:0 0 6px 0'>Overall Assessment Summary</p>
            <p style='font-size:12px;color:#374151;margin:0;line-height:1.7'>{overall_summary}</p>
        </div>
        <div style='background:#fff7ed;border-radius:6px;padding:10px;margin-bottom:10px'>
            <p style='font-size:12px;font-weight:bold;color:#9a3412;margin:0 0 4px 0'>Systemic Weaknesses</p>
            <ul style='margin:0;padding-left:18px'>{weakness_html}</ul>
        </div>
        <div style='background:#faf5ff;border-radius:6px;padding:10px;margin-bottom:10px'>
            <p style='font-size:12px;font-weight:bold;color:#6d28d9;margin:0 0 4px 0'>Common Attack Patterns</p>
            <p style='font-size:12px;color:#374151;margin:0;line-height:1.6'>{common_patterns}</p>
        </div>
    </div>
    <h4 style='margin:12px 0 8px 0;color:#1e40af'>Individual Path Reviews ({len(path_reviews)} paths)</h4>
    {path_html if path_html else "<div class='card'><p>No path reviews available.</p></div>"}
    """


def _render_functional_level_html(functional_data: Optional[dict]) -> str:
    
    if not functional_data:
        return "<div class='card'><p style='color:#6b7280'>No functional-level scenarios available. Provide a Gemini API key to enable this section.</p></div>"

    fa = functional_data.get("functional_level_analysis", functional_data)

    
    summary = _safe_text(
        fa.get("summary_narrative") or
        fa.get("summary_narrative_en") or
        fa.get("summary_narrative_ko") or "-"
    )
    cross_insights = _safe_text(
        fa.get("cross_scenario_insights") or
        fa.get("cross_scenario_insights_ko") or "-"
    )
    priority_mitigation = _safe_text(
        fa.get("priority_mitigation_plan") or
        fa.get("priority_mitigation_ko") or "-"
    )
    lifecycle = _safe_text(fa.get("lifecycle_considerations") or "-")
    novel_summary = _safe_text(fa.get("novel_attack_surfaces_summary") or "")
    priority_ids = fa.get("priority_threat_ids") or []
    scenarios = fa.get("functional_scenarios") or []

    impact_color = {
        "Severe": "#dc2626", "Major": "#ea580c", "Moderate": "#d97706",
        "Negligible": "#16a34a", "Low": "#84cc16",
    }
    cs_color = {
        "Confidentiality": "#7c3aed", "Integrity": "#2563eb",
        "Availability": "#dc2626", "Authenticity": "#d97706",
    }

    def _impact_badge(label: str, value: str) -> str:
        color = impact_color.get(value, "#6b7280")
        return (f"<div style='text-align:center;background:#f8fafc;border-radius:6px;padding:6px'>"
                f"<div style='font-size:9px;color:#6b7280;font-weight:bold'>{label}</div>"
                f"<div style='font-size:12px;font-weight:bold;color:{color}'>{value or '-'}</div>"
                f"</div>")

    scenarios_html = ""
    for sc in scenarios:
        sid = _safe_text(sc.get("scenario_id") or "-")
        func_name = _safe_text(sc.get("affected_function_name") or "-")
        func_cat = _safe_text(sc.get("affected_function_category") or "-")
        cs_goal = sc.get("cybersecurity_goal") or "-"
        is_novel = sc.get("is_novel_finding") or False
        novel_desc = _safe_text(sc.get("novel_finding_description") or "")
        confidence = _safe_text(sc.get("confidence") or "-")
        
        _s_i = sc.get("safety_impact") or "Negligible"
        _f_i = sc.get("financial_impact") or "Negligible"
        _o_i = sc.get("operational_impact") or "Negligible"
        _p_i = sc.get("privacy_impact") or "Negligible"
        _feas_r = sc.get("overall_feasibility_rating") or "Medium"
        risk_level = _calc_risk_level(_max_impact_label([_s_i, _f_i, _o_i, _p_i]), _feas_r)
        feasibility = _safe_text(_feas_r)
        feasibility_score = sc.get("overall_feasibility_score") or 0
        source_paths = ", ".join(sc.get("source_enterprise_path_ids") or [])
        source_threats = ", ".join(sc.get("source_threat_ids") or [])

        
        impact_text = _safe_text(sc.get("functional_impact") or sc.get("functional_impact_ko") or "-")
        attack_text = _safe_text(sc.get("attack_narrative") or sc.get("attack_narrative_ko") or "-")
        damage_text = _safe_text(sc.get("damage_scenario") or sc.get("damage_scenario_ko") or "-")

        
        safety_i = sc.get("safety_impact") or "Negligible"
        financial_i = sc.get("financial_impact") or "Negligible"
        operational_i = sc.get("operational_impact") or "Negligible"
        privacy_i = sc.get("privacy_impact") or "Negligible"

        max_impact = max([safety_i, financial_i, operational_i, privacy_i],
                         key=lambda x: IMPACT_ORDER.get(x, 0))
        border_color = impact_color.get(max_impact, "#e5e7eb")

        
        comp = sc.get("component_details_used") or {}
        comp_html = ""
        if comp:
            comp_parts = []
            for k, v in comp.items():
                
                if k.lower() in ("cves", "cve_list", "cve", "cve_refs", "asset_kind"):
                    continue
                
                if k.lower() not in ("hardware", "software", "interfaces"):
                    continue
                if v and v != "..." and v != [] and v != "[INFERRED]":
                    v_str = ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
                    if v_str.strip() and v_str.strip() != "...":
                        comp_parts.append(f"<b>{escape(k.title())}:</b> {escape(v_str[:150])}")
            if comp_parts:
                comp_html = "<div style='font-size:11px;color:#6b7280;margin-bottom:6px'>" + " &nbsp;|&nbsp; ".join(comp_parts) + "</div>"

        
        atree = sc.get("attack_tree") or {}
        atree_html = ""
        if atree.get("root_goal"):
            steps = atree.get("sub_steps") or []
            steps_html = "".join(
                f"<li style='font-size:11px'>[{escape(s.get('logical_operator','OR'))}] {escape(s.get('description','')[:120])} "
                f"<span style='color:#6b7280'>→ {escape(s.get('feasibility_scores',{}).get('rating',''))}</span></li>"
                for s in steps[:5]
            )
            atree_html = f"""<div style='background:#f8fafc;border-radius:6px;padding:8px;margin-bottom:8px'>
                <p style='font-size:11px;font-weight:bold;color:#374151;margin:0 0 4px 0'>Attack Tree [{escape(atree.get('logical_structure','OR'))}]: {escape(atree.get('root_goal','')[:100])}</p>
                <ul style='margin:0;padding-left:16px'>{steps_html}</ul>
            </div>"""

        
        reqs = sc.get("cybersecurity_requirements") or []
        mits = sc.get("recommended_mitigations") or []
        inferences = sc.get("inferences_made") or []
        equipment = sc.get("required_equipment") or []
        req_html = "".join(f"<li style='font-size:11px'>{escape(str(r))}</li>" for r in reqs) if reqs else "<li>-</li>"
        mit_html = "".join(f"<li style='font-size:11px'>{escape(str(m))}</li>" for m in mits) if mits else ""
        inf_html = "".join(f"<li style='font-size:11px;color:#d97706'>{escape(str(i))}</li>" for i in inferences) if inferences else ""
        eq_func_html = "".join(f"<li style='font-size:11px'><span style='background:#1e3a8a;color:white;padding:1px 6px;border-radius:3px;font-size:9px;margin-right:4px'>EQ</span>{escape(str(e))}</li>" for e in equipment) if equipment else ""

        cs_badge_color = cs_color.get(cs_goal, "#6b7280")
        novel_badge = f"<span style='background:#16a34a;color:white;padding:2px 8px;border-radius:4px;font-size:10px;margin-left:6px'>NOVEL FINDING</span>" if is_novel else ""

        scenarios_html += f"""
        <div class='card avoid-break' style='margin-bottom:16px;border-left:5px solid {border_color}'>
            <div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;margin-bottom:10px'>
                <div>
                    <span style='font-size:13px;font-weight:bold;color:#1e40af'>{sid}</span>
                    <span style='margin-left:8px;font-size:12px;color:#374151;font-weight:bold'>{func_name}</span>
                    {novel_badge}
                </div>
                <div style='display:flex;gap:6px;flex-wrap:wrap'>
                    <span style='background:{cs_badge_color};color:white;padding:2px 8px;border-radius:4px;font-size:10px'>{escape(cs_goal)}</span>
                    <span style='background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:4px;font-size:10px'>Feasibility: {feasibility} ({feasibility_score})</span>
                    <span style='background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:4px;font-size:10px'>Risk Level: {risk_level}</span>
                    <span style='background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:4px;font-size:10px'>Confidence: {confidence}</span>
                </div>
            </div>
            <div style='display:grid;grid-template-columns:repeat(2,1fr);gap:6px;font-size:11px;color:#6b7280;margin-bottom:8px'>
                <div><b>Function Category:</b> {func_cat}</div>
                <div><b>Source Paths:</b> {escape(source_paths) if source_paths else "-"}</div>
                <div><b>Source Threats:</b> {escape(source_threats) if source_threats else "-"}</div>
            </div>
            {comp_html}
            {f'<div style="background:#f0fdf4;border-radius:6px;padding:8px;margin-bottom:6px"><p style="font-size:11px;font-weight:bold;color:#166534;margin:0 0 3px 0">Novel Attack Surface</p><p style="font-size:11px;margin:0">{novel_desc}</p></div>' if is_novel and novel_desc else ""}
            <div style='display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:10px'>
                {_impact_badge("Safety", safety_i)}
                {_impact_badge("Financial", financial_i)}
                {_impact_badge("Operational", operational_i)}
                {_impact_badge("Privacy", privacy_i)}
            </div>
            <div style='background:#fef9ec;border:1px solid #fde68a;border-radius:6px;padding:10px;margin-bottom:8px'>
                <p style='font-size:12px;font-weight:bold;color:#92400e;margin:0 0 4px 0'>Functional Impact</p>
                <p style='font-size:12px;color:#374151;margin:0;line-height:1.6'>{impact_text}</p>
            </div>
            <div style='background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:10px;margin-bottom:8px'>
                <p style='font-size:12px;font-weight:bold;color:#991b1b;margin:0 0 4px 0'>Attack Narrative</p>
                <p style='font-size:12px;color:#374151;margin:0;line-height:1.6'>{attack_text}</p>
            </div>
            <div style='background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:10px;margin-bottom:8px'>
                <p style='font-size:12px;font-weight:bold;color:#1e40af;margin:0 0 4px 0'>Damage Scenario</p>
                <p style='font-size:12px;color:#374151;margin:0;line-height:1.6'>{damage_text}</p>
            </div>
            {atree_html}
            <div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px'>
                <div>
                    <p style='font-size:11px;font-weight:bold;color:#374151;margin:0 0 4px 0'>Cybersecurity Requirements</p>
                    <ul style='margin:0;padding-left:16px'>{req_html}</ul>
                </div>
                {f"<div><p style='font-size:11px;font-weight:bold;color:#374151;margin:0 0 4px 0'>Recommended Mitigations</p><ul style='margin:0;padding-left:16px'>{mit_html}</ul></div>" if mit_html else ""}
            </div>
            {f"<div style='margin-top:6px'><p style='font-size:11px;font-weight:bold;color:#d97706;margin:0 0 2px 0'>Inferences Made</p><ul style='margin:0;padding-left:16px'>{inf_html}</ul></div>" if inf_html else ""}
            {f"<div style='margin-top:8px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:8px'><p style='font-size:11px;font-weight:bold;color:#1e40af;margin:0 0 4px 0'>Required Attack Equipment</p><ul style='margin:0;padding-left:16px'>{eq_func_html}</ul></div>" if eq_func_html else ""}
        </div>
        """

    priority_html = "".join(f"<span class='pill' style='background:#dc2626;color:white'>{escape(t)}</span>" for t in priority_ids)

    novel_block = f"""<div style='background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:10px;margin-bottom:10px'>
        <p style='font-size:12px;font-weight:bold;color:#166534;margin:0 0 4px 0'>Novel Attack Surfaces Identified</p>
        <p style='font-size:12px;color:#374151;margin:0;line-height:1.6'>{novel_summary}</p>
    </div>""" if novel_summary and novel_summary != "-" else ""

    return f"""
    <div class='card' style='margin-bottom:14px'>
        <div style='background:#f8fafc;border-radius:6px;padding:12px;margin-bottom:10px'>
            <p style='font-size:13px;font-weight:bold;color:#374151;margin:0 0 6px 0'>Functional-Level Analysis Summary</p>
            <p style='font-size:12px;color:#374151;margin:0;line-height:1.7'>{summary}</p>
        </div>
        {novel_block}
        <div style='margin-top:8px;margin-bottom:4px'>
            <b style='font-size:12px'>Priority Threats:</b> {priority_html if priority_html else "N/A"}
        </div>
    </div>
    <h4 style='margin:12px 0 8px 0;color:#7c3aed'>Threat Scenarios ({len(scenarios)} total)</h4>
    {scenarios_html if scenarios_html else "<div class='card'><p>No scenarios generated. Run analysis with a Gemini API key.</p></div>"}
    <div class='card' style='margin-top:14px'>
        <p style='font-size:13px;font-weight:bold;color:#374151;margin:0 0 8px 0'>Cross-Scenario Insights</p>
        <p style='font-size:12px;color:#374151;line-height:1.6;margin:0 0 12px 0'>{cross_insights}</p>
        <p style='font-size:13px;font-weight:bold;color:#374151;margin:0 0 6px 0'>Priority Mitigation Plan</p>
        <p style='font-size:12px;color:#374151;line-height:1.6;margin:0 0 12px 0'>{priority_mitigation}</p>
        <p style='font-size:13px;font-weight:bold;color:#374151;margin:0 0 6px 0'>Lifecycle Considerations</p>
        <p style='font-size:12px;color:#374151;line-height:1.6;margin:0'>{lifecycle}</p>
    </div>
    """


def generate_html_report(
    report_path,
    attack_graph_path,
    out_path,
    threat_cti_path,
    asset_map_path,
    attack_vector_path,
    impact_map_path,
    attack_graph_with_risk_path,
    tm7_path,
    gemini_enterprise_review=None,
    gemini_functional=None,
):

    try:
        data = _read_json(out_path) if out_path and Path(str(out_path)).exists() else {}
    except Exception:
        data = {}
    mode = data.get("mode") or "-"
    target_asset_name = data.get("target_asset_name") or "-"
    boundary_name = data.get("boundary_name") or "-"
    threat_ids = _collect_unique_threat_ids(data)

    def _safe_load(fn, *args):
        try:
            if args and (not args[0] or not Path(str(args[0])).exists()):
                return {}
            return fn(*args)
        except Exception:
            return {}

    threat_index       = _safe_load(_load_threat_index, threat_cti_path)
    target_asset       = _safe_load(_load_target_asset_record, asset_map_path, target_asset_name)
    impact_record      = _safe_load(_load_impact_record, impact_map_path, target_asset_name)
    feasibility_index  = _safe_load(_load_feasibility_index, attack_vector_path)
    impact_label       = _severity_label_from_impact(impact_record)
    cal_label          = _calc_cal_label(impact_label, mode)
    path_rows          = _build_path_descriptions(data)
    try:
        data_with_risk = _read_json(attack_graph_with_risk_path) if attack_graph_with_risk_path and Path(str(attack_graph_with_risk_path)).exists() else {}
    except Exception:
        data_with_risk = {}
    path_with_risk_rows = _build_path_descriptions_for_path_with_risk(data_with_risk)
    try:
        cy_model = _build_cytoscape_dfd_model(Path(tm7_path), data) if tm7_path and Path(str(tm7_path)).exists() else {"nodes": [], "edges": []}
        if not cy_model.get("nodes"):
            cy_model = _build_cytoscape_fallback_model(data)
    except Exception:
        cy_model = _build_cytoscape_fallback_model(data)
    cy_model_json = json.dumps(cy_model, ensure_ascii=False)

    direct_asset_threats = []
    direct_asset_threat_index = {}
    for th in target_asset.get("threats", []):
        tid = th.get("id")
        if not tid:
            continue
        direct_asset_threats.append(tid)
        direct_asset_threat_index[tid] = th

    observed_tactic_index = _collect_observed_tactics(data)

    damage_ids = []
    for tid in direct_asset_threats:
        th = direct_asset_threat_index.get(tid, {})
        direct_tactic = ", ".join(th.get("tactics", [])) if isinstance(th.get("tactics"), list) else str(th.get("tactics") or "")
        if _is_out_tactic(direct_tactic):
            damage_ids.append(tid)

    threat_ids_for_report = []
    for tid in threat_ids:
        if tid not in damage_ids and tid not in threat_ids_for_report:
            threat_ids_for_report.append(tid)
    for tid in direct_asset_threats:
        if tid not in damage_ids and tid not in threat_ids_for_report:
            threat_ids_for_report.append(tid)

    relevant_threat_count = len(set(threat_ids_for_report + damage_ids))

    scenario_rows = []
    threat_scenario_rows = []
    damage_scenario_rows = []

    for tid in threat_ids_for_report:
        base = threat_index.get(tid, {})
        mapped = feasibility_index.get(tid, {})
        direct_th = direct_asset_threat_index.get(tid, {})
        threat_name = (
            base.get("name")
            or mapped.get("name")
            or direct_th.get("name")
            or tid
        )
        tactic = (
            observed_tactic_index.get(tid)
            or base.get("tactic")
            or (", ".join(direct_th.get("tactics", [])) if isinstance(direct_th.get("tactics"), list) else None)
            or (", ".join(base.get("tactics", [])) if isinstance(base.get("tactics"), list) else None)
            or (", ".join(mapped.get("tactics", [])) if isinstance(mapped.get("tactics"), list) else None)
            or "-"
        )
        feasibility_label = _normalize_feasibility_label(mapped.get("feasibility"), mode)
        risk_level = _calc_risk_level(impact_label, feasibility_label)
        treatment = _risk_treatment_for_level(risk_level)
        row = {
            "threat_id": tid,
            "threat_name": threat_name,
            "tactic": tactic,
            "scenario_type": "Threat Scenario",
            "scenario_text": _make_threat_scenario_text(target_asset_name, mode, threat_name, impact_label),
            "feasibility": feasibility_label,
            "risk_level": risk_level,
            "treatment": treatment,
        }
        scenario_rows.append(row)
        threat_scenario_rows.append(row)

    for tid in damage_ids:
        base = threat_index.get(tid, {})
        mapped = feasibility_index.get(tid, {})
        direct_th = direct_asset_threat_index.get(tid, {})
        threat_name = (
            direct_th.get("name")
            or base.get("name")
            or mapped.get("name")
            or tid
        )
        tactic = ", ".join(direct_th.get("tactics", [])) if isinstance(direct_th.get("tactics"), list) else str(direct_th.get("tactics") or "-")
        feasibility_label = _normalize_feasibility_label(mapped.get("feasibility"), mode)
        risk_level = _calc_risk_level(impact_label, feasibility_label)
        treatment = _risk_treatment_for_level(risk_level)
        row = {
            "threat_id": tid,
            "threat_name": threat_name,
            "tactic": tactic,
            "scenario_type": "Damage Scenario",
            "scenario_text": _make_damage_scenario_text(target_asset_name, mode, threat_name, impact_label),
            "feasibility": feasibility_label,
            "risk_level": risk_level,
            "treatment": treatment,
        }
        scenario_rows.append(row)
        damage_scenario_rows.append(row)

    threat_rows_html = "".join(
        f"""
        <tr>
            <td>{_safe_text(row['threat_id'])}</td>
            <td>{_safe_text(_eng_name(row.get('threat_name') or ''))}</td>
            <td>{_safe_text(row['tactic'])}</td>
            <td>{_safe_text(row['scenario_text'])}</td>
        </tr>
        """
        for row in threat_scenario_rows
    ) or "<tr><td colspan='4'>No threat scenario identified.</td></tr>"

    damage_rows_html = "".join(
        f"""
        <tr>
            <td>{_safe_text(row['threat_id'])}</td>
            <td>{_safe_text(_eng_name(row.get('threat_name') or ''))}</td>
            <td>{_safe_text(row['tactic'])}</td>
            <td>{_safe_text(row['scenario_text'])}</td>
        </tr>
        """
        for row in damage_scenario_rows
    ) or "<tr><td colspan='4'>No damage scenario identified.</td></tr>"

    feasibility_rows_html = "".join(
        f"""
        <tr>
            <td>{_safe_text(row['threat_id'])}</td>
            <td>{_safe_text(_eng_name(row.get('threat_name') or ''))}</td>
            <td>{_safe_text(row['feasibility'])}</td>
            <td>{_safe_text(row['risk_level'])}</td>
            <td>{_safe_text(cal_label)}</td>
            <td>{_safe_text(row['treatment'])}</td>
        </tr>
        """
        for row in scenario_rows
    ) or "<tr><td colspan='6'>No feasibility information available.</td></tr>"

    path_rows_html = "".join(
        f"<tr><td class='path-id-col'>P{idx}</td><td>{_format_path_fixed(path['row'])}</td><td style=\"width: 10px;\">{path['risk']}</td></tr>"
        for idx, path in enumerate(path_with_risk_rows, start=1)
    ) or "<tr><td colspan='3'>No valid attack path identified.</td></tr>"

    
    attack_graph_img_html = "<p>No attack graph image generated.</p>"
    if attack_graph_path and Path(attack_graph_path).exists():
        try:
            import base64 as _b64
            _img_suffix = Path(attack_graph_path).suffix.lower().lstrip(".")
            _mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                     "svg": "image/svg+xml"}.get(_img_suffix, "image/png")
            with open(attack_graph_path, "rb") as _f:
                _img_b64 = _b64.b64encode(_f.read()).decode("ascii")
            attack_graph_img_html = (
                "<div class='figure-wrap avoid-break'>"
                f"<img class='graph-image' src='data:{_mime};base64,{_img_b64}'>"
                "</div>"
            )
        except Exception as _ie:
            attack_graph_img_html = f"<p>Could not embed attack graph image: {_ie}</p>" 

    
    enterprise_review_html = _render_enterprise_level_review_html(gemini_enterprise_review)
    functional_level_html = _render_functional_level_html(gemini_functional)

    ai_badge = ""
    if gemini_enterprise_review or gemini_functional:
        ai_badge = "<span style='background:#8b5cf6;color:white;padding:2px 10px;border-radius:4px;font-size:11px;margin-left:8px'>Included AI analysis</span>"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\">
    <title>TARA Report for Concept Phase</title>
    <script src="https://unpkg.com/cytoscape/dist/cytoscape.min.js"></script>
    <script src="https://unpkg.com/@popperjs/core@2"></script>
    <script src="https://unpkg.com/cytoscape-popper/cytoscape-popper.js"></script>
    <script src="https://unpkg.com/tippy.js@6/dist/tippy-bundle.umd.min.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/tippy.js@6/animations/scale.css"/>
    <style>
        @page {{ size: A4 portrait; margin: 16mm 14mm; }}
        body {{ font-family: Arial, sans-serif; margin: 0; color: #1a1a1a; line-height: 1.45; font-size: 13px; background: #f5f7fb; }}
        .container {{ max-width: 1160px; margin: 16px auto; padding: 0 16px 22px; box-sizing: border-box; }}
        h1 {{ font-size: 28px; border-bottom: 3px solid #1f2937; padding-bottom: 8px; margin: 0 0 8px 0; break-after: avoid-page; page-break-after: avoid; }}
        h2 {{ font-size: 20px; margin: 0 0 10px 0; border-left: 6px solid #374151; padding-left: 10px; break-after: avoid-page; page-break-after: avoid; }}
        h3 {{ font-size: 16px; margin-top: 14px; margin-bottom: 8px; break-after: avoid-page; page-break-after: avoid; }}
        p, li {{ font-size: 13px; }}
        .note {{ color: #4b5563; margin-bottom: 14px; font-size: 12px; }}
        .card {{ background: #f8fafc; border: 1px solid #d1d5db; padding: 12px 14px; border-radius: 8px; margin-top: 10px; break-inside: avoid-page; page-break-inside: avoid; }}
        .section {{ margin-top: 22px; break-inside: avoid-page; page-break-inside: avoid; }}
        .ai-section {{ margin-top: 22px; border: 2px solid #8b5cf6; border-radius: 10px; padding: 16px; background: #faf5ff; }}
        .ai-section h2 {{ border-left-color: #8b5cf6; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, minmax(160px, 1fr)); gap: 10px; break-inside: avoid-page; page-break-inside: avoid; }}
        .metric {{ background: #ffffff; border: 1px solid #d1d5db; border-radius: 8px; padding: 10px; }}
        .metric b {{ display: block; font-size: 12px; color: #374151; margin-bottom: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; break-inside: avoid-page; page-break-inside: avoid; font-size: 12px; table-layout: fixed; }}
        th, td {{ border: 1px solid #d1d5db; padding: 7px 8px; text-align: left; vertical-align: top; }}
        th {{ background: #eef2f7; font-size: 12px; }}
        img {{ max-width: 100%; height: auto; border: 1px solid #d1d5db; padding: 6px; background: #fff; border-radius: 8px; }}
        .figure-wrap {{ display: flex; justify-content: flex-start; align-items: center; overflow: visible; width: 100%; }}
        .graph-image {{ display: block; width: 100%; height: auto; max-width: 100%; max-height: 135mm; object-fit: contain; margin: 0; }}
        .avoid-break {{ break-inside: avoid; page-break-inside: avoid; }}
        .small {{ font-size: 10px; color: #4b5563; }}
        .pill {{ display: inline-block; padding: 2px 7px; border-radius: 999px; background: #e5e7eb; font-size: 9px; margin-right: 5px; }}
        .path-id-col {{ white-space: nowrap; width: 72px; }}
        ul {{ margin-top: 6px; }}
        thead {{ display: table-header-group; }}
        tr, img, .metric, .card, .figure-wrap {{ break-inside: avoid-page; page-break-inside: avoid; }}
        p, li, td, th {{ orphans: 3; widows: 3; }}
        .diagram-section {{ border: 1px solid #d1d5db; border-radius: 10px; padding: 14px; margin-top: 10px; background: #fff; break-inside: avoid-page; page-break-inside: avoid; }}
        .diagram-layout {{ display: grid; grid-template-columns: 300px 1fr; gap: 12px; height: 640px; }}
        .side-panel {{ border: 1px solid #ddd; border-radius: 10px; padding: 12px; overflow: auto; background: #fafafa; }}
        .dfd-area {{ border: 1px solid #ddd; border-radius: 10px; overflow: hidden; background: #fff; position: relative; min-height: 620px; }}
        #cy {{ width: 100%; height: 100%; }}
        .detail-pre {{ margin: 10px 0 0 0; padding: 10px; background: #fff; border: 1px solid #eee; border-radius: 8px; overflow: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }}
        .screen-only {{ display: block; }}
        .print-only {{ display: none; }}
        @media print {{
            body {{ font-size: 10.5pt; line-height: 1.35; background: #ffffff; }}
            .container {{ max-width: none; margin: 0; padding: 0; }}
            .section {{ break-inside: avoid-page; page-break-inside: avoid; margin-top: 14px; }}
            .ai-section {{ break-inside: avoid-page; border: 1px solid #8b5cf6; }}
            h1 {{ font-size: 16pt; }}
            h2 {{ font-size: 12pt; }}
            h3 {{ font-size: 10.5pt; }}
            p, li {{ font-size: 10.5pt; }}
            table, th, td {{ font-size: 10pt; }}
            .note, .small {{ font-size: 9pt; }}
            .diagram-layout {{ grid-template-columns: 1fr; height: auto; }}
            .screen-only {{ display: none !important; }}
            .print-only {{ display: block !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
    <h1>Threat Analysis and Risk Assessment Report {ai_badge}</h1>
    <p class=\"note\">This report presents the identified attack paths, generated threat scenarios, and risk analysis results for the selected system.</p>

    <div class=\"section\">
    <h2>1. Item Definition</h2>
    <div class=\"grid\">
        <div class=\"metric\"><b>Target Asset</b>{_safe_text(target_asset_name)}</div>
        <div class=\"metric\"><b>Attack Vector Mode</b>{_safe_text(mode)}</div>
        <div class=\"metric\"><b>Boundary</b>{_safe_text(boundary_name)}</div>
    </div>
    </div>

    <div class=\"section\">
    <h2>2. Asset Identification</h2>
    <div class=\"card\">
        <p><b>Asset:</b> {_safe_text(target_asset_name)}</p>
        <p><b>Relevant Threat Count:</b> {relevant_threat_count}</p>
        <p class=\"small\">The target asset was selected from the TM7 item model and the threat scenarios were collected from the asset-to-threat mapping and the filtered attack graph result.</p>
    </div>
    </div>

    <div class=\"section\">
    <h2>3. Impact Rating</h2>
    <div class=\"grid\">
        <div class=\"metric\"><b>Safety</b>{_safe_text(impact_record.get('safety'))}</div>
        <div class=\"metric\"><b>Financial</b>{_safe_text(impact_record.get('financial'))}</div>
        <div class=\"metric\"><b>Operational</b>{_safe_text(impact_record.get('operational'))}</div>
        <div class=\"metric\"><b>Privacy</b>{_safe_text(impact_record.get('privacy'))}</div>
        <div class=\"metric\"><b>Maximum Impact</b>{_safe_text(impact_label)}</div>
        <div class=\"metric\"><b>Impact Score</b>{_safe_text(impact_record.get('score'))}</div>
    </div>
    </div>

    <div class=\"section\">
    <h2>4. Damage Scenario Identification</h2>
    <table>
        <thead>
            <tr>
                <th style="width:10%;">Threat ID</th>
                <th style="width:20%;">Threat Name</th>
                <th style="width:18%;">Tactic</th>
                <th style="width:52%;">Damage Scenario</th>
            </tr>
        </thead>
        <tbody>
            {damage_rows_html}
        </tbody>
    </table>
    </div>

    <div class=\"section\">
    <h2>5. Threat Scenario Identification</h2>
    <table>
        <thead>
            <tr>
                <th style="width:10%;">Threat ID</th>
                <th style="width:20%;">Threat Name</th>
                <th style="width:18%;">Tactic</th>
                <th style="width:52%;">Threat Scenario</th>
            </tr>
        </thead>
        <tbody>
            {threat_rows_html}
        </tbody>
    </table>
    </div>

    <div class=\"section\">
    <h2>6. Attack Path Analysis</h2>

    <h3 style=\"border-left:5px solid #1e40af;padding-left:10px;margin-top:16px\">6-A. Enterprise-Level Attack Paths <span style=\"font-size:11px;color:#8b5cf6;font-weight:normal\">(AI-Generated)</span></h3>
    <p class=\"small\" style=\"color:#374151\">AI-generated attack path assessments for each UKC path. Each entry includes an attacker-perspective narrative, phase sequence, key assets, tactics, recommendations and required equipment.</p>

    <div class=\"diagram-section\">
        <h4 style=\"margin:8px 0\">DFD Attack Graph</h4>
        <div class=\"screen-only\">
            <div class=\"diagram-layout\">
                <aside class=\"side-panel\">
                    <div class=\"small\">
                        Phase colours:<br>
                        <span style=\"color:#22c55e;\"><b>In</b></span> &nbsp;
                        <span style=\"color:#f59e0b;\"><b>Through</b></span> &nbsp;
                        <span style=\"color:#ef4444;\"><b>Out</b></span>
                    </div>
                    <pre id=\"detail\" class=\"detail-pre\">(No element selected)</pre>
                </aside>
                <div class=\"dfd-area\"><div id=\"cy\"></div></div>
            </div>
        </div>
        <div class=\"print-only\">
            <div class=\"card\">
                <p class=\"small\">Static image — interactive view available in browser.</p>
                {attack_graph_img_html}
            </div>
        </div>
    </div>

    {enterprise_review_html}

    <h3 style=\"border-left:5px solid #7c3aed;padding-left:10px;margin-top:28px\">6-B. Functional-Level Threat Scenarios <span style=\"font-size:11px;color:#7c3aed;font-weight:normal\">(AI-Generated)</span></h3>
    <p class=\"small\" style=\"color:#374151\">Function-level threat scenarios derived from enterprise-level paths. Each scenario maps an attack path to a specific enterprise function or asset, with feasibility ratings and SFOP-style impact assessment.</p>
    {functional_level_html}

    </div>

    <div class=\"section\">
    <h2>7. Attack Feasibility Rating</h2>
    <div class=\"card\">
        <span class=\"pill\">Mode: {_safe_text(mode)}</span>
        <span class=\"pill\">Derived CAL: {_safe_text(cal_label)}</span>
        <span class=\"pill\">Impact Basis: {_safe_text(impact_label)}</span>
    </div>
    <table>
        <thead>
            <tr>
                <th style="width:10%;">Threat ID</th>
                <th style="width:20%;">Threat Name</th>
                <th style="width:12%;">Feasibility</th>
                <th style="width:12%;">Risk Level</th>
                <th style="width:10%;">CAL</th>
                <th style="width:36%;">Risk Treatment Decision</th>
            </tr>
        </thead>
        <tbody>
            {feasibility_rows_html}
        </tbody>
    </table>
    </div>

    <div class=\"section\">
    <h2>8. Risk Value Determination</h2>
    <div class=\"card\">
        <p><b>Internal Rule:</b> Risk level is derived from <i>maximum impact</i> and <i>attack feasibility</i>. The score is calculated as Impact(0-4) + Feasibility(0-4), then mapped to Low, Medium, High, or Critical.</p>
        <ul>
            <li>0-2: Low</li>
            <li>3-4: Medium</li>
            <li>5-6: High</li>
            <li>7-8: Critical</li>
        </ul>
    </div>
    </div>

    <div class=\"section\">
    <h2>9. Risk Treatment Decision</h2>
    <div class=\"card\">
        <p>For each identified threat scenario, the recommended treatment is shown in the table above. High or Critical risks should be reduced and traced to cybersecurity goals. Medium risks may be reduced or retained with an explicit rationale. Low risks may be retained with documented assumptions and monitoring.</p>
    </div>
    </div>



    <script>
    const cyContainer = document.getElementById('cy');

    if (cyContainer) {{
        const model = {cy_model_json};
        const detail = document.getElementById('detail');

        if (!model.nodes || model.nodes.length === 0) {{
            cyContainer.innerHTML = '<div style="padding:16px;color:#6b7280;font-size:12px">No Cytoscape graph data available. Check whether the TM7 file and attack graph JSON contain DFD nodes and flows.</div>';
        }} else if (typeof cytoscape === 'undefined') {{
            cyContainer.innerHTML = '<div style="padding:16px;color:#b91c1c;font-size:12px">Cytoscape library could not be loaded. Check internet access to unpkg.com or bundle cytoscape.min.js locally.</div>';
        }} else {{
            // Runtime guard: even if a malformed edge slips through Python,
            // remove it before Cytoscape initialisation. Otherwise Cytoscape
            // can abort rendering and leave the panel blank.
            const nodeIds = new Set((model.nodes || [])
                .map(n => n && n.data && n.data.id)
                .filter(Boolean));
            const safeEdges = (model.edges || []).filter(e =>
                e && e.data && nodeIds.has(e.data.source) && nodeIds.has(e.data.target)
            );

            const cy = cytoscape({{
              container: cyContainer,
              elements: [...(model.nodes || []), ...safeEdges],
              layout: {{ name: 'preset' }},
              style: [
                {{
                  selector: 'node',
                  style: {{
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': 11,
                    'width': 150,
                    'height': 55,
                    'shape': 'round-rectangle',
                    'border-width': 1.2,
                    'border-color': '#64748b',
                    'background-color': '#ffffff',
                    'color': '#111827',
                    'text-wrap': 'wrap',
                    'text-max-width': 120
                  }}
                }},
                {{
                  selector: 'node[type="process"]',
                  style: {{
                    'shape': 'ellipse',
                    'width': 95,
                    'height': 95
                  }}
                }},
                {{
                  selector: 'node[type="datastore"]',
                  style: {{
                    'shape': 'round-rectangle',
                    'width': 180,
                    'height': 55
                  }}
                }},
                {{
                  selector: 'node[type="external"]',
                  style: {{
                    'shape': 'rectangle',
                    'width': 150,
                    'height': 55
                  }}
                }},
                {{
                  selector: 'node[highlighted="yes"]',
                  style: {{
                    'border-width': 4,
                    'border-color': 'data(borderColor)'
                  }}
                }},
                {{
                  selector: 'node[phase = "In"]',
                  style: {{
                    'border-color': '#22c55e',
                    'background-color': '#f0fdf4'
                  }}
                }},
                {{
                  selector: 'node[phase = "Through"]',
                  style: {{
                    'border-color': '#f59e0b',
                    'background-color': '#fffbeb'
                  }}
                }},
                {{
                  selector: 'node[phase = "Out"]',
                  style: {{
                    'border-color': '#ef4444',
                    'background-color': '#fef2f2'
                  }}
                }},
                {{
                  selector: 'edge',
                  style: {{
                    'curve-style': 'bezier',
                    'target-arrow-shape': 'triangle',
                    'label': 'data(label)',
                    'font-size': 10,
                    'text-rotation': 'autorotate',
                    'text-margin-y': -8,
                    'arrow-scale': 0.8,
                    'width': 1.8,
                    'line-color': '#94a3b8',
                    'target-arrow-color': '#94a3b8',
                    'color': '#475569'
                  }}
                }},
                {{
                  selector: 'edge[phase = "In"]',
                  style: {{
                    'width': 4,
                    'line-color': '#22c55e',
                    'target-arrow-color': '#22c55e'
                  }}
                }},
                {{
                  selector: 'edge[phase = "Through"]',
                  style: {{
                    'width': 4,
                    'line-color': '#f59e0b',
                    'target-arrow-color': '#f59e0b'
                  }}
                }},
                {{
                  selector: 'edge[phase = "Out"]',
                  style: {{
                    'width': 4,
                    'line-color': '#ef4444',
                    'target-arrow-color': '#ef4444'
                  }}
                }},
                {{
                  selector: ':selected',
                  style: {{
                    'overlay-opacity': 0,
                    'border-width': 5
                  }}
                }}
              ]
            }});

            function fitGraph() {{
                cy.resize();
                cy.fit(undefined, 40);
                cy.center();
            }}

            cy.ready(fitGraph);
            requestAnimationFrame(fitGraph);
            setTimeout(fitGraph, 150);
            window.addEventListener('resize', fitGraph);

            cy.on('tap', 'node, edge', (evt) => {{
              const d = evt.target.data();
              if (detail) {{
                detail.textContent = d.desc || JSON.stringify(d, null, 2);
              }}
            }});

            cy.on('tap', (evt) => {{
              if (evt.target === cy && detail) {{
                detail.textContent = '(No element selected)';
              }}
            }});

            // Tooltips are optional. Do not let missing tippy/popper libraries break graph rendering.
            if (typeof tippy !== 'undefined') {{
                function makeTippy(ele) {{
                  if (typeof ele.popperRef !== 'function') return null;
                  const ref = ele.popperRef();
                  const dummy = document.createElement('div');
                  document.body.appendChild(dummy);
                  return tippy(dummy, {{
                    getReferenceClientRect: ref.getBoundingClientRect,
                    content: ele.data('label') || ele.data('desc') || '',
                    trigger: 'manual',
                    placement: 'top',
                    animation: 'scale'
                  }});
                }}

                cy.nodes().forEach(n => n.data('tip', makeTippy(n)));
                cy.edges().forEach(e => e.data('tip', makeTippy(e)));

                cy.on('mouseover', 'node, edge', (evt) => {{
                    const tip = evt.target.data('tip');
                    if (tip) tip.show();
                }});
                cy.on('mouseout', 'node, edge', (evt) => {{
                    const tip = evt.target.data('tip');
                    if (tip) tip.hide();
                }});
            }}
        }}
    }}
</script>

  </body>
</html>
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Annex H styled HTML report generated: {report_path}")


def local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag

def get_child_text(el: ET.Element, child_name: str) -> Optional[str]:
    for c in el:
        if local(c.tag) == child_name:
            return c.text
    return None

def get_itype(el: ET.Element) -> Optional[str]:
    for k, v in el.attrib.items():
        if k.endswith("type"):
            return v
    return None

def extract_properties(el: ET.Element) -> Dict[str, Optional[str]]:
    props: Dict[str, Optional[str]] = {}
    props_el = None
    for c in el:
        if local(c.tag) == "Properties":
            props_el = c
            break
    if props_el is None:
        return props

    for anytype in list(props_el):
        name = None
        disp = None
        value = None
        for c in list(anytype):
            t = local(c.tag)
            if t == "Name":
                name = c.text
            elif t == "DisplayName":
                disp = c.text
            elif t == "Value":
                value = c.text
        key = name or disp
        if key is not None:
            props[key] = value
    return props

def safe_float(x: Optional[str]) -> Optional[float]:
    if x is None:
        return None
    try:
        return float(x)
    except ValueError:
        return None


@dataclass(frozen=True)
class DFDNode:
    guid: str
    name: str
    stencil_type: str
    left: float
    top: float
    width: float
    height: float

@dataclass(frozen=True)
class DFDFlow:
    guid: str
    source_guid: str
    target_guid: str
    label: Optional[str]

@dataclass(frozen=True)
class ThreatInfo:
    threat_id: str
    threat_name: str
    tactic: str
    phase: str 

PHASE_ORDER = {"In": 0, "Through": 1, "Out": 2}



def path_phase_counts_remote(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> Dict[str, int]:
    cnt = {"Entry": 0, "In": 0, "Through": 0, "Out": 0}
    for nid in path_node_ids:
        ph = graph_nodes.get(nid, {}).get("phase")
        if ph in cnt:
            cnt[ph] += 1
    return cnt

def is_valid_attack_path_remote(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> bool:
    cnt = path_phase_counts_remote(path_node_ids, graph_nodes)
    return (cnt["Entry"] >= 1 and cnt["In"] >= 1 and cnt["Through"] >= 1 and cnt["Out"] == 1)

def path_phase_counts_local(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> Dict[str, int]:
    cnt = {"In": 0, "Through": 0, "Out": 0}
    for nid in path_node_ids:
        ph = graph_nodes.get(nid, {}).get("phase")
        if ph in cnt:
            cnt[ph] += 1
    return cnt

def is_valid_attack_path_local(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> bool:
    cnt = path_phase_counts_local(path_node_ids, graph_nodes)
    return (cnt["In"] >= 1 and cnt["Through"] >= 1 and cnt["Out"] == 1)

def dedupe_paths(paths: List[List[str]]) -> List[List[str]]:
    seen: Set[Tuple[str, ...]] = set()
    out: List[List[str]] = []
    for p in paths:
        key = tuple(p)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out



def build_merged_dfd_subgraph(
    *,
    used_node_ids: Set[str],
    used_edges: Set[Tuple[str, str, str]],
    graph_nodes: Dict[str, dict],
    nodes_by_guid: Dict[str, DFDNode],
    flows: List[DFDFlow],
    paths: List[List[str]],
) -> dict:
    used_asset_guids: Set[str] = set()
    for nid in used_node_ids:
        g = graph_nodes.get(nid, {}).get("asset_guid")
        if g:
            used_asset_guids.add(g)

    dfd_nodes_out: List[dict] = []
    for g in sorted(used_asset_guids):
        n = nodes_by_guid.get(g)
        if not n:
            continue
        dfd_nodes_out.append(
            {
                "guid": n.guid,
                "name": n.name,
                "stencil_type": n.stencil_type,
                "left": n.left,
                "top": n.top,
                "width": n.width,
                "height": n.height,
            }
        )

    flow_map: Dict[str, DFDFlow] = {f.guid: f for f in flows}
    used_flow_guids: Set[str] = {fg for (_, _, fg) in used_edges if fg}

    dfd_edges_out: List[dict] = []
    for fg in sorted(used_flow_guids):
        f = flow_map.get(fg)
        if not f:
            continue
        dfd_edges_out.append(
            {
                "guid": f.guid,
                "source_guid": f.source_guid,
                "target_guid": f.target_guid,
                "label": f.label,
            }
        )

    start_asset_guids: Set[str] = set()
    end_asset_guids: Set[str] = set()
    for p in paths:
        if not p:
            continue
        s = graph_nodes.get(p[0], {}).get("asset_guid")
        e = graph_nodes.get(p[-1], {}).get("asset_guid")
        if s:
            start_asset_guids.add(s)
        if e:
            end_asset_guids.add(e)

    return {
        "dfd_nodes": dfd_nodes_out,
        "dfd_edges": dfd_edges_out,
        "start_asset_guids": sorted(start_asset_guids),
        "end_asset_guids": sorted(end_asset_guids),
        "node_count": len(dfd_nodes_out),
        "edge_count": len(dfd_edges_out),
    }



def norm_tactic(t: str) -> str:
    return " ".join((t or "").strip().split()).lower()

def build_tactic_to_phase(threat_to_tactic_json: dict) -> Dict[str, str]:
    tactic_to_phase: Dict[str, str] = {}

    ukc = threat_to_tactic_json.get("UnifiedKillChain", {}) or {}
    if isinstance(ukc, dict):
        for phase in ("In", "Through", "Out"):
            for tactic in ukc.get(phase, []) or []:
                tactic_to_phase[norm_tactic(tactic)] = phase

    for item in threat_to_tactic_json.get("tactics", []) or []:
        if not isinstance(item, dict):
            continue
        tactic = item.get("tactic") or item.get("name")
        phase = item.get("ukc_phase") or item.get("phase")
        if tactic and phase in PHASE_ORDER:
            tactic_to_phase[norm_tactic(tactic)] = phase

    return tactic_to_phase

def load_asset_threats(asset_to_threats_path: Path) -> Dict[str, List[dict]]:
    data = json.loads(asset_to_threats_path.read_text(encoding="utf-8"))
    out: Dict[str, List[dict]] = {}
    for a in data.get("assets", []) if isinstance(data, dict) else []:
        name = a.get("asset_name")
        if not name:
            continue
        out.setdefault(name, [])
        out[name].extend(a.get("threats", []) or [])
    return out

def load_asset_name_id_map(asset_to_threats_path: Path) -> Dict[str, str]:
    data = json.loads(asset_to_threats_path.read_text(encoding="utf-8"))
    out: Dict[str, str] = {}
    for a in data.get("assets", []) if isinstance(data, dict) else []:
        name = a.get("asset_name")
        aid = a.get("asset_id")
        if name and aid:
            out[str(name)] = str(aid)
    return out

def load_attack_vectors(attack_vector_path: Path) -> Dict[str, Set[str]]:
    raw = json.loads(attack_vector_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        items = raw.get("threats", [])
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    out: Dict[str, Set[str]] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        tid = it.get("id") or it.get("threat_id")
        if not tid:
            continue
        vecs = it.get("attack_vector") or it.get("attack_vectors") or []
        if isinstance(vecs, str):
            vecset = {vecs.strip().lower()}
        else:
            vecset = {str(v).strip().lower() for v in vecs if v is not None}
        # Normalize legacy naming.
        if "network" in vecset:
            vecset.add("remote")
        if "remote" in vecset:
            vecset.add("network")
        if vecset:
            out[str(tid)] = vecset
    return out

def load_dependencies(dependency_path: Path) -> List[dict]:
    raw = json.loads(dependency_path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, list) else []

def build_dependency_indexes(dependencies: List[dict]) -> dict:
    asset_id_to_classes: Dict[str, Set[str]] = {}
    threat_asset_compat: Dict[str, Set[str]] = {}
    threat_chain_rules: List[dict] = []
    promise_chain_source: Dict[str, dict] = {}
    ukc_tactic_order: Dict[str, List[str]] = {}

    for rule in dependencies or []:
        if not isinstance(rule, dict):
            continue
        rtype = rule.get("type")

        if rtype == "ASSET_CLASS_MAP":
            for cls, asset_ids in (rule.get("classes") or {}).items():
                for aid in asset_ids or []:
                    asset_id_to_classes.setdefault(str(aid), set()).add(str(cls))

        elif rtype == "THREAT_ASSET_COMPAT":
            for tid, classes in (rule.get("compat") or {}).items():
                threat_asset_compat[str(tid)] = {str(c) for c in (classes or [])}

        elif rtype == "THREAT_CHAIN":
            enables = {str(x) for x in (rule.get("enables") or [])}
            requires = {str(x) for x in (rule.get("requires_one_of") or rule.get("requires") or [])}
            if enables and requires:
                threat_chain_rules.append({
                    "id": rule.get("id") or "threat_chain",
                    "description": rule.get("description") or "",
                    "bypass_at_entry": bool(rule.get("bypass_at_entry", False)),
                    "enables": enables,
                    "requires_one_of": requires,
                })

        elif rtype == "PROMISE_CHAIN_SOURCE":
            techs = rule.get("techniques") or {}
            if isinstance(techs, dict):
                promise_chain_source.update({str(k): v for k, v in techs.items() if isinstance(v, dict)})

        elif rtype == "UKC_TACTIC_ORDER":
            ukc = rule.get("UnifiedKillChain") or {}
            if isinstance(ukc, dict):
                ukc_tactic_order = {str(k): list(v or []) for k, v in ukc.items()}

    return {
        "asset_id_to_classes": asset_id_to_classes,
        "threat_asset_compat": threat_asset_compat,
        "threat_chain_rules": threat_chain_rules,
        "promise_chain_source": promise_chain_source,
        "ukc_tactic_order": ukc_tactic_order,
    }

def _classes_for_asset_name(asset_name: str, asset_name_to_id: Dict[str, str], dep_idx: dict) -> Set[str]:
    aid = asset_name_to_id.get(str(asset_name))
    if not aid:
        return set()
    return set((dep_idx or {}).get("asset_id_to_classes", {}).get(aid, set()))

def _threat_asset_compatible(asset_name: str, tid: str, asset_name_to_id: Dict[str, str], dep_idx: dict) -> bool:
    compat = (dep_idx or {}).get("threat_asset_compat", {})
    allowed = compat.get(str(tid))
    if not allowed:
        return True
    classes = _classes_for_asset_name(asset_name, asset_name_to_id, dep_idx)
    if not classes:
        return True
    return bool(classes.intersection(allowed))



def parse_tm7(tm7_path: Path) -> Tuple[Dict[str, DFDNode], List[DFDFlow], List[dict]]:
    tree = ET.parse(str(tm7_path))
    root = tree.getroot()

    node_types = {"StencilRectangle", "StencilEllipse", "StencilParallelLines"}
    nodes_by_guid: Dict[str, DFDNode] = {}

    for el in root.iter():
        itype = get_itype(el)
        if itype in node_types:
            guid = get_child_text(el, "Guid")
            if not guid:
                continue
            props = extract_properties(el)
            name = props.get("Name") or props.get("Label") or props.get("DisplayName") or guid
            name = name.strip() if isinstance(name, str) else str(name)
            left = safe_float(get_child_text(el, "Left")) or 0.0
            top = safe_float(get_child_text(el, "Top")) or 0.0
            width = safe_float(get_child_text(el, "Width")) or 0.0
            height = safe_float(get_child_text(el, "Height")) or 0.0
            nodes_by_guid[guid] = DFDNode(guid, name, itype, left, top, width, height)

    flows: List[DFDFlow] = []
    for el in root.iter():
        if get_itype(el) != "Connector":
            continue
        guid = get_child_text(el, "Guid")
        src = get_child_text(el, "SourceGuid")
        dst = get_child_text(el, "TargetGuid")
        if not guid or not src or not dst:
            continue
        props = extract_properties(el)
        label = props.get("Name") or props.get("Label") or None
        flows.append(DFDFlow(guid=guid, source_guid=src, target_guid=dst, label=label))

    boundaries: List[dict] = []
    for el in root.iter():
        if get_itype(el) != "BorderBoundary":
            continue
        guid = get_child_text(el, "Guid")
        props = extract_properties(el)
        name = (props.get("Name") or "").strip()
        left = safe_float(get_child_text(el, "Left")) or 0.0
        top = safe_float(get_child_text(el, "Top")) or 0.0
        width = safe_float(get_child_text(el, "Width")) or 0.0
        height = safe_float(get_child_text(el, "Height")) or 0.0
        boundaries.append({"guid": guid, "name": name, "left": left, "top": top, "width": width, "height": height})

    return nodes_by_guid, flows, boundaries



def threat_candidates_for_asset(
    asset_name: str,
    asset_to_threats: Dict[str, List[dict]],
    tactic_to_phase: Dict[str, str],
    max_phase_allowed: int,
    require_phase: Optional[str] = None,
    in_attack_vector_required: Optional[str] = None,
    attack_vectors_by_threat: Optional[Dict[str, Set[str]]] = None,
) -> List[ThreatInfo]:
    threats = asset_to_threats.get(asset_name, [])
    cands: List[ThreatInfo] = []
    need_vec = (in_attack_vector_required or "").strip().lower()
    vec_map = attack_vectors_by_threat or {}

    for th in threats:
        tid = th.get("id")
        if not tid:
            continue
        tid = str(tid)
        tname = th.get("name") or tid
        tactics = th.get("tactics") or []

        for tactic in tactics:
            phase = tactic_to_phase.get(norm_tactic(tactic))
            if not phase:
                continue
            if require_phase and phase != require_phase:
                continue
            if PHASE_ORDER[phase] > max_phase_allowed:
                continue
            if phase == "In" and need_vec:
                allowed_vecs = vec_map.get(tid)
                if allowed_vecs and need_vec not in allowed_vecs:
                    continue
            cands.append(ThreatInfo(threat_id=tid, threat_name=tname, tactic=str(tactic), phase=phase))

    cands.sort(key=lambda x: PHASE_ORDER[x.phase], reverse=True)
    return cands



def _threat_expr_satisfied(op: str, items: List[str], present: Set[str]) -> bool:
    opn = (op or "-").strip().upper()
    lst = [str(x) for x in (items or [])]
    if not lst:
        return False
    if opn == "OR":
        return any(t in present for t in lst)
    return all(t in present for t in lst)

def _flow_result_item_present(item: dict, asset_threat_pairs: Set[Tuple[str, str]]) -> bool:
    if not isinstance(item, dict):
        return False
    a = item.get("apply_to")
    ths = item.get("threats") or []
    if not a or not ths:
        return False
    for t in ths:
        if (str(a), str(t)) in asset_threat_pairs:
            return True
    return False

def _flow_results_expr_triggers(op: str, items: List[dict], asset_threat_pairs: Set[Tuple[str, str]]) -> bool:
    opn = (op or "-").strip().upper()
    presences = [_flow_result_item_present(it, asset_threat_pairs) for it in (items or [])]
    if not presences:
        return False
    if opn == "AND":
        return all(presences)
    return any(presences)

def _build_path_flow_pairs(
    path: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
) -> Set[Tuple[str, str]]:
    edge_lookup = {(a, b): fg for (a, b, fg) in graph_edges}
    flows: Set[Tuple[str, str]] = set()
    for i in range(len(path) - 1):
        a = path[i]
        b = path[i + 1]
        if (a, b) not in edge_lookup:
            continue
        na = graph_nodes.get(a, {})
        nb = graph_nodes.get(b, {})
        sa = na.get("asset_name")
        sb = nb.get("asset_name")
        if sa and sb:
            flows.add((str(sa), str(sb)))
    return flows

def path_satisfies_dependencies(
    path: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    dependencies: List[dict],
    target_asset_name: str,
    asset_name_to_id: Optional[Dict[str, str]] = None,
    dependency_indexes: Optional[dict] = None,
) -> bool:
    asset_name_to_id = asset_name_to_id or {}
    dep_idx = dependency_indexes or build_dependency_indexes(dependencies)

    asset_threat_pairs: Set[Tuple[str, str]] = set()
    threats_in_path: Set[str] = set()
    ordered_threats: List[Tuple[int, str, str, str]] = []  

    for idx, nid in enumerate(path):
        node = graph_nodes.get(nid, {})
        asset = node.get("asset_name")
        tid = node.get("threat_id")
        phase = node.get("phase")
        if asset and tid:
            asset_s = str(asset)
            tid_s = str(tid)
            asset_threat_pairs.add((asset_s, tid_s))
            threats_in_path.add(tid_s)
            ordered_threats.append((idx, asset_s, tid_s, str(phase or "")))

            if not _threat_asset_compatible(asset_s, tid_s, asset_name_to_id, dep_idx):
                return False

    flows_in_path = _build_path_flow_pairs(path, graph_nodes, graph_edges)

    threat_chain_rules = dep_idx.get("threat_chain_rules", []) if isinstance(dep_idx, dict) else []
    for pos, asset, tid, phase in ordered_threats:
        earlier_threats = {t for (pidx, _a, t, _ph) in ordered_threats if pidx < pos}
        for rule in threat_chain_rules:
            if tid not in rule.get("enables", set()):
                continue
            required = set(rule.get("requires_one_of", set()))
            if not required:
                continue
            if rule.get("bypass_at_entry") and not earlier_threats:
                continue
            if not earlier_threats.intersection(required):
                return False

    for rule in dependencies:
        if not isinstance(rule, dict):
            continue
        rtype = rule.get("type")

        if rtype in {"ASSET_CLASS_MAP", "THREAT_ASSET_COMPAT", "UKC_TACTIC_ORDER", "THREAT_CHAIN", "PROMISE_CHAIN_SOURCE"}:
            continue

        if rtype == "FLOW_IMPLY_THREATS":
            when = rule.get("when") or {}
            src = str(when.get("source_asset") or "")
            dst = str(when.get("dest_asset") or "")
            if not src or not dst:
                continue
            then = rule.get("then") or {}
            results = then.get("results") or {}
            op = results.get("op") or "-"
            items = results.get("items") or []
            triggers = _flow_results_expr_triggers(op, items, asset_threat_pairs)
            if not triggers:
                continue
            if (src, dst) not in flows_in_path:
                return False

        elif rtype == "PRE_THREAT_ENABLES_POST_THREAT":
            when = rule.get("when") or {}
            then = rule.get("then") or {}
            pre_expr = when.get("pre_threats") or {}
            post_expr = then.get("post_threats") or {}
            pre_op = pre_expr.get("op") or "-"
            pre_items = [str(x) for x in (pre_expr.get("items") or [])]
            post_op = post_expr.get("op") or "-"
            post_items = [str(x) for x in (post_expr.get("items") or [])]
            if _threat_expr_satisfied("OR" if post_op == "OR" else "OR", post_items, threats_in_path):
                if not _threat_expr_satisfied(pre_op, pre_items, threats_in_path):
                    return False

        elif rtype == "TARGET_ASSET_FORBIDS_THREATS":
            when = rule.get("when") or {}
            then = rule.get("then") or {}
            tasset = str(when.get("target_asset") or "")
            if not tasset:
                continue
            if str(target_asset_name) != tasset:
                continue
            forbid = then.get("forbid_threats") or {}
            forbid_items = [str(x) for x in (forbid.get("items") or [])]
            if any(t in threats_in_path for t in forbid_items):
                return False

        elif rtype == "THREAT_FORBIDS_THREATS":
            when = rule.get("when") or {}
            then = rule.get("then") or {}
            pre_expr = when.get("pre_threats") or {}
            pre_op = pre_expr.get("op") or "-"
            pre_items = [str(x) for x in (pre_expr.get("items") or [])]
            forbid_expr = then.get("forbid_threats") or {}
            forbid_items = [str(x) for x in (forbid_expr.get("items") or [])]
            if _threat_expr_satisfied(pre_op if pre_op else "OR", pre_items, threats_in_path):
                if any(t in threats_in_path for t in forbid_items):
                    return False
        else:
            continue

    return True



@dataclass
class GraphBuildState:
    nodes_by_guid: Dict[str, DFDNode]
    flows: List[DFDFlow]
    incoming: Dict[str, List[DFDFlow]]
    asset_to_threats: Dict[str, List[dict]]
    tactic_to_phase: Dict[str, str]
    max_depth: int

    boundary_rect: Optional[dict] = None
    side_of_guid: Optional[Dict[str, str]] = None

    threat_side: Optional[str] = None
    entry_side: Optional[str] = None

    mode: Optional[str] = None
    attack_vectors_by_threat: Optional[Dict[str, Set[str]]] = None

def build_incoming_index(flows: List[DFDFlow]) -> Dict[str, List[DFDFlow]]:
    incoming: Dict[str, List[DFDFlow]] = {}
    for f in flows:
        incoming.setdefault(f.target_guid, []).append(f)
    return incoming

def make_graph_node_id(asset_guid: str, threat_id: str, phase: str, tactic: str) -> str:
    return f"{asset_guid}::{threat_id}::{phase}::{tactic}"

def make_entry_node_id(asset_guid: str) -> str:
    return f"{asset_guid}::ENTRY"

def is_inside_rect(node: DFDNode, rect: dict) -> bool:
    return (
        node.left >= rect["left"]
        and node.top >= rect["top"]
        and (node.left + node.width) <= (rect["left"] + rect["width"])
        and (node.top + node.height) <= (rect["top"] + rect["height"])
    )

def find_boundary_rect(boundaries: List[dict], boundary_name: str) -> Optional[dict]:
    for b in boundaries:
        if (b.get("name") or "") == boundary_name:
            return {"left": b["left"], "top": b["top"], "width": b["width"], "height": b["height"]}
    return None



def add_single_entry_before_in(
    st: GraphBuildState,
    in_guid: str,
    in_node_id: str,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    incoming_flows = st.incoming.get(in_guid, [])
    for flow in incoming_flows:
        src_guid = flow.source_guid
        if src_guid in visited_assets:
            continue
        if not st.side_of_guid or not st.entry_side:
            continue
        if st.side_of_guid.get(src_guid) != st.entry_side:
            continue
        src_node = st.nodes_by_guid.get(src_guid)
        if not src_node:
            continue

        entry_id = make_entry_node_id(src_guid)
        if entry_id not in graph_nodes:
            graph_nodes[entry_id] = {
                "node_id": entry_id,
                "asset_guid": src_guid,
                "asset_name": src_node.name,
                "stencil_type": src_node.stencil_type,
                "phase": "Entry",
                "threat_id": None,
                "threat_name": None,
                "tactic": None,
            }

        path_node_ids.append(entry_id)
        graph_edges.add((entry_id, in_node_id, flow.guid))
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        path_node_ids.pop()



def dfs_backward_remote(
    st: GraphBuildState,
    target_guid: str,
    cur_guid: str,
    allowed_max_phase: int,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    if len(path_node_ids) >= st.max_depth:
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    dfd_node = st.nodes_by_guid.get(cur_guid)
    if not dfd_node:
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    if cur_guid == target_guid and path_node_ids:
        last_id = path_node_ids[-1]
        last_node = graph_nodes.get(last_id, {})
        if last_node.get("asset_guid") == target_guid and last_node.get("phase") == "Out":
            incoming_flows = st.incoming.get(cur_guid, [])
            for flow in incoming_flows:
                src_guid = flow.source_guid
                if src_guid in visited_assets:
                    continue
                visited_assets.add(src_guid)
                before_nodes = set(graph_nodes.keys())

                dfs_backward_remote(
                    st=st,
                    target_guid=target_guid,
                    cur_guid=src_guid,
                    allowed_max_phase=allowed_max_phase,
                    visited_assets=visited_assets,
                    path_node_ids=path_node_ids,
                    graph_nodes=graph_nodes,
                    graph_edges=graph_edges,
                    all_paths=all_paths,
                )

                after_nodes = set(graph_nodes.keys())
                new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
                for up_id in new_upstream_nodes:
                    graph_edges.add((up_id, last_id, flow.guid))

                visited_assets.remove(src_guid)
            return

    cands = threat_candidates_for_asset(
        asset_name=dfd_node.name,
        asset_to_threats=st.asset_to_threats,
        tactic_to_phase=st.tactic_to_phase,
        max_phase_allowed=allowed_max_phase,
        require_phase=None,
        in_attack_vector_required=st.mode,
        attack_vectors_by_threat=st.attack_vectors_by_threat,
    )

    if not cands:
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    for th in cands:
        if th.phase == "Out" and cur_guid != target_guid:
            continue

        node_id = make_graph_node_id(dfd_node.guid, th.threat_id, th.phase, th.tactic)
        if node_id not in graph_nodes:
            graph_nodes[node_id] = {
                "node_id": node_id,
                "asset_guid": dfd_node.guid,
                "asset_name": dfd_node.name,
                "stencil_type": dfd_node.stencil_type,
                "threat_id": th.threat_id,
                "threat_name": th.threat_name,
                "phase": th.phase,
                "tactic": th.tactic,
            }

        path_node_ids.append(node_id)

        if th.phase == "In":
            add_single_entry_before_in(
                st=st,
                in_guid=cur_guid,
                in_node_id=node_id,
                visited_assets=visited_assets,
                path_node_ids=path_node_ids,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )
            incoming_flows = st.incoming.get(cur_guid, [])
            for flow in incoming_flows:
                src_guid = flow.source_guid
                if src_guid in visited_assets:
                    continue
                visited_assets.add(src_guid)
                before_nodes = set(graph_nodes.keys())
                dfs_backward_remote(
                    st=st,
                    target_guid=target_guid,
                    cur_guid=src_guid,
                    allowed_max_phase=PHASE_ORDER["In"],
                    visited_assets=visited_assets,
                    path_node_ids=path_node_ids,
                    graph_nodes=graph_nodes,
                    graph_edges=graph_edges,
                    all_paths=all_paths,
                )
                after_nodes = set(graph_nodes.keys())
                new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
                for up_id in new_upstream_nodes:
                    graph_edges.add((up_id, node_id, flow.guid))
                visited_assets.remove(src_guid)
            path_node_ids.pop()
            continue

        next_allowed = PHASE_ORDER[th.phase]
        incoming_flows = st.incoming.get(cur_guid, [])
        for flow in incoming_flows:
            src_guid = flow.source_guid
            if src_guid in visited_assets:
                continue
            visited_assets.add(src_guid)
            before_nodes = set(graph_nodes.keys())

            dfs_backward_remote(
                st=st,
                target_guid=target_guid,
                cur_guid=src_guid,
                allowed_max_phase=next_allowed,
                visited_assets=visited_assets,
                path_node_ids=path_node_ids,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )

            after_nodes = set(graph_nodes.keys())
            new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
            for up_id in new_upstream_nodes:
                graph_edges.add((up_id, node_id, flow.guid))

            visited_assets.remove(src_guid)

        path_node_ids.pop()



def dfs_backward_local_physical(
    st: GraphBuildState,
    target_guid: str,
    cur_guid: str,
    allowed_max_phase: int,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    if len(path_node_ids) >= st.max_depth:
        if is_valid_attack_path_local(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    dfd_node = st.nodes_by_guid.get(cur_guid)
    if not dfd_node:
        if is_valid_attack_path_local(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    if cur_guid == target_guid and path_node_ids:
        last_id = path_node_ids[-1]
        last_node = graph_nodes.get(last_id, {})
        if last_node.get("asset_guid") == target_guid and last_node.get("phase") == "Out":
            incoming_flows = st.incoming.get(cur_guid, [])
            for flow in incoming_flows:
                src_guid = flow.source_guid
                if src_guid in visited_assets:
                    continue
                visited_assets.add(src_guid)
                before_nodes = set(graph_nodes.keys())

                dfs_backward_local_physical(
                    st=st,
                    target_guid=target_guid,
                    cur_guid=src_guid,
                    allowed_max_phase=allowed_max_phase,
                    visited_assets=visited_assets,
                    path_node_ids=path_node_ids,
                    graph_nodes=graph_nodes,
                    graph_edges=graph_edges,
                    all_paths=all_paths,
                )

                after_nodes = set(graph_nodes.keys())
                new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
                for up_id in new_upstream_nodes:
                    graph_edges.add((up_id, last_id, flow.guid))

                visited_assets.remove(src_guid)
            return

    cands = threat_candidates_for_asset(
        asset_name=dfd_node.name,
        asset_to_threats=st.asset_to_threats,
        tactic_to_phase=st.tactic_to_phase,
        max_phase_allowed=allowed_max_phase,
        require_phase=None,
        in_attack_vector_required=st.mode,
        attack_vectors_by_threat=st.attack_vectors_by_threat,
    )

    if not cands:
        if is_valid_attack_path_local(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    for th in cands:
        if th.phase == "Out" and cur_guid != target_guid:
            continue

        node_id = make_graph_node_id(dfd_node.guid, th.threat_id, th.phase, th.tactic)
        if node_id not in graph_nodes:
            graph_nodes[node_id] = {
                "node_id": node_id,
                "asset_guid": dfd_node.guid,
                "asset_name": dfd_node.name,
                "stencil_type": dfd_node.stencil_type,
                "threat_id": th.threat_id,
                "threat_name": th.threat_name,
                "phase": th.phase,
                "tactic": th.tactic,
            }

        path_node_ids.append(node_id)

        if th.phase == "In":
            if st.mode in ("local", "physical"):
                if not st.side_of_guid or not st.boundary_rect:
                    path_node_ids.pop()
                    continue
                if st.side_of_guid.get(cur_guid) != "outside":
                    path_node_ids.pop()
                    continue

            if is_valid_attack_path_local(path_node_ids, graph_nodes):
                all_paths.append(list(path_node_ids))
            incoming_flows = st.incoming.get(cur_guid, [])
            for flow in incoming_flows:
                src_guid = flow.source_guid
                if src_guid in visited_assets:
                    continue
                visited_assets.add(src_guid)
                before_nodes = set(graph_nodes.keys())
                dfs_backward_local_physical(
                    st=st,
                    target_guid=target_guid,
                    cur_guid=src_guid,
                    allowed_max_phase=PHASE_ORDER["In"],
                    visited_assets=visited_assets,
                    path_node_ids=path_node_ids,
                    graph_nodes=graph_nodes,
                    graph_edges=graph_edges,
                    all_paths=all_paths,
                )
                after_nodes = set(graph_nodes.keys())
                new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
                for up_id in new_upstream_nodes:
                    graph_edges.add((up_id, node_id, flow.guid))
                visited_assets.remove(src_guid)
            path_node_ids.pop()
            continue

        next_allowed = PHASE_ORDER[th.phase]
        incoming_flows = st.incoming.get(cur_guid, [])
        for flow in incoming_flows:
            src_guid = flow.source_guid
            if src_guid in visited_assets:
                continue
            visited_assets.add(src_guid)
            before_nodes = set(graph_nodes.keys())

            dfs_backward_local_physical(
                st=st,
                target_guid=target_guid,
                cur_guid=src_guid,
                allowed_max_phase=next_allowed,
                visited_assets=visited_assets,
                path_node_ids=path_node_ids,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )

            after_nodes = set(graph_nodes.keys())
            new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
            for up_id in new_upstream_nodes:
                graph_edges.add((up_id, node_id, flow.guid))

            visited_assets.remove(src_guid)

        path_node_ids.pop()


def build_attack_graph_remote_adjacent(
    tm7_path: Path,
    target_asset_name: str,
    boundary_name: str,
    asset_to_threats_path: Path,
    threat_to_tactic_path: Path,
    attack_vector_path: Path,
    dependency_path: Path,
    mode: str,
    max_depth: int = 30,
) -> dict:
    nodes_by_guid, flows, boundaries = parse_tm7(tm7_path)
    incoming = build_incoming_index(flows)

    asset_to_threats = load_asset_threats(asset_to_threats_path)
    threat_to_tactic = json.loads(threat_to_tactic_path.read_text(encoding="utf-8"))
    tactic_to_phase = build_tactic_to_phase(threat_to_tactic)
    attack_vectors_by_threat = load_attack_vectors(attack_vector_path)
    dependencies = load_dependencies(dependency_path)
    asset_name_to_id = load_asset_name_id_map(asset_to_threats_path)
    dependency_indexes = build_dependency_indexes(dependencies)

    rect = find_boundary_rect(boundaries, boundary_name)
    if rect is None:
        return {
            "ok": False,
            "reason": f"TM7: BorderBoundary '{boundary_name}' not found.",
            "tm7_path": str(tm7_path),
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    side_of_guid: Dict[str, str] = {}
    for g, n in nodes_by_guid.items():
        side_of_guid[g] = "inside" if is_inside_rect(n, rect) else "outside"

    threat_applicable_guids: List[str] = []
    for g, n in nodes_by_guid.items():
        if n.name in asset_to_threats and asset_to_threats.get(n.name):
            threat_applicable_guids.append(g)

    if not threat_applicable_guids:
        return {
            "ok": False,
            "reason": "No DFD nodes with threat mappings found in asset_to_threats.",
            "tm7_path": str(tm7_path),
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    inside_cnt = sum(1 for g in threat_applicable_guids if side_of_guid.get(g) == "inside")
    outside_cnt = len(threat_applicable_guids) - inside_cnt
    threat_side = "inside" if inside_cnt >= outside_cnt else "outside"
    entry_side = "outside" if threat_side == "inside" else "inside"

    target_guids = [g for g, n in nodes_by_guid.items() if n.name == target_asset_name]
    if not target_guids:
        return {
            "ok": False,
            "reason": f"Target asset '{target_asset_name}' not found in DFD.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    graph_nodes: Dict[str, dict] = {}
    graph_edges: Set[Tuple[str, str, str]] = set()
    all_paths: List[List[str]] = []

    st = GraphBuildState(
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        incoming=incoming,
        asset_to_threats=asset_to_threats,
        tactic_to_phase=tactic_to_phase,
        max_depth=max_depth,
        boundary_rect=rect,
        side_of_guid=side_of_guid,
        threat_side=threat_side,
        entry_side=entry_side,
        mode=mode,
        attack_vectors_by_threat=attack_vectors_by_threat,
    )

    any_start = False
    for tgt_guid in target_guids:
        tgt_node = nodes_by_guid[tgt_guid]
        out_cands = threat_candidates_for_asset(
            asset_name=tgt_node.name,
            asset_to_threats=asset_to_threats,
            tactic_to_phase=tactic_to_phase,
            max_phase_allowed=PHASE_ORDER["Out"],
            require_phase="Out",
            in_attack_vector_required=mode,
            attack_vectors_by_threat=attack_vectors_by_threat,
        )
        if not out_cands:
            continue
        any_start = True

        for out_th in out_cands:
            start_node_id = make_graph_node_id(tgt_guid, out_th.threat_id, out_th.phase, out_th.tactic)
            if start_node_id not in graph_nodes:
                graph_nodes[start_node_id] = {
                    "node_id": start_node_id,
                    "asset_guid": tgt_guid,
                    "asset_name": tgt_node.name,
                    "stencil_type": tgt_node.stencil_type,
                    "threat_id": out_th.threat_id,
                    "threat_name": out_th.threat_name,
                    "phase": out_th.phase,
                    "tactic": out_th.tactic,
                }

            visited_assets = {tgt_guid}
            dfs_backward_remote(
                st=st,
                target_guid=tgt_guid,
                cur_guid=tgt_guid,
                allowed_max_phase=PHASE_ORDER["Out"],
                visited_assets=visited_assets,
                path_node_ids=[start_node_id],
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )

    if not any_start:
        return {
            "ok": False,
            "reason": f"Target asset '{target_asset_name}' has no Out-phase threats — cannot build attack graph.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths_raw = [p for p in all_paths if is_valid_attack_path_remote(p, graph_nodes)]
    valid_paths_raw = dedupe_paths(valid_paths_raw)
    if not valid_paths_raw:
        return {
            "ok": False,
            "reason": (
                f"Among paths discovered from target asset '{target_asset_name}': "
                f"No paths satisfy Entry>=1 & In>=1 & Through>=1 & Out>=1 validity conditions."
            ),
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths = [list(reversed(p)) for p in valid_paths_raw]
    valid_paths = [
        p
        for p in valid_paths
        if path_satisfies_dependencies(
            path=p,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            dependencies=dependencies,
            target_asset_name=target_asset_name,
            asset_name_to_id=asset_name_to_id,
            dependency_indexes=dependency_indexes,
        )
    ]

    if not valid_paths:
        return {
            "ok": False,
            "reason": "Valid phase-condition paths exist but none satisfy all dependency.json constraints.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "tm7_path": str(tm7_path),
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    used_node_ids: Set[str] = set()
    for p in valid_paths:
        used_node_ids.update(p)

    used_edges = set()
    for (src_node_id, dst_node_id, flow_guid) in graph_edges:
        if src_node_id in used_node_ids and dst_node_id in used_node_ids:
            used_edges.add((src_node_id, dst_node_id, flow_guid))

    flow_label_map = {f.guid: f.label for f in flows}
    edges_out = []
    for (src_node_id, dst_node_id, flow_guid) in sorted(used_edges):
        edges_out.append(
            {
                "from": src_node_id,
                "to": dst_node_id,
                "dfd_flow_guid": flow_guid,
                "dfd_flow_label": flow_label_map.get(flow_guid),
            }
        )

    nodes_out = [graph_nodes[nid] for nid in used_node_ids if nid in graph_nodes]

    merged_dfd_subgraph = build_merged_dfd_subgraph(
        used_node_ids=used_node_ids,
        used_edges=used_edges,
        graph_nodes=graph_nodes,
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        paths=valid_paths,
    )

    return {
        "ok": True,
        "mode": mode,
        "target_asset_name": target_asset_name,
        "boundary_name": boundary_name,
        "tm7_path": str(tm7_path),
        "nodes": nodes_out,
        "edges": edges_out,
        "paths": valid_paths,
        "merged_dfd_subgraph": merged_dfd_subgraph,
        "phase_order": ["Entry", "In", "Through", "Out"],
        "path_constraint": "Entry==1 & In==1 & Through>=1 & Out==1",
        "in_phase_policy": {
            "attack_vector_mode": mode,
            "attack_vector_map": str(attack_vector_path),
            "note": "Only threats with matching attack_vector are allowed as In.",
        },
        "dependency_policy": {
            "dependency_map": str(dependency_path),
            "note": "Enterprise dependency rules are enforced: asset-class compatibility, ordered THREAT_CHAIN rules, and legacy dependency rules when present.",
        },
        "out_phase_policy": "Out phase is allowed only on the target asset in this search.",
        "boundary_policy": {
            "boundary_rect": rect,
            "threat_side": threat_side,
            "entry_side": entry_side,
            "note": "Entry node is chosen from the opposite side of the boundary relative to threat-applicable nodes.",
        },
    }



def build_attack_graph_local_physical(
    tm7_path: Path,
    target_asset_name: str,
    boundary_name: str,
    asset_to_threats_path: Path,
    threat_to_tactic_path: Path,
    attack_vector_path: Path,
    dependency_path: Path,
    mode: str,
    max_depth: int = 30,
) -> dict:
    nodes_by_guid, flows, boundaries = parse_tm7(tm7_path)
    incoming = build_incoming_index(flows)

    asset_to_threats = load_asset_threats(asset_to_threats_path)
    threat_to_tactic = json.loads(threat_to_tactic_path.read_text(encoding="utf-8"))
    tactic_to_phase = build_tactic_to_phase(threat_to_tactic)
    attack_vectors_by_threat = load_attack_vectors(attack_vector_path)
    dependencies = load_dependencies(dependency_path)
    asset_name_to_id = load_asset_name_id_map(asset_to_threats_path)
    dependency_indexes = build_dependency_indexes(dependencies)

    rect = find_boundary_rect(boundaries, boundary_name)
    if rect is None:
        return {
            "ok": False,
            "reason": f"TM7: BorderBoundary '{boundary_name}' not found.",
            "tm7_path": str(tm7_path),
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    side_of_guid: Dict[str, str] = {}
    for g, n in nodes_by_guid.items():
        side_of_guid[g] = "inside" if is_inside_rect(n, rect) else "outside"

    target_guids = [g for g, n in nodes_by_guid.items() if n.name == target_asset_name]
    if not target_guids:
        return {
            "ok": False,
            "reason": f"Target asset '{target_asset_name}' not found in DFD.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    graph_nodes: Dict[str, dict] = {}
    graph_edges: Set[Tuple[str, str, str]] = set()
    all_paths: List[List[str]] = []

    st = GraphBuildState(
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        incoming=incoming,
        asset_to_threats=asset_to_threats,
        tactic_to_phase=tactic_to_phase,
        max_depth=max_depth,
        boundary_rect=rect,
        side_of_guid=side_of_guid,
        mode=mode,
        attack_vectors_by_threat=attack_vectors_by_threat,
    )

    any_start = False
    for tgt_guid in target_guids:
        tgt_node = nodes_by_guid[tgt_guid]
        out_cands = threat_candidates_for_asset(
            asset_name=tgt_node.name,
            asset_to_threats=asset_to_threats,
            tactic_to_phase=tactic_to_phase,
            max_phase_allowed=PHASE_ORDER["Out"],
            require_phase="Out",
            in_attack_vector_required=mode,
            attack_vectors_by_threat=attack_vectors_by_threat,
        )
        if not out_cands:
            continue
        any_start = True

        for out_th in out_cands:
            start_node_id = make_graph_node_id(tgt_guid, out_th.threat_id, out_th.phase, out_th.tactic)
            if start_node_id not in graph_nodes:
                graph_nodes[start_node_id] = {
                    "node_id": start_node_id,
                    "asset_guid": tgt_guid,
                    "asset_name": tgt_node.name,
                    "stencil_type": tgt_node.stencil_type,
                    "threat_id": out_th.threat_id,
                    "threat_name": out_th.threat_name,
                    "phase": out_th.phase,
                    "tactic": out_th.tactic,
                }

            visited_assets = {tgt_guid}
            dfs_backward_local_physical(
                st=st,
                target_guid=tgt_guid,
                cur_guid=tgt_guid,
                allowed_max_phase=PHASE_ORDER["Out"],
                visited_assets=visited_assets,
                path_node_ids=[start_node_id],
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )

    if not any_start:
        return {
            "ok": False,
            "reason": f"Target asset '{target_asset_name}' has no Out-phase threats — cannot build attack graph.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths_raw = [p for p in all_paths if is_valid_attack_path_local(p, graph_nodes)]
    valid_paths_raw = dedupe_paths(valid_paths_raw)
    if not valid_paths_raw:
        return {
            "ok": False,
            "reason": (
                f"Among paths discovered from target asset '{target_asset_name}': "
                f"No paths satisfy In>=1 & Through>=1 & Out>=1 validity conditions."
            ),
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths = [list(reversed(p)) for p in valid_paths_raw]
    valid_paths = [
        p
        for p in valid_paths
        if path_satisfies_dependencies(
            path=p,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            dependencies=dependencies,
            target_asset_name=target_asset_name,
            asset_name_to_id=asset_name_to_id,
            dependency_indexes=dependency_indexes,
        )
    ]

    if not valid_paths:
        return {
            "ok": False,
            "reason": "Valid phase-condition paths exist but none satisfy all dependency.json constraints.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "tm7_path": str(tm7_path),
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    used_node_ids: Set[str] = set()
    for p in valid_paths:
        used_node_ids.update(p)

    used_edges = set()
    for (src_node_id, dst_node_id, flow_guid) in graph_edges:
        if src_node_id in used_node_ids and dst_node_id in used_node_ids:
            used_edges.add((src_node_id, dst_node_id, flow_guid))

    flow_label_map = {f.guid: f.label for f in flows}
    edges_out = []
    for (src_node_id, dst_node_id, flow_guid) in sorted(used_edges):
        edges_out.append(
            {
                "from": src_node_id,
                "to": dst_node_id,
                "dfd_flow_guid": flow_guid,
                "dfd_flow_label": flow_label_map.get(flow_guid),
            }
        )

    nodes_out = [graph_nodes[nid] for nid in used_node_ids if nid in graph_nodes]

    merged_dfd_subgraph = build_merged_dfd_subgraph(
        used_node_ids=used_node_ids,
        used_edges=used_edges,
        graph_nodes=graph_nodes,
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        paths=valid_paths,
    )

    return {
        "ok": True,
        "mode": mode,
        "target_asset_name": target_asset_name,
        "boundary_name": boundary_name,
        "tm7_path": str(tm7_path),
        "nodes": nodes_out,
        "edges": edges_out,
        "paths": valid_paths,
        "merged_dfd_subgraph": merged_dfd_subgraph,
        "phase_order": ["In", "Through", "Out"],
        "path_constraint": "In==1 & Through>=1 & Out==1",
        "in_phase_policy": {
            "attack_vector_mode": mode,
            "attack_vector_map": str(attack_vector_path),
            "note": "Only threats with matching attack_vector are allowed as In.",
        },
        "dependency_policy": {
            "dependency_map": str(dependency_path),
            "note": "Enterprise dependency rules are enforced: asset-class compatibility, ordered THREAT_CHAIN rules, and legacy dependency rules when present.",
        },
        "out_phase_policy": "Out phase is allowed only on the target asset in this search.",
        "boundary_policy": {
            "boundary_rect": rect,
            "note": "For Local/Physical, In-node asset is restricted to boundary 'outside' side.",
        },
    }



def _shape_from_stencil(stencil_type: str) -> str:
    if stencil_type == "StencilParallelLines":
        return "cylinder"
    if stencil_type == "StencilEllipse":
        return "circle"
    return "box"

def _phase_style(phases: Set[str]) -> Tuple[str, str]:
    p = set(phases)
    p.discard(None)
    if p == {"Out"}:
        return "red", "Out"
    if p == {"In"}:
        return "lightgreen", "In"
    if p == {"Through"}:
        return "orange", "Through"
    if p.issuperset({"In", "Through"}) and "Out" not in p:
        return "orange", "In/Through"
    if p == {"Entry"}:
        return "lightgrey", "Entry"
    if "Out" in p:
        return "red", "/".join(sorted(p))
    if "Through" in p:
        note = "In/Through" if "In" in p else "Through"
        return "orange", note
    if "In" in p:
        return "lightgreen", "In"
    return "white", ""

def wrap_label(text: str, max_len: int = 14) -> str:
    words = text.split(" ")
    lines = []
    cur = ""
    for w in words:
        if len(cur) + len(w) <= max_len:
            cur = (cur + " " + w).strip()
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return "<BR/>".join(lines)

def render_merged_attack_graph_graphviz(
    result: dict,
    out_prefix: Path | str,
    fmt: str = "pdf",
    font: str = "Malgun Gothic",
) -> Optional[Path]:
    if not result.get("ok"):
        return None

    out_prefix = Path(out_prefix)
    merged = result.get("merged_dfd_subgraph") or {}
    dfd_nodes = merged.get("dfd_nodes") or []
    dfd_edges = merged.get("dfd_edges") or []
    if not dfd_nodes:
        return None

    phases_by_guid: Dict[str, Set[str]] = {}
    for n in (result.get("nodes") or []):
        g = n.get("asset_guid")
        ph = n.get("phase")
        if not g or not ph:
            continue
        phases_by_guid.setdefault(g, set()).add(ph)

    dot = Digraph("MergedAttackGraph", format=fmt)
    dot.attr("graph", fontname=font, rankdir="LR", nodesep="0.45", ranksep="0.75", splines="true")
    dot.attr("node", fontname=font, fontsize="12", style="filled", fixedsize="true", width="1.8", height="1.8")
    dot.attr("edge", fontname=font, fontsize="10", color="black")

    for n in dfd_nodes:
        guid = n.get("guid")
        name = n.get("name") or guid
        stencil = n.get("stencil_type") or ""
        phases = phases_by_guid.get(guid, set())
        fillcolor, note = _phase_style(phases)
        shape = _shape_from_stencil(stencil)

        if note:
            wrapped_name = wrap_label(name)
            label = f"<<B><FONT POINT-SIZE='12'>{wrapped_name}</FONT></B><BR/><FONT POINT-SIZE='9'>{note}</FONT>>"
        else:
            label = f"<<B>{name}</B>>"

        dot.node(guid, label=label, shape=shape, fillcolor=fillcolor)

    for e in dfd_edges:
        src = e.get("source_guid")
        dst = e.get("target_guid")
        if not src or not dst:
            continue
        lbl = e.get("label")
        if lbl:
            dot.edge(src, dst, label=str(lbl))
        else:
            dot.edge(src, dst)

    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    rendered = dot.render(str(out_prefix), cleanup=True)
    return Path(rendered)

def _render_report_preview_from_graph(result: dict, out_prefix: Path | str, font: str = "Malgun Gothic") -> Optional[Path]:
    preview_prefix = Path(out_prefix)
    return render_merged_attack_graph_graphviz(result=result, out_prefix=preview_prefix, fmt="png", font=font)



def _gv_escape(s: str) -> str:
    if s is None:
        return ""
    return str(s).replace('"', '\\"')

def _sanitize_id(s: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", str(s))

def _one_line_label(node_obj: dict) -> str:
    asset = (node_obj.get("asset_name") or "").strip()
    tid = (node_obj.get("threat_id") or "").strip()
    tname = (node_obj.get("threat_name") or "").strip()
    parts = [p for p in [asset, tid] if p]
    if not parts:
        parts = [tname] if tname else ["node"]
    return " | ".join(parts)

def _ensure_dot() -> str:
    p = shutil.which("dot")
    if not p:
        raise FileNotFoundError("Graphviz 'dot' executable not found.")
    return p

def _attack_tree_phase_fillcolor(phases: Set[str]) -> str:
    if "Out" in phases:
        return "red"
    if "Through" in phases:
        return "orange"
    if "In" in phases:
        return "lightgreen"
    if "Entry" in phases:
        return "lightgrey"
    return "white"

def _collect_phases_by_asset_guid(node_map: dict) -> Dict[str, Set[str]]:
    phases_by_guid = defaultdict(set)
    for nid, obj in node_map.items():
        g = obj.get("asset_guid")
        ph = obj.get("phase")
        if g and ph:
            phases_by_guid[g].add(ph)
    return phases_by_guid

def _attack_tree_node_attrs(node_obj: dict, phases_by_asset_guid: Dict[str, Set[str]]) -> dict:
    ph = node_obj.get("phase")
    asset_guid = node_obj.get("asset_guid")
    phases = set()
    if asset_guid and asset_guid in phases_by_asset_guid:
        phases = phases_by_asset_guid[asset_guid]
    elif ph:
        phases = {ph}
    fillcolor = _attack_tree_phase_fillcolor(phases)
    return {
        "shape": "box",
        "style": "filled,rounded",
        "fillcolor": fillcolor,
        "color": "black",
        "fontcolor": "black",
        "penwidth": "1.2",
    }

def _attack_tree_build_merged_edges(data: dict, reverse_arrows: bool = True):
    nodes = data.get("nodes", [])
    paths = data.get("paths", [])
    node_map = {n["node_id"]: n for n in nodes if "node_id" in n}
    if not paths:
        raise ValueError("paths is empty.")

    edges = set()
    goals = set()

    for p in paths:
        if not p:
            continue
        goal = p[-1]
        goals.add(goal)
        steps = p[:-1]
        steps = list(reversed(steps))
        prev = goal
        for s in steps:
            if reverse_arrows:
                edges.add((s, prev))
            else:
                edges.add((prev, s))
            prev = s

    return list(goals), edges, node_map

def attack_tree_to_dot(data: dict, reverse_arrows: bool = True) -> str:
    target_asset_name = data.get("target_asset_name", "Target")
    goals, edges, node_map = _attack_tree_build_merged_edges(data, reverse_arrows=reverse_arrows)
    phases_by_asset_guid = _collect_phases_by_asset_guid(node_map)

    lines = []
    lines.append("digraph AttackTree {")
    lines.append("  rankdir=BT;")
    lines.append('  graph [splines=true, nodesep=0.25, ranksep=0.45, concentrate=true];')
    lines.append('  node  [fontsize=11];')
    lines.append('  edge  [arrowsize=0.7];')
    lines.append("")

    root = "ROOT"
    lines.append(
        f'  {root} [shape=box, style="filled,bold", fillcolor="lightgrey", '
        f'label="{_gv_escape("Goal: " + target_asset_name)}"];'
    )

    for g in goals:
        gid = _sanitize_id(g)
        gobj = node_map.get(g, {"asset_name": target_asset_name, "threat_id": "GOAL", "phase": "Out"})
        glabel = "Goal | " + _one_line_label(gobj)
        attrs = _attack_tree_node_attrs(gobj, phases_by_asset_guid)
        lines.append(
            f'  {gid} [shape={attrs["shape"]}, style="{attrs["style"]},rounded,bold", '
            f'fillcolor="{attrs["fillcolor"]}", color="{attrs["color"]}", fontcolor="{attrs["fontcolor"]}", '
            f'penwidth={attrs["penwidth"]}, label="{_gv_escape(glabel)}"];'
        )
        if reverse_arrows:
            lines.append(f"  {gid} -> {root};")
        else:
            lines.append(f"  {root} -> {gid};")

    used = set()
    for u, v in edges:
        used.add(u)
        used.add(v)

    for nid in used:
        if nid in goals:
            continue
        gv_id = _sanitize_id(nid)
        obj = node_map.get(nid, {"asset_name": "", "threat_id": nid})
        label = _one_line_label(obj)
        attrs = _attack_tree_node_attrs(obj, phases_by_asset_guid)
        lines.append(
            f'  {gv_id} [shape={attrs["shape"]}, style="{attrs["style"]}", '
            f'fillcolor="{attrs["fillcolor"]}", color="{attrs["color"]}", fontcolor="{attrs["fontcolor"]}", '
            f'penwidth={attrs["penwidth"]}, label="{_gv_escape(label)}"];'
        )

    lines.append("")
    for u, v in sorted(edges):
        lines.append(f"  {_sanitize_id(u)} -> {_sanitize_id(v)};")

    lines.append("}")
    return "\n".join(lines)

def render_attack_tree_from_attack_graph_json(
    attack_graph_json_path: Path,
    png_path: Path,
    dot_path: Optional[Path] = None,
    no_reverse: bool = False,
):
    with attack_graph_json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    dot_text = attack_tree_to_dot(data, reverse_arrows=(not no_reverse))

    if dot_path is None:
        dot_path = png_path.with_suffix(".dot")

    dot_path.parent.mkdir(parents=True, exist_ok=True)
    dot_path.write_text(dot_text, encoding="utf-8")

    dot_exe = _ensure_dot()
    png_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([dot_exe, "-Tpng", str(dot_path), "-o", str(png_path)], check=True)
    print(f"[OK] AttackTree PNG: {png_path}")



def add_risk_to_paths(in_json_path, out_json_path, asset_feasability_json_path, asset_to_threat_json, threat_to_tactic_json, impact_map_json, impact_feasability_map):
    result = _read_json(in_json_path)
    threat_feasability = _read_json(asset_feasability_json_path)
    asset_to_threat = _read_json(asset_to_threat_json)
    threat_to_tactic = _read_json(threat_to_tactic_json)
    impact_map = _read_json(impact_map_json)
    if impact_feasability_map and Path(str(impact_feasability_map)).exists():
        impact_feasability_map = _read_json(impact_feasability_map)
    else:
        impact_feasability_map = None

    for idx in range(len(result["paths"])):
        p = result["paths"][idx]
        risk_per_asset = []
        current_feasability = ""
        current_severity = ""
        for target_node_id in p:
            for node in result["nodes"]:
                if node["node_id"] == target_node_id:
                    if node["phase"] == "Entry":
                        risk_per_asset.append("-")
                        break
                    if not current_feasability:
                        for record in threat_feasability:
                            if record["id"] == node["threat_id"]:
                                current_feasability = record["feasibility"]
                    tactics = get_tactics_by_asset_name(asset_to_threat, node["asset_name"])
                    phases = get_ukc_phases(tactics, threat_to_tactic)

                    current_im_score = 0
                    for im_record in impact_map:
                        if node["asset_name"] == im_record["asset_name"]:
                            current_im_score = im_record["score"]

                    if impact_feasability_map:
                        for if_record in impact_feasability_map["impact_severity_map_record"]:
                            if set(phases) == set(if_record["phase"]):
                                if set(phases) == set(["In"]):
                                    current_severity = if_record["severity"]
                                    break
                                if current_im_score == if_record["impact"]:
                                    current_severity = if_record["severity"]
                                    break

                        for ifm_record in impact_feasability_map["impact_feasability_map_record"]:
                            if ifm_record["severity"] == current_severity and ifm_record["feasability"] == current_feasability:
                                risk_per_asset.append(ifm_record["risk"])
                    else:
                        impact_label = IMPACT_BY_SCORE.get(max(0, min(4, int(current_im_score or 0))), "Negligible")
                        feas_label = _normalize_feasibility_label(current_feasability, result.get("mode", "remote"))
                        level = _calc_risk_level(impact_label, feas_label)
                        risk_per_asset.append({"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(level, 1))

        result["paths"][idx] = {"path": result["paths"][idx], "risk": sum(x for x in risk_per_asset if x != "-"), "risk_per_asset": risk_per_asset}

    risks = [item["risk"] for item in result["paths"] if "risk" in item]
    max_risk = max(risks) if risks else 0
    min_risk = min(risks) if risks else 0
    result["total_risk"] = (max_risk + min_risk) / 2

    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)


def get_tactics_by_asset_name(json_data, asset_name):
    tactics_set = set()
    for asset in json_data["assets"]:
        if asset["asset_name"] == asset_name:
            for threat in asset.get("threats", []):
                for tactic in threat.get("tactics", []):
                    tactics_set.add(tactic)
    return list(tactics_set)


def get_ukc_phases(tactics, json_data):
    phases = set()
    tactic_to_phase = build_tactic_to_phase(json_data if isinstance(json_data, dict) else {})
    for tactic in tactics:
        phase = tactic_to_phase.get(norm_tactic(tactic))
        if phase:
            phases.add(phase)
    return list(phases)




def main():
    ap = argparse.ArgumentParser(description="Enterprise TM7-based attack graph (JSON) generation")
    ap.add_argument("--tm7", default="")
    ap.add_argument("--type", default="remote", choices=["remote", "adjacent", "local", "physical"])
    ap.add_argument("--target", default="")
    ap.add_argument("--boundary", default="")
    ap.add_argument("--asset-map", default="asset_to_threats_enterprise.json")
    ap.add_argument("--threat-map", default="threat_to_tactic_enterprise.json")
    ap.add_argument("--attack-vector-map", default="attack_vector_feasibility_enterprise.json")
    ap.add_argument("--impact-map", default="impact_map_enterprise.json")
    ap.add_argument("--dependency-map", default="dependency_enterprise.json")
    ap.add_argument("--max-depth", type=int, default=30)
    ap.add_argument("--out", default="attack_graph.json")
    ap.add_argument("--render-merged-graph", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--merged-graph-out", default="../out/merged_attack_graph")
    ap.add_argument("--merged-graph-format", default="pdf", choices=["png", "svg", "pdf"])
    ap.add_argument("--render-attack-tree", action=argparse.BooleanOptionalAction, default=False)
    ap.add_argument("--attack-tree-png", default="../out/attack_tree.png")
    ap.add_argument("--attack-tree-dot", default="")
    ap.add_argument("--attack-tree-no-reverse", action="store_true")
    ap.add_argument("--detection-report", default="../out/attack_report.html")
    ap.add_argument("--detection-report-pdf", default="")
    ap.add_argument("--llm-api-key", default="", help="[Deprecated] AI is now run exclusively by tool_attack_paths. Kept for CLI compatibility.")
    ap.add_argument("--gemini-model", default="gemini-2.0-flash", help="[Deprecated] AI model selection moved to tool_attack_paths.")
    ap.add_argument("--additional-info", default="", help="Additional system context (passed through for legacy compatibility).")
    ap.add_argument("--regenerate-report", action="store_true",
                    help="Regenerate HTML report from existing gemini_analysis.json without rerunning full analysis")
    ap.add_argument("--gemini-analysis", default="",
                    help="Path to gemini_analysis.json to use for report regeneration")
    ap.add_argument("--report-html", default="",
                    help="Output HTML report path (used with --regenerate-report)")

    args = ap.parse_args()

    if getattr(args, "regenerate_report", False):
        _ga_path = args.gemini_analysis or os.environ.get("TARA_GEMINI_ANALYSIS", "")
        _rp = args.report_html or args.detection_report
        if not _ga_path or not Path(_ga_path).exists():
            print(f"[ERROR] --gemini-analysis file not found: {_ga_path}", file=sys.stderr)
            sys.exit(2)
        if not _rp:
            _rp = getattr(args, "detection_report", "") or ""
        if not _rp:
            print("[ERROR] --report-html (or --detection-report) required with --regenerate-report", file=sys.stderr)
            sys.exit(2)
        try:
            with open(_ga_path, encoding="utf-8") as _f:
                _gb = json.load(_f)
            _vr = _gb.get("enterprise_level_review")
            _fa = _gb.get("functional_level_analysis")
            _gemini_vr   = {"enterprise_level_review": _vr} if _vr else None
            _gemini_func = _fa
            _ga_dir = Path(_ga_path).parent

            _out_path = _gb.get("backend_json_path") or ""
            if not _out_path or not Path(_out_path).exists():
                _ag_jsons = sorted(_ga_dir.glob("_ag_tmp_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
                _out_path = str(_ag_jsons[0]) if _ag_jsons else ""
            if not _out_path or not Path(_out_path).exists():
                _ap_jsons = sorted(_ga_dir.glob("attack_paths_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
                _out_path = str(_ap_jsons[0]) if _ap_jsons else ""

            if _out_path and Path(_out_path).exists():
                _od = json.loads(Path(_out_path).read_text(encoding="utf-8"))
                _patched = False
                for _k, _bk in [("mode","attack_mode"),("target_asset_name","target_asset"),("boundary_name","boundary_name")]:
                    if not _od.get(_k) and _gb.get(_bk):
                        _od[_k] = _gb[_bk]; _patched = True
                if not _od.get("mode") and _od.get("meta",{}).get("mode"):
                    _od["mode"] = _od["meta"]["mode"]; _patched = True
                if not _od.get("target_asset_name") and _od.get("meta",{}).get("target"):
                    _od["target_asset_name"] = _od["meta"]["target"]; _patched = True
                if _patched:
                    import tempfile as _tf
                    _t = _tf.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
                    json.dump(_od, _t, ensure_ascii=False); _t.close()
                    _out_path = _t.name

            _risk_path = str(_ga_dir / "attack_graph_with_risk_temp.json")
            _report_path = Path(_rp)

            def _first_existing_path(*values):
                for _v in values:
                    if not _v:
                        continue
                    try:
                        _p = Path(str(_v))
                        if _p.exists():
                            return str(_p)
                    except Exception:
                        pass
                return ""

            _tm7_path = _first_existing_path(args.tm7, _gb.get("tm7_path"), _gb.get("tm7"))
            _asset_map_path = _first_existing_path(args.asset_map, _gb.get("asset_map_path"), _gb.get("asset_map"))
            _threat_map_path = _first_existing_path(args.threat_map, _gb.get("threat_map_path"), _gb.get("threat_map"))
            _attack_vector_path = _first_existing_path(args.attack_vector_map, _gb.get("attack_vector_map_path"), _gb.get("attack_vector_map"), _gb.get("av_map"))
            _impact_map_path = _first_existing_path(args.impact_map, _gb.get("impact_map_path"), _gb.get("impact_map"))

            _ag_img = ""
            for _ext in [".png", ".pdf", ".svg"]:
                for _stem in ["merged_attack_graph", "_ag_graph"]:
                    _c = _ga_dir / f"{_stem}{_ext}"
                    if _c.exists():
                        _ag_img = str(_c)
                        break
                if _ag_img:
                    break
            if not _ag_img:
                _imgs = sorted(
                    list(_ga_dir.glob("*.png")) + list(_ga_dir.glob("*.pdf")) + list(_ga_dir.glob("*.svg")),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if _imgs:
                    _ag_img = str(_imgs[0])

            print(f"[INFO] Regenerate report input JSON: {_out_path or '-'}")
            print(f"[INFO] Regenerate report TM7: {_tm7_path or '-'}")
            print(f"[INFO] Regenerate report asset map: {_asset_map_path or '-'}")

            generate_html_report(
                report_path=_report_path,
                attack_graph_path=_ag_img,
                out_path=_out_path or "",
                threat_cti_path=_threat_map_path,
                asset_map_path=_asset_map_path,
                attack_vector_path=_attack_vector_path,
                impact_map_path=_impact_map_path,
                attack_graph_with_risk_path=_risk_path,
                tm7_path=_tm7_path,
                gemini_enterprise_review=_gemini_vr,
                gemini_functional=_gemini_func,
            )
            print(f"[OK] Report regenerated: {_report_path}")
        except Exception as _e:
            import traceback as _tb
            print(f"[ERROR] Report regeneration failed: {_e}", file=sys.stderr)
            _tb.print_exc()
            sys.exit(1)
        sys.exit(0)

    if not args.tm7:
        print("[ERROR] --tm7 is required (unless using --regenerate-report)", file=sys.stderr)
        sys.exit(2)
    tm7_path = Path(args.tm7)
    if not tm7_path.exists():
        print(f"[ERROR] tm7 not found: {tm7_path}", file=sys.stderr)
        sys.exit(2)

    if not args.type:
        print("[ERROR] --type is required (unless using --regenerate-report)", file=sys.stderr)
        sys.exit(2)
    if not args.target:
        print("[ERROR] --target is required (unless using --regenerate-report)", file=sys.stderr)
        sys.exit(2)

    asset_map = Path(args.asset_map)
    threat_map = Path(args.threat_map)
    attack_vector_map = Path(args.attack_vector_map)
    dependency_map = Path(args.dependency_map)
    impact_map = Path(args.impact_map)

    for pth, nm in [
        (asset_map, "asset-map"),
        (threat_map, "threat-map"),
        (attack_vector_map, "attack-vector-map"),
        (dependency_map, "dependency-map"),
        (impact_map, "impact-map"),
    ]:
        if not pth.exists():
            print(f"[ERROR] {nm} not found: {pth}", file=sys.stderr)
            sys.exit(2)

    if args.type in ("remote", "adjacent", "local", "physical"):
        if not args.boundary:
            print("[ERROR] --boundary is required", file=sys.stderr)
            sys.exit(2)

    if args.type in ("remote", "adjacent"):
        result = build_attack_graph_remote_adjacent(
            tm7_path=tm7_path,
            target_asset_name=args.target,
            boundary_name=args.boundary,
            asset_to_threats_path=asset_map,
            threat_to_tactic_path=threat_map,
            attack_vector_path=attack_vector_map,
            dependency_path=dependency_map,
            mode=args.type,
            max_depth=args.max_depth,
        )
    else:
        result = build_attack_graph_local_physical(
            tm7_path=tm7_path,
            target_asset_name=args.target,
            boundary_name=args.boundary,
            asset_to_threats_path=asset_map,
            threat_to_tactic_path=threat_map,
            attack_vector_path=attack_vector_map,
            dependency_path=dependency_map,
            mode=args.type,
            max_depth=args.max_depth,
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] wrote: {out_path}")
    print(f"[INFO] identified attack paths: {len(result.get('paths') or [])}")

    if not result.get("ok", False):
        print(f"[INFO] reason: {result.get('reason')}")

    rendered = None
    report_preview_graph = None
    if args.render_merged_graph:
        try:
            rendered = render_merged_attack_graph_graphviz(result, out_prefix=args.merged_graph_out, fmt=args.merged_graph_format)
            print(f"[OK] rendered merged attack graph: {rendered}")
            if args.merged_graph_format.lower() != "png":
                preview_prefix = str(Path(args.merged_graph_out).with_name(Path(args.merged_graph_out).name + "_preview"))
                report_preview_graph = _render_report_preview_from_graph(result=result, out_prefix=preview_prefix)
                if report_preview_graph:
                    print(f"[OK] rendered preview: {report_preview_graph}")
            else:
                report_preview_graph = rendered
        except Exception as e:
            print(f"[WARN] merged graphviz rendering failed: {e}", file=sys.stderr)

    risk_path = str(Path(args.out).parent / "attack_graph_with_risk_temp.json")
    try:
        add_risk_to_paths(out_path, risk_path, attack_vector_map, asset_map, threat_map, impact_map, "./threat_library/impact_feasability_map.json")
    except Exception as _risk_e:
        print(f"[WARN] Risk score calculation failed (non-fatal): {_risk_e}", file=sys.stderr)

    if args.render_attack_tree:
        try:
            attack_tree_path = Path(args.attack_tree_png)
            dot_path = Path(args.attack_tree_dot) if args.attack_tree_dot else None
            render_attack_tree_from_attack_graph_json(
                attack_graph_json_path=out_path,
                png_path=attack_tree_path,
                dot_path=dot_path,
                no_reverse=args.attack_tree_no_reverse,
            )
        except Exception as e:
            print(f"[WARN] attack tree rendering failed: {e}", file=sys.stderr)


    gemini_enterprise_review = None
    gemini_functional = None

    report_path = Path(args.detection_report)
    if report_preview_graph is not None:
        attack_graph_path = str(report_preview_graph)
    elif rendered is not None:
        attack_graph_path = str(rendered)
    else:
        attack_graph_path = args.merged_graph_out + "." + args.merged_graph_format

    if not gemini_enterprise_review and not gemini_functional:
        _search_dirs = []
        _search_dirs.append(Path(args.out).parent)
        if args.detection_report:
            _search_dirs.append(Path(args.detection_report).parent)
        for _lvl in [1, 2]:
            _search_dirs.append(Path(args.out).parents[_lvl])

        _seen_dirs = set()
        _unique_dirs = []
        for _d in _search_dirs:
            _dk = str(_d.resolve())
            if _dk not in _seen_dirs:
                _seen_dirs.add(_dk)
                _unique_dirs.append(_d)

        for _sd in _unique_dirs:
            _gp = _sd / "gemini_analysis.json"
            if _gp.exists():
                try:
                    with open(_gp, encoding="utf-8") as _f:
                        _gb = json.load(_f)

                    _vr = _gb.get("enterprise_level_review")
                    _fa = _gb.get("functional_level_analysis")

                    if _vr:
                        gemini_enterprise_review = {"enterprise_level_review": _vr}
                    if _fa:
                        gemini_functional = {"functional_level_analysis": _fa}

                    if _vr or _fa:
                        print(f"[OK] Loaded AI analysis from: {_gp}")
                        break

                except Exception as _e:
                    print(f"[WARN] Could not load gemini_analysis.json: {_e}", file=sys.stderr)

    if args.detection_report:
        try:
            _ag_path = ""
            if report_preview_graph and Path(str(report_preview_graph)).exists():
                _ag_path = str(report_preview_graph)
            elif rendered and Path(str(rendered)).exists():
                _ag_path = str(rendered)

            generate_html_report(
                report_path=report_path,
                attack_graph_path=_ag_path,
                out_path=str(out_path),
                threat_cti_path=str(threat_map),
                asset_map_path=str(asset_map),
                attack_vector_path=str(attack_vector_map),
                impact_map_path=str(impact_map),
                attack_graph_with_risk_path=risk_path,
                tm7_path=str(tm7_path),
                gemini_enterprise_review=gemini_enterprise_review,
                gemini_functional=gemini_functional,
            )

            if not report_path.exists():
                raise RuntimeError(f"HTML report was not created: {report_path}")

            print(f"[OK] report written: {report_path}")

        except Exception as _rpt_e:
            import traceback as _tb
            print(f"[ERROR] Report generation error: {_rpt_e}", file=sys.stderr)
            _tb.print_exc(file=sys.stderr)
            sys.exit(1)

        pdf_report_path = Path(args.detection_report_pdf) if args.detection_report_pdf else report_path.with_suffix(".pdf")
        if _convert_html_to_pdf(report_path, pdf_report_path):
            print(f"[OK] PDF report written: {pdf_report_path}")



if __name__ == "__main__":
    main()
