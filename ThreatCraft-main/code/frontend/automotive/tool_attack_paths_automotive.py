#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

def _ensure_packages():
    import importlib, subprocess, sys, threading

    REQUIRED = [
        ("google.genai",  "google-genai",  ""),
        ("openai",        "openai",        ""),
    ]

    def _pip_install(pkg):
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass  

    missing = []
    for import_name, pip_pkg, _ in REQUIRED:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_pkg)

    if missing:
        
        threads = [threading.Thread(target=_pip_install, args=(p,), daemon=True)
                   for p in missing]
        for t in threads:
            t.start()
        
        for t in threads:
            t.join(timeout=60)

_ensure_packages()


import argparse, csv, io, json, sys, threading, traceback
import tkinter as tk
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, FrozenSet, List, Set, Tuple
from html import escape

_FS_IMPACT_ORDER = {
    "Negligible": 0, "Moderate": 1, "Major": 2, "Severe": 3,
    
    "NEG": 0, "MOD": 1, "MAJ": 2, "SEV": 3,
}
_FS_FEASIBILITY_ORDER = {
    "very low": 0, "low": 1, "medium": 2, "high": 3,
}


_FS_IMPACT_ORDER = {
    "Negligible": 0, "Moderate": 1, "Major": 2, "Severe": 3,
    "NEG": 0, "MOD": 1, "MAJ": 2, "SEV": 3,
}
_FS_FEASIBILITY_ORDER = {"very low": 0, "low": 1, "medium": 2, "high": 3}

def _calc_risk_level_fs(safety, financial, operational, privacy, feasibility_rating):
    
    max_impact = max(
        _FS_IMPACT_ORDER.get(str(safety).strip(), 1),
        _FS_IMPACT_ORDER.get(str(financial).strip(), 1),
        _FS_IMPACT_ORDER.get(str(operational).strip(), 1),
        _FS_IMPACT_ORDER.get(str(privacy).strip(), 1),
    )
    feas = _FS_FEASIBILITY_ORDER.get(str(feasibility_rating).strip().lower(), 2)
    if max_impact == 0: return "Low"
    score = max_impact + feas
    if score >= 5: return "Critical"
    if score >= 4: return "High"
    if score >= 2: return "Medium"
    return "Low"



def _calc_risk_level_fs(safety, financial, operational, privacy, feasibility_rating):
    
    max_impact = max(
        _FS_IMPACT_ORDER.get(str(safety).strip(), 1),
        _FS_IMPACT_ORDER.get(str(financial).strip(), 1),
        _FS_IMPACT_ORDER.get(str(operational).strip(), 1),
        _FS_IMPACT_ORDER.get(str(privacy).strip(), 1),
    )
    feas = _FS_FEASIBILITY_ORDER.get(str(feasibility_rating).strip().lower(), 2)
    if max_impact == 0:
        return "Low"
    score = max_impact + feas
    if score >= 5:
        return "Critical"
    if score >= 4:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"
try:
    from PIL import Image, ImageTk
    _PIL_OK = True
except Exception:
    Image = None
    ImageTk = None
    _PIL_OK = False

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

_SPLASH_LOGO_PATH = (_SCRIPT_DIR / "../../../asset/logo.png").resolve()


try:
    from tool_threat_mapper_automotive import (
        DEFAULT_BACKEND, DEFAULT_ASSET_MAP, DEFAULT_THREAT_MAP,
        DEFAULT_AV_MAP, DEFAULT_DEP_MAP, DEFAULT_IMPACT_MAP, DEFAULT_OUT_DIR,
        HIERARCHY_JSON,
        _load_h, _list_cats, _list_types, _list_kinds, _list_props,
        _get_source, _get_cwes, _get_cwes_merged, _get_threats,
        _get_threats_from_hierarchy, _get_dfd_threats, _merge_threats,
        run_path_filter, extract_elements,
        AssetMapDialog, _center,
        build_result_json, build_result_csv,
    )
    _SHARED_OK = True
except ImportError as _e:
    _SHARED_OK = False
    _IMPORT_ERR = str(_e)
    from pathlib import Path as _P
    _sd = _P(__file__).resolve().parent
    DEFAULT_BACKEND    = (_sd / "../backend/parse_attack_graph_automotive.py").resolve()
    DEFAULT_ASSET_MAP  = (_sd / "../backend/threat_library/automotive/asset_to_threats_automotive.json").resolve()
    DEFAULT_THREAT_MAP = (_sd / "../backend/threat_library/automotive/threat_to_tactic_automotive.json").resolve()
    DEFAULT_AV_MAP     = (_sd / "../backend/threat_library/automotive/attack_vector_feasibility_automotive.json").resolve()
    DEFAULT_DEP_MAP    = (_sd / "../backend/threat_library/automotive/dependency_automotive.json").resolve()
    DEFAULT_IMPACT_MAP = (_sd / "../backend/threat_library/automotive/impact_map_automotive.json").resolve()
    DEFAULT_OUT_DIR    = (_sd / "../out").resolve()

    def _center(win, w: int, h: int) -> None:
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


def _draw_top_banner(canvas: tk.Canvas, title: str, subtitle: str) -> None:
    canvas.delete("all")
    w = max(canvas.winfo_width(), 1)
    h = max(canvas.winfo_height(), 1)

    steps = 40
    for i in range(steps):
        t = i / (steps - 1)
        r1, g1, b1 = (10, 24, 55)
        r2, g2, b2 = (0, 120, 140)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        color = f"#{r:02x}{g:02x}{b:02x}"
        y0 = int(i * h / steps)
        y1 = int((i + 1) * h / steps)
        canvas.create_rectangle(0, y0, w, y1, outline=color, fill=color)

    for x in range(0, w, 48):
        canvas.create_line(x, 0, x, h, fill="#20324f")
    for y in range(0, h, 24):
        canvas.create_line(0, y, w, y, fill="#20324f")

    canvas.create_text(
        18, 22, anchor="w",
        text=title,
        fill="white",
        font=("Segoe UI", 16, "bold")
    )
    canvas.create_text(
        18, 52, anchor="w",
        text=subtitle,
        fill="#d7f3ff",
        font=("Segoe UI", 10, "normal")
    )

    cx = w - 220
    cy = 54
    body = [
        (cx - 80, cy + 10),
        (cx + 90, cy + 10),
        (cx + 110, cy - 2),
        (cx + 70, cy - 18),
        (cx - 10, cy - 18),
        (cx - 40, cy - 6),
        (cx - 80, cy - 6),
    ]
    canvas.create_polygon(body, fill="#eaf6ff", outline="#c5e6ff", width=2)

    win = [(cx - 5, cy - 16), (cx + 55, cy - 16), (cx + 70, cy - 6), (cx - 20, cy - 6)]
    canvas.create_polygon(win, fill="#0b1c33", outline="#c5e6ff", width=2)

    canvas.create_oval(cx - 55, cy + 2, cx - 25, cy + 32, fill="#0b1c33", outline="#c5e6ff", width=2)
    canvas.create_oval(cx + 55, cy + 2, cx + 85, cy + 32, fill="#0b1c33", outline="#c5e6ff", width=2)
    canvas.create_oval(cx - 47, cy + 10, cx - 33, cy + 24, fill="#eaf6ff", outline="")
    canvas.create_oval(cx + 63, cy + 10, cx + 77, cy + 24, fill="#eaf6ff", outline="")

    lx = w - 70
    ly = 28
    canvas.create_arc(
        lx - 18, ly - 18, lx + 18, ly + 18,
        start=200, extent=140, style="arc", width=4, outline="#ffffff"
    )
    canvas.create_rectangle(lx - 20, ly + 12, lx + 20, ly + 46, fill="#ffffff", outline="#ffffff")
    canvas.create_oval(lx - 4, ly + 24, lx + 4, ly + 32, fill="#0b1c33", outline="#0b1c33")
    canvas.create_rectangle(lx - 2, ly + 32, lx + 2, ly + 40, fill="#0b1c33", outline="#0b1c33")


_DEFAULT_UKC = {
    "In":      ["Reconnaissance","Manipulate Environment","Initial Access",
                "Persistence","Defense Evasion","Command and Control","Command & Control"],
    "Through": ["Discovery","Privilege Escalation","Execution",
                "Credential Access","credential access","Lateral Movement"],
    "Out":     ["Collection","Exfiltration","Affect Vehicle Function","Impact"],
}
_TACTIC_TO_PHASE: Dict[str, str] = {}


_OTHER_SENTINEL = "Other"

def _patch_asset_map_dialog_other(dlg: tk.Toplevel) -> None:
    def _all_comboboxes(widget):
        result = []
        if isinstance(widget, ttk.Combobox):
            result.append(widget)
        for child in widget.winfo_children():
            result.extend(_all_comboboxes(child))
        return result

    def _make_other_handler(cb: ttk.Combobox):
        def handler(event=None):
            if cb.get() != _OTHER_SENTINEL:
                return

            top = tk.Toplevel(dlg)
            top.title("Enter custom value")
            top.resizable(False, False)
            top.grab_set()
            top.transient(dlg)

            cb.update_idletasks()
            cx = cb.winfo_rootx()
            cy = cb.winfo_rooty() + cb.winfo_height()
            top.geometry(f"320x70+{cx}+{cy}")

            tk.Label(
                top,
                text="Custom value:",
                font=("Segoe UI", 9),
                bg="white"
            ).pack(anchor="w", padx=8, pady=(8, 2))

            e = tk.Entry(
                top,
                font=("Segoe UI", 10),
                width=38,
                bg="#FAFAFA",
                relief="solid"
            )
            e.pack(padx=8)
            e.focus_set()

            def _confirm(event=None):
                val = e.get().strip()
                if not val:
                    top.destroy()
                    return

                current_vals = list(cb["values"])
                if val not in current_vals:
                    idx = current_vals.index(_OTHER_SENTINEL)
                    current_vals.insert(idx, val)
                    cb["values"] = current_vals

                cb.set(val)
                top.destroy()

            def _cancel(event=None):
                cb.set("")
                top.destroy()

            e.bind("<Return>", _confirm)
            e.bind("<Escape>", _cancel)

            btn_row = tk.Frame(top, bg="white")
            btn_row.pack(fill="x", padx=8, pady=4)

            tk.Button(
                btn_row,
                text="OK",
                font=("Segoe UI", 9, "bold"),
                bg="#1565C0",
                fg="white",
                relief="flat",
                padx=14,
                command=_confirm
            ).pack(side="left", padx=(0, 6))

            tk.Button(
                btn_row,
                text="Cancel",
                font=("Segoe UI", 9),
                bg="#EEEEEE",
                relief="flat",
                padx=10,
                command=_cancel
            ).pack(side="left")

        return handler

    def _add_other_to_combobox(cb: ttk.Combobox):
        vals = list(cb["values"])
        if not vals:
            return
        if _OTHER_SENTINEL in vals:
            return

        vals.append(_OTHER_SENTINEL)
        cb["values"] = vals
        cb.bind("<<ComboboxSelected>>", _make_other_handler(cb), add="+")

    def _do_patch():
        combos = _all_comboboxes(dlg)

        from collections import defaultdict
        rows = defaultdict(list)

        for cb in combos:
            try:
                y = cb.winfo_rooty()
                x = cb.winfo_rootx()
                rows[y].append((x, cb))
            except Exception:
                pass

        for y_key in sorted(rows):

            row_cbs = [cb for x, cb in sorted(rows[y_key], key=lambda t: t[0])]

            if len(row_cbs) >= 2:
                _add_other_to_combobox(row_cbs[1])
            if len(row_cbs) >= 3:
                _add_other_to_combobox(row_cbs[2])

    dlg.after(200, _do_patch)


def _build_tactic_map(ukc_dict: dict) -> None:
    global _TACTIC_TO_PHASE
    _TACTIC_TO_PHASE = {}
    for phase, tactics in ukc_dict.items():
        for t in tactics:
            _TACTIC_TO_PHASE[t.lower()] = phase
    for ph in ("In", "Through", "Out", "Entry"):
        _TACTIC_TO_PHASE[ph.lower()] = ph

def _tactic_to_ukc(tactic: str) -> str:
    if not tactic:
        return "?"
    t = tactic.strip()
    if t in ("In", "Through", "Out", "Entry"):
        return t
    r = _TACTIC_TO_PHASE.get(t.lower())
    if r:
        return r
    for phase, tactics in _DEFAULT_UKC.items():
        if any(t.lower() == tac.lower() for tac in tactics):
            return phase
    return "Through"


class PathNode:
    __slots__ = ("node_id","asset_guid","asset_name","threat_id","threat_name","tactic","phase","ukc_phase")

    def __init__(self, raw: dict):
        self.node_id    = raw.get("node_id", "")
        self.asset_guid = raw.get("asset_guid", "")
        self.asset_name = raw.get("asset_name", "")
        self.threat_id  = raw.get("threat_id", "") or ""
        self.threat_name= raw.get("threat_name", "") or ""
        self.tactic     = raw.get("tactic", "") or ""
        self.phase      = raw.get("phase", "")
        self.ukc_phase  = (
            self.phase if self.phase in ("In", "Through", "Out", "Entry")
            else _tactic_to_ukc(self.tactic or self.phase)
        )

    def brief(self) -> dict:
        return {
            "asset": self.asset_name,
            "threat_id": self.threat_id,
            "threat_name": self.threat_name,
            "tactic": self.tactic,
            "ukc_phase": self.ukc_phase
        }


class UKCCycle:
    def __init__(self, nodes: List[PathNode]):
        self.nodes = nodes

    @property
    def entry_nodes(self) -> List[PathNode]:
        return [n for n in self.nodes if n.ukc_phase == "Entry"]

    @property
    def in_nodes(self) -> List[PathNode]:
        return [n for n in self.nodes if n.ukc_phase == "In"]

    @property
    def through_nodes(self) -> List[PathNode]:
        return [n for n in self.nodes if n.ukc_phase == "Through"]

    @property
    def out_nodes(self) -> List[PathNode]:
        return [n for n in self.nodes if n.ukc_phase == "Out"]

    @property
    def is_valid(self) -> bool:
        return len(self.in_nodes) >= 1 and len(self.out_nodes) >= 1

    @property
    def in_asset_guids(self) -> Set[str]:
        return {n.asset_guid for n in self.in_nodes}

    @property
    def pivot_asset_guids(self) -> Set[str]:
        return {n.asset_guid for n in self.through_nodes} | {n.asset_guid for n in self.out_nodes}

    @property
    def threat_key(self) -> FrozenSet[Tuple[str, str]]:
        keys = []
        for n in self.nodes:
            if n.threat_id:
                keys.append((n.asset_guid, n.threat_id))
            elif n.ukc_phase == "Entry":
                keys.append((n.asset_guid, "::ENTRY"))
        return frozenset(keys)

    def to_dict(self) -> dict:
        return {
            "entry": [n.brief() for n in self.entry_nodes],
            "in": [n.brief() for n in self.in_nodes],
            "through": [n.brief() for n in self.through_nodes],
            "out": [n.brief() for n in self.out_nodes]
        }

    def summary(self) -> str:
        ea = ",".join(dict.fromkeys(n.asset_name for n in self.entry_nodes))
        ia = ",".join(dict.fromkeys(n.asset_name for n in self.in_nodes))
        ta = ",".join(dict.fromkeys(n.asset_name for n in self.through_nodes))
        oa = ",".join(dict.fromkeys(n.asset_name for n in self.out_nodes))
        entry_str = f"Entry({ea}) -> " if ea else ""
        return f"{entry_str}In({ia}) -> Through({ta}) -> Out({oa})"


class MultiCyclePath:
    def __init__(self, cycles: List[UKCCycle]):
        self.cycles = cycles

    @property
    def cycle_count(self) -> int:
        return len(self.cycles)

    @property
    def all_assets(self) -> List[str]:
        seen: Dict[str, None] = {}
        for c in self.cycles:
            for n in c.nodes:
                seen[n.asset_name] = None
        return list(seen.keys())

    @property
    def all_threats(self) -> List[str]:
        seen: Dict[str, None] = {}
        for c in self.cycles:
            for n in c.nodes:
                if n.threat_id:
                    seen[n.threat_id] = None
        return list(seen.keys())

    @property
    def final_targets(self) -> List[str]:
        if not self.cycles:
            return []
        return list(dict.fromkeys(n.asset_name for n in self.cycles[-1].out_nodes))

    def path_summary(self) -> str:
        return " => ".join(f"[Cycle {i+1}: {c.summary()}]" for i, c in enumerate(self.cycles))

    def to_dict(self) -> dict:
        return {
            "cycle_count": self.cycle_count,
            "all_assets": self.all_assets,
            "all_threats": self.all_threats,
            "final_targets": self.final_targets,
            "path_summary": self.path_summary(),
            "cycles": [c.to_dict() for c in self.cycles]
        }


def enumerate_multi_cycle_paths(raw_paths, node_index, max_cycles=3, max_single=500, max_multi=1500):
    single_results: List[MultiCyclePath] = []
    multi_results: List[MultiCyclePath] = []
    seen_single: Set = set()
    seen_multi: Set = set()

    cycles_pool = [UKCCycle([node_index[nid] for nid in rp if nid in node_index]) for rp in raw_paths]
    cycles_pool = [c for c in cycles_pool if c.is_valid]

    in_guid_to_cycles: Dict[str, List[UKCCycle]] = defaultdict(list)
    for c in cycles_pool:
        for g in c.in_asset_guids:
            in_guid_to_cycles[g].append(c)

    for c in cycles_pool:
        k = c.threat_key
        if k not in seen_single:
            seen_single.add(k)
            single_results.append(MultiCyclePath([c]))
        if len(single_results) >= max_single:
            break

    def _chain_key(chain):
        return tuple(c.threat_key for c in chain)

    def _extend(chain, depth):
        if depth >= max_cycles or len(multi_results) >= max_multi:
            return
        last = chain[-1]
        for pg in last.pivot_asset_guids:
            for nc in in_guid_to_cycles.get(pg, []):
                if nc.threat_key == last.threat_key:
                    continue
                new_chain = chain + [nc]
                k = _chain_key(new_chain)
                if k not in seen_multi:
                    seen_multi.add(k)
                    multi_results.append(MultiCyclePath(new_chain))
                if len(multi_results) < max_multi:
                    _extend(new_chain, depth + 1)

    for c in cycles_pool:
        _extend([c], 1)
        if len(multi_results) >= max_multi:
            break

    combined = multi_results + single_results
    combined.sort(key=lambda x: (-x.cycle_count, -len(x.all_threats)))
    return combined


def build_full_json(mapping, multi_paths, meta):
    base = build_result_json(mapping, meta)
    base["meta"]["tool"] = "tool_attack_paths v4"
    base["meta"]["total_paths"] = len(multi_paths)
    base["meta"]["multi_cycle_paths"] = sum(1 for p in multi_paths if p.cycle_count > 1)
    base["attack_paths"] = [
        {
            "path_id": i + 1,
            "cycle_count": p.cycle_count,
            "all_assets": p.all_assets,
            "all_threats": p.all_threats,
            "final_targets": p.final_targets,
            "path_summary": p.path_summary(),
            "cycles": [c.to_dict() for c in p.cycles]
        }
        for i, p in enumerate(multi_paths)
    ]
    return base


def build_full_csv(mapping, multi_paths):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["## SECTION: ASSET_MAPPING"])
    for line in build_result_csv(mapping).splitlines():
        w.writerow(line.split(","))
    w.writerow([])
    w.writerow(["## SECTION: ATTACK_PATHS"])
    w.writerow(["path_id","cycle_count","cycle_no","ukc_phase","asset_name",
                "threat_id","threat_name","tactic","final_targets","path_summary"])
    for i, p in enumerate(multi_paths):
        for ci, c in enumerate(p.cycles):
            for n in c.nodes:
                w.writerow([
                    i + 1, p.cycle_count, ci + 1, n.ukc_phase, n.asset_name,
                    n.threat_id, n.threat_name, n.tactic,
                    ";".join(p.final_targets) if ci == 0 and n == c.nodes[0] else "",
                    p.path_summary() if ci == 0 and n == c.nodes[0] else ""
                ])
    return buf.getvalue()


class _AutosecBaseAgent:
    SYSTEM_PROMPT: str = ""   

    def __init__(self, *, provider: str, model: str,
                 gemini_client=None, oai_client=None,
                 log_fn, set_progress_fn, repair_json_fn):
        self.provider       = provider
        self.model          = model
        self._gc            = gemini_client   
        self._oc            = oai_client      
        self._log           = log_fn          
        self._progress      = set_progress_fn
        self._repair        = repair_json_fn
        self._messages: list = []             
        self._chat           = None           
        import time as _t, re as _r, json as _j
        self._time = _t
        self._re   = _r
        self._json = _j

    def reset(self):
        self._messages = []
        self._chat     = None

    def send(self, user_msg: str, *, max_retries: int = 4, base_delay: int = 5) -> str:
        if self.provider == "gemini":
            return self._send_gemini(user_msg, max_retries, base_delay)
        return self._send_oai_with_continuation(user_msg, max_retries, base_delay)

    def _send_gemini(self, user_msg: str, max_retries: int, base_delay: int) -> str:
        from google.genai import types as _gt
        if self._chat is None:
            self._chat = self._gc.chats.create(
                model=self.model,
                config=_gt.GenerateContentConfig(
                    system_instruction=self.SYSTEM_PROMPT,
                    temperature=0.1,
                    max_output_tokens=16384,
                )
            )
        last_err = None
        for attempt in range(max_retries):
            try:
                resp = self._chat.send_message(user_msg)
                return (resp.text or "").strip()
            except Exception as ex:
                last_err = ex
                err = str(ex)
                self._log(f"[WARN] Gemini error (attempt {attempt+1}/{max_retries}): {err[:300]}")
                is_busy = any(x in err for x in [
                    "503", "UNAVAILABLE", "overloaded", "high demand",
                    "temporarily unavailable", "429", "RESOURCE_EXHAUSTED", "quota"])
                if is_busy:
                    delay = base_delay * (2 ** attempt)
                    self._log(f"[WARN] Gemini busy — retry {attempt+1}/{max_retries} in {delay}s...")
                    self._progress(f"Server busy — retrying in {delay}s...", -1)
                    self._time.sleep(delay)
                    continue
                raise
        raise RuntimeError(f"Gemini agent failed after {max_retries} retries: {last_err}")

    def _send_oai(self, user_msg: str, max_retries: int, base_delay: int) -> str:
        self._messages.append({"role": "user", "content": user_msg})
        msgs = [{"role": "system", "content": self.SYSTEM_PROMPT}] + self._messages
        pname = self.provider.upper()
        last_err = None
        for attempt in range(max_retries):
            try:
                resp = self._oc.chat.completions.create(
                    model=self.model, messages=msgs,
                    max_tokens=16384, temperature=0.1)
                text = (resp.choices[0].message.content or "").strip()
                self._messages.append({"role": "assistant", "content": text})
                return text
            except Exception as ex:
                last_err = ex
                err = str(ex)
                
                self._log(f"[WARN] {pname} error (attempt {attempt+1}/{max_retries}): {err[:400]}")
                is_busy = any(x in err.lower() for x in [
                    "503", "overloaded", "server_error", "temporarily unavailable",
                    "429", "rate_limit", "quota", "too many requests"])
                if is_busy:
                    delay = base_delay * (2 ** attempt)
                    self._log(f"[WARN] {pname} busy — retry {attempt+1}/{max_retries} in {delay}s...")
                    self._progress(f"Server busy — retrying in {delay}s...", -1)
                    self._time.sleep(delay)
                    continue
                
                raise RuntimeError(f"{pname} API error: {err}") from ex

        raise RuntimeError(
            f"{pname} agent failed after {max_retries} retries. "
            f"Last error: {last_err}"
        )

    def _send_oai_with_continuation(self, user_msg: str,
                                     max_retries: int, base_delay: int) -> str:
        pname = self.provider.upper()
        self._messages.append({"role": "user", "content": user_msg})
        msgs = [{"role": "system", "content": self.SYSTEM_PROMPT}] + self._messages
        last_err = None

        for attempt in range(max_retries):
            try:
                resp = self._oc.chat.completions.create(
                    model=self.model, messages=msgs,
                    max_tokens=16384, temperature=0.1)
                choice  = resp.choices[0]
                text    = (choice.message.content or "").strip()
                reason  = getattr(choice, "finish_reason", "stop") or "stop"

             
                if reason == "length":
                    self._log(
                        f"[WARN] {pname} response truncated (max_tokens reached). "
                        "Requesting continuation..."
                    )
                    
                    self._messages.append({"role": "assistant", "content": text})
                    cont_msgs = [
                        {"role": "system", "content": self.SYSTEM_PROMPT}
                    ] + self._messages + [
                        {"role": "user",
                         "content":
                             "Your previous response was cut off mid-JSON due to the output "
                             "token limit.  Please continue the JSON from EXACTLY where you "
                             "left off — no preamble, no markdown fences, just raw JSON "
                             "continuation (the characters that follow your last character)."}
                    ]
                    try:
                        cont_resp = self._oc.chat.completions.create(
                            model=self.model, messages=cont_msgs,
                            max_tokens=16384, temperature=0.1)
                        cont_text = (cont_resp.choices[0].message.content or "").strip()
                        
                        cont_text = self._re.sub(r"^```[a-z]*\s*", "", cont_text)
                        cont_text = self._re.sub(r"\s*```\s*$", "", cont_text)
                        text = text + cont_text
                        self._log(f"[INFO] {pname} continuation received "
                                  f"({len(cont_text)} chars). Merging fragments.")
                        
                        self._messages.pop()
                    except Exception as _ce:
                        self._log(f"[WARN] {pname} continuation failed: {_ce!s:.200}")
                        

                self._messages.append({"role": "assistant", "content": text})
                return text

            except Exception as ex:
                last_err = ex
                err = str(ex)
                self._log(f"[WARN] {pname} error (attempt {attempt+1}/{max_retries}): {err[:400]}")
                is_busy = any(x in err.lower() for x in [
                    "503", "overloaded", "server_error", "temporarily unavailable",
                    "429", "rate_limit", "quota", "too many requests"])
                if is_busy:
                    delay = base_delay * (2 ** attempt)
                    self._log(f"[WARN] {pname} busy — retry {attempt+1}/{max_retries} in {delay}s...")
                    self._progress(f"Server busy — retrying in {delay}s...", -1)
                    self._time.sleep(delay)
                    continue
                raise RuntimeError(f"{pname} API error: {err}") from ex

        raise RuntimeError(
            f"{pname} agent failed after {max_retries} retries. "
            f"Last error: {last_err}"
        )


    def send_and_parse(self, user_msg: str) -> dict:
        raw = self.send(user_msg)
        raw = self._re.sub(r"^```json\s*", "", raw, flags=self._re.MULTILINE)
        raw = self._re.sub(r"^```\s*$",    "", raw, flags=self._re.MULTILINE)
        raw = raw.strip()
        try:
            return self._json.loads(raw)
        except self._json.JSONDecodeError:
            return self._json.loads(self._repair(raw))

    def run(self, **kwargs) -> dict:
        raise NotImplementedError


class VehicleLevelReviewerAgent(_AutosecBaseAgent):
    SYSTEM_PROMPT = """\
You are a senior automotive cybersecurity architect with deep expertise in ISO/SAE 21434, WP.29 R155, UNECE CS regulations, and the MITRE ATT&CK for Vehicles / Unified Kill Chain (UKC) framework.

Your task is to produce publication-quality, technically rigorous narrative assessments of every vehicle-level attack path in the provided JSON. Treat this as a formal TARA deliverable.

=== ANTI-HALLUCINATION — HIGHEST PRIORITY ===
- Cite ONLY threat IDs, asset names, and tactics that appear verbatim in the input JSON.
- Never invent CVE numbers, software versions, or asset names not present in the input.
- If you draw an inference, prefix it with [INFERRED] and explain the basis.

=== SCOPE ===
- Focus exclusively on In-Vehicle Network (IVN) topology, UKC phase transitions, and threat tactics.
- Do NOT include CVE numbers or software version specifics (reserved for functional-level analysis).
- Evaluate each path against UKC validity: Entry ≥ 1 node, In ≥ 1, Through ≥ 1, Out ≥ 1.

=== UKC PHASE DEFINITIONS ===
- Entry: External attacker foothold — wireless interfaces (Bluetooth, Wi-Fi, cellular), physical OBD-II port, USB, RF key fob replay.
- In (Reconnaissance, Manipulate Environment, Initial Access, Persistence, Defense Evasion, Command and Control): First ECU compromised, credential theft, firmware implant, persistent backdoor.
- Through (Discovery, Privilege Escalation, Execution, Credential Access, Lateral Movement): CAN bus pivoting, gateway bypass, ECU-to-ECU command injection, diagnostic protocol abuse (UDS, XCP), CAN ID spoofing.
- Out (Collection, Exfiltration, Affect Vehicle Function, Impact): Unauthorized actuation (door unlock, brake manipulation, engine kill), sensitive data exfiltration, denial-of-service on safety ECU.

=== GENERATION RULES ===
1. Generate EXACTLY one path_review per path in the input (P1...PN). Never merge or skip paths.
2. MINIMUM 10 path_reviews. If input has fewer than 10 paths, generate additional attacker-perspective variations (different objectives, different Entry tactics) to reach 10.
3. Assign path_ids in DESCENDING risk order: P1 = highest risk_score, P2 = second, etc.
4. Output path_reviews array ordered by risk_score DESCENDING (P1 first).
5. COMPLETE SENTENCES ONLY: every narrative field must be grammatically complete. Never truncate mid-word. If token budget is tight, write shorter complete sentences rather than cutting words.
6. The narrative field must contain at least five complete sentences and should be written as specifically and accurately as possible. It must cover: (1) the attacker profile and entry vector with the specific interface used, (2) the concrete attack method corresponding to the UKC In phase, (3) the concrete UKC Through attack method required to reach the target asset, including protocol-level details, (4) the final impact on the target asset and its specific consequences under the UKC Out phase, and (5) an assessment of structural plausibility and real-world realism.
7. entry_point_assessment: describe the specific physical or wireless interface exploited, its exposure level, and why it is a viable entry point for the stated attack mode.
8. attack_objective: state the precise attacker goal — what asset is compromised, what capability is gained or denied, and what real-world harm results.
9. recommendations: Include at least 2 actionable and specific recommendations per path (e.g., "Implement CAN bus message authentication using AUTOSAR SecOC with AES-128 CMAC on all BCM-bound frames" rather than generic advice such as "improve security"). However, the example is illustrative only and must not unduly constrain the output. Do not fixate on the example, repeat it verbatim, or rely on the same recommendation pattern across multiple paths. Instead, generate technically accurate, path-specific, and diverse recommendations grounded in the actual attack path, affected assets, interfaces, protocols, threats, and broadly applicable security best practices.
10. required_equipment: Include at least 3 tools with EXACT product names and versions that are relevant to the specific interfaces of this path (e.g., "HackRF One SDR for 315/433 MHz key fob replay", "Vector CANalyzer 17.0 with AUTOSAR add-on for CAN frame injection", "Segger J-Link EDU for JTAG firmware extraction"). However, these examples are provided only to illustrate the expected format and level of specificity, and they must not unduly constrain the output. Do not fixate on these examples or repeat the same equipment patterns across multiple paths. Instead, select technically appropriate, path-specific, and diverse tools based on the actual interfaces, protocols, assets, and attack steps involved in the input.


OUTPUT — valid JSON only, no markdown fences, no commentary outside JSON:
{{
  "vehicle_level_review": {{
    "target_asset": "...",
    "attack_mode": "remote|adjacent|local|physical",
    "overall_validity": "valid|partial|invalid",
    "overall_confidence": "high|medium|low",
    "overall_summary": "Minimum 6 complete sentences: (1) attacker goal and primary motivation, (2) identified entry points and their exposure rationale, (3) lateral movement topology across IVN with named protocols, (4) critical backbone ECUs and why they are pivotal, (5) dominant attack tactics and their UKC phase mapping, (6) overall risk posture and most dangerous path.",
    "path_reviews": [
      {{
        "path_id": "P1",
        "phase_sequence": "Entry(asset_name)->In(asset_name)->Through(asset_name)->Out(asset_name)",
        "phase_validity": {{"has_entry": true, "has_in": true, "has_through": true, "has_out": true, "sequence_is_logical": true}},
        "narrative": "Five complete sentences: (1) specific entry interface and initial foothold method; (2) Initial Access asset name, exploitation tactic, and how persistence is achieved; (3) lateral movement path with protocol names (CAN, LIN, Ethernet, UDS) and intermediate ECUs; (4) final impact on target asset with concrete consequences (e.g., 'sends fraudulent UDS DiagnosticSessionControl frames to BCM, unlocking all doors without key'); (5) structural plausibility and attacker capability requirements.",
        "entry_point_assessment": "Specific interface name (e.g., 'Bluetooth Low Energy 4.2 stack on TCU'), its attack surface exposure, authentication weaknesses, and why this attack mode can reach it.",
        "attack_objective": "Precise objective: which asset is compromised, which function is affected, and what the attacker gains or causes (e.g., 'Gain unauthorized physical access by unlocking all doors via injected BCM CAN frames without triggering the immobilizer').",
        "critical_assets": ["asset names from input only"],
        "key_threat_ids": ["threat IDs from input only"],
        "dominant_tactics": ["tactics from input only — UKC phase names"],
        "risk_score": 0,
        "structural_plausibility": "high|medium|low",
        "confidence": "high|medium|low",
        "recommendations": [
          "Specific actionable recommendation with technology and standard (e.g., 'Deploy AUTOSAR SecOC message authentication on all CAN frames between Gateway and BCM using AES-128 CMAC per ISO 17987-7').",
          "Second specific recommendation."
        ],
        "required_equipment": [
          "Exact product: HackRF One (1 MHz–6 GHz SDR) for RF entry vector replay attacks at 315/433/868 MHz",
          "Exact product: Vector CANalyzer 17.0 with CANdb++ for CAN frame injection and monitoring",
          "Exact product: ELM327 v2.2 OBD-II adapter with python-obd library for UDS diagnostic session abuse"
        ]
      }},
      {{
        "path_id": "P2",
        "phase_sequence": "...", "phase_validity": {{"has_entry": true, "has_in": true, "has_through": true, "has_out": true, "sequence_is_logical": true}},
        "narrative": "...", "entry_point_assessment": "...", "attack_objective": "...",
        "critical_assets": [], "key_threat_ids": [], "dominant_tactics": [],
        "risk_score": 0, "structural_plausibility": "high|medium|low", "confidence": "high|medium|low",
        "recommendations": ["..."], "required_equipment": ["..."]
      }}
    ],
    "common_attack_patterns": "Minimum 3 complete sentences describing: (1) recurring attacker entry vectors and why they are consistently viable, (2) common IVN protocol weaknesses exploited across multiple paths, (3) systemic architectural vulnerabilities that span multiple ECUs.",
    "highest_risk_path_id": "P1",
    "systemic_weaknesses": [
      "Complete sentence describing one specific systemic weakness (e.g., 'The CAN bus lacks message authentication, allowing any ECU with CAN access to inject arbitrary frames targeting safety-critical actuators').",
      "Complete sentence for second weakness."
    ],
    "data_quality_assessment": "One complete sentence assessing whether the input data is sufficient for high-confidence analysis."
  }}
}}
FINAL RULES:
- path_reviews MUST contain MINIMUM 10 entries ordered by risk_score descending.
- Every text field: complete grammatical sentences. Never truncate. Never use "..." as content.
- Do not treat the examples as the only acceptable content or simply restate their wording. They are illustrative examples only. Use their format and level of specificity as guidance, and write the output as rigorously and precisely as possible based on the actual input data."""

    def run(self, summary: dict) -> dict:
        summary_str = self._json.dumps(summary, ensure_ascii=False, indent=2)

        self._log("[AGENT-1] Turn 1 — generating vehicle-level review...")
        result = self.send_and_parse(
            "Analyze the following attack graph JSON and produce a complete "
            "vehicle-level review per your role instructions:\n\n" + summary_str
        )

        self._log("[AGENT-1] Turn 2 — self-validating output...")
        validated = self.send_and_parse(
            "Review your previous JSON output against these criteria:\n"
            "1. path_reviews has MINIMUM 10 entries.\n"
            "2. path_reviews are ordered by risk_score DESCENDING (highest first).\n"
            "3. Every narrative/summary/assessment field contains only complete "
            "grammatical sentences — no truncation, no '...' placeholders.\n"
            "4. recommendations has ≥ 2 specific entries per path.\n"
            "5. required_equipment has ≥ 3 exact tool names per path.\n"
            "6. All path_ids, asset names, threat IDs reference input data only.\n\n"
            "If issues found: output the fully corrected JSON.\n"
            "If everything is correct: output the same JSON unchanged.\n"
            "Output valid JSON only. No markdown fences."
        )
        self._log("[AGENT-1] Vehicle-level review complete.")
        return validated


class FunctionalLevelGeneratorAgent(_AutosecBaseAgent):

    SYSTEM_PROMPT = """\
You are a senior automotive cybersecurity researcher performing ISO/SAE 21434 Clause 15 function-level TARA. You generate technically rigorous, component-specific threat scenarios with precise CVE exploitation analysis and detailed attack trees.

=== ANTI-HALLUCINATION — HIGHEST PRIORITY ===
- Asset names and threat IDs: ONLY values present verbatim in the input JSON.
- CVE IDs in cve_refs: ONLY CVE IDs that appear in the asset "cves" array in the input JSON. NEVER invent CVE numbers.
- If you must infer something not in the input, mark it (Inferred) and explain the basis.

=== GENERATION RULES ===
1. ALL affected_function_name values MUST be UNIQUE across every scenario. No two scenarios may share the same function name.
2. Name functions with maximum specificity by explicitly referencing the ECU, protocol, and attack vector (e.g., "TCU Bluetooth RFCOMM Stack Buffer Overflow via CVE-2021-22779 Enabling BCM Command Injection" rather than "TCU Communication"). Any CVE included in the function name must be a real and accurate identifier that actually exists, not a placeholder or invented number. In addition to the example above, other applicable CVEs may be used whenever they are relevant to the scenario. Use diverse and scenario-appropriate CVEs whenever possible to maximize specificity and variation across generated functions.
3. Generate ONE scenario per unique combination of (source_vehicle_path_id × cybersecurity_goal × affected_function). Cover ALL meaningful combinations.
4. MINIMUM 10 scenarios — generate as many as the input data supports. More is always better.
5. Order scenarios by combined SFOP impact DESCENDING (most severe first).
6. COMPLETE SENTENCES: Every narrative field (functional_impact, attack_narrative, damage_scenario) must be full grammatical sentences. Minimum lengths enforced below.

=== CVE EXPLOITATION ANALYSIS (MANDATORY) ===
For each scenario, examine the "cves" array of every source_asset in the input.
- Include ALL CVEs from those assets that are relevant to this attack scenario in cve_refs[].
- For each CVE entry provide:
  * cve_id: exact CVE identifier (e.g., CVE-2013-2802, CVE-2020-3566)
  * affected_component: specific component name and version if known (e.g., "Schneider Electric Modicon M340 firmware v3.20 — PLC web server")
  * vulnerability_description: exact technical description — CWE type, vulnerable function/service, root cause (e.g., "Stack-based buffer overflow in the HTTP request parsing routine of the embedded web server due to missing bounds check on the Content-Length header (CWE-121)")
  * exploitation_in_attack: step-by-step exploitation mechanics in this specific attack path (e.g., "Attacker sends crafted HTTP POST request with oversized Content-Length to port 80 of TCU web interface → triggers buffer overflow in http_parse_request() → overwrites return address with shellcode pointer → achieves arbitrary code execution on TCU ARM Cortex-M4 processor → installs CAN frame injector payload")
  * cvss_severity: Critical (9.0–10.0) | High (7.0–8.9) | Medium (4.0–6.9) | Low (0.1–3.9)
  * cvss_score: numeric score if known, else "unknown"
- If source assets have no CVEs in the input, set cve_refs to [] and note "(No CVEs in input for these assets)" in inferences_made.

=== FEASIBILITY SCORING (ISO 21434 Annex B) ===
Score each sub-step and compute overall:
- Elapsed Time (ET): ≤1 day=0, ≤1 week=1, ≤2 weeks=2, ≤1 month=3, ≤3 months=4, ≤6 months=5
- Specialist Expertise (SE): layman=0, proficient=2, expert=4, multiple experts=6
- Knowledge of Item (KoI): public=0, restricted=3, confidential=5, strictly confidential=7
- Window of Opportunity (WoO): unlimited=0, easy=1, moderate=4, difficult=10
- Equipment (Eq): standard=0, specialized=1, bespoke=2, multiple bespoke=3
- Total: 0–9=High, 10–13=Medium, 14–19=Low, 20+=Very Low

=== IMPACT RATING (ISO 21434 Annex H) ===
Rate Safety, Financial, Operational, Privacy independently:
- Negligible: No physical harm; financial loss < €1k; minor service degradation; no personal data exposure
- Moderate: Minor injury; financial loss €1k–€10k; reduced service quality; personal data of limited group exposed
- Major: Severe injury (hospitalization); financial loss €10k–€1M; significant service disruption; personal data of many exposed
- Severe: Life-threatening injury or death; financial loss > €1M; complete service failure; sensitive personal data mass exposure

=== REQUIRED EQUIPMENT SPECIFICITY ===
The tools listed below are illustrative examples only and must not unduly constrain the output. If more accurate, technically appropriate, and practically usable equipment exists for the relevant interface, protocol, CVE, or attack step, select that equipment instead.
List 3–6 tools per scenario with EXACT product names. Match tools to the specific interfaces and CVEs:
- CAN/LIN: Vector CANalyzer 17.0, python-can 4.x + PEAK PCAN-USB Pro, Kvaser Leaf Light v2, socketcand, Wireshark with SocketCAN plugin
- RF/Wireless: HackRF One (1 MHz–6 GHz), YARD Stick One (Sub-GHz), rtl-sdr v3 dongle, GNU Radio Companion 3.10, Proxmark3 RDV4
- OBD-II/UDS: ELM327 v2.2 OBD adapter, CANdela Studio (Vector), J2534 PassThru device (Drew Technologies MongoosePro), python-uds, OpenXC Vehicle Interface
- TCP/IP: Metasploit Framework 6.3, Burp Suite Pro 2023, nmap 7.94, Wireshark 4.2, scapy 2.5
- JTAG/UART/SWD: Segger J-Link EDU Mini, ST-Link V3, Bus Pirate v4, JTAGulator, Saleae Logic 8, CP2102 USB-UART
- Firmware: Binwalk 2.4, Ghidra 11.0, IDA Pro 8.3, flashrom 1.3, OpenOCD 0.12, strings/hexdump
- Bluetooth/BLE: Ubertooth One, btlejuice, nRF Sniffer for Bluetooth LE, gattacker, Wireshark HCI capture


OUTPUT — valid JSON only, no markdown fences:
{{
  "functional_level_analysis": {{
    "target_asset": "...",
    "analysis_methodology": "ISO/SAE 21434 Clause 15 function-level TARA — CVE-based component attack trees with SFOP impact rating",
    "summary_narrative": "Minimum 8 complete sentences covering: (1) which specific ECU functions are at highest risk and why; (2) which CVEs from the asset inventory are most critical and what vulnerabilities they represent; (3) how this functional-level analysis differs from and deepens the vehicle-level view; (4) the highest-risk scenario and its specific attack chain; (5) novel attack surfaces discovered beyond the static threat library; (6) cross-scenario patterns in vulnerability types (e.g., consistent lack of authentication on CAN); (7) lifecycle implications — which vulnerabilities require immediate OTA patching vs architectural redesign; (8) overall security posture and recommended priority remediation order.",
    "functional_scenarios": [
      {{
        "scenario_id": "FS-001",
        "source_vehicle_path_ids": ["P1"],
        "source_threat_ids": ["threat IDs from input only"],
        "source_assets": ["asset names from input only"],
        "is_novel_finding": false,
        "novel_finding_description": "",
        "affected_function_category": "Access Control|Propulsion Control|Communication|Safety Systems|Infotainment|Diagnostics",
        "affected_function_name": "Specific function name with ECU, protocol, and CVE reference where applicable",
        "cybersecurity_goal": "Confidentiality|Integrity|Availability",
        "component_details_used": {{
          "hardware": "Specific hardware component (e.g., 'NXP MPC5748G microcontroller in TCU')",
          "software": "Specific software/firmware (e.g., 'AUTOSAR BSW stack v4.3 with lwIP 2.1.2 TCP/IP stack')",
          "interfaces": "Specific interfaces (e.g., 'Bluetooth 4.2 LE + CAN 2.0B at 500 kbps + UART debug port')",
          "asset_kind": "...",
          "cwe_refs": [
            {{"id": "CWE-121", "name": "Stack-based Buffer Overflow", "exploited_in_step": "S1 — overflow triggered in http_parse_request() enabling arbitrary code execution"}}
          ]
        }},
        "cve_refs": [
          {{
            "cve_id": "CVE-YYYY-NNNNN",
            "affected_component": "Specific component name and firmware version",
            "vulnerability_description": "Technical description: CWE type, vulnerable function, root cause, and scope of impact",
            "exploitation_in_attack": "Step-by-step: attacker sends [specific payload/frame] to [specific interface/port] → triggers [specific vulnerability in named function] → achieves [specific result: code execution/authentication bypass/data leak] → enables [next attack step]",
            "cvss_severity": "Critical|High|Medium|Low",
            "cvss_score": "9.8 or unknown",
            "source": "hierarchy_data_automotive.json"
          }}
        ],
        "attack_tree": {{
          "root_goal": "Specific attacker goal with target ECU and consequence",
          "logical_structure": "AND|OR",
          "sub_steps": [
            {{
              "step_id": "S1",
              "description": "Specific atomic step — e.g., 'Send crafted UDS 0x27 SecurityAccess request with brute-forced seed/key pair to bypass TCU authentication (exploiting CVE-2021-22779 missing rate-limit)'",
              "logical_operator": "AND|OR",
              "cve_exploited": "CVE-YYYY-NNNNN or empty string",
              "cwe_exploited": "CWE-XXX or empty string",
              "feasibility_scores": {{"elapsed_time": 0, "specialist_expertise": 0, "knowledge_of_item": 0, "window_of_opportunity": 0, "equipment": 0, "total": 0, "rating": "High|Medium|Low|Very Low"}},
              "child_steps": []
            }}
          ]
        }},
        "functional_impact": "Minimum 4 complete sentences: (1) explicitly state exactly which vehicle function is degraded or compromised by name; (2) describe the specific operational consequence for the driver, occupant, or infrastructure (e.g., 'all door locks actuate simultaneously regardless of vehicle speed or driver input'); (3) explain in detail what cascading abnormal behavior this functional compromise could trigger in other ECUs, control logic, or connected functions of the vehicle; (4) explain what final safety-related failure state this functional compromise could lead to, and whether it could result in hazardous behavior or an ASIL-related issue from the perspective of ISO 26262.",
        "attack_narrative": "Minimum 6 complete sentences: (1) describe the attacker's starting position and required initial capability (e.g., 'the attacker is within 10 meters of the vehicle with a laptop running custom BLE scanning software'); (2) explicitly identify the real vulnerability exploited at the Entry/In phase using an actual CVE-YYYY-NNNNN identifier, and explain with technical detail how that CVE is abused within the attack path to achieve initial access, privilege gain, or code execution (e.g., 'the attacker exploits CVE-2021-39298 in the TCU by sending crafted network input, achieves remote code execution, and uses the compromised unit as an initial foothold for movement into the in-vehicle network'); if no directly applicable CVE exists for that step, describe the relevant threat or attack method in as much technical detail as possible (e.g., 'the attacker abuses an exposed UDS diagnostic service and a weak seed-key implementation to bypass security access and enter the BCM diagnostic session without authorization'); (3) describe the UKC Through technique with protocol and frame-level specifics (e.g., 'injects CAN ID 0x18DA00F1 UDS frames at 500 kbps targeting the BCM diagnostic session'); (4) describe the exact command or payload used in the final target exploitation and its outcome; (5) describe the resulting functional failure and how it manifests in the real world; (6) describe detectability — whether IDS, logging, or backend monitoring would detect the attack, and why or why not.",
        "damage_scenario": "Minimum 4 complete sentences: (1) describe the specific failure mode with technical detail (e.g., 'the BCM firmware is corrupted, causing all door locks, windows, and interior lights to remain unresponsive until the ECU is reflashed at a service center'); (2) describe the quantified physical, financial, and reputational harm; (3) explicitly identify whether this damage scenario affects one or more CIA properties (Confidentiality, Integrity, Availability), and explain specifically why each affected property is impacted; (4) describe the lifecycle-wide and fleet-wide impact if the vulnerability remains unpatched.",
        "overall_feasibility_rating": "High|Medium|Low|Very Low",
        "overall_feasibility_score": 0,
        "safety_impact": "Negligible|Moderate|Major|Severe",
        "financial_impact": "Negligible|Moderate|Major|Severe",
        "operational_impact": "Negligible|Moderate|Major|Severe",
        "privacy_impact": "Negligible|Moderate|Major|Severe",
        "cybersecurity_requirements": [
          "CSR-001: Implement UDS SecurityAccess rate-limiting — maximum 3 failed authentication attempts before 60-second lockout (addresses CVE-YYYY-NNNNN).",
          "CSR-002: Enable AUTOSAR SecOC message authentication on CAN ID 0x18DA00F1 with AES-128 CMAC and 24-bit freshness counter."
        ],
        "recommended_mitigations": [
          "Apply vendor patch for CVE-YYYY-NNNNN via OTA update within 30 days — update TCU firmware to version X.Y.Z.",
          "Deploy CAN intrusion detection system (e.g., Argus Cyber Security IDS) monitoring for anomalous UDS frame sequences targeting BCM."
        ],
        "confidence": "high|medium|low",
        "inferences_made": ["(Inferred) Specific inference with reasoning — e.g., '(Inferred) TCU runs lwIP stack based on firmware strings; actual version unconfirmed'"],
        "required_equipment": [
          "HackRF One (1 MHz–6 GHz SDR) for Bluetooth sniffing and replay at 2.4 GHz",
          "Vector CANalyzer 17.0 with AUTOSAR add-on for CAN ID 0x18DA00F1 frame injection",
          "python-uds library with ELM327 v2.2 for UDS SecurityAccess brute-force scripting"
        ]
      }},
      {{
        "scenario_id": "FS-002",
        "source_vehicle_path_ids": ["P1", "P2"], "source_threat_ids": [], "source_assets": [],
        "is_novel_finding": false, "novel_finding_description": "",
        "affected_function_category": "...", "affected_function_name": "...", "cybersecurity_goal": "Confidentiality|Integrity|Availability",
        "component_details_used": {{"hardware": "...", "software": "...", "interfaces": "...", "asset_kind": "...", "cwe_refs": []}},
        "cve_refs": [{{"cve_id": "CVE-YYYY-NNNNN", "affected_component": "...", "vulnerability_description": "...", "exploitation_in_attack": "...", "cvss_severity": "High", "cvss_score": "unknown", "source": "hierarchy_data_automotive.json"}}],
        "attack_tree": {{"root_goal": "...", "logical_structure": "AND|OR", "sub_steps": []}},
        "functional_impact": "...", "attack_narrative": "...", "damage_scenario": "...",
        "overall_feasibility_rating": "High|Medium|Low|Very Low", "overall_feasibility_score": 0,
        "safety_impact": "Negligible|Moderate|Major|Severe", "financial_impact": "Negligible|Moderate|Major|Severe",
        "operational_impact": "Negligible|Moderate|Major|Severe", "privacy_impact": "Negligible|Moderate|Major|Severe",
        "cybersecurity_requirements": [], "recommended_mitigations": [],
        "confidence": "high|medium|low", "inferences_made": [],
        "required_equipment": ["3–6 specific tools with exact product names for this scenario"]
      }}
    ],
    "cross_scenario_insights": "Minimum 3 complete sentences: (1) which CVE IDs or CWE types appear across multiple scenarios indicating systemic vulnerability patterns; (2) which ECUs are most frequently targeted and why their architectural position makes them high-value; (3) recommended priority sequence for remediation based on combined impact and exploitability.",
    "priority_mitigation_plan": "Minimum 3 complete sentences: (1) immediate actions — CVEs requiring OTA patch within 30 days with specific firmware version targets; (2) medium-term architectural mitigations — authentication protocols, network segmentation, or ECU replacement timelines; (3) long-term monitoring requirements — IDS rules, logging requirements, and penetration testing cadence.",
    "lifecycle_considerations": "Minimum 2 complete sentences: (1) which CVEs require urgent OTA patching due to active exploitation risk and fleet-wide exposure; (2) which vulnerabilities require ECU hardware revision or end-of-life planning.",
    "novel_attack_surfaces_summary": "",
    "priority_threat_ids": []
  }}
}}
FINAL RULES:
1. functional_scenarios[] MINIMUM 10 entries, ordered by combined SFOP impact DESCENDING.
2. cve_refs[]: ONLY CVEs present in the asset "cves" field of the input JSON. NEVER invent CVE IDs.
3. recommended_mitigations must reference specific CVE IDs, CWE IDs, or AUTOSAR standards where applicable.
4. Every text field: COMPLETE grammatical sentences. Never truncate mid-word or use "..." as content.
5. affected_function_name values must ALL be UNIQUE across the entire scenarios array.
6. Do not treat the examples as the only acceptable content or simply restate their wording. They are illustrative examples only. Use their format and level of specificity as guidance, and write the output as rigorously and precisely as possible based on the actual input data."""

    def run(self, summary: dict, vehicle_review: dict, additional_info: str = "") -> dict:

        vr_str = self._json.dumps(vehicle_review, ensure_ascii=False, indent=2)
        if len(vr_str) > 12000:
            vr_inner = vehicle_review.get("vehicle_level_review", vehicle_review)
            vr_str = self._json.dumps({
                "target_asset":           vr_inner.get("target_asset", ""),
                "overall_summary":        vr_inner.get("overall_summary", ""),
                "path_reviews":           vr_inner.get("path_reviews", [])[:10],
                "common_attack_patterns": vr_inner.get("common_attack_patterns", ""),
                "highest_risk_path_id":   vr_inner.get("highest_risk_path_id", ""),
                "systemic_weaknesses":    vr_inner.get("systemic_weaknesses", []),
            }, ensure_ascii=False, indent=2)
        sum_str = self._json.dumps(summary, ensure_ascii=False, indent=2)


        self._log("[AGENT-2] Turn 1 — generating functional-level scenarios...")
        result = self.send_and_parse(
            "Generate functional-level threat scenarios based on the following inputs.\n\n"
            "=== Vehicle-Level Review (from Agent-1) ===\n" + vr_str + "\n\n"
            "=== Attack Graph + Asset Details (includes cves[] and cwes[] per asset) ===\n"
            + sum_str + "\n\n"
            "=== Additional System Context ===\n"
            + (additional_info or "None provided.")
        )


        self._log("[AGENT-2] Turn 2 — self-validating scenarios...")
        validated = self.send_and_parse(
            "Review your previous JSON output against these criteria:\n"
            "1. ALL affected_function_name values are UNIQUE — no two scenarios share "
            "the same name.\n"
            "2. functional_scenarios has MINIMUM 10 entries.\n"
            "3. Scenarios are ordered by combined SFOP impact DESCENDING.\n"
            "4. All cve_refs[] contain ONLY CVE IDs present in the input 'cves' arrays "
            "— never invented.\n"
            "5. functional_impact, attack_narrative, damage_scenario fields contain only "
            "complete grammatical sentences with no truncation.\n"
            "6. cybersecurity_requirements and recommended_mitigations each have ≥ 2 "
            "entries per scenario.\n\n"
            "If issues found: output the fully corrected JSON.\n"
            "If everything is correct: output the same JSON unchanged.\n"
            "Output valid JSON only. No markdown fences."
        )
        self._log("[AGENT-2] Functional-level scenarios complete.")
        return validated



class FullResultWindow(tk.Toplevel):
    def __init__(self, parent, mapping, multi_paths, out_json, out_csv, attack_graph_png=None, report_html_path=None, gemini_analysis_path=None):
        super().__init__(parent)
        self.title("Results")
        self.geometry("1320x900")
        _center(self, 1320, 900)
        self.configure(bg="white")


        _s = ttk.Style(self)
        _s.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        _s.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        self._attack_graph_png = attack_graph_png
        self._report_html_path = report_html_path
        self._attack_graph_img = None
        self._attack_graph_src_pil = None


        self._gemini_data = None
        if gemini_analysis_path and Path(gemini_analysis_path).exists():
            try:
                with open(gemini_analysis_path, encoding="utf-8") as f:
                    self._gemini_data = json.load(f)
            except Exception:
                self._gemini_data = None

        self._graph_states = {
            "asset_tab": {
                "zoom": 1.0,
                "fit_scale": 1.0,
                "canvas": None,
                "canvas_img_id": None,
                "after_id": None,
            },
            "path_tab": {
                "zoom": 1.0,
                "fit_scale": 1.0,
                "canvas": None,
                "canvas_img_id": None,
                "after_id": None,
            },
        }

        self._build(mapping, multi_paths, out_json, out_csv)

    def _build_attack_graph_panel(self, parent, state_key: str):
        graph_frame = tk.LabelFrame(
            parent,
            text=" Attack Graph ",
            font=("Arial", 9, "bold"),
            bg="white",
            fg="#555",
            bd=1,
            relief="solid"
        )
        graph_frame.pack(fill="x", padx=4, pady=(4, 4))

        topbar = tk.Frame(graph_frame, bg="white")
        topbar.pack(fill="x", padx=8, pady=(6, 2))

        def _open_graph():
            try:
                import os
                os.startfile(self._attack_graph_png)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self)

        tk.Label(
            topbar,
            text="Scroll: zoom  |  Double-click: fit to width",
            font=("Arial", 8),
            fg="#666",
            bg="white"
        ).pack(side="left")

        tk.Button(
            topbar,
            text="Open Image",
            font=("Arial", 8, "bold"),
            relief="flat",
            bg="#1565C0",
            fg="white",
            padx=10,
            pady=3,
            cursor="hand2",
            command=_open_graph
        ).pack(side="right")

        canvas_wrap = tk.Frame(graph_frame, bg="white")
        canvas_wrap.pack(fill="both", expand=True, padx=8, pady=(2, 8))

        xsb = ttk.Scrollbar(canvas_wrap, orient="horizontal")
        ysb = ttk.Scrollbar(canvas_wrap, orient="vertical")
        canvas = tk.Canvas(
            canvas_wrap,
            bg="white",
            highlightthickness=0,
            xscrollcommand=xsb.set,
            yscrollcommand=ysb.set,
            height=260
        )
        xsb.config(command=canvas.xview)
        ysb.config(command=canvas.yview)

        ysb.pack(side="right", fill="y")
        xsb.pack(side="bottom", fill="x")
        canvas.pack(side="left", fill="both", expand=True)

        st = self._graph_states[state_key]
        st["canvas"] = canvas
        st["canvas_img_id"] = canvas.create_image(0, 0, anchor="nw")

        canvas.bind("<Configure>", lambda e, k=state_key: self._on_graph_canvas_configure(k))
        canvas.bind("<MouseWheel>", lambda e, k=state_key: self._on_graph_mousewheel(e, k))
        canvas.bind("<Button-4>", lambda e, k=state_key: self._on_graph_mousewheel(e, k))
        canvas.bind("<Button-5>", lambda e, k=state_key: self._on_graph_mousewheel(e, k))
        canvas.bind("<Double-Button-1>", lambda e, k=state_key: self._on_graph_double_click(k))

        self.after(50, lambda k=state_key: self._fit_graph_to_width(k))

    def _build(self, mapping, multi_paths, out_json, out_csv):
        hdr = tk.Frame(self, bg="#1C2333")
        hdr.pack(fill="x")
        tk.Label(
            hdr,
            text=f"{len(mapping)} Assets  | {len(multi_paths)} attack paths",
            font=("Arial", 11, "bold"),
            fg="white",
            bg="#1C2333",
            pady=8
        ).pack(side="left", padx=14)
        tk.Label(
            hdr,
            text=f"{Path(out_json).name}  /  {Path(out_csv).name}",
            font=("Arial", 8),
            fg="#8899AA",
            bg="#1C2333"
        ).pack(side="right", padx=12)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=4)

        if self._attack_graph_png and Path(self._attack_graph_png).exists() and _PIL_OK:
            try:
                self._attack_graph_src_pil = Image.open(self._attack_graph_png).convert("RGBA")
            except Exception:
                self._attack_graph_src_pil = None

        tab1 = tk.Frame(nb, bg="white")
        nb.add(tab1, text="Asset Mapping")

        if self._attack_graph_png and Path(self._attack_graph_png).exists():
            if not _PIL_OK:
                graph_frame = tk.LabelFrame(
                    tab1,
                    text=" Attack Graph ",
                    font=("Arial", 9, "bold"),
                    bg="white",
                    fg="#555",
                    bd=1,
                    relief="solid"
                )
                graph_frame.pack(fill="x", padx=4, pady=(4, 4))
                tk.Label(
                    graph_frame,
                    text="Pillow is not installed. Image preview unavailable.\nRun: pip install pillow",
                    font=("Arial", 9),
                    fg="#C62828",
                    bg="white",
                    pady=10,
                    justify="center"
                ).pack()
            elif self._attack_graph_src_pil is not None:
                self._build_attack_graph_panel(tab1, "asset_tab")
            else:
                graph_frame = tk.LabelFrame(
                    tab1,
                    text=" Attack Graph ",
                    font=("Arial", 9, "bold"),
                    bg="white",
                    fg="#555",
                    bd=1,
                    relief="solid"
                )
                graph_frame.pack(fill="x", padx=4, pady=(4, 4))
                tk.Label(
                    graph_frame,
                    text="The “Attack Graph” image could not be loaded.",
                    font=("Arial", 9),
                    fg="#C62828",
                    bg="white",
                    pady=10
                ).pack()

        save_bar = tk.Frame(tab1, bg="#F8F8F8")
        save_bar.pack(fill="x", padx=4, pady=(4, 0))
        tk.Label(
            save_bar, text="Threat Mapping Results", font=("Arial", 9),
            bg="#F8F8F8", fg="#555"
        ).pack(side="left", padx=8, pady=4)

        def _save_mapping_json():
            p = filedialog.asksaveasfilename(
                title="Save Threat Mapping JSON",
                defaultextension=".json",
                filetypes=[("JSON","*.json"),("All","*.*")],
                initialfile=f"threat_mapping_{datetime.now():%Y%m%d_%H%M%S}.json"
            )
            if not p:
                return
            meta = {
                "tm7": self.master.v_tm7.get() if hasattr(self.master, "v_tm7") else "",
                "mode": self.master.v_mode.get() if hasattr(self.master, "v_mode") else "",
                "target": self.master.v_target.get() if hasattr(self.master, "v_target") else ""
            }
            with open(p, "w", encoding="utf-8") as f:
                json.dump(build_result_json(mapping, meta), f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Saved", p, parent=self)

        def _save_mapping_csv():
            p = filedialog.asksaveasfilename(
                title="Save Threat Mapping CSV",
                defaultextension=".csv",
                filetypes=[("CSV","*.csv"),("All","*.*")],
                initialfile=f"threat_mapping_{datetime.now():%Y%m%d_%H%M%S}.csv"
            )
            if not p:
                return
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(build_result_csv(mapping))
            messagebox.showinfo("Saved", p, parent=self)

        def _open_report_html():
            if not self._report_html_path:
                messagebox.showinfo(
                    "Info",
                    "Generated report HTML path is empty.",
                    parent=self
                )
                return

            if not Path(self._report_html_path).exists():
                messagebox.showinfo(
                    "Info",
                    f"Generated report HTML file not found.\n\nPath:\n{self._report_html_path}",
                    parent=self
                )
                return

            try:
                import os
                os.startfile(self._report_html_path)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self)

        bkw2 = dict(font=("Arial",9,"bold"), relief="flat", bd=0, padx=12, pady=4, cursor="hand2")
        tk.Button(
            save_bar, text="Save JSON", bg="#1565C0", fg="white",
            command=_save_mapping_json, **bkw2
        ).pack(side="left", padx=4, pady=3)
        tk.Button(
            save_bar, text="Save CSV", bg="#2E7D32", fg="white",
            command=_save_mapping_csv, **bkw2
        ).pack(side="left", padx=2, pady=3)
        tk.Button(
            save_bar, text="Open Report", bg="#6D4C41", fg="white",
            command=_open_report_html, **bkw2
        ).pack(side="left", padx=2, pady=3)

        paned = ttk.PanedWindow(tab1, orient="vertical")
        paned.pack(fill="both", expand=True, padx=0, pady=0)

        top_frame = tk.Frame(paned, bg="white")
        paned.add(top_frame, weight=3)

        cols1 = ("Type","Name","Phase","Category","Asset Kind","Properties","CWE","Threats")
        t1 = ttk.Treeview(top_frame, columns=cols1, show="headings")
        for c, w in zip(cols1, [55,200,65,110,170,60,55,55]):
            t1.heading(c, text=c)
            t1.column(
                c,
                width=w,
                anchor="center" if c in ["Type","Phase","CWE","Threats","Properties"] else "w"
            )
        s1 = ttk.Scrollbar(top_frame, orient="vertical", command=t1.yview)
        t1.configure(yscrollcommand=s1.set)
        s1.pack(side="right", fill="y")
        t1.pack(fill="both", expand=True)

        for tag, bg in [("n_in","#F3FFF5"),("n_thr","#FFFCF0"),
                        ("n_out","#FFF3F3"),("n_ent","#F6F6F6"),("edge","#EEF4FF")]:
            t1.tag_configure(tag, background=bg)
        ph_tag = {"In":"n_in","Through":"n_thr","Out":"n_out","Entry":"n_ent"}

        for m in mapping:
            n_p = len(m.get("asset_properties") or [])
            etype = m.get("type", "node")
            ph = m.get("phase", "")
            tag = "edge" if etype == "edge" else ph_tag.get(ph, "n_ent")
            cats = m.get("categories") or []
            if cats:
                first = cats[0] if isinstance(cats[0], dict) else {}
                cat_disp = first.get("category") or m.get("category") or "—"
                kind_disp = first.get("asset_kind") or m.get("asset_kind") or "—"
                if len(cats) > 1:
                    cat_disp = f"{cat_disp} (+{len(cats)-1})"
                    kind_disp = f"{kind_disp} (+{len(cats)-1})"
            else:
                cat_disp = m.get("category") or "—"
                kind_disp = m.get("asset_kind") or "—"
            t1.insert("", "end", values=(
                "NODE" if etype == "node" else "EDGE",
                m["name"][:50], ph,
                cat_disp,
                kind_disp,
                f"{n_p}" if n_p else "—",
                m["cwe_count"],
                m["threat_count"],
            ), tags=(tag,))

        bot_frame = tk.Frame(paned, bg="white")
        paned.add(bot_frame, weight=2)

        nb2 = ttk.Notebook(bot_frame)
        nb2.pack(fill="both", expand=True, padx=2, pady=2)

        tab_c = tk.Frame(nb2)
        nb2.add(tab_c, text="CWE")
        dt1 = ttk.Treeview(tab_c, columns=("ID","Weakness Name","Description"), show="headings")
        dt1.column("ID", width=85, anchor="center")
        dt1.column("Weakness Name", width=300)
        dt1.column("Description", width=560)
        for c in ("ID", "Weakness Name", "Description"):
            dt1.heading(c, text=c)
        ds1 = ttk.Scrollbar(tab_c, orient="vertical", command=dt1.yview)
        dt1.configure(yscrollcommand=ds1.set)
        ds1.pack(side="right", fill="y")
        dt1.pack(fill="both", expand=True)

        tab_t = tk.Frame(nb2)
        nb2.add(tab_t, text="Threats")
        tt1 = ttk.Treeview(tab_t, columns=("TID","Threat Name","Tactic"), show="headings")
        tt1.column("TID", width=100, anchor="center")
        tt1.column("Threat Name", width=420)
        tt1.column("Tactic", width=200)
        for c in ("TID","Threat Name","Tactic"):
            tt1.heading(c, text=c)
        ts1 = ttk.Scrollbar(tab_t, orient="vertical", command=tt1.yview)
        tt1.configure(yscrollcommand=ts1.set)
        ts1.pack(side="right", fill="y")
        tt1.pack(fill="both", expand=True)

        def on_asset_sel(e):
            sel = t1.selection()
            if not sel:
                return
            m = mapping[t1.index(sel[0])]
            for r in dt1.get_children():
                dt1.delete(r)
            for r in tt1.get_children():
                tt1.delete(r)
            for cwe in m.get("cwes", []):
                dt1.insert("", "end", values=(
                    f"CWE-{cwe['id']}",
                    cwe.get("name","")[:70],
                    (cwe.get("desc","") or "")[:100],
                ))
            for th in m.get("threats", []):
                tacs = ",".join(th.get("tactics", []) or [th.get("tactic","—")])
                tt1.insert("", "end", values=(
                    th.get("tid","—"),
                    th.get("name","")[:70],
                    tacs[:60],
                ))
        t1.bind("<<TreeviewSelect>>", on_asset_sel)

        tab2 = tk.Frame(nb, bg="white")
        nb.add(tab2, text=f"Attack Paths  ({len(multi_paths)})")

        if self._attack_graph_png and Path(self._attack_graph_png).exists():
            if not _PIL_OK:
                graph_frame2 = tk.LabelFrame(
                    tab2,
                    text=" Attack Graph ",
                    font=("Arial", 9, "bold"),
                    bg="white",
                    fg="#555",
                    bd=1,
                    relief="solid"
                )
                graph_frame2.pack(fill="x", padx=4, pady=(4, 4))
                tk.Label(
                    graph_frame2,
                    text="Pillow is not installed. Image preview unavailable.\nRun: pip install pillow",
                    font=("Arial", 9),
                    fg="#C62828",
                    bg="white",
                    pady=10,
                    justify="center"
                ).pack()
            elif self._attack_graph_src_pil is not None:
                self._build_attack_graph_panel(tab2, "path_tab")
            else:
                graph_frame2 = tk.LabelFrame(
                    tab2,
                    text=" Attack Graph ",
                    font=("Arial", 9, "bold"),
                    bg="white",
                    fg="#555",
                    bd=1,
                    relief="solid"
                )
                graph_frame2.pack(fill="x", padx=4, pady=(4, 4))
                tk.Label(
                    graph_frame2,
                    text="The “Attack Graph” image could not be loaded.",
                    font=("Arial", 9),
                    fg="#C62828",
                    bg="white",
                    pady=10
                ).pack()

        self._mpaths = multi_paths

        paned2 = ttk.PanedWindow(tab2, orient="vertical")
        paned2.pack(fill="both", expand=True)

        top2 = tk.Frame(paned2, bg="white")
        paned2.add(top2, weight=3)
        bot2 = tk.Frame(paned2, bg="white")
        paned2.add(bot2, weight=2)

        pcols = ("Path ID", "Related Assets", "Threats", "Final Target", "Path Summary")
        self._t2 = ttk.Treeview(top2, columns=pcols, show="headings")
        for c, w in zip(pcols, [70, 320, 65, 200, 680]):
            self._t2.heading(c, text=c)
            self._t2.column(
                c, width=w,
                anchor="center" if c in ["Path ID", "Threats"] else "w"
            )
        ps = ttk.Scrollbar(top2, orient="vertical", command=self._t2.yview)
        self._t2.configure(yscrollcommand=ps.set)
        ps.pack(side="right", fill="y")
        self._t2.pack(fill="both", expand=True)

        dcols2 = ("UKC Phase", "Asset Name", "Threat ID", "Tactic", "Threat Name")
        self._dt2 = ttk.Treeview(bot2, columns=dcols2, show="headings")
        for c, w in zip(dcols2, [90, 220, 110, 180, 700]):
            self._dt2.heading(c, text=c)
            self._dt2.column(
                c, width=w,
                anchor="center" if c in ["UKC Phase", "Threat ID"] else "w"
            )
        ds2 = ttk.Scrollbar(bot2, orient="vertical", command=self._dt2.yview)
        self._dt2.configure(yscrollcommand=ds2.set)
        ds2.pack(side="right", fill="y")
        self._dt2.pack(fill="both", expand=True)

        for ph, fg in [("In","#1B5E20"),("Through","#E65100"),
                       ("Out","#C62828"),("Entry","#888888")]:
            self._dt2.tag_configure(ph, foreground=fg)
        self._reload_paths()

        def on_path_sel(e):
            sel = self._t2.selection()
            if not sel:
                return
            shown = self._shown_paths
            idx = int(self._t2.item(sel[0], "values")[0]) - 1
            if idx < 0 or idx >= len(shown):
                return
            p = shown[idx]
            for r in self._dt2.get_children():
                self._dt2.delete(r)
            for ci, c in enumerate(p.cycles):
                for n in c.nodes:
                    self._dt2.insert(
                        "", "end",
                        values=(n.ukc_phase,
                                n.asset_name, n.threat_id or "—",
                                n.tactic or "—", n.threat_name or "—"),
                        tags=(n.ukc_phase,)
                    )
        self._t2.bind("<<TreeviewSelect>>", on_path_sel)


        if self._gemini_data:
            ai_tab = tk.Frame(nb, bg="white")
            nb.add(ai_tab, text="AI Analysis")
            self._build_ai_tab(ai_tab)


    def _build_ai_tab(self, parent):

        banner = tk.Frame(parent, bg="#7B1FA2", pady=6)
        banner.pack(fill="x")
        tk.Label(
            banner,
            text="This attack path has been analyzed in detail using AI.",
            font=("Arial", 9, "bold"),
            fg="white",
            bg="#7B1FA2",
        ).pack(side="left", padx=12)

        nb_ai = ttk.Notebook(parent)
        nb_ai.pack(fill="both", expand=True, padx=6, pady=4)


        vl_tab = tk.Frame(nb_ai, bg="white")
        nb_ai.add(vl_tab, text="Vehicle-Level Review")
        self._build_vehicle_level_tab(vl_tab)

        fl_tab = tk.Frame(nb_ai, bg="white")
        nb_ai.add(fl_tab, text="Functional-Level Scenarios")
        self._build_functional_level_tab(fl_tab)

    def _build_vehicle_level_tab(self, parent):
        vr = self._gemini_data.get("vehicle_level_review") or {}
        if not vr:
            tk.Label(parent, text="No vehicle-level review data (API key not provided or error occurred).",
                     font=("Arial", 11), fg="#888", bg="white").pack(pady=40)
            return


        summary_frame = tk.LabelFrame(
            parent, text="  Overall Assessment Summary  ", font=("Arial", 9, "bold"),
            bg="#F3E5F5", fg="#4A148C", bd=2, relief="groove"
        )
        summary_frame.pack(fill="x", padx=8, pady=(8, 4))

        summary = vr.get("overall_summary", "") or vr.get("overall_summary_en", "") or vr.get("overall_summary_ko", "")
        highest = vr.get("highest_risk_path_id", "")
        patterns = vr.get("common_attack_patterns", "") or ""
        weaknesses = vr.get("systemic_weaknesses", [])

        meta_row = tk.Frame(summary_frame, bg="#F3E5F5")
        meta_row.pack(fill="x", padx=8, pady=(4, 0))
        if highest:
            tk.Label(meta_row, text=f"Highest Risk Path: {highest}",
                     font=("Arial", 9, "bold"), fg="#B71C1C", bg="#F3E5F5").pack(side="left", padx=4)
        conf = vr.get("overall_confidence", "")
        validity = vr.get("overall_validity", "")
        if conf or validity:
            tk.Label(meta_row, text=f"  |  Validity: {validity}  |  Confidence: {conf}",
                     font=("Arial", 9), fg="#4A148C", bg="#F3E5F5").pack(side="left")

        _vsf = tk.Frame(summary_frame, bg="#F3E5F5")
        _vsf.pack(fill="both", expand=True, padx=8, pady=(2,6))
        _vsc = ttk.Scrollbar(_vsf, orient="vertical")
        txt_summary = tk.Text(_vsf, height=7, wrap="word",
                              font=("Segoe UI", 9), bg="#F3E5F5", fg="#222",
                              relief="flat", bd=0, yscrollcommand=_vsc.set)
        _vsc.config(command=txt_summary.yview)
        _vsc.pack(side="right", fill="y")
        txt_summary.pack(side="left", fill="both", expand=True)
        txt_summary.insert("1.0", summary)
        txt_summary.config(state="disabled")



        if weaknesses:
            w_row = tk.Frame(summary_frame, bg="#FFF3E0")
            w_row.pack(fill="x", padx=8, pady=(0, 6))
            w_text = "  |  ".join(weaknesses[:3]) if isinstance(weaknesses, list) else str(weaknesses)[:200]
            tk.Label(w_row, text="Systemic Weaknesses: " + w_text,
                     font=("Arial", 8), fg="#E65100", bg="#FFF3E0", wraplength=900, justify="left"
                     ).pack(anchor="w", padx=4, pady=2)


        paned = ttk.PanedWindow(parent, orient="vertical")
        paned.pack(fill="both", expand=True, padx=6, pady=4)

        top_frame = tk.Frame(paned, bg="white")
        paned.add(top_frame, weight=2)
        bot_frame = tk.Frame(paned, bg="white")
        paned.add(bot_frame, weight=3)

        path_reviews = vr.get("path_reviews", []) or []

        import re as _re_pid
        def _pid_key(p):
            m = _re_pid.search(r"\d+", p.get("path_id","P0"))
            return int(m.group()) if m else 0
        path_reviews = sorted(path_reviews, key=_pid_key)

        cols = ("Path ID", "Confidence", "Narrative Summary")
        tv = ttk.Treeview(top_frame, columns=cols, show="headings", height=10)
        for c, w in zip(cols, [65, 80, 1400]):
            tv.heading(c, text=c)
            tv.column(c, width=w, minwidth=w, anchor="center" if c in ("Path ID","Confidence") else "w")
        tv.column("Narrative Summary", stretch=True)
        sc = ttk.Scrollbar(top_frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sc.set)
        sc.pack(side="right", fill="y")
        tv.pack(fill="both", expand=True)

        for pr in path_reviews:
            pid = pr.get("path_id", "—")
            conf = pr.get("confidence", "—")
            plaus = pr.get("structural_plausibility", "-") or "-"
            narr = pr.get("narrative", "") or pr.get("narrative_en", "") or pr.get("narrative_ko", "") or ""
            plaus_tag = {"high": "ok", "medium": "warn", "low": "err"}.get(plaus.lower(), "ok")
            def _complete(txt, maxlen=350):
                if not txt: return txt
                txt = txt[:maxlen]
                for sep in [". ", "! ", "? "]:
                    last = txt.rfind(sep)
                    if last > 40:
                        return txt[:last+1]
                return txt if txt[-1:] in ".!?" else ""
            tv.insert("", "end", values=(pid, conf, _complete(narr)), tags=(plaus_tag,))

        tv.tag_configure("ok", background="#F1F8E9")
        tv.tag_configure("warn", background="#FFF8E1")
        tv.tag_configure("err", background="#FFEBEE")


        detail_label = tk.Label(bot_frame, text="Click a path row to view detailed narrative",
                                 font=("Arial", 9), fg="#888", bg="white", pady=6)
        detail_label.pack()

        txt_detail = tk.Text(bot_frame, wrap="word", font=("Segoe UI", 9),
                             bg="#FAFAFA", fg="#222", relief="flat", bd=0,
                             padx=10, pady=8, state="disabled")
        sc2 = ttk.Scrollbar(bot_frame, orient="vertical", command=txt_detail.yview)
        txt_detail.configure(yscrollcommand=sc2.set)
        sc2.pack(side="right", fill="y")
        txt_detail.pack(fill="both", expand=True)

        txt_detail.tag_configure("h1", font=("Segoe UI", 11, "bold"), foreground="#4A148C", spacing3=4)
        txt_detail.tag_configure("h2", font=("Segoe UI", 10, "bold"), foreground="#1565C0", spacing1=4, spacing3=2)
        txt_detail.tag_configure("body", font=("Segoe UI", 9))
        txt_detail.tag_configure("ok_tag", foreground="#2E7D32", font=("Segoe UI", 9, "bold"))
        txt_detail.tag_configure("warn_tag", foreground="#E65100", font=("Segoe UI", 9, "bold"))
        txt_detail.tag_configure("err_tag", foreground="#C62828", font=("Segoe UI", 9, "bold"))
        txt_detail.tag_configure("sep", foreground="#CCCCCC")

        def on_select(e):
            sel = tv.selection()
            if not sel:
                return
            idx = tv.index(sel[0])
            if idx >= len(path_reviews):
                return
            pr = path_reviews[idx]

            detail_label.pack_forget()
            txt_detail.config(state="normal")
            txt_detail.delete("1.0", "end")

            pid = pr.get("path_id", "—")
            conf = pr.get("confidence", "—")
            txt_detail.insert("end", f"Path {pid}  —  Confidence: {conf}", "h1")
            txt_detail.insert("end", "\n" + "─" * 80 + "\n", "sep")


            seq = pr.get("phase_sequence", "")
            if seq:
                txt_detail.insert("end", f"\nPhase Sequence: {seq}\n", "body")


            narr = pr.get("narrative", "") or pr.get("narrative_en", "") or pr.get("narrative_ko", "") or ""
            if narr:
                txt_detail.insert("end", "\nAttack Path Narrative\n", "h2")
                txt_detail.insert("end", narr + "\n", "body")


            entry = pr.get("entry_point_assessment", "") or pr.get("entry_point_description", "") or ""
            if entry:
                txt_detail.insert("end", "\nEntry Point Assessment\n", "h2")
                txt_detail.insert("end", entry + "\n", "body")


            phase_val = pr.get("phase_validity", {}) or {}
            if phase_val:
                txt_detail.insert("end", "\nUKC Phase Validity\n", "h2")
                for ph, ok in phase_val.items():
                    tag_name = "ok_tag" if ok else "err_tag"
                    mark = "[OK]" if ok else "[FAIL]"
                    txt_detail.insert("end", f"  {mark} {ph}\n", tag_name)




            recs = pr.get("recommendations", []) or []
            if recs:
                txt_detail.insert("end", "\nRecommendations\n", "h2")
                for r in recs:
                    txt_detail.insert("end", f"  -> {r}\n", "body")


            obj = pr.get("attack_objective", "") or pr.get("attack_goal", "") or ""
            if obj:
                txt_detail.insert("end", "\nAttack Objective\n", "h2")
                txt_detail.insert("end", "  " + obj + "\n", "body")


            tactics = pr.get("dominant_tactics", []) or []
            if tactics:
                txt_detail.insert("end", "\nDominant Tactics\n", "h2")
                txt_detail.insert("end", "  " + ", ".join(tactics) + "\n", "body")

            txt_detail.config(state="disabled")

        tv.bind("<<TreeviewSelect>>", on_select)

    def _build_functional_level_tab(self, parent):
        fa = self._gemini_data.get("functional_level_analysis") or {}
        if not fa:
            tk.Label(parent, text="No functional-level scenarios available. Run analysis with a Gemini API key.",
                     font=("Arial", 11), fg="#888", bg="white").pack(pady=40)
            return

        scenarios = fa.get("functional_scenarios", []) or []


        summary_frame = tk.LabelFrame(
            parent, text="  Functional-Level Analysis Summary  ", font=("Arial", 9, "bold"),
            bg="#E3F2FD", fg="#0D47A1", bd=2, relief="groove"
        )
        summary_frame.pack(fill="x", padx=8, pady=(8, 4))

        summary_ko = fa.get("summary_narrative_ko", "") or ""
        summary_en = fa.get("summary_narrative_en", "") or ""
        summary_text = fa.get("summary_narrative", "") or summary_en or summary_ko

        _fsf = tk.Frame(summary_frame, bg="#E3F2FD")
        _fsf.pack(fill="both", expand=True, padx=8, pady=(4,6))
        _fsc = ttk.Scrollbar(_fsf, orient="vertical")
        txt_sum = tk.Text(_fsf, height=7, wrap="word",
                          font=("Segoe UI", 9), bg="#E3F2FD", fg="#222",
                          relief="flat", bd=0, yscrollcommand=_fsc.set)
        _fsc.config(command=txt_sum.yview)
        _fsc.pack(side="right", fill="y")
        txt_sum.pack(side="left", fill="both", expand=True)
        txt_sum.insert("1.0", summary_text)
        txt_sum.config(state="disabled")


        novel = fa.get("novel_attack_surfaces_summary", "")
        if novel:
            nrow = tk.Frame(summary_frame, bg="#E8F5E9")
            nrow.pack(fill="x", padx=8, pady=(0, 4))
            def _trim_complete(t, ml=400):
                import re as _r; t=t[:ml]
                for s in [". ","! ","? "]:
                    lp=t.rfind(s)
                    if lp>40: return t[:lp+1]
                return t if t[-1:] in ".!?" else ""
            novel_safe=_trim_complete(novel)
            if not novel_safe: nrow.destroy()
            else:
                tk.Label(nrow, text="Novel Findings: " + novel_safe,
                     font=("Arial", 8), fg="#1B5E20", bg="#E8F5E9", wraplength=1000, justify="left"
                     ).pack(anchor="w", padx=4, pady=2)


        paned = ttk.PanedWindow(parent, orient="vertical")
        paned.pack(fill="both", expand=True, padx=6, pady=4)

        top_f = tk.Frame(paned, bg="white")
        paned.add(top_f, weight=2)
        bot_f = tk.Frame(paned, bg="white")
        paned.add(bot_f, weight=3)

        scols = ("ID", "Function Name", "CS Goal", "Feasibility", "Safety", "Financial", "Operational", "Privacy", "Risk Lvl")
        sv = ttk.Treeview(top_f, columns=scols, show="headings", height=10)
        for c, w in zip(scols, [65, 340, 120, 90, 75, 75, 90, 75, 70]):
            sv.heading(c, text=c)
            sv.column(c, width=w, minwidth=w, anchor="center" if c not in ("Function Name",) else "w")
        sv.column("Function Name", stretch=True)
        ssc = ttk.Scrollbar(top_f, orient="vertical", command=sv.yview)
        sv.configure(yscrollcommand=ssc.set)
        ssc.pack(side="right", fill="y")
        sv.pack(fill="both", expand=True)

        _impact_color = {"severe": "#C62828", "major": "#E65100", "moderate": "#F9A825", "negligible": "#2E7D32"}

        def _impact_str(val):
            if not val:
                return "—"
            return val[:3].upper()

        def _impact_rank(val):
            return {"severe": 4, "major": 3, "moderate": 2, "negligible": 1}.get((val or "").lower(), 0)

        for sc_item in scenarios:
            sid = sc_item.get("scenario_id", "—")
            fname = sc_item.get("affected_function_name", "—")
            cgoal = sc_item.get("cybersecurity_goal", "—")
            feasibility = sc_item.get("overall_feasibility_rating", "—")
            safety = _impact_str(sc_item.get("safety_impact"))
            fin = _impact_str(sc_item.get("financial_impact"))
            ops = _impact_str(sc_item.get("operational_impact"))
            priv = _impact_str(sc_item.get("privacy_impact"))

            rlvl = _calc_risk_level_fs(
                sc_item.get("safety_impact", "Negligible"),
                sc_item.get("financial_impact", "Negligible"),
                sc_item.get("operational_impact", "Negligible"),
                sc_item.get("privacy_impact", "Negligible"),
                sc_item.get("overall_feasibility_rating", "Medium"),
            )
            is_novel = sc_item.get("is_novel_finding", False)
            top_rank = max(_impact_rank(sc_item.get(k)) for k in ("safety_impact","financial_impact","operational_impact","privacy_impact"))
            tag = {4:"severe",3:"major",2:"moderate",1:"negligible"}.get(top_rank, "negligible")
            display_name = ("* " if is_novel else "") + fname[:40]
            sv.insert("", "end", values=(sid, display_name, cgoal, feasibility, safety, fin, ops, priv, rlvl), tags=(tag,))

        sv.tag_configure("severe", background="#FFEBEE")
        sv.tag_configure("major", background="#FFF3E0")
        sv.tag_configure("moderate", background="#FFFDE7")
        sv.tag_configure("negligible", background="#F1F8E9")


        txt_det = tk.Text(bot_f, wrap="word", font=("Segoe UI", 9),
                          bg="#FAFAFA", fg="#222", relief="flat", bd=0,
                          padx=10, pady=8, state="disabled")
        sc2 = ttk.Scrollbar(bot_f, orient="vertical", command=txt_det.yview)
        txt_det.configure(yscrollcommand=sc2.set)
        sc2.pack(side="right", fill="y")
        txt_det.pack(fill="both", expand=True)

        txt_det.tag_configure("h1", font=("Segoe UI", 11, "bold"), foreground="#0D47A1", spacing3=4)
        txt_det.tag_configure("h2", font=("Segoe UI", 10, "bold"), foreground="#1565C0", spacing1=6, spacing3=2)
        txt_det.tag_configure("body", font=("Segoe UI", 9))
        txt_det.tag_configure("novel_t", foreground="#1B5E20", font=("Segoe UI", 9, "bold"))
        txt_det.tag_configure("severe_t", foreground="#C62828", font=("Segoe UI", 9, "bold"))
        txt_det.tag_configure("major_t", foreground="#E65100", font=("Segoe UI", 9, "bold"))
        txt_det.tag_configure("moderate_t", foreground="#F57F17", font=("Segoe UI", 9, "bold"))
        txt_det.tag_configure("negligible_t", foreground="#2E7D32", font=("Segoe UI", 9, "bold"))
        txt_det.tag_configure("sep", foreground="#CCCCCC")
        txt_det.tag_configure("req", font=("Segoe UI", 9), foreground="#1A237E")
        txt_det.tag_configure("code", font=("Courier New", 9), foreground="#333", background="#F5F5F5")

        _level_tags = {"severe":"severe_t","major":"major_t","moderate":"moderate_t","negligible":"negligible_t"}

        def on_sc_select(e):
            sel = sv.selection()
            if not sel:
                return
            idx = sv.index(sel[0])
            if idx >= len(scenarios):
                return
            sc_item = scenarios[idx]

            txt_det.config(state="normal")
            txt_det.delete("1.0", "end")

            sid = sc_item.get("scenario_id", "—")
            fname = sc_item.get("affected_function_name", "—")
            cgoal = sc_item.get("cybersecurity_goal", "—")
            feasibility = sc_item.get("overall_feasibility_rating", "")
            feasibility_score = sc_item.get("overall_feasibility_score", "")

            risk_level = _calc_risk_level_fs(
                sc_item.get("safety_impact", "Negligible"),
                sc_item.get("financial_impact", "Negligible"),
                sc_item.get("operational_impact", "Negligible"),
                sc_item.get("privacy_impact", "Negligible"),
                sc_item.get("overall_feasibility_rating", "Medium"),
            )
            is_novel = sc_item.get("is_novel_finding", False)

            txt_det.insert("end", f"{sid}  —  {fname}\n", "h1")
            if is_novel:
                txt_det.insert("end", "  [NOVEL FINDING — Not in Static Threat Library]\n", "novel_t")
            txt_det.insert("end", f"CS Goal: {cgoal}", "body")
            if feasibility:
                txt_det.insert("end", f"   |   Feasibility: {feasibility}", "body")
                if feasibility_score:
                    txt_det.insert("end", f" (score: {feasibility_score})", "body")
            if risk_level:
                txt_det.insert("end", f"   |   Risk Level: {risk_level}", "body")
            txt_det.insert("end", "\n" + "─" * 80 + "\n\n", "sep")


            if is_novel:
                novel_desc = sc_item.get("novel_finding_description", "")
                if novel_desc:
                    txt_det.insert("end", "Novel Attack Surface Description\n", "h2")
                    txt_det.insert("end", novel_desc + "\n", "novel_t")


            comp = sc_item.get("component_details_used", {}) or {}
            if any(comp.values()):
                txt_det.insert("end", "\nComponent Details\n", "h2")
                for k, v in comp.items():
                    if v:
                        if isinstance(v, list):
                            v_str = ", ".join(str(x) for x in v) if v else "—"
                        else:
                            v_str = str(v)
                        txt_det.insert("end", f"  {k.capitalize()}: {v_str}\n", "code")


            fi = sc_item.get("functional_impact", "") or sc_item.get("functional_impact_ko", "") or ""
            if fi:
                txt_det.insert("end", "\nFunctional Impact\n", "h2")
                txt_det.insert("end", fi + "\n", "body")


            an = sc_item.get("attack_narrative", "") or sc_item.get("attack_narrative_ko", "") or ""
            if an:
                txt_det.insert("end", "\nAttack Narrative (Detailed)\n", "h2")
                txt_det.insert("end", an + "\n", "body")


            atree = sc_item.get("attack_tree", {}) or {}
            if atree:
                root_goal = atree.get("root_goal", "")
                logic = atree.get("logical_structure", "")
                steps = atree.get("sub_steps", []) or []
                if root_goal or steps:
                    txt_det.insert("end", "\nAttack Tree\n", "h2")
                    if root_goal:
                        txt_det.insert("end", f"  Goal: {root_goal}  [{logic}]\n", "body")
                    for step in steps:
                        s_desc = step.get("description", "")
                        s_op = step.get("logical_operator", "")
                        s_fscore = step.get("feasibility_scores", {}) or {}
                        s_rating = s_fscore.get("rating", "")
                        txt_det.insert("end", f"  [{s_op}] {s_desc}", "code")
                        if s_rating:
                            txt_det.insert("end", f"  -> Feasibility: {s_rating}", "body")
                        txt_det.insert("end", "\n", "body")


            ds = sc_item.get("damage_scenario", "") or sc_item.get("damage_scenario_ko", "") or ""
            if ds:
                txt_det.insert("end", "\nDamage Scenario\n", "h2")
                txt_det.insert("end", ds + "\n", "body")


            txt_det.insert("end", "\nImpact Ratings\n", "h2")
            for label, key in [("Safety", "safety_impact"), ("Financial", "financial_impact"),
                                ("Operational", "operational_impact"), ("Privacy", "privacy_impact")]:
                val = (sc_item.get(key) or "negligible").lower()
                tag_n = _level_tags.get(val, "negligible_t")
                txt_det.insert("end", f"  {label}: ", "body")
                txt_det.insert("end", val.upper() + "\n", tag_n)


            reqs = sc_item.get("cybersecurity_requirements", []) or []
            if reqs:
                txt_det.insert("end", "\nCybersecurity Requirements\n", "h2")
                for r in reqs:
                    txt_det.insert("end", f"  * {r}\n", "req")

 
            mits = sc_item.get("recommended_mitigations", []) or []
            if mits:
                txt_det.insert("end", "\nRecommended Mitigations\n", "h2")
                for m in mits:
                    txt_det.insert("end", f"  -> {m}\n", "body")


            inferences = sc_item.get("inferences_made", []) or []
            if inferences:
                txt_det.insert("end", "\nInferences Made\n", "h2")
                for inf in inferences:
                    txt_det.insert("end", f"  [INFERRED] {inf}\n", "moderate_t")

            txt_det.config(state="disabled")

        sv.bind("<<TreeviewSelect>>", on_sc_select)

    def _reload_paths(self):
        shown = self._mpaths
        self._shown_paths = shown
        for r in self._t2.get_children():
            self._t2.delete(r)
        for i, p in enumerate(shown):
            self._t2.insert("", "end", values=(
                i + 1,
                ", ".join(p.all_assets[:5]),
                len(p.all_threats),
                ", ".join(p.final_targets[:2]),
                p.path_summary()[:120],
            ), tags=("row",))
        self._t2.tag_configure("row", background="#FAFAFA")

    def _on_graph_canvas_configure(self, state_key: str):
        st = self._graph_states[state_key]
        if st["after_id"]:
            try:
                self.after_cancel(st["after_id"])
            except Exception:
                pass
        st["after_id"] = self.after(80, lambda k=state_key: self._fit_graph_to_width(k))

    def _fit_graph_to_width(self, state_key: str):
        st = self._graph_states[state_key]
        canvas = st["canvas"]
        if canvas is None or self._attack_graph_src_pil is None:
            return
        canvas_w = max(1, canvas.winfo_width() - 4)
        img_w = max(1, self._attack_graph_src_pil.width)
        st["fit_scale"] = canvas_w / img_w
        st["zoom"] = 1.0
        self._render_graph_image(state_key)

    def _render_graph_image(self, state_key: str):
        st = self._graph_states[state_key]
        canvas = st["canvas"]
        img_id = st["canvas_img_id"]

        if canvas is None or img_id is None or self._attack_graph_src_pil is None or not _PIL_OK:
            return

        total_scale = st["fit_scale"] * st["zoom"]
        total_scale = max(0.05, min(total_scale, 8.0))

        src_w, src_h = self._attack_graph_src_pil.size
        dst_w = max(1, int(src_w * total_scale))
        dst_h = max(1, int(src_h * total_scale))

        resized = self._attack_graph_src_pil.resize((dst_w, dst_h), Image.LANCZOS)
        tk_img = ImageTk.PhotoImage(resized)

        st["tk_img"] = tk_img
        canvas.itemconfigure(img_id, image=tk_img)
        canvas.coords(img_id, 0, 0)
        canvas.configure(scrollregion=(0, 0, dst_w, dst_h))

    def _on_graph_mousewheel(self, event, state_key: str):
        st = self._graph_states[state_key]
        if st["canvas"] is None or self._attack_graph_src_pil is None:
            return

        if hasattr(event, "delta") and event.delta:
            delta = event.delta
        elif getattr(event, "num", None) == 4:
            delta = 120
        elif getattr(event, "num", None) == 5:
            delta = -120
        else:
            delta = 0

        if delta > 0:
            st["zoom"] *= 1.12
        elif delta < 0:
            st["zoom"] /= 1.12

        st["zoom"] = max(0.2, min(st["zoom"], 8.0))
        self._render_graph_image(state_key)

    def _on_graph_double_click(self, state_key: str):
        self._fit_graph_to_width(state_key)



class SplashScreen(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.overrideredirect(True)
        self.configure(bg="white")

        self._logo_img = None

        width, height = 520, 320
        _center(self, width, height)

        outer = tk.Frame(self, bg="white", bd=1, relief="solid")
        outer.pack(fill="both", expand=True)

        card = tk.Frame(outer, bg="white")
        card.pack(fill="both", expand=True, padx=18, pady=18)


        logo_wrap = tk.Frame(card, bg="white")
        logo_wrap.pack(pady=(8, 12))

        if _PIL_OK and _SPLASH_LOGO_PATH.exists():
            try:
                img = Image.open(_SPLASH_LOGO_PATH).convert("RGBA")
                img.thumbnail((180, 180), Image.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
                tk.Label(
                    logo_wrap,
                    image=self._logo_img,
                    bg="white"
                ).pack()
            except Exception:
                tk.Label(
                    logo_wrap,
                    text="[ Logo ]",
                    font=("Segoe UI", 16, "bold"),
                    bg="white",
                    fg="#1C2333"
                ).pack()
        else:
            tk.Label(
                logo_wrap,
                text="[ Logo ]",
                font=("Segoe UI", 16, "bold"),
                bg="white",
                fg="#1C2333"
            ).pack()

        tk.Label(
            card,
            text="Vehicle Attack Scenario Automation",
            font=("Segoe UI", 10, "bold"),
            bg="white",
            fg="#1C2333"
        ).pack(pady=(4, 4))

        tk.Label(
            card,
            text="Loading application...",
            font=("Segoe UI", 10),
            bg="white",
            fg="#666666"
        ).pack(pady=(0, 14))

        pb_style = ttk.Style(self)
        pb_style.configure(
            "Splash.Horizontal.TProgressbar",
            troughcolor="#EAEAEA"
        )

        self.pb = ttk.Progressbar(
            card,
            mode="indeterminate",
            length=280,
            style="Splash.Horizontal.TProgressbar"
        )
        self.pb.pack(pady=(0, 12))
        self.pb.start(12)

        self.status = tk.Label(
            card,
            text="Initialising modules...",
            font=("Segoe UI", 9, "italic"),
            bg="white",
            fg="#7C3AED"
        )
        self.status.pack()

        self.update_idletasks()


class AttackPathsGUI(tk.Tk):
    def __init__(self, backend_script=None):
        super().__init__()
        self.withdraw()  
        self._splash = SplashScreen(self)
        self.title("Attack Path Analyzer")
        self.geometry("980x680")
        self.minsize(860,580)
        _center(self,980,680)
        self.configure(bg="white")


        _style = ttk.Style(self)
        _style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        _style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        if not _SHARED_OK:
            try:
                if getattr(self, "_splash", None) is not None:
                    self._splash.destroy()
                    self._splash = None
            except Exception:
                pass
            messagebox.showerror(
                "Import error",
                f"Please place tool_threat_mapper_automotive.py in the same folder.\n{_IMPORT_ERR}"
            )
            self.destroy()
            return

        self.backend_path = (
            Path(backend_script).resolve() if backend_script
            else DEFAULT_BACKEND if DEFAULT_BACKEND.exists() else None
        )
        self.v_tm7 = tk.StringVar()
        self.v_llm_api_key = tk.StringVar()
        self.v_additional_info = tk.StringVar()   
        self.v_mode = tk.StringVar(value="remote")
        self.v_target = tk.StringVar()
        self.v_boundary = tk.StringVar()
        self.v_asset = tk.StringVar(value=str(DEFAULT_ASSET_MAP) if DEFAULT_ASSET_MAP.exists() else "")
        self.v_threat = tk.StringVar(value=str(DEFAULT_THREAT_MAP) if DEFAULT_THREAT_MAP.exists() else "")
        self.v_av = tk.StringVar(value=str(DEFAULT_AV_MAP) if DEFAULT_AV_MAP.exists() else "")
        self.v_dep = tk.StringVar(value=str(DEFAULT_DEP_MAP) if DEFAULT_DEP_MAP.exists() else "")
        self.v_impact = tk.StringVar(value=str(DEFAULT_IMPACT_MAP) if DEFAULT_IMPACT_MAP.exists() else "")
        self.v_depth = tk.StringVar(value="30")
        self.v_max_cyc = tk.StringVar(value="4")
        self.v_max_paths = tk.StringVar(value="2000")
        self.v_out_dir = tk.StringVar(value=str(DEFAULT_OUT_DIR))
        self.v_proj = tk.StringVar()

        self._mapping_cache = None
        self._paths_cache = None
        self._at_data = None
        self._json_expanded = False
        self._attack_graph_png = None
        self._report_html_path = None

        self.banner_title = tk.StringVar(value="Vehicle Attack Scenario Automation")
        self.banner_sub = tk.StringVar(value="Rule-Based Attack Path Discovery with LLM-Guided Scenario Generation")

        self._build_ui()
        self.after(900, self._show_main_window)

    def _build_banner(self, parent):
        self.banner_canvas = tk.Canvas(parent, height=92, highlightthickness=0)
        self.banner_canvas.pack(fill="x", expand=True)
        self.banner_canvas.bind("<Configure>", lambda e: self._draw_banner())
        self.after(50, self._draw_banner)

    def _draw_banner(self):
        _draw_top_banner(
            self.banner_canvas,
            self.banner_title.get(),
            self.banner_sub.get()
        )

    def _build_ui(self):
        banner_wrap = tk.Frame(self, bg="white")
        banner_wrap.pack(fill="x", padx=10, pady=(10, 6))
        self._build_banner(banner_wrap)

        inp = tk.LabelFrame(
            self, text=" Settings ", font=("Arial",9,"bold"),
            bg="white", fg="#555", bd=1, relief="solid"
        )
        inp.pack(fill="x", padx=10, pady=6)

        inner = tk.Frame(inp, bg="white")
        inner.pack(fill="x", padx=10, pady=8)

        left_card = tk.LabelFrame(
            inner,
            text=" Input Files / Libraries ",
            font=("Arial", 9, "bold"),
            bg="white",
            fg="#374151",
            bd=1,
            relief="solid",
            padx=8,
            pady=8
        )
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left_card.columnconfigure(1, weight=1)

        right_card = tk.LabelFrame(
            inner,
            text=" Analysis Options ",
            font=("Arial", 9, "bold"),
            bg="white",
            fg="#374151",
            bd=1,
            relief="solid",
            padx=8,
            pady=8
        )
        right_card.grid(row=0, column=1, sticky="nsew")

        inner.columnconfigure(0, weight=3)
        inner.columnconfigure(1, weight=2)

        def _left_row(p, r, label, var, browse=None, w=48, show=None):
            tk.Label(
                p, text=label, font=("Arial",9), bg="white",
                anchor="e", width=15, fg="#333"
            ).grid(row=r, column=0, padx=(2, 8), pady=3, sticky="e")
            e = tk.Entry(
                p, textvariable=var, width=w, font=("Arial",9),
                bg="#FAFAFA", relief="solid", show=show
            )
            e.grid(row=r, column=1, padx=0, pady=3, ipady=2, sticky="ew")
            if browse:
                tk.Button(
                    p, text="...", font=("Arial",8), command=browse,
                    relief="flat", bg="#ECECEC", padx=7
                ).grid(row=r, column=2, padx=(6, 0), pady=4)
            p.columnconfigure(1, weight=1)

        _left_row(left_card, 0, "TM7 File", self.v_tm7, self._br_tm7)

       
        self.v_ai_provider = tk.StringVar(value="gemini")
        self.v_ai_model    = tk.StringVar(value="gemini-3.1-flash-lite-preview")

        _ai_outer = tk.Frame(left_card, bg="white")
        _ai_outer.grid(row=1, column=0, columnspan=3, sticky="ew", pady=2)
        _ai_outer.columnconfigure(1, weight=1)

        _lbl_kw = dict(font=("Arial", 9), bg="white", fg="#333", anchor="e", width=15)

       
        tk.Label(_ai_outer, text="AI Model", **_lbl_kw
                 ).grid(row=0, column=0, padx=(2, 8), pady=3, sticky="e")
        _provider_cb = ttk.Combobox(_ai_outer, textvariable=self.v_ai_provider,
                                    values=["gemini", "gpt", "ollama"],
                                    width=20, state="readonly", font=("Arial", 9))
        _provider_cb.grid(row=0, column=1, sticky="ew", pady=3, padx=(0, 4))

        def _on_provider_change(e=None):
            defaults = {
                "gemini": "gemini-3.1-flash-lite-preview",
                "gpt":    "gpt-4o",
                "ollama": "llama3.8",
            }
            prov = self.v_ai_provider.get()
            self.v_ai_model.set(defaults.get(prov, ""))
            
            if prov == "ollama":
                _lbl_api_key.config(text="Base URL")
                _hint_model.config(text="e.g. llama3.8")
                _lbl_key_hint.config(text="leave blank → localhost:11434")
            elif prov == "gpt":
                _lbl_api_key.config(text="AI API Key")
                _hint_model.config(text="e.g. gpt-4o / gpt-4-turbo")
                _lbl_key_hint.config(text="sk-...")
            else:
                _lbl_api_key.config(text="AI API Key")
                _hint_model.config(text="e.g. gemini-3.1-flash-lite-preview")
                _lbl_key_hint.config(text="AIza...")
        _provider_cb.bind("<<ComboboxSelected>>", _on_provider_change)

        
        tk.Label(_ai_outer, text="AI Model Type", **_lbl_kw
                 ).grid(row=1, column=0, padx=(2, 8), pady=3, sticky="e")
        tk.Entry(_ai_outer, textvariable=self.v_ai_model,
                 font=("Arial", 9), bg="#FAFAFA", relief="solid"
                 ).grid(row=1, column=1, sticky="ew", pady=3, padx=(0, 4))
        _hint_model = tk.Label(_ai_outer, text="e.g. gemini-2.0-flash / gpt-4o",
                 font=("Arial", 7), fg="#aaa", bg="white")
        _hint_model.grid(row=1, column=2, sticky="w", padx=(0, 4))

        
        _lbl_api_key = tk.Label(_ai_outer, text="AI API Key", **_lbl_kw)
        _lbl_api_key.grid(row=2, column=0, padx=(2, 8), pady=3, sticky="e")

        _key_row = tk.Frame(_ai_outer, bg="white")
        _key_row.grid(row=2, column=1, columnspan=2, sticky="ew", pady=3)
        _key_row.columnconfigure(0, weight=1)

        tk.Entry(_key_row, textvariable=self.v_llm_api_key,
                 show="*", font=("Arial", 9), bg="#FAFAFA", relief="solid"
                 ).grid(row=0, column=0, sticky="ew", padx=(0, 6))

        def _test_api_key():
            provider = self.v_ai_provider.get().strip()
            key      = self.v_llm_api_key.get().strip()
            model    = self.v_ai_model.get().strip()

            
            if provider == "gemini":
                model = model or "gemini-3.1-flash-lite-preview"
                if not key:
                    messagebox.showwarning("No API Key", "Please enter a Gemini API key first.")
                    return
                try:
                    from google import genai
                    from google.genai import types
                except ImportError:
                    messagebox.showerror("Package Missing",
                        "The google-genai package is not installed.\n\n"
                        "Run:  pip install google-genai\n\nThen restart.")
                    return
                self._log(f"[INFO] Testing Gemini: {model}...")
                def _do_test_gemini():
                    try:
                        client = genai.Client(api_key=key)
                        resp = client.models.generate_content(
                            model=model, contents="Reply with exactly: OK",
                            config=types.GenerateContentConfig(max_output_tokens=10))
                        txt = (resp.text or "").strip()
                        self.after(0, lambda t=txt: messagebox.showinfo("Connection OK",
                            f"Gemini connection successful!\nModel: {model}\nResponse: \"{t}\""))
                        self.after(0, lambda: self._log("[OK] Gemini API key test passed."))
                    except Exception as ex:
                        m = str(ex)
                        self.after(0, lambda msg=m: messagebox.showerror("Connection Error",
                            f"Gemini call failed (model: {model}):\n\n{msg[:400]}\n\n"
                            "Check: API key validity, model name spelling, network access."))
                        self.after(0, lambda msg=m: self._log(f"[ERROR] Gemini test failed: {msg[:150]}"))
                import threading as _t
                _t.Thread(target=_do_test_gemini, daemon=True).start()

          
            elif provider == "gpt":
                model = model or "gpt-4o"
                if not key:
                    messagebox.showwarning("No API Key", "Please enter an OpenAI API key first.")
                    return
                try:
                    from openai import OpenAI as _OAI
                except ImportError:
                    messagebox.showerror("Package Missing",
                        "The openai package is not installed.\n\n"
                        "Run:  pip install openai\n\nThen restart.")
                    return
                self._log(f"[INFO] Testing GPT: {model}...")
                def _do_test_gpt():
                    try:
                        client = _OAI(api_key=key)
                        resp = client.chat.completions.create(
                            model=model,
                            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
                            max_tokens=10, temperature=0)
                        txt = (resp.choices[0].message.content or "").strip()
                        self.after(0, lambda t=txt: messagebox.showinfo("Connection OK",
                            f"GPT connection successful!\nModel: {model}\nResponse: \"{t}\""))
                        self.after(0, lambda: self._log("[OK] GPT API key test passed."))
                    except Exception as ex:
                        m = str(ex)
                        self.after(0, lambda msg=m: messagebox.showerror("Connection Error",
                            f"GPT call failed (model: {model}):\n\n{msg[:400]}\n\n"
                            "Check: API key validity, model name, billing status."))
                        self.after(0, lambda msg=m: self._log(f"[ERROR] GPT test failed: {msg[:150]}"))
                import threading as _t
                _t.Thread(target=_do_test_gpt, daemon=True).start()

            
            elif provider == "ollama":
                model    = model or "llama3.8"
                base_url = key if key else "http://localhost:11434"
                
                if not base_url.rstrip("/").endswith("/v1"):
                    base_url = base_url.rstrip("/") + "/v1"
                try:
                    from openai import OpenAI as _OAI
                except ImportError:
                    messagebox.showerror("Package Missing",
                        "The openai package is not installed.\n\n"
                        "Run:  pip install openai\n\nThen restart.")
                    return
                self._log(f"[INFO] Testing Ollama: {model} @ {base_url}...")
                def _do_test_ollama():
                    try:
                        client = _OAI(base_url=base_url, api_key="ollama")
                        resp = client.chat.completions.create(
                            model=model,
                            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
                            max_tokens=10, temperature=0)
                        txt = (resp.choices[0].message.content or "").strip()
                        self.after(0, lambda t=txt: messagebox.showinfo("Connection OK",
                            f"Ollama connection successful!\nModel: {model}\nResponse: \"{t}\""))
                        self.after(0, lambda: self._log("[OK] Ollama test passed."))
                    except Exception as ex:
                        m = str(ex)
                        self.after(0, lambda msg=m: messagebox.showerror("Connection Error",
                            f"Ollama call failed (model: {model}, url: {base_url}):\n\n{msg[:400]}\n\n"
                            "Check: Ollama is running (ollama serve), model is pulled (ollama pull {model})."))
                        self.after(0, lambda msg=m: self._log(f"[ERROR] Ollama test failed: {msg[:150]}"))
                import threading as _t
                _t.Thread(target=_do_test_ollama, daemon=True).start()

            else:
                messagebox.showwarning("Unknown Provider", f"Unsupported AI provider: {provider}")

        tk.Button(_key_row, text="Test", font=("Arial", 8, "bold"),
                  bg="#388E3C", fg="white", relief="flat", padx=14, pady=2,
                  cursor="hand2", command=_test_api_key
                  ).grid(row=0, column=1)
        _lbl_key_hint = tk.Label(_key_row, text="AIza...",
                                 font=("Arial", 7), fg="#aaa", bg="white")
        _lbl_key_hint.grid(row=0, column=2, sticky="w", padx=(6, 0))

        self._json_frame = tk.Frame(left_card, bg="white")
        self._json_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        self._json_frame.grid_remove()

        def _jrow(r, label, var, browse):
            tk.Label(
                self._json_frame, text=label, font=("Arial",9), bg="white",
                anchor="e", width=12, fg="#333"
            ).grid(row=r, column=0, padx=(2, 8), pady=3, sticky="e")
            e = tk.Entry(
                self._json_frame, textvariable=var, width=48, font=("Arial",9),
                bg="#FAFAFA", relief="solid"
            )
            e.grid(row=r, column=1, padx=0, pady=3, sticky="ew")
            tk.Button(
                self._json_frame, text="...", font=("Arial",8), command=browse,
                relief="flat", bg="#ECECEC", padx=7
            ).grid(row=r, column=2, padx=(6, 0), pady=3)
            self._json_frame.columnconfigure(1, weight=1)

        self._toggle_btn = tk.Button(
            left_card, text="▶ Library File Settings",
            font=("Arial",8), relief="flat",
            bg="#EEF2FF", fg="#3730A3", padx=10, pady=4,
            cursor="hand2", command=self._toggle_json
        )
        self._toggle_btn.grid(row=2, column=0, columnspan=3, sticky="w", padx=2, pady=(8, 2))

        _jrow(0, "Asset Map", self.v_asset, lambda: self._br_json(self.v_asset))
        _jrow(1, "Threat Map", self.v_threat, lambda: self._br_json(self.v_threat))
        _jrow(2, "Attack Vector", self.v_av, lambda: self._br_json(self.v_av))
        _jrow(3, "Dependency", self.v_dep, lambda: self._br_json(self.v_dep))
        _jrow(4, "Impact Map", self.v_impact, lambda: self._br_json(self.v_impact))

        def _right_row(p, r, label, var, extra=None):
            tk.Label(
                p, text=label, font=("Arial",9), bg="white",
                anchor="e", width=12, fg="#333"
            ).grid(row=r, column=0, sticky="e", padx=(2, 8), pady=4)
            if extra == "mode":
                ttk.Combobox(
                    p, textvariable=self.v_mode,
                    values=["remote","adjacent","local","physical"],
                    state="readonly", width=18, font=("Arial",9)
                ).grid(row=r, column=1, sticky="ew", pady=4)
            else:
                tk.Entry(
                    p, textvariable=var, width=24, font=("Arial",9),
                    bg="#FAFAFA", relief="solid"
                ).grid(row=r, column=1, sticky="ew", pady=4)
            p.columnconfigure(1, weight=1)

        _right_row(right_card, 0, "Target Asset", self.v_target)
        _right_row(right_card, 1, "Trust Boundary", self.v_boundary)
        _right_row(right_card, 2, "Attack Mode", None, extra="mode")
        _right_row(right_card, 3, "Max Depth", self.v_depth)
        _right_row(right_card, 4, "Max Cycles", self.v_max_cyc)
        _right_row(right_card, 5, "Max Paths", self.v_max_paths)
        _right_row(right_card, 6, "Output Folder", self.v_out_dir)

        btn_f = tk.Frame(self, bg="white")
        btn_f.pack(fill="x", padx=10, pady=4)
        bkw = dict(font=("Arial",10,"bold"), relief="flat", bd=0, padx=16, pady=7, cursor="hand2")
        tk.Button(
            btn_f, text="Run Analysis", bg="#1C2333", fg="white",
            command=self._run, **bkw
        ).pack(side="left", padx=4)
        tk.Button(
            btn_f, text="Save", bg="#2E7D32", fg="white",
            command=self._save, **bkw
        ).pack(side="left", padx=4)
        self._spin_chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        self._spin_idx = 0
        self._spin_after_id = None
        self._spin_active = False
        self._progress_cur = 0
        self._progress_target = 0
        self._progress_text = ""
        self._pct_after_id = None

        self.lbl_spin = tk.Label(btn_f, text="", font=("Segoe UI Emoji",12), bg="white", fg="#7C3AED", width=2)
        self.lbl_spin.pack(side="right")

        self.lbl_status = tk.Label(btn_f, text="", font=("Segoe UI",9,"italic"), bg="white", fg="#888")
        self.lbl_status.pack(side="right", padx=4)

        log_f = tk.Frame(self, bg="#1E1E2E")
        log_f.pack(fill="both", expand=True, padx=10, pady=4)
        self.txt_log = tk.Text(
            log_f, font=("Courier",9), bg="#1E1E2E", fg="#AAFFAA",
            state="disabled", relief="flat", height=9
        )
        lsb = ttk.Scrollbar(log_f, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right", fill="y")
        self.txt_log.pack(fill="both", expand=True)

    def _show_main_window(self):
        try:
            if getattr(self, "_splash", None) is not None:
                try:
                    self._splash.pb.stop()
                except Exception:
                    pass
                self._splash.destroy()
                self._splash = None
        except Exception:
            pass

        self.deiconify()
        self.lift()
        self.focus_force()

    def _toggle_json(self):
        if self._json_expanded:
            self._json_frame.grid_remove()
            self._toggle_btn.config(text="▶ Library File Settings")
            self._json_expanded = False
        else:
            self._json_frame.grid()
            self._toggle_btn.config(text="▼ Library File Settings")
            self._json_expanded = True

    def _br_tm7(self):
        p = filedialog.askopenfilename(filetypes=[("TM7","*.tm7"),("All","*.*")])
        if p:
            self.v_tm7.set(p)

    def _br_json(self, var):
        p = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
        if p:
            var.set(p)

    def _log(self, msg):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", msg + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _start_spinner(self):
        self._spin_active = True
        self._spin_idx = 0
        self._progress_cur = 0
        self._progress_target = 0
        def _tick():
            if not self._spin_active:
                self.lbl_spin.config(text="")
                return
            self.lbl_spin.config(text=self._spin_chars[self._spin_idx % len(self._spin_chars)])
            self._spin_idx += 1
            self._spin_after_id = self.after(120, _tick)
        _tick()

    def _stop_spinner(self):
        self._spin_active = False
        if self._spin_after_id:
            try: self.after_cancel(self._spin_after_id)
            except: pass
        self.lbl_spin.config(text="")

    def _set_progress(self, text: str, pct: int = -1):
        """Update status. If pct given, animate counter from current to pct."""
        self._progress_text = text
        if pct >= 0:
            self._progress_target = pct
            self._progress_cur = getattr(self, "_progress_cur", 0)
          
            _prev = getattr(self, "_pct_after_id", None)
            if _prev:
                try: self.after_cancel(_prev)
                except: pass
            self._tick_progress()
        else:
            self.lbl_status.config(text=text, fg="#888")

    def _tick_progress(self):
        """Smoothly increment displayed % toward target."""
        cur = getattr(self, "_progress_cur", 0)
        tgt = getattr(self, "_progress_target", cur)
        txt = getattr(self, "_progress_text", "")
        if cur < tgt:
            cur += 1
            self._progress_cur = cur
            self.lbl_status.config(text=f"{txt}  {cur}%", fg="#7C3AED")
            self._pct_after_id = self.after(30, self._tick_progress)
        else:
            self._progress_cur = tgt
            self.lbl_status.config(text=f"{txt}  {tgt}%", fg="#7C3AED")

    def _validate(self):
        if not self.backend_path or not Path(self.backend_path).exists():
            messagebox.showerror("Error", f"Backend not found:\n{self.backend_path}")
            return False
        if not self.v_tm7.get() or not Path(self.v_tm7.get()).exists():
            messagebox.showerror("Error", "Please select a TM7 file.")
            return False
        if not self.v_target.get().strip():
            messagebox.showerror("Error", "Please enter a Target Asset name.")
            return False
        if not self.v_boundary.get().strip():
            messagebox.showerror("Error", "Please enter a Trust Boundary.")
            return False
        return True

    def _run(self):
        if not self._validate():
            return
        self._set_progress("Running...", 0)
        self._start_spinner()
        self.update()

        self._attack_graph_png = None
        self._report_html_path = None
        self._gemini_analysis_path = None

        ap = self.v_asset.get()
        if ap and Path(ap).exists():
            try:
                with open(ap, encoding="utf-8") as f:
                    self._at_data = json.load(f)
                self._log(f"[OK] asset_to_threats loaded: {Path(ap).name}")
            except Exception:
                self._at_data = None

        backend_path = Path(self.backend_path).resolve()
        llm_api_key  = self.v_llm_api_key.get().strip()
        user_model   = self.v_ai_model.get().strip() or "gemini-3.1-flash-lite-preview"

        
        additional_info = ""

               

        def worker():
            try:
                self.after(0, lambda: self._log(f"[{datetime.now():%H:%M:%S}] Backend execution started"))
                run_bundle = run_path_filter(
                    backend_path=backend_path,
                    tm7_path=self.v_tm7.get(),
                    mode=self.v_mode.get(),
                    target=self.v_target.get().strip(),
                    boundary=self.v_boundary.get().strip(),
                    asset_map=self.v_asset.get(),
                    threat_map=self.v_threat.get(),
                    av_map=self.v_av.get(),
                    dep_map=self.v_dep.get(),
                    impact_map=self.v_impact.get(),
                    max_depth=int(self.v_depth.get() or 30),
                    llm_api_key="",   
                )
                result = run_bundle["result"]
                self._attack_graph_png = run_bundle.get("attack_graph_png")
                self._report_html_path = run_bundle.get("report_html")

                
                if not self._report_html_path:
                    _be_err = (run_bundle.get("backend_stderr") or "").strip()
                    _be_out = (run_bundle.get("backend_stdout") or "").strip()
                    if _be_err:
                        self.after(0, lambda e=_be_err[:600]: self._log(f"[WARN] Backend stderr:\n{e}"))
                    
                    out_dir_fb = Path(self.v_out_dir.get())
                    html_files = sorted(out_dir_fb.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True) if out_dir_fb.exists() else []
                    if html_files:
                        self._report_html_path = str(html_files[0])
                        self.after(0, lambda p=str(html_files[0]): self._log(f"[OK] Report HTML (fallback): {Path(p).name}"))

                if not result.get("ok", False):
                    self.after(0, lambda: self._log(f"[WARN] ok=False: {result.get('reason','')}"))

                if self._attack_graph_png:
                    self.after(0, lambda: self._log(f"[OK] Attack Graph PNG: {self._attack_graph_png}"))
                if self._report_html_path:
                    self.after(0, lambda: self._log(f"[OK] Report HTML: {self._report_html_path}"))

                n_p = len(result.get("paths", []))
                n_n = len(result.get("nodes", []))
                self.after(0, lambda: self._log(f"[OK] Paths: {n_p} | Nodes: {n_n}"))

                
                self._raw_result_for_gemini = result
                self._gemini_analysis_path = None
                
                out_dir_check = Path(self.v_out_dir.get())
                for _d in ([Path(self._report_html_path).parent] if self._report_html_path else []) + [out_dir_check]:
                    _gp = _d / "gemini_analysis.json"
                    if _gp.exists():
                        self._gemini_analysis_path = str(_gp)
                        self.after(0, lambda p=str(_gp): self._log(f"[OK] Previous Gemini analysis found: {p}"))
                        break

                tp = self.v_threat.get()
                if tp and Path(tp).exists():
                    with open(tp, encoding="utf-8") as f:
                        tt_data = json.load(f)
                    _build_tactic_map(tt_data.get("UnifiedKillChain", {}))
                    self.after(0, lambda: self._log("[OK] UKC tactic map loaded"))
                else:
                    _build_tactic_map({})

                elements = extract_elements(result)
                n_nodes = sum(1 for e in elements if e["type"]=="node")
                n_edges = sum(1 for e in elements if e["type"]=="edge")
                self.after(0, lambda: self._log(f"[OK] Elements: {n_nodes} nodes, {n_edges} edges"))

                node_index: Dict[str, PathNode] = {}
                for n in result.get("nodes", []):
                    nid = n.get("node_id", "")
                    if nid:
                        node_index[nid] = PathNode(n)

                raw_paths = result.get("paths", [])
                self.after(0, lambda: self._show_mapping_and_paths(
                    elements, result, raw_paths, node_index
                ))

            except Exception as e:
                err = traceback.format_exc()
                self.after(0, lambda: self._log(f"[ERROR]\n{err}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, lambda: self._stop_spinner())
                self.after(0, lambda: self._set_progress("Error"))

        threading.Thread(target=worker, daemon=True).start()

    def _show_mapping_and_paths(self, elements, result, raw_paths, node_index):
        self._set_progress("Mapping assets...", 20)
        dlg = AssetMapDialog(self, elements, at_data=self._at_data)
       
        _patch_asset_map_dialog_other(dlg)
        self.wait_window(dlg)
        if not dlg.confirmed:
            self._stop_spinner()
            self.lbl_status.config(text="Cancelled")
            return

        mapping = dlg.get_mapping()
        self._mapping_cache = mapping
        self._set_progress("Enumerating paths...", 40)
        self.update()

        max_cyc = int(self.v_max_cyc.get() or 3)
        max_paths = int(self.v_max_paths.get() or 2000)
        multi_paths = enumerate_multi_cycle_paths(
            raw_paths, node_index,
            max_cycles=max_cyc,
            max_single=max_paths // 4,
            max_multi=max_paths - max_paths // 4
        )
        self._paths_cache = multi_paths

        n_multi = sum(1 for p in multi_paths if p.cycle_count > 1)
        self._log(f"[OK] Paths: {len(multi_paths)} (multi {n_multi} / single {len(multi_paths)-n_multi})")

        out_dir = Path(self.v_out_dir.get())
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_json = str(out_dir / f"attack_paths_{ts}.json")
        out_csv  = str(out_dir / f"attack_paths_{ts}.csv")
        meta = {
            "project": self.v_proj.get(),
            "tm7": self.v_tm7.get(),
            "mode": self.v_mode.get(),
            "target": self.v_target.get(),
            "boundary": self.v_boundary.get(),
            "raw_path_count": len(raw_paths)
        }

        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(build_full_json(mapping, multi_paths, meta), f, ensure_ascii=False, indent=2)
        with open(out_csv, "w", encoding="utf-8", newline="") as f:
            f.write(build_full_csv(mapping, multi_paths))

        if self._attack_graph_png:
            self._log(f"[OK] Attack Graph PNG: {self._attack_graph_png}")
        if self._report_html_path:
            self._log(f"[OK] Report HTML: {self._report_html_path}")
        self._log(f"[OK] JSON: {out_json}  |  CSV: {out_csv}")


        mapping_by_name: dict = {}
        for m in mapping:
            aname = m.get("name") or m.get("asset_name") or ""
            if aname:
                mapping_by_name[aname] = m

        enriched_result = dict(result)
        enriched_nodes = []
        for node in result.get("nodes", []):
            n = dict(node)
            aname = n.get("asset_name", "")
            if aname in mapping_by_name:
                m = mapping_by_name[aname]
                n["category"]        = m.get("category") or n.get("category")
                n["asset_type"]      = m.get("asset_type") or n.get("asset_type")
                n["asset_kind"]      = m.get("asset_kind") or n.get("asset_kind")
                n["asset_properties"]= m.get("asset_properties") or []
                n["cwes"]            = m.get("cwes") or []
                n["cwe_count"]       = m.get("cwe_count") or 0
                n["threats"]         = m.get("threats") or []
                n["threat_count"]    = m.get("threat_count") or 0
                n["source"]          = m.get("source") or ""
            enriched_nodes.append(n)
        enriched_result["nodes"] = enriched_nodes

        llm_api_key = self.v_llm_api_key.get().strip()

        if llm_api_key:
            self._set_progress("Running AI Analysis...", 50)
            self._log("[INFO] Asset mapping complete. Starting AI analysis with enriched asset data...")
            _call_gemini_direct = getattr(self, "_call_gemini_direct_fn", None)
            out_dir_ai = out_dir

            def _open_result_window():
                self._stop_spinner()
                if getattr(self, "_pct_after_id", None):
                    try: self.after_cancel(self._pct_after_id)
                    except: pass
                self._progress_cur = 0; self._progress_target = 0
                self.lbl_status.config(text=f"Done — {len(multi_paths)} paths", fg="#2E7D32")
                FullResultWindow(
                    self, mapping, multi_paths, out_json, out_csv,
                    attack_graph_png=self._attack_graph_png,
                    report_html_path=self._report_html_path,
                    gemini_analysis_path=getattr(self, "_gemini_analysis_path", None),
                )

            def _ai_worker():
                try:
                    gpath = self._run_ai_with_mapping(enriched_result, out_dir_ai)
                    self._gemini_analysis_path = gpath
                    self.after(0, _open_result_window)
                except Exception as e:
                    err = traceback.format_exc()
                    self.after(0, lambda: self._log(f"[ERROR] AI analysis failed:\n{err[:400]}"))
                    self.after(0, _open_result_window)

            threading.Thread(target=_ai_worker, daemon=True).start()
        else:
            self._stop_spinner()
            if getattr(self, "_pct_after_id", None):
                try: self.after_cancel(self._pct_after_id)
                except: pass
            self._progress_cur = 0; self._progress_target = 0
            self.lbl_status.config(text=f"Done — {len(multi_paths)} paths", fg="#2E7D32")
            FullResultWindow(
                self, mapping, multi_paths, out_json, out_csv,
                attack_graph_png=self._attack_graph_png,
                report_html_path=self._report_html_path,
                gemini_analysis_path=getattr(self, "_gemini_analysis_path", None),
            )

    @staticmethod
    def _repair_json(raw: str) -> str:
        raw = raw.strip()
        if not raw:
            return raw
        depth_brace = depth_bracket = 0
        in_str = esc = False
        for ch in raw:
            if esc: esc = False; continue
            if ch == '\\': esc = True; continue
            if ch == '"': in_str = not in_str; continue
            if in_str: continue
            if ch == '{': depth_brace += 1
            elif ch == '}': depth_brace = max(0, depth_brace - 1)
            elif ch == '[': depth_bracket += 1
            elif ch == ']': depth_bracket = max(0, depth_bracket - 1)
        import re as _r
        raw = _r.sub(r',\s*$', '', raw.rstrip())
        if in_str: raw += '"'
        raw += ']' * depth_bracket + '}' * depth_brace
        return raw


    def _embed_ai_into_report(self, report_path, vehicle_review_data, functional_data):
        if not report_path or not Path(report_path).exists():
            return False
        try:
            from html import escape as _esc
            import re as _re_inj

            # helpers
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

            IMPACT_ORDER = {
                "Negligible": 0,
                "Low": 1,
                "Moderate": 2,
                "Major": 3,
                "Severe": 4,
            }
            FEASIBILITY_ORDER = {
                "very low": 0,
                "low": 1,
                "medium": 2,
                "high": 3,
                "very high": 4,
            }

            def _max_impact_label(labels):
                return max(labels, key=lambda x: IMPACT_ORDER.get(x, 0)) if labels else "Negligible"

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

            # renderers
            def _render_vehicle_level_review_html(vehicle_review_data: Optional[dict]) -> str:
                if not vehicle_review_data:
                    return "<div class='card'><p style='color:#6b7280'>No vehicle-level AI review available. Provide a Gemini API key to enable this section.</p></div>"

                vr = vehicle_review_data.get("vehicle_level_review", vehicle_review_data)
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
                    source_paths = ", ".join(sc.get("source_vehicle_path_ids") or [])
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
                            f"<li style='font-size:11px'>[{escape(s.get('logical_operator','OR'))}] {escape(s.get('description',''))} " #[:120] 생략
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

            veh_html = _render_vehicle_level_review_html(vehicle_review_data)
            fun_html = _render_functional_level_html(functional_data)

            html = Path(report_path).read_text(encoding="utf-8")
            FUNC_PH = ("No functional-level scenarios available. "
                       "Provide a Gemini API key to enable this section.")
            VEH_PH  = ("No vehicle-level AI review available. "
                       "Provide a Gemini API key to enable this section.")
            f_div = "<div class='card'><p style='color:#6b7280'>" + FUNC_PH + "</p></div>"
            v_div = "<div class='card'><p style='color:#6b7280'>" + VEH_PH  + "</p></div>"
            html = html.replace(f_div, fun_html, 1)
            html = html.replace(v_div, veh_html, 1)
            if FUNC_PH in html:
                html = _re_inj.sub(r"<div[^>]*><p[^>]*>" + _re_inj.escape(FUNC_PH) + r"</p></div>", fun_html, html, 1)
            if VEH_PH in html:
                html = _re_inj.sub(r"<div[^>]*><p[^>]*>" + _re_inj.escape(VEH_PH)  + r"</p></div>", veh_html, html, 1)
            Path(report_path).write_text(html, encoding="utf-8")
            return True
        except Exception:
            import traceback as _tb
            _et = _tb.format_exc()
            self.after(0, lambda e=_et: self._log(f"[WARN] embed failed:\n{e}"))
            return False


    def _run_ai_with_mapping(self, result_data: dict, out_dir: Path):
        """Run AI analysis after AssetMapDialog — supports Gemini, GPT, and Ollama.
        Uses enriched asset data (category, asset_type, asset_kind, properties, CWEs)."""
        provider    = self.v_ai_provider.get().strip() or "gemini"
        llm_api_key = self.v_llm_api_key.get().strip()
        user_model  = self.v_ai_model.get().strip()
        additional_info = ""
        import re as _re
        import time as _time

        _gemini_client = None
        _oai_client    = None

        if provider == "gemini":
            user_model = user_model or "gemini-3.1-flash-lite-preview"
            if not llm_api_key:
                return None
            try:
                from google import genai as _genai
                from google.genai import types as _gtypes
            except ImportError as _ie:
                self.after(0, lambda: messagebox.showerror(
                    "Package Not Installed",
                    "The 'google-genai' package is required for Gemini.\n\n"
                    "Run:  pip install google-genai\n\nThen restart.\n\n"
                    f"(Detail: {_ie})"
                ))
                self.after(0, lambda: self._log("[ERROR] google-genai not installed."))
                return None
            _gemini_client = _genai.Client(api_key=llm_api_key)

        elif provider == "gpt":
            user_model = user_model or "gpt-4o"
            if not llm_api_key:
                return None
            try:
                from openai import OpenAI as _OAI
            except ImportError as _ie:
                self.after(0, lambda: messagebox.showerror(
                    "Package Not Installed",
                    "The 'openai' package is required for GPT.\n\n"
                    "Run:  pip install openai\n\nThen restart.\n\n"
                    f"(Detail: {_ie})"
                ))
                self.after(0, lambda: self._log("[ERROR] openai not installed."))
                return None
            _oai_client = _OAI(api_key=llm_api_key)

        elif provider == "ollama":
            user_model = user_model or "llama3.8"
            base_url   = llm_api_key if llm_api_key else "http://localhost:11434"
            if not base_url.rstrip("/").endswith("/v1"):
                base_url = base_url.rstrip("/") + "/v1"
            try:
                from openai import OpenAI as _OAI
            except ImportError as _ie:
                self.after(0, lambda: messagebox.showerror(
                    "Package Not Installed",
                    "The 'openai' package is required for Ollama.\n\n"
                    "Run:  pip install openai\n\nThen restart.\n\n"
                    f"(Detail: {_ie})"
                ))
                self.after(0, lambda: self._log("[ERROR] openai not installed."))
                return None
            _oai_client = _OAI(base_url=base_url, api_key="ollama")

        else:
            self.after(0, lambda: self._log(f"[ERROR] Unknown AI provider: {provider}"))
            return None

        def _compact(data: dict) -> dict:
            nodes = data.get("nodes", [])
            paths = data.get("paths", [])
            edges = data.get("edges", [])

            ni = {n.get("node_id"): n for n in nodes if n.get("node_id")}

            cp = []
            for i, path in enumerate(paths):
                steps = []
                for x in path:
                    n = ni.get(x, {})
                    steps.append({
                        "asset": n.get("asset_name", "?"),
                        "threat_id": n.get("threat_id"),
                        "threat_name": n.get("threat_name"),
                        "phase": n.get("phase"),
                        "tactic": n.get("tactic"),
                    })
                cp.append({
                    "path_id": f"P{i+1}",
                    "steps": steps
                })

            ut: dict = {}
            for n in nodes:
                tid = n.get("threat_id")
                if tid and tid not in ut:
                    ut[tid] = {
                        "id": tid,
                        "name": n.get("threat_name"),
                        "phase": n.get("phase"),
                        "tactic": n.get("tactic"),
                    }

            ad: dict = {}
            for n in nodes:
                a = n.get("asset_name")
                if a and a not in ad:
                    ad[a] = {
                        "asset_name": a,
                        "stencil_type": n.get("stencil_type"),
                        "category": n.get("category"),
                        "asset_type": n.get("asset_type"),
                        "asset_kind": n.get("asset_kind"),
                        "asset_properties": n.get("asset_properties", []),
                        "properties": n.get("properties", []),
                        "hardware": n.get("hardware", []),
                        "software": n.get("software", []),
                        "interfaces": n.get("interfaces", []),
                        "cwe_list": n.get("cwe_list", []),
                        "cve_list": n.get("cve_list", []),
                        "cwes": n.get("cwes", []),
                        "threats": n.get("threats", []),
                        "source": n.get("source"),
                        "cwe_count": n.get("cwe_count", 0),
                        "threat_count": n.get("threat_count", 0),
                    }

            r: dict = {
                "meta": {
                    "target_asset": data.get("target_asset_name", "?"),
                    "attack_mode": data.get("mode", "?"),
                    "boundary": data.get("boundary_name", "?"),
                    "total_paths": len(paths),
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                },
                "paths": cp,
                "unique_threats": list(ut.values()),
                "asset_details": list(ad.values()),
                "data_flows": [
                    {
                        "from": e.get("from"),
                        "to": e.get("to"),
                        "label": e.get("dfd_flow_label") or e.get("label"),
                    }
                    for e in edges
                ],
            }

            if additional_info:
                r["additional_system_context"] = additional_info

            return r
        
        summary = _compact(result_data)

        def _make_log(msg):
            self.after(0, lambda m=msg: self._log(m))

        def _make_progress(msg, pct=-1):
            self.after(0, lambda m=msg, p=pct: self._set_progress(m, p))

        _agent_kwargs = dict(
            provider        = provider,
            model           = user_model,
            gemini_client   = _gemini_client if provider == "gemini" else None,
            oai_client      = _oai_client    if provider in ("gpt", "ollama") else None,
            log_fn          = _make_log,
            set_progress_fn = _make_progress,
            repair_json_fn  = self._repair_json,
        )
        reviewer  = VehicleLevelReviewerAgent(**_agent_kwargs)
        generator = FunctionalLevelGeneratorAgent(**_agent_kwargs)

        self.after(0, lambda: self._log(
            f"[INFO] Agent-1 (Vehicle Reviewer) starting [{provider}/{user_model}]..."))
        self.after(0, lambda: self._set_progress("Agent-1: Vehicle-Level Review...", 55))
        vehicle_review = None
        try:
            vehicle_review = reviewer.run(summary=summary)
            self.after(0, lambda: self._log("[OK] Agent-1 complete."))
            self.after(0, lambda: self._set_progress("Agent-2: Functional Scenarios...", 70))
        except Exception as e:
            err_str = str(e)
            self.after(0, lambda m=err_str: self._log(
                f"[ERROR] Agent-1 (Vehicle Reviewer) failed: {m[:400]}"))
            _busy_kw = ["429","503","resource_exhausted","unavailable","quota",
                        "high demand","rate_limit","overloaded","too many requests"]
            _is_busy = any(x in err_str.lower() for x in _busy_kw)
            if _is_busy:
                self.after(0, lambda m=err_str, p=provider: messagebox.showerror(
                    "Agent-1 Rate-Limited",
                    f"Vehicle-level agent hit API rate/quota limit ({p}/{user_model}).\n\n"
                    f"Error detail:\n{m[:500]}\n\n"
                    "Solutions:\n"
                    "• Wait a few minutes and try again\n"
                    "• Switch to a paid API tier (higher TPM limit)\n"
                    "• Reduce the number of assets/threats in your graph\n"
                    "• Try Gemini (often more permissive free tier)"
                ))
            else:
                self.after(0, lambda m=err_str, p=provider: messagebox.showerror(
                    "Agent-1 Error",
                    f"Vehicle-level agent failed ({p}/{user_model}):\n\n{m[:500]}\n\n"
                    "Check: API key, model name, network connection.\n"
                    "Use the 'Test API' button to diagnose."
                ))

        func_data = None
        if vehicle_review:
            self.after(0, lambda: self._log(
                f"[INFO] Agent-2 (Functional Generator) starting [{provider}/{user_model}]..."))
            try:
                func_data = generator.run(
                    summary         = summary,
                    vehicle_review  = vehicle_review,
                    additional_info = additional_info,
                )
                self.after(0, lambda: self._log("[OK] Agent-2 complete."))
                self.after(0, lambda: self._set_progress("AI: Saving...", 90))
            except Exception as e:
                err_str = str(e)
                self.after(0, lambda m=err_str: self._log(
                    f"[ERROR] Agent-2 (Functional Generator) failed: {m[:500]}"))
                _busy_kw2 = ["429","503","resource_exhausted","unavailable","quota",
                             "high demand","rate_limit","overloaded","too many requests"]
                _is_busy2 = any(x in err_str.lower() for x in _busy_kw2)
                if _is_busy2:
                    self.after(0, lambda m=err_str: messagebox.showwarning(
                        "Agent-2 Rate-Limited",
                        f"Functional-level agent hit API rate/quota limit.\n\n"
                        f"Error detail:\n{m[:500]}\n\n"
                        "Vehicle-level review was saved.\n\n"
                        "Solutions:\n"
                        "• Wait a few minutes and try again\n"
                        "• Switch to a paid API tier (higher TPM limit)\n"
                        "• Reduce the number of assets/threats in your graph"
                    ))
                else:
                    self.after(0, lambda m=err_str: messagebox.showwarning(
                        "Agent-2 Warning",
                        f"Functional-level agent failed:\n\n{m[:500]}\n\n"
                        "Vehicle-level review was saved. Functional tab will be empty."
                    ))

        _backend_json = None
        _ag_candidates = sorted(out_dir.glob("_ag_tmp_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if _ag_candidates:
            _backend_json = str(_ag_candidates[0])
        bundle = {
            "vehicle_level_review": vehicle_review.get("vehicle_level_review", vehicle_review) if vehicle_review else None,
            "functional_level_analysis": func_data.get("functional_level_analysis", func_data) if func_data else None,
            "target_asset": result_data.get("target_asset_name"),
            "attack_mode": result_data.get("mode"),
            "boundary_name": result_data.get("boundary_name", ""),
            "additional_info_used": additional_info or None,
            "backend_json_path": _backend_json,
        }
        gpath = out_dir / "gemini_analysis.json"

        try:
            with open(gpath, "w", encoding="utf-8") as f:
                json.dump(bundle, f, ensure_ascii=False, indent=2)
            self.after(0, lambda p=str(gpath): self._log(f"[OK] AI analysis saved: {p}"))


            _vr_embed = ({"vehicle_level_review": bundle["vehicle_level_review"]}
                         if bundle.get("vehicle_level_review") else None)
            _fa_embed = ({"functional_level_analysis": bundle["functional_level_analysis"]}
                         if bundle.get("functional_level_analysis") else None)
            _html_path = self._report_html_path

            if _html_path and Path(_html_path).exists():
                self.after(0, lambda: self._log(
                    "[INFO] Injecting AI results into HTML report..."))
                _ok = self._embed_ai_into_report(_html_path, _vr_embed, _fa_embed)
                if _ok:
                    self.after(0, lambda: self._log(
                        "[OK] AI results injected into HTML report successfully."))
                else:
                    self.after(0, lambda: self._log(
                        "[WARN] Direct HTML injection failed — trying backend regeneration..."))
                    self._regenerate_final_report_from_backend()
            else:

                self.after(0, lambda: self._log(
                    "[INFO] No existing report found — regenerating via backend..."))
                self._regenerate_final_report_from_backend()

            return str(gpath)
        except Exception as e:
            self.after(0, lambda err=e: self._log(
                f"[WARN] Could not save gemini_analysis.json: {err}"))
            return None

    def _regenerate_final_report_from_backend(self):
        """Re-run backend so it loads gemini_analysis.json and generates the final HTML in one shot."""
        try:
            backend_path = Path(self.backend_path).resolve()

            self.after(0, lambda: self._log("[INFO] Regenerating final report from backend..."))

            run_bundle = run_path_filter(
                backend_path=backend_path,
                tm7_path=self.v_tm7.get(),
                mode=self.v_mode.get(),
                target=self.v_target.get().strip(),
                boundary=self.v_boundary.get().strip(),
                asset_map=self.v_asset.get(),
                threat_map=self.v_threat.get(),
                av_map=self.v_av.get(),
                dep_map=self.v_dep.get(),
                impact_map=self.v_impact.get(),
                max_depth=int(self.v_depth.get() or 30),
                llm_api_key="",  
            )

            report_html = run_bundle.get("report_html")
            backend_stderr = (run_bundle.get("backend_stderr") or "").strip()

            if not report_html:
                out_dir_fb = Path(self.v_out_dir.get())
                html_files = sorted(
                    out_dir_fb.glob("*.html"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True
                ) if out_dir_fb.exists() else []
                if html_files:
                    report_html = str(html_files[0])

            if report_html and Path(report_html).exists():
                self._report_html_path = report_html
                self.after(0, lambda p=report_html: self._log(f"[OK] Final report HTML: {p}"))
                return True

            if backend_stderr:
                self.after(0, lambda e=backend_stderr: self._log(f"[WARN] Backend stderr:\n{e}"))

            self.after(0, lambda: self._log("[WARN] Final report HTML was not generated."))
            return False

        except Exception:
            err = traceback.format_exc()
            self.after(0, lambda e=err: self._log(f"[ERROR] Report regeneration failed:\n{e}"))
            return False
    
    def _save(self):
        if not self._mapping_cache:
            messagebox.showinfo("Info", "Please run the analysis first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("CSV","*.csv")],
            initialfile=f"attack_paths_{datetime.now():%Y%m%d_%H%M%S}.json"
        )
        if not p:
            return

        if p.endswith(".csv"):
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(build_full_csv(self._mapping_cache, self._paths_cache or []))
        else:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(
                    build_full_json(self._mapping_cache, self._paths_cache or [], {}),
                    f, ensure_ascii=False, indent=2
                )
        messagebox.showinfo("Saved", p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default=None)
    args = ap.parse_args()
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    AttackPathsGUI(backend_script=args.backend).mainloop()


if __name__ == "__main__":
    main()
