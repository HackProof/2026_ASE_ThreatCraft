#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse, csv, io, json, os, subprocess, sys, threading, traceback
import tkinter as tk
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Set, Tuple


_SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BACKEND    = (_SCRIPT_DIR / "../../backend/parse_attack_graph_automotive.py").resolve()
DEFAULT_ASSET_MAP  = (_SCRIPT_DIR / "../../backend/threat_library/automotive/asset_to_threats_automotive.json").resolve()
DEFAULT_THREAT_MAP = (_SCRIPT_DIR / "../../backend/threat_library/automotive/threat_to_tactic_automotive.json").resolve()
DEFAULT_AV_MAP     = (_SCRIPT_DIR / "../../backend/threat_library/automotive/attack_vector_feasibility_automotive.json").resolve()
DEFAULT_DEP_MAP    = (_SCRIPT_DIR / "../../backend/threat_library/automotive/dependency_automotive.json").resolve()
DEFAULT_IMPACT_MAP = (_SCRIPT_DIR / "../../backend/threat_library/automotive/impact_map_automotive.json").resolve()
DEFAULT_OUT_DIR    = (_SCRIPT_DIR / "../../out").resolve()
HIERARCHY_JSON     = _SCRIPT_DIR / "hierarchy_data_automotive.json"

_H: Optional[dict] = None
def _load_h() -> dict:
    global _H
    if _H is None:
        if not HIERARCHY_JSON.exists():
            raise FileNotFoundError(f"hierarchy_data_automotive.json not found: {HIERARCHY_JSON}")
        with open(HIERARCHY_JSON, encoding="utf-8") as f:
            _H = json.load(f)
    return _H

def _list_cats() -> List[str]: return list(_load_h().keys())
def _list_types(cat): return list(_load_h().get(cat, {}).keys())
def _list_kinds(cat, typ): return list(_load_h().get(cat,{}).get(typ,{}).get("kinds",{}).keys())
def _list_props(cat, typ, knd):
    k = _load_h().get(cat,{}).get(typ,{}).get("kinds",{}).get(knd,{})
    p = k.get("properties",{}); return list(p.keys()) if isinstance(p,dict) else []
def _get_source(cat, typ, knd):
    return _load_h().get(cat,{}).get(typ,{}).get("kinds",{}).get(knd,{}).get("source","")

def _get_cwes_merged(cat, typ, knd, props=None):
    if not (cat and typ and knd): return []
    kd  = _load_h().get(cat,{}).get(typ,{}).get("kinds",{}).get(knd,{})
    src = kd.get("source","")
    merged: Dict[str,dict] = {}
    def _add(c, origin):
        cid = str(c.get("id","")).strip()
        if not cid: return
        entry = dict(c); entry.setdefault("sources",[])
        if origin not in entry["sources"]: entry["sources"].append(origin)
        if cid not in merged:
            merged[cid] = entry
        else:
            ex = merged[cid]
            if len(str(c.get("name","")))>len(str(ex.get("name",""))): ex["name"]=c["name"]
            if len(str(c.get("desc","") or ""))>len(str(ex.get("desc","") or "")): ex["desc"]=c["desc"]
            if ex.get("likelihood","—") in ("—",None,"") and c.get("likelihood","—") not in ("—",None,""): ex["likelihood"]=c["likelihood"]
            if origin not in ex.get("sources",[]): ex.setdefault("sources",[]).append(origin)
    if src=="CWE-1000":
        for c in kd.get("cwes",[]): _add(c,"CWE-1000")
        for c in kd.get("emb3d_extra_cwes",[]): _add(c,"EMB3D")
    elif src=="EMB3D":
        all_p = kd.get("properties",{}) or {}
        if isinstance(all_p,dict):
            targets = props if props else list(all_p.keys())
            for p in targets:
                for c in (all_p.get(p) or {}).get("cwes") or []: _add(c,"EMB3D")
    return list(merged.values())

def _get_cwes(cat,typ,knd,prop=None): return _get_cwes_merged(cat,typ,knd,[prop] if prop else None)

def _get_threats_from_hierarchy(cat, typ, knd, props=None):
    if not (cat and typ and knd): return []
    kd = _load_h().get(cat,{}).get(typ,{}).get("kinds",{}).get(knd,{})
    result_threats = []
    seen: Set[str] = set()
    if kd.get("source") == "CWE-1000":
        for t in kd.get("emb3d_threats",[]):
            k = t.get("tid","")
            if k and k not in seen: seen.add(k); result_threats.append(t)
        return result_threats
    if kd.get("source") != "EMB3D": return []
    all_p = kd.get("properties",{}) or {}
    if not isinstance(all_p,dict): return []
    targets = props if props else list(all_p.keys())
    for p in targets:
        for t in (all_p.get(p) or {}).get("threats") or []:
            k = t.get("tid","")
            if k not in seen: seen.add(k); result_threats.append(t)
    return result_threats

def _get_threats(cat,typ,knd,prop=None): return _get_threats_from_hierarchy(cat,typ,knd,[prop] if prop else None)

def _get_dfd_threats(asset_name, at_data):
    if not at_data or not asset_name: return []
    for a in at_data.get("assets",[]):
        if a.get("asset_name","") == asset_name: return a.get("threats",[])
    return []

def _merge_threats(hierarchy_threats, dfd_threats):
    seen: Set[str] = set(); out = []
    for t in hierarchy_threats:
        k = t.get("tid","")
        if k and k not in seen: seen.add(k); out.append({**t,"_src":"EMB3D"})
    for t in dfd_threats:
        k = t.get("id","")
        if k and k not in seen:
            seen.add(k)
            out.append({"tid":k,"name":t.get("name",""),"tactics":t.get("tactics",[]),
                        "cwes":[],"cves":[],"maturity":"","_src":"asset_map"})
    return out

def _center(win, w, h):
    win.update_idletasks()
    sw,sh=win.winfo_screenwidth(),win.winfo_screenheight()
    win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

def run_path_filter(backend_path,tm7_path,mode,target,boundary,
                    asset_map,threat_map,av_map,dep_map,impact_map,
                    max_depth=30, llm_api_key=None):
    DEFAULT_OUT_DIR.mkdir(parents=True,exist_ok=True)
    ts=datetime.now().strftime("%H%M%S%f")
    out_json=str(DEFAULT_OUT_DIR/f"_ag_tmp_{ts}.json")
    tmp_report=str(DEFAULT_OUT_DIR/f"_ag_tmp_{ts}.html")
    merged_prefix=str(DEFAULT_OUT_DIR/f"_ag_graph_{ts}")
    merged_png=str(Path(merged_prefix).with_suffix(".png"))

    cmd=[sys.executable,str(backend_path),
         "--tm7",tm7_path,"--type",mode,"--target",target,
         "--boundary",boundary or "","--asset-map",asset_map,
         "--threat-map",threat_map,"--attack-vector-map",av_map,
         "--dependency-map",dep_map,"--impact-map",impact_map,
         "--max-depth",str(max_depth),"--out",out_json,
         "--render-merged-graph",
         "--merged-graph-out",merged_prefix,
         "--merged-graph-format","png",
         "--no-render-attack-tree",
         "--detection-report",tmp_report]

    if llm_api_key:
        cmd.extend(["--llm-api-key", llm_api_key])

    proc=subprocess.run(cmd,cwd=str(backend_path.parent),
                        capture_output=True,text=True,encoding="utf-8",errors="replace")
    out_file=Path(out_json)
    if not out_file.exists():
        raise RuntimeError(f"Backend failed (code={proc.returncode}):\n{(proc.stderr or proc.stdout or '')[:600]}")

    with open(out_file,encoding="utf-8") as f:
        result=json.load(f)

    report_html = tmp_report if Path(tmp_report).exists() else None

    return {
        "result": result,
        "attack_graph_png": merged_png if Path(merged_png).exists() else None,
        "report_html": report_html,
        "backend_stdout": proc.stdout or "",
        "backend_stderr": proc.stderr or "",
    }


def extract_elements(result):
    PRI={"Out":3,"Through":2,"In":1,"Entry":0}
    asset_phase: Dict[str,str]={}
    asset_name:  Dict[str,str]={}
    for n in result.get("nodes",[]):
        g,ph,nm=n.get("asset_guid",""),n.get("phase",""),n.get("asset_name","")
        if not g: continue
        asset_name[g]=nm
        if PRI.get(ph,-1)>PRI.get(asset_phase.get(g,""),-1): asset_phase[g]=ph
    elements=[]
    for g,nm in asset_name.items():
        elements.append({"name":nm,"type":"node","phase":asset_phase.get(g,"?"),"asset_guid":g})
    seen=set()
    for e in result.get("edges",[]):
        fg=e.get("dfd_flow_guid","")
        if not fg or fg in seen: continue
        seen.add(fg)
        fn,tn=e.get("from",""),e.get("to","")
        sg=fn.split("::")[0] if "::" in fn else fn
        tg=tn.split("::")[0] if "::" in tn else tn
        lbl=e.get("dfd_flow_label","") or ""
        elements.append({"name":f"{asset_name.get(sg,sg[:10])} → {asset_name.get(tg,tg[:10])}"+(f" [{lbl}]" if lbl else ""),
                          "type":"edge","phase":asset_phase.get(sg,"?"),
                          "asset_guid":fg,"src_guid":sg,"tgt_guid":tg,"label":lbl})
    ORDER={"In":0,"Entry":1,"Through":2,"Out":3}
    elements.sort(key=lambda x:ORDER.get(x.get("phase",""),9))
    return elements


def build_attack_graph_dot(result: dict, mapping: List[dict]) -> str:
    node_idx = {n['node_id']: n for n in result.get('nodes',[])}
    asset_nm = {n['asset_guid']: n['asset_name'] for n in result.get('nodes',[])}
    for path in result.get('paths',[]):
        for nid in path:
            if nid not in node_idx:
                g=nid.split('::')[0]
                node_idx[nid]={'asset_guid':g,'asset_name':asset_nm.get(g,'Entry'),
                               'phase':'Entry','threat_id':None,'threat_name':None,'tactic':None}
    map_idx = {m['name']: m for m in mapping}

    PH_COLOR = {"In":"#1B7C2E","Through":"#C85000","Out":"#B71C1C","Entry":"#555555"}
    PH_FILL  = {"In":"#EAF3DE","Through":"#FAEEDA","Out":"#FCEBEB","Entry":"#F1EFE8"}
    EDGE_COLOR= {"In":"#1B7C2E","Through":"#C85000","Out":"#B71C1C","Entry":"#888888"}

    PRI={"Out":3,"Through":2,"In":1,"Entry":0}
    asset_phase: Dict[str,str]={}
    asset_threats: Dict[str,List[str]]=defaultdict(list)
    for n in result.get('nodes',[]):
        g,ph=n.get('asset_guid',''),n.get('phase','')
        if PRI.get(ph,-1)>PRI.get(asset_phase.get(g,''),-1): asset_phase[g]=ph
        if n.get('threat_id'): asset_threats[n['asset_guid']].append(n['threat_id'])

    seen_edges: Set[Tuple[str,str]]=set()
    edges_out: List[Tuple[str,str,str,str]]=[]
    for e in result.get('edges',[]):
        fn=e.get('from',''); tn=e.get('to','')
        sg=fn.split('::')[0] if '::' in fn else fn
        tg=tn.split('::')[0] if '::' in tn else tn
        if (sg,tg) in seen_edges: continue
        seen_edges.add((sg,tg))
        ph=asset_phase.get(sg,'Entry')
        lbl=e.get('dfd_flow_label','') or ''
        edges_out.append((sg,tg,lbl,ph))

    def get_mapped_threats(asset_name):
        m=map_idx.get(asset_name,{})
        threats=m.get('threats',[])
        return threats[:4]

    lines=[]
    lines.append('digraph attack_graph {')
    lines.append('  graph [rankdir=LR fontname="Arial" bgcolor="white" pad=0.5 splines=ortho nodesep=0.6 ranksep=1.2]')
    lines.append('  node  [fontname="Arial" fontsize=10 style="filled,rounded" shape=box margin="0.15,0.08"]')
    lines.append('  edge  [fontname="Arial" fontsize=8 arrowsize=0.7]')
    lines.append('')

    entry_gs=[g for g,ph in asset_phase.items() if ph=='Entry']
    in_gs   =[g for g,ph in asset_phase.items() if ph=='In']
    thr_gs  =[g for g,ph in asset_phase.items() if ph=='Through']
    out_gs  =[g for g,ph in asset_phase.items() if ph=='Out']

    def sanitize(s): return s.replace('"','\\\"').replace('\n','\\n')
    def node_id(g): return f"n_{g.replace('-','_').replace('{','').replace('}','')[:30]}"

    for g, ph in asset_phase.items():
        nm  = asset_nm.get(g,g[:12])
        col = PH_COLOR.get(ph,'#555')
        fill= PH_FILL.get(ph,'#F5F5F5')
        m   = map_idx.get(nm,{})
        cats_list = m.get('categories') or []
        kind_parts = [(c.get('asset_kind_full') or c.get('asset_kind') or '') for c in cats_list
                      if (c.get('asset_kind_full') or c.get('asset_kind'))]
        kind= ' | '.join(kind_parts) if kind_parts else (
              m.get('asset_kind_full') or m.get('asset_kind','') or '')
        threats_in_graph = list(dict.fromkeys(asset_threats.get(g,[])))[:3]
        mapped_threats   = get_mapped_threats(nm)
        n_cwe  = m.get('cwe_count',0)
        n_thr  = m.get('threat_count',0)
        n_cat  = len(cats_list)

        label_parts=[f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="1" CELLPADDING="3">']
        elem_type = m.get('type','node')
        type_badge = "NODE" if elem_type=="node" else "EDGE"
        type_color = "#1B5E20" if elem_type=="node" else "#0D47A1"
        label_parts.append(f'<TR><TD ALIGN="LEFT"><B><FONT COLOR="{col}">{sanitize(nm)}</FONT></B>  <FONT COLOR="{type_color}" POINT-SIZE="8">[{type_badge}]</FONT></TD></TR>')
        label_parts.append(f'<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8" COLOR="#888888">{ph}</FONT></TD></TR>')
        if kind:
            label_parts.append(f'<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8" COLOR="#444">{sanitize(kind)}</FONT></TD></TR>')
        if n_cwe or n_thr or n_cat:
            label_parts.append(f'<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8" COLOR="#555">Cats:{n_cat}  CWE:{n_cwe}  Threats:{n_thr}</FONT></TD></TR>')
        if threats_in_graph:
            thr_str = ', '.join(threats_in_graph)
            label_parts.append(f'<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="7" COLOR="#854F0B">{sanitize(thr_str)}</FONT></TD></TR>')
        if mapped_threats:
            tname = sanitize(mapped_threats[0].get('name','')[:35])
            label_parts.append(f'<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="7" COLOR="#1565C0">{tname}</FONT></TD></TR>')
        label_parts.append('</TABLE>>')
        label = ''.join(label_parts)
        lines.append(f'  {node_id(g)} [label={label} fillcolor="{fill}" color="{col}" penwidth=1.5]')

    lines.append('')
    if entry_gs: lines.append('  { rank=same; '+'; '.join(node_id(g) for g in entry_gs)+' }')
    if in_gs:    lines.append('  { rank=same; '+'; '.join(node_id(g) for g in in_gs)+' }')
    if thr_gs:   lines.append('  { rank=same; '+'; '.join(node_id(g) for g in thr_gs)+' }')
    if out_gs:   lines.append('  { rank=same; '+'; '.join(node_id(g) for g in out_gs)+' }')

    lines.append('')
    for sg,tg,lbl,ph in edges_out:
        col=EDGE_COLOR.get(ph,'#888')
        lbl_str = f' label="{sanitize(lbl)}"' if lbl else ''
        lines.append(f'  {node_id(sg)} -> {node_id(tg)} [color="{col}" fontcolor="{col}"{lbl_str}]')

    lines.append('}')
    return '\n'.join(lines)

def render_graphviz(dot_src: str, out_path: str) -> bool:
    try:
        result = subprocess.run(
            ['dot','-Tpng','-o',out_path],
            input=dot_src, capture_output=True, text=True,
            encoding='utf-8', timeout=30)
        return result.returncode == 0 and Path(out_path).exists()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class _PropPickerDialog(tk.Toplevel):
    def __init__(self, parent, props, selected):
        super().__init__(parent); self.title("Select Properties")
        self.resizable(False,False); self.grab_set()
        self.result=None; self._vars=[]; self._props=props
        tk.Label(self,text="Select properties (multiple selection allowed)",
                 font=("Arial",10,"bold"),pady=8).pack(fill="x",padx=14)
        tk.Frame(self,height=1,bg="#DDD").pack(fill="x")
        frm=tk.Frame(self); frm.pack(fill="both",expand=True,padx=10,pady=6)
        canvas=tk.Canvas(frm,highlightthickness=0,height=min(len(props)*26,380))
        sb=ttk.Scrollbar(frm,orient="vertical",command=canvas.yview)
        inner=tk.Frame(canvas)
        inner.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0),window=inner,anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right",fill="y"); canvas.pack(side="left",fill="both",expand=True)
        for p in props:
            v=tk.BooleanVar(value=(p in selected)); self._vars.append(v)
            tk.Checkbutton(inner,text=p,variable=v,font=("Arial",9),
                           anchor="w",wraplength=520).pack(fill="x",padx=4,pady=1)
        tk.Frame(self,height=1,bg="#DDD").pack(fill="x")
        bot=tk.Frame(self,pady=6); bot.pack()
        tk.Button(bot,text="Select All",font=("Arial",9),relief="flat",bg="#F0F0F0",padx=10,
                  command=lambda:[v.set(True) for v in self._vars]).pack(side="left",padx=4)
        tk.Button(bot,text="Deselect All",font=("Arial",9),relief="flat",bg="#F0F0F0",padx=10,
                  command=lambda:[v.set(False) for v in self._vars]).pack(side="left",padx=4)
        tk.Button(bot,text="OK",font=("Arial",10,"bold"),relief="flat",
                  bg="#1565C0",fg="white",padx=16,command=self._ok).pack(side="left",padx=8)
        tk.Button(bot,text="Cancel",font=("Arial",9),relief="flat",
                  bg="#F0F0F0",padx=10,command=self.destroy).pack(side="left",padx=2)
        self.update_idletasks()
        w=min(max(self.winfo_reqwidth(),420),640); h=self.winfo_reqheight()
        _center(self,w,h)
    def _ok(self):
        self.result=[p for v,p in zip(self._vars,self._props) if v.get()]; self.destroy()


class AssetMapDialog(tk.Toplevel):
    def __init__(self, parent, elements, at_data=None):
        super().__init__(parent); self.title("Asset Property Mapping")
        self.geometry("1180x720"); self.minsize(1000,500)
        _center(self,1180,720); self.configure(bg="white"); self.grab_set()
        self.elements=elements; self.at_data=at_data
        self.rows=[]; self.confirmed=False; self._build()

    def _build(self):
        hdr=tk.Frame(self,bg="#1C2333"); hdr.pack(fill="x")
        tk.Label(hdr,text=f"Identified Assets / Data Flows ({len(self.elements)})",
                font=("Arial",11,"bold"),fg="white",bg="#1C2333",pady=8).pack(side="left",padx=14)
        tk.Label(hdr,text="Click [+ Add Category] to assign multiple categories per element",
                 font=("Arial",9,"italic"),fg="#AACCFF",bg="#1C2333").pack(side="right",padx=14)

        wrap=tk.Frame(self,bg="#F0F0F4"); wrap.pack(fill="both",expand=True)
        canvas=tk.Canvas(wrap,bg="#F0F0F4",highlightthickness=0)
        sb=ttk.Scrollbar(wrap,orient="vertical",command=canvas.yview)
        self._sf=tk.Frame(canvas,bg="#F0F0F4")
        self._sf.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        _cw=canvas.create_window((0,0),window=self._sf,anchor="nw")
        canvas.configure(yscrollcommand=sb.set)

        canvas.bind("<Configure>",lambda e:canvas.itemconfig(_cw,width=e.width))
        sb.pack(side="right",fill="y"); canvas.pack(side="left",fill="both",expand=True)
        canvas.bind_all("<MouseWheel>",lambda e:canvas.yview_scroll(-1*(e.delta//120),"units"))
        for i,el in enumerate(self.elements):
            row=_MapRow(self._sf,i,el,self.at_data)
            row.frame.pack(fill="x",padx=6,pady=4)
            self.rows.append(row)

        bot=tk.Frame(self,bg="#F8F8F8"); bot.pack(fill="x",side="bottom")
        tk.Frame(bot,height=1,bg="#DDD").pack(fill="x")
        bkw=dict(font=("Arial",10,"bold"),relief="flat",bd=0,padx=14,pady=6,cursor="hand2")
        tk.Button(bot,text="Reset All",bg="#ECEFF1",fg="#37474F",
                  command=lambda:[r.clear() for r in self.rows],**bkw).pack(side="left",padx=10,pady=5)
        tk.Button(bot,text="Cancel",bg="#ECEFF1",fg="#37474F",
                  command=self.destroy,**bkw).pack(side="right",padx=6,pady=5)
        tk.Button(bot,text="OK",bg="#1565C0",fg="white",
                  command=self._ok,**bkw).pack(side="right",padx=2,pady=5)

    def _ok(self): self.confirmed=True; self.destroy()
    def get_mapping(self): return [r.to_dict() for r in self.rows]


class _MapRow:
    def __init__(self, parent, idx, el, at_data=None):
        self.idx=idx; self.el=el; self.at_data=at_data
        self.entries: List[_CategoryEntry] = []
        ph=el.get("phase","?")
        etype=el.get("type","node")
        if etype=="edge":
            bg="#EEF4FF"
        else:
            bg={"In":"#F3FFF5","Out":"#FFF3F3","Through":"#FFFCF0","Entry":"#F6F6F6"}.get(ph,"white")
        self.bg=bg


        self.frame=tk.Frame(parent,bg=bg,highlightthickness=1,highlightbackground="#C9CED6")
        self._build_header(bg,ph,etype)


        self.cats_frame=tk.Frame(self.frame,bg=bg)
        self.cats_frame.pack(fill="x",padx=10,pady=(0,2))


        btnf=tk.Frame(self.frame,bg=bg)
        btnf.pack(fill="x",padx=10,pady=(2,8))
        self._add_btn=tk.Button(btnf,text="＋  Add Category",font=("Arial",9,"bold"),
                                 relief="flat",bg="#E3F2FD",fg="#1565C0",
                                 cursor="hand2",padx=12,pady=3,bd=0,
                                 command=self._add_entry)
        self._add_btn.pack(side="left")
        self._count_lbl=tk.Label(btnf,text="",bg=bg,
                                  font=("Arial",8,"italic"),fg="#555")
        self._count_lbl.pack(side="left",padx=12)

        self._add_entry()

    def _build_header(self, bg, ph, etype):
        hdr=tk.Frame(self.frame,bg=bg)
        hdr.pack(fill="x",padx=10,pady=(6,4))

        tk.Label(hdr,text=f"#{self.idx+1}",bg=bg,font=("Arial",9,"bold"),
                 fg="#555",width=4,anchor="w").pack(side="left")

        tc="#1B5E20" if etype=="node" else "#0D47A1"
        tbg="#E8F5E9" if etype=="node" else "#E3F2FD"
        tk.Label(hdr,text="NODE" if etype=="node" else "EDGE",
                 bg=tbg,font=("Arial",8,"bold"),fg=tc,
                 width=6,anchor="center",padx=4,
                 relief="solid",bd=1).pack(side="left",padx=(0,6))

        tk.Label(hdr,text=self.el.get("name","?")[:55],
                 bg=bg,font=("Arial",10,"bold"),fg="#1A1A1A",
                 anchor="w").pack(side="left",padx=4)

        ph_clr={"In":"#1B5E20","Through":"#E65100","Out":"#C62828","Entry":"#777"}.get(ph,"#555")
        tk.Label(hdr,text=f"[{ph}]",bg=bg,font=("Arial",9,"bold"),
                 fg=ph_clr).pack(side="left",padx=6)

        dfd_threats=_get_dfd_threats(self.el.get("name",""),self.at_data)
        preview=", ".join(t.get("id","") for t in dfd_threats[:3])
        if len(dfd_threats)>3: preview+=f" +{len(dfd_threats)-3}"
        tk.Label(hdr,text=f"DFD Threats: {preview or '—'}",
                 bg=bg,font=("Arial",8),fg="#1565C0",
                 anchor="e").pack(side="right",padx=4)

    def _add_entry(self):
        entry=_CategoryEntry(self.cats_frame,self)
        entry.frame.pack(fill="x",pady=1)
        self.entries.append(entry)
        self._update_count()

    def _remove_entry(self, entry):
        if len(self.entries) <= 1:
            entry.clear()
            self._update_count()
            return
        entry.frame.destroy()
        if entry in self.entries:
            self.entries.remove(entry)
        self._update_count()

    def _update_count(self):
        total=len(self.entries)
        filled=sum(1 for e in self.entries if e.is_filled())
        self._count_lbl.config(text=f"Categories: {filled}/{total}  (Union CWE: {self._union_cwe_count()})")

    def _union_cwe_count(self):
        seen: Set[str]=set()
        for e in self.entries:
            if not e.is_filled(): continue
            for c in _get_cwes_merged(e.v_cat.get(),e.v_type.get(),e.v_kind.get(),
                                       e._selected_props or None):
                cid=str(c.get("id",""))
                if cid: seen.add(cid)
        return len(seen)

    def notify_change(self):
        self._update_count()

    def clear(self):
        while len(self.entries)>1:
            e=self.entries.pop()
            e.frame.destroy()
        if self.entries:
            self.entries[0].clear()
        self._update_count()

    def to_dict(self):
        categories_list: List[dict] = []
        all_cwes: List[dict] = []
        seen_cwe_ids: Set[str] = set()
        all_hier_threats: List[dict] = []
        seen_tids: Set[str] = set()

        for entry in self.entries:
            if not entry.is_filled(): continue
            ed=entry.to_dict()
            categories_list.append(ed)
            cat,typ,knd=ed["category"],ed["asset_type"],ed["asset_kind"]
            props=ed["asset_properties"] or None

            for c in _get_cwes_merged(cat,typ,knd,props):
                cid=str(c.get("id",""))
                if cid and cid not in seen_cwe_ids:
                    seen_cwe_ids.add(cid); all_cwes.append(c)

            for t in _get_threats_from_hierarchy(cat,typ,knd,props):
                tid=t.get("tid","")
                if tid and tid not in seen_tids:
                    seen_tids.add(tid); all_hier_threats.append(t)

        dfd_thr=_get_dfd_threats(self.el.get("name",""),self.at_data)
        threats=_merge_threats(all_hier_threats,dfd_thr)

        primary=categories_list[0] if categories_list else {
            "category":None,"asset_type":None,"asset_kind":None,
            "asset_kind_detail":None,"asset_kind_full":None,
            "asset_properties":[],"source":None}

        return {
            "name": self.el.get("name",""),
            "type": self.el.get("type","node"),
            "phase": self.el.get("phase",""),
            "asset_guid": self.el.get("asset_guid",""),
            "category":          primary.get("category"),
            "asset_type":        primary.get("asset_type"),
            "asset_kind":        primary.get("asset_kind"),
            "asset_kind_detail": primary.get("asset_kind_detail"),
            "asset_kind_full":   primary.get("asset_kind_full") or primary.get("asset_kind"),
            "asset_properties":  primary.get("asset_properties") or [],
            "source":            primary.get("source"),
            "categories":        categories_list,
            "category_count":    len(categories_list),
            "cwes":              all_cwes,
            "cwe_count":         len(all_cwes),
            "threats":           threats,
            "threat_count":      len(threats),
        }


class _CategoryEntry:
    def __init__(self, parent, row: _MapRow):
        self.row=row
        self.v_cat=tk.StringVar()
        self.v_type=tk.StringVar()
        self.v_kind=tk.StringVar()
        self.v_detail=tk.StringVar()
        self.v_ncwe=tk.StringVar(value="—")
        self._selected_props: List[str] = []
        self.frame=tk.Frame(parent,bg=row.bg)
        self._build(row.bg)

        self.v_cat.trace_add("write",self._on_cat)
        self.v_type.trace_add("write",self._on_type_changed)
        self.v_kind.trace_add("write",self._on_kind_changed)

        self.cb_type.bind("<<ComboboxSelected>>",self._on_type_selected)
        self.cb_kind.bind("<<ComboboxSelected>>",self._on_kind_selected)

    def _build(self, bg):
        f=self.frame

        tk.Label(f,text="•",bg=bg,font=("Arial",12,"bold"),fg="#888",
                 width=2).pack(side="left")

        self.cb_cat=ttk.Combobox(f,textvariable=self.v_cat,width=14,
                                  state="readonly",font=("Arial",9))
        self.cb_cat["values"]=_list_cats()
        self.cb_cat.pack(side="left",padx=2,pady=2)

        self.cb_type=ttk.Combobox(f,textvariable=self.v_type,width=16,
                                   state="disabled",font=("Arial",9))
        self.cb_type.pack(side="left",padx=2,pady=2)


        self.cb_kind=ttk.Combobox(f,textvariable=self.v_kind,width=18,
                                   state="disabled",font=("Arial",9))
        self.cb_kind.pack(side="left",padx=2,pady=2)


        tk.Label(f,text="＋",bg=bg,font=("Arial",10,"bold"),
                 fg="#4A90E2").pack(side="left",padx=(4,0))
        self.e_detail=tk.Entry(f,textvariable=self.v_detail,width=12,
                                font=("Arial",9),bg="white",
                                relief="solid",bd=1,
                                disabledbackground="#EEE",
                                disabledforeground="#AAA",
                                state="disabled")
        self.e_detail.pack(side="left",padx=(0,2),pady=2)


        self._pbtn=tk.Button(f,text="Select Properties",width=16,
                              font=("Arial",8),relief="flat",bd=1,
                              bg="#E8F0FE",fg="#1A73E8",cursor="hand2",
                              state="disabled",command=self._pick)
        self._pbtn.pack(side="left",padx=2,pady=2)


        tk.Label(f,text="CWE",bg=bg,font=("Arial",8),fg="#666"
                 ).pack(side="left",padx=(8,0))
        tk.Label(f,textvariable=self.v_ncwe,bg="#FFF8F0",width=4,
                 font=("Arial",9,"bold"),fg="#E65100",relief="solid",bd=1,
                 anchor="center").pack(side="left",padx=2)


        self._del_btn=tk.Button(f,text="✕",font=("Arial",9,"bold"),
                                 relief="flat",bg="#FFEBEE",fg="#C62828",
                                 width=2,cursor="hand2",bd=0,
                                 command=self._on_delete)
        self._del_btn.pack(side="left",padx=(10,4))


    def _on_delete(self):
        self.row._remove_entry(self)

    def _on_cat(self,*_):
        cat=self.v_cat.get()
        self.v_type.set(""); self.v_kind.set(""); self.v_detail.set("")
        self._selected_props=[]; self._upbtn(); self.v_ncwe.set("—")
        if cat:
            self.cb_type["state"]="normal"   # editable
            self.cb_type["values"]=_list_types(cat)
        else:
            self.cb_type["state"]="disabled"
            self.cb_type["values"]=[]
        self.cb_kind["state"]="disabled"; self.cb_kind["values"]=[]
        self._pbtn["state"]="disabled"
        self.e_detail["state"]="disabled"
        self.row.notify_change()

    def _on_type_selected(self, event=None):
        cat=self.v_cat.get(); typ=self.v_type.get()
        self.v_kind.set(""); self.v_detail.set("")
        self._selected_props=[]; self._upbtn(); self.v_ncwe.set("—")
        kinds=_list_kinds(cat,typ) if (cat and typ) else []
        self.cb_kind["state"]="normal"   # editable
        self.cb_kind["values"]=kinds
        self._pbtn["state"]="disabled"
        self.e_detail["state"]="disabled"

    def _on_type_changed(self,*_):
        cat=self.v_cat.get(); typ=self.v_type.get()
        if not typ:
            self.cb_kind["state"]="disabled"; self.cb_kind["values"]=[]
            self._pbtn["state"]="disabled"
            self.e_detail["state"]="disabled"
            self.v_ncwe.set("—")
        else:
            if str(self.cb_kind["state"])=="disabled":
                self.cb_kind["state"]="normal"
                self.cb_kind["values"]=_list_kinds(cat,typ) if cat else []
            self._upcwe()
        self.row.notify_change()

    def _on_kind_selected(self, event=None):
        cat=self.v_cat.get(); typ=self.v_type.get(); knd=self.v_kind.get()
        self._selected_props=[]; self.v_detail.set("")
        self._upbtn()
        props=_list_props(cat,typ,knd) if (cat and typ and knd) else []
        self._pbtn["state"]="normal" if props else "disabled"
        self.e_detail["state"]="normal"
        self._upcwe()

    def _on_kind_changed(self,*_):
        cat=self.v_cat.get(); typ=self.v_type.get(); knd=self.v_kind.get()
        if not knd:
            self._pbtn["state"]="disabled"
            self.e_detail["state"]="disabled"
            self.v_ncwe.set("—")
        else:
            if str(self.e_detail["state"])=="disabled":
                self.e_detail["state"]="normal"
            props=_list_props(cat,typ,knd) if (cat and typ) else []
            if props and str(self._pbtn["state"])=="disabled":
                self._pbtn["state"]="normal"
            elif not props:
                self._pbtn["state"]="disabled"
                if self._selected_props:
                    self._selected_props=[]; self._upbtn()
            self._upcwe()
        self.row.notify_change()

    def _pick(self):
        cat,typ,knd=self.v_cat.get(),self.v_type.get(),self.v_kind.get()
        all_p=_list_props(cat,typ,knd)
        if not all_p: return
        dlg=_PropPickerDialog(self.frame.winfo_toplevel(),all_p,self._selected_props)
        self.frame.wait_window(dlg)
        if dlg.result is not None: self._selected_props=dlg.result
        self._upbtn(); self._upcwe()
        self.row.notify_change()

    def _upbtn(self):
        n=len(self._selected_props)
        if n==0:
            self._pbtn["text"]="Select Properties"
            self._pbtn["bg"]="#E8F0FE"; self._pbtn["fg"]="#1A73E8"
        else:
            self._pbtn["text"]=f"{n} selected"
            self._pbtn["bg"]="#1565C0"; self._pbtn["fg"]="white"

    def _upcwe(self):
        cat,typ,knd=self.v_cat.get(),self.v_type.get(),self.v_kind.get()
        if not (cat and typ and knd): self.v_ncwe.set("—"); return
        self.v_ncwe.set(str(len(_get_cwes_merged(cat,typ,knd,self._selected_props or None))))

    def is_filled(self):
        return bool(self.v_cat.get().strip() and
                    self.v_type.get().strip() and
                    self.v_kind.get().strip())

    def clear(self):
        self.v_cat.set(""); self.v_type.set(""); self.v_kind.set(""); self.v_detail.set("")
        self._selected_props=[]; self._upbtn(); self.v_ncwe.set("—")
        self.cb_type["state"]="disabled"; self.cb_kind["state"]="disabled"
        self._pbtn["state"]="disabled"
        self.e_detail["state"]="disabled"

    def to_dict(self):
        cat=self.v_cat.get().strip() or None
        typ=self.v_type.get().strip() or None
        knd=self.v_kind.get().strip() or None
        detail=self.v_detail.get().strip() or None
        props=list(self._selected_props) if self._selected_props else []
        kind_full=f"{knd} {detail}" if (knd and detail) else knd
        return {
            "category": cat,
            "asset_type": typ,
            "asset_kind": knd,
            "asset_kind_detail": detail,
            "asset_kind_full": kind_full,
            "asset_properties": props,
            "source": _get_source(cat,typ,knd) if (cat and typ and knd) else None,
        }


class ResultWindow(tk.Toplevel):
    def __init__(self, parent, mapping, out_json, out_csv,
                 ag_result=None):
        super().__init__(parent)
        self.title("Mapping Results"); self.geometry("1220x760"); _center(self,1220,760)
        self.configure(bg="white")
        self._ag_result = ag_result
        self._mapping   = mapping
        self._build(mapping, out_json, out_csv)

    def _build(self, mapping, out_json, out_csv):
        hdr=tk.Frame(self,bg="#1C2333"); hdr.pack(fill="x")
        tk.Label(hdr,text=f"Threat + CWE Mapping  |  {len(mapping)} Assets/Edges",
                 font=("Arial",11,"bold"),fg="white",bg="#1C2333",pady=8).pack(side="left",padx=14)
        tk.Label(hdr,text=f"{Path(out_json).name}  /  {Path(out_csv).name}",
                 font=("Arial",8),fg="#8899AA",bg="#1C2333").pack(side="right",padx=12)

        nb=ttk.Notebook(self); nb.pack(fill="both",expand=True,padx=4,pady=4)

        tab1=tk.Frame(nb,bg="white"); nb.add(tab1,text="Assets / Edges")
        cols=("Type","Name","Phase","Cats","Category","Asset Kind","Source","CWE","Threats")
        tree=ttk.Treeview(tab1,columns=cols,show="headings",height=10)
        widths={"Type":55,"Name":200,"Phase":65,"Cats":50,
                "Category":130,"Asset Kind":180,"Source":80,"CWE":55,"Threats":65}
        for c in cols:
            tree.heading(c,text=c)
            tree.column(c,width=widths[c],
                         anchor="center" if c in ["Type","Phase","Source","CWE","Threats","Cats"] else "w")
        sb=ttk.Scrollbar(tab1,orient="vertical",command=tree.yview)
        tree.configure(yscrollcommand=sb.set); sb.pack(side="right",fill="y"); tree.pack(fill="both",expand=True)
        for tag,bg in [("n_in","#F3FFF5"),("n_thr","#FFFCF0"),("n_out","#FFF3F3"),
                       ("n_ent","#F6F6F6"),("edge","#EEF4FF")]:
            tree.tag_configure(tag,background=bg)
        for m in mapping:
            cats=m.get("categories") or []
            if cats:
                cat_disp=cats[0].get("category") or "—"
                kind_disp=cats[0].get("asset_kind_full") or cats[0].get("asset_kind") or "—"
                src_disp=cats[0].get("source") or "—"
                if len(cats)>1:
                    cat_disp += f"  +{len(cats)-1}"
                    kind_disp += f"  +{len(cats)-1}"
            else:
                cat_disp=m.get("category") or "—"
                kind_disp=m.get("asset_kind_full") or m.get("asset_kind") or "—"
                src_disp=m.get("source") or "—"
            etype=m.get("type","node"); ph=m.get("phase","")
            if etype=="edge": tag="edge"
            else: tag={"In":"n_in","Through":"n_thr","Out":"n_out","Entry":"n_ent"}.get(ph,"n_ent")
            tree.insert("","end",values=(
                "NODE" if etype=="node" else "EDGE",
                m["name"][:50], ph,
                len(cats) if cats else 0,
                cat_disp, kind_disp, src_disp,
                m["cwe_count"], m["threat_count"]), tags=(tag,))

        nb2=ttk.Notebook(tab1); nb2.pack(fill="x",padx=2,pady=4)

        tab_cats=tk.Frame(nb2); nb2.add(tab_cats,text="Categories")
        ct=ttk.Treeview(tab_cats,columns=("#","Category","Asset Type","Asset Kind","Detail","Properties","Source"),
                         show="headings",height=5)
        for c,w in zip(("#","Category","Asset Type","Asset Kind","Detail","Properties","Source"),
                        (40,140,150,180,90,200,80)):
            ct.heading(c,text=c); ct.column(c,width=w,anchor="center" if c in ("#","Source","Detail") else "w")
        cts=ttk.Scrollbar(tab_cats,orient="vertical",command=ct.yview); ct.configure(yscrollcommand=cts.set)
        cts.pack(side="right",fill="y"); ct.pack(fill="both",expand=True)

        tab_c=tk.Frame(nb2); nb2.add(tab_c,text="CWE")
        dt=ttk.Treeview(tab_c,columns=("ID","Vulnerability Name","Source","Description"),show="headings",height=5)
        dt.column("ID",width=85,anchor="center"); dt.column("Vulnerability Name",width=255)
        dt.column("Source",width=85,anchor="center"); dt.column("Description",width=450)
        for c in ("ID","Vulnerability Name","Source","Description"): dt.heading(c,text=c)
        ds=ttk.Scrollbar(tab_c,orient="vertical",command=dt.yview); dt.configure(yscrollcommand=ds.set)
        ds.pack(side="right",fill="y"); dt.pack(fill="both",expand=True)

        tab_t=tk.Frame(nb2); nb2.add(tab_t,text="Threats")
        tt2=ttk.Treeview(tab_t,columns=("TID","Threat Name","Tactic","Source"),show="headings",height=5)
        tt2.column("TID",width=90,anchor="center"); tt2.column("Threat Name",width=330)
        tt2.column("Tactic",width=160); tt2.column("Source",width=80,anchor="center")
        for c in ("TID","Threat Name","Tactic","Source"): tt2.heading(c,text=c)
        ts2=ttk.Scrollbar(tab_t,orient="vertical",command=tt2.yview); tt2.configure(yscrollcommand=ts2.set)
        ts2.pack(side="right",fill="y"); tt2.pack(fill="both",expand=True)

        def on_sel(e):
            sel=tree.selection()
            if not sel: return
            m=mapping[tree.index(sel[0])]
            for r in ct.get_children(): ct.delete(r)
            for i,c in enumerate(m.get("categories") or [],start=1):
                props=", ".join(c.get("asset_properties") or [])
                ct.insert("","end",values=(
                    i,
                    c.get("category") or "—",
                    c.get("asset_type") or "—",
                    c.get("asset_kind") or "—",
                    c.get("asset_kind_detail") or "—",
                    props or "—",
                    c.get("source") or "—"))
            for r in dt.get_children(): dt.delete(r)
            for cwe in m.get("cwes",[]):
                srcs=" | ".join(cwe.get("sources",[]) or ["—"])
                dt.insert("","end",values=(f"CWE-{cwe['id']}",cwe.get("name","")[:60],
                    srcs,(cwe.get("desc","") or "")[:80]))
            for r in tt2.get_children(): tt2.delete(r)
            for th in m.get("threats",[]):
                src=th.get("_src","EMB3D")
                tacs=", ".join(th.get("tactics",[]) or [th.get("tactic","—")])
                tt2.insert("","end",values=(th.get("tid","—"),th.get("name","")[:60],tacs[:55],src))
        tree.bind("<<TreeviewSelect>>",on_sel)

        if self._ag_result:
            tab2=tk.Frame(nb,bg="white"); nb.add(tab2,text="Attack Graph (Graphviz)")
            self._build_graph_tab(tab2)

    def _build_graph_tab(self, tab):
        ctrl=tk.Frame(tab,bg="#F8F8F8"); ctrl.pack(fill="x",padx=6,pady=4)
        tk.Label(ctrl,text="Render Graphviz dot",
                 font=("Arial",9,"bold"),bg="#F8F8F8").pack(side="left",padx=8)
        self._v_dot_path=tk.StringVar()
        tk.Button(ctrl,text="Save/Open PNG",font=("Arial",9),relief="flat",
                  bg="#1565C0",fg="white",padx=10,command=self._render_graph
                  ).pack(side="left",padx=6)
        tk.Button(ctrl,text="View DOT Source",font=("Arial",9),relief="flat",
                  bg="#F0F0F0",padx=10,command=self._show_dot
                  ).pack(side="left",padx=2)
        self._graph_status=tk.Label(ctrl,text="",font=("Arial",8),bg="#F8F8F8",fg="#555")
        self._graph_status.pack(side="left",padx=8)

        self._img_frame=tk.Frame(tab,bg="white"); self._img_frame.pack(fill="both",expand=True)
        self._canvas_img=tk.Canvas(self._img_frame,bg="#F5F5F5",highlightthickness=0)
        sb_h=ttk.Scrollbar(self._img_frame,orient="horizontal",command=self._canvas_img.xview)
        sb_v=ttk.Scrollbar(self._img_frame,orient="vertical",command=self._canvas_img.yview)
        self._canvas_img.configure(xscrollcommand=sb_h.set,yscrollcommand=sb_v.set)
        sb_h.pack(side="bottom",fill="x"); sb_v.pack(side="right",fill="y")
        self._canvas_img.pack(fill="both",expand=True)
        self._graph_status.config(text="Click the 'Save/Open PNG' button to render the graph")

    def _render_graph(self):
        if not self._ag_result: return
        dot_src=build_attack_graph_dot(self._ag_result, self._mapping)
        DEFAULT_OUT_DIR.mkdir(parents=True,exist_ok=True)
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        dot_path=str(DEFAULT_OUT_DIR/f"attack_graph_{ts}.dot")
        png_path=str(DEFAULT_OUT_DIR/f"attack_graph_{ts}.png")
        with open(dot_path,'w',encoding='utf-8') as f: f.write(dot_src)
        ok=render_graphviz(dot_src,png_path)
        if ok:
            self._graph_status.config(text=f"PNG saved: {Path(png_path).name}")
            self._show_png(png_path)
            try: os.startfile(png_path)
            except: pass
        else:
            self._graph_status.config(text="graphviz(dot) not found → only the DOT file was saved")
            messagebox.showinfo("Notice",
                f"Graphviz is not installed.\n"
                f"The DOT file has been saved:\n{dot_path}\n\n"
                f"Install it from https://graphviz.org and try again.")

    def _show_png(self, png_path):
        try:
            from PIL import Image, ImageTk
            img=Image.open(png_path)
            max_w=1600
            if img.width>max_w:
                ratio=max_w/img.width
                img=img.resize((max_w,int(img.height*ratio)),Image.LANCZOS)
            self._tk_img=ImageTk.PhotoImage(img)
            self._canvas_img.delete("all")
            self._canvas_img.create_image(0,0,anchor="nw",image=self._tk_img)
            self._canvas_img.configure(scrollregion=(0,0,img.width,img.height))
        except ImportError:
            self._graph_status.config(text="PNG saved (preview: pip install Pillow)")

    def _show_dot(self):
        if not self._ag_result: return
        dot_src=build_attack_graph_dot(self._ag_result, self._mapping)
        win=tk.Toplevel(self); win.title("DOT Source")
        win.geometry("900x600"); _center(win,900,600)
        txt=tk.Text(win,font=("Courier",9),bg="#1E1E2E",fg="#DCDCDC",relief="flat")
        sb=ttk.Scrollbar(win,command=txt.yview); txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right",fill="y"); txt.pack(fill="both",expand=True)
        txt.insert("end",dot_src)
        tk.Button(win,text="Copy to Clipboard",font=("Arial",9),relief="flat",
                  bg="#1565C0",fg="white",padx=12,pady=5,
                  command=lambda:[win.clipboard_clear(),win.clipboard_append(dot_src)]
                  ).pack(pady=6)


def build_result_json(mapping, meta):
    return {"meta":{"generated_at":datetime.now().isoformat(timespec="seconds"),
                    "tool":"tool_threat_mapper v6 (multi-category + editable type/kind + detail)",**meta},
            "assets":[{"name":m["name"],"element_type":m["type"],"phase":m["phase"],
                        "asset_guid":m.get("asset_guid",""),
                        "category":m.get("category"),
                        "asset_type":m.get("asset_type"),
                        "asset_kind":m.get("asset_kind"),
                        "asset_kind_detail":m.get("asset_kind_detail"),
                        "asset_kind_full":m.get("asset_kind_full") or m.get("asset_kind"),
                        "asset_properties":m.get("asset_properties",[]),
                        "source":m.get("source"),
                        "categories":m.get("categories",[]),
                        "category_count":m.get("category_count",len(m.get("categories",[]))),
                        "cwe_count":m["cwe_count"],
                        "threat_count":m["threat_count"],
                        "cwes":m["cwes"],
                        "threats":m.get("threats",[])}
                       for m in mapping]}

def build_result_csv(mapping):
    buf=io.StringIO(); w=csv.writer(buf)
    w.writerow(["element_type","name","phase",
                "category","asset_type","asset_kind","asset_kind_detail",
                "asset_properties","source",
                "all_categories",
                "cwe_id","cwe_name","cwe_sources","cwe_desc",
                "threat_id","threat_name","threat_tactic","threat_source"])
    for m in mapping:
        cats=m.get("categories") or []
        def _fmt_cat(c):
            base=f"{c.get('category','')}>{c.get('asset_type','')}>{c.get('asset_kind','')}"
            if c.get('asset_kind_detail'): base += f" {c.get('asset_kind_detail')}"
            if c.get('asset_properties'):  base += f"({','.join(c.get('asset_properties'))})"
            return base
        all_cats_str=" | ".join(_fmt_cat(c) for c in cats) if cats else ""
        primary=cats[0] if cats else {}
        base=[m.get("type",""), m["name"], m["phase"],
              primary.get("category") or m.get("category") or "",
              primary.get("asset_type") or m.get("asset_type") or "",
              primary.get("asset_kind") or m.get("asset_kind") or "",
              primary.get("asset_kind_detail") or m.get("asset_kind_detail") or "",
              "|".join(primary.get("asset_properties") or m.get("asset_properties") or []),
              primary.get("source") or m.get("source") or "",
              all_cats_str]
        cwes=m.get("cwes",[]); threats=m.get("threats",[])
        if not cwes and not threats:
            w.writerow(base+["","","","","","",""]); continue
        for cwe in cwes:
            w.writerow(base+[f"CWE-{cwe['id']}",cwe.get("name",""),
                             "|".join(cwe.get("sources",[]) or ["—"]),
                             (cwe.get("desc","") or "")[:120],"","","",""])
        for th in threats:
            tacs=",".join(th.get("tactics",[]) or [th.get("tactic","—")])
            src=th.get("_src","EMB3D")
            for cwe in (th.get("cwes") or [{"id":"—","name":""}]):
                w.writerow(base+[f"CWE-{cwe['id']}" if cwe["id"]!="—" else "—",
                                 cwe.get("name",""),"EMB3D","",
                                 th.get("tid",""),th.get("name",""),tacs,src])
    return buf.getvalue()


class ThreatMapperGUI(tk.Tk):
    def __init__(self, backend_script=None):
        super().__init__()
        self.title("Threat Mapper"); self.geometry("1020x680"); self.minsize(900,580)
        _center(self,1020,680); self.configure(bg="white")
        self.backend_path=(Path(backend_script).resolve() if backend_script
                           else DEFAULT_BACKEND if DEFAULT_BACKEND.exists() else None)
        self.v_tm7=tk.StringVar(); self.v_mode=tk.StringVar(value="remote")
        self.v_target=tk.StringVar(); self.v_boundary=tk.StringVar()
        self.v_asset  =tk.StringVar(value=str(DEFAULT_ASSET_MAP)  if DEFAULT_ASSET_MAP.exists()  else "")
        self.v_threat =tk.StringVar(value=str(DEFAULT_THREAT_MAP) if DEFAULT_THREAT_MAP.exists() else "")
        self.v_av     =tk.StringVar(value=str(DEFAULT_AV_MAP)     if DEFAULT_AV_MAP.exists()     else "")
        self.v_dep    =tk.StringVar(value=str(DEFAULT_DEP_MAP)    if DEFAULT_DEP_MAP.exists()    else "")
        self.v_impact =tk.StringVar(value=str(DEFAULT_IMPACT_MAP) if DEFAULT_IMPACT_MAP.exists() else "")
        self.v_depth=tk.StringVar(value="30"); self.v_out_dir=tk.StringVar(value=str(DEFAULT_OUT_DIR))
        self.v_proj=tk.StringVar()
        self.v_backend=tk.StringVar(value=str(self.backend_path) if self.backend_path else "")
        self._mapping_cache=None; self._at_data=None; self._ag_result=None
        self._build_ui()

    def _build_ui(self):
        hdr=tk.Frame(self,bg="#1C2333"); hdr.pack(fill="x")
        tk.Label(hdr,text="Threat Mapper  —  DFD-Based Asset Property Mapping + Threats / CWE + Attack Graph",
                 font=("Arial",11,"bold"),fg="white",bg="#1C2333",pady=9).pack(side="left",padx=14)
        inp=tk.LabelFrame(self,text=" Settings ",font=("Arial",9,"bold"),
                          bg="white",fg="#555",bd=1,relief="solid")
        inp.pack(fill="x",padx=10,pady=6)
        def _row(p,r,label,var,browse=None,w=46):
            tk.Label(p,text=label,font=("Arial",9),bg="white",
                     anchor="e",width=16).grid(row=r,column=0,padx=4,pady=2,sticky="e")
            e=tk.Entry(p,textvariable=var,width=w,font=("Arial",9),bg="#FAFAFA",relief="solid")
            e.grid(row=r,column=1,padx=4,pady=2,sticky="ew")
            if browse:
                tk.Button(p,text="…",font=("Arial",8),command=browse,
                          relief="flat",bg="#ECECEC",padx=4).grid(row=r,column=2,padx=2,pady=2)
        _row(inp,0,"Backend Script",self.v_backend,self._br_backend)
        _row(inp,1,"TM7 File",self.v_tm7,self._br_tm7)
        _row(inp,2,"Asset Map",self.v_asset,lambda:self._br_json(self.v_asset))
        _row(inp,3,"Threat Map",self.v_threat,lambda:self._br_json(self.v_threat))
        _row(inp,4,"Attack Vector",self.v_av,lambda:self._br_json(self.v_av))
        _row(inp,5,"Dependency",self.v_dep,lambda:self._br_json(self.v_dep))
        _row(inp,6,"Impact Map",self.v_impact,lambda:self._br_json(self.v_impact))
        r2=tk.Frame(inp,bg="white"); r2.grid(row=0,column=3,rowspan=7,padx=12,sticky="n")
        for idx,(lbl,var,extra) in enumerate([
            ("Target Asset",self.v_target,None),("Trust Boundary",self.v_boundary,None),
            ("Attack Mode",None,"mode"),("Max Depth",self.v_depth,None),
            ("Output Folder",self.v_out_dir,None),("Project Name",self.v_proj,None)]):
            tk.Label(r2,text=lbl+":",font=("Arial",9),bg="white").grid(row=idx,column=0,sticky="e",padx=4,pady=2)
            if extra=="mode":
                ttk.Combobox(r2,textvariable=self.v_mode,
                             values=["remote","adjacent","local","physical"],
                             state="readonly",width=14,font=("Arial",9)).grid(row=idx,column=1,padx=4,pady=2,sticky="w")
            else:
                tk.Entry(r2,textvariable=var,width=22,font=("Arial",9),
                         bg="#FAFAFA",relief="solid").grid(row=idx,column=1,padx=4,pady=2)
        inp.columnconfigure(1,weight=1)
        btn_f=tk.Frame(self,bg="white"); btn_f.pack(fill="x",padx=10,pady=4)
        bkw=dict(font=("Arial",10,"bold"),relief="flat",bd=0,padx=16,pady=7,cursor="hand2")
        tk.Button(btn_f,text="▶  Run",bg="#1565C0",fg="white",command=self._run,**bkw).pack(side="left",padx=4)
        tk.Button(btn_f,text="Save",bg="#2E7D32",fg="white",command=self._save,**bkw).pack(side="left",padx=4)
        self.lbl_status=tk.Label(btn_f,text="",font=("Arial",9,"italic"),bg="white",fg="#888")
        self.lbl_status.pack(side="right",padx=8)
        log_f=tk.Frame(self,bg="#1E1E2E"); log_f.pack(fill="both",expand=True,padx=10,pady=4)
        self.txt_log=tk.Text(log_f,font=("Courier",9),bg="#1E1E2E",fg="#AAFFAA",
                              state="disabled",relief="flat",height=8)
        lsb=ttk.Scrollbar(log_f,command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right",fill="y"); self.txt_log.pack(fill="both",expand=True)

    def _br_backend(self):
        p=filedialog.askopenfilename(filetypes=[("Python","*.py"),("All","*.*")])
        if p: self.v_backend.set(p)
    def _br_tm7(self):
        p=filedialog.askopenfilename(filetypes=[("TM7","*.tm7"),("All","*.*")])
        if p: self.v_tm7.set(p)
    def _br_json(self,var):
        p=filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
        if p: var.set(p)
    def _log(self,msg):
        self.txt_log.configure(state="normal"); self.txt_log.insert("end",msg+"\n")
        self.txt_log.see("end"); self.txt_log.configure(state="disabled")
    def _validate(self):
        b=self.v_backend.get().strip()
        if not b or not Path(b).exists():
            messagebox.showerror("Error",f"Backend Script not found:\n{b}"); return False
        if not self.v_tm7.get() or not Path(self.v_tm7.get()).exists():
            messagebox.showerror("Error","Please select a TM7 File."); return False
        if not self.v_target.get().strip():
            messagebox.showerror("Error","Please enter the Target Asset name."); return False
        if not self.v_boundary.get().strip():
            messagebox.showerror("Error","Please enter the Trust Boundary."); return False
        return True
    def _run(self):
        if not self._validate(): return
        self.lbl_status.config(text="Running…"); self.update()
        ap=self.v_asset.get()
        if ap and Path(ap).exists():
            try:
                with open(ap,encoding="utf-8") as f: self._at_data=json.load(f)
                self._log(f"[OK] asset_to_threats loaded: {Path(ap).name}")
            except Exception: self._at_data=None
        backend_path=Path(self.v_backend.get().strip()).resolve()
        def worker():
            try:
                self.after(0,lambda:self._log(f"[{datetime.now():%H:%M:%S}] Backend execution started"))
                bundle=run_path_filter(
                    backend_path=backend_path,tm7_path=self.v_tm7.get(),
                    mode=self.v_mode.get(),target=self.v_target.get().strip(),
                    boundary=self.v_boundary.get().strip(),
                    asset_map=self.v_asset.get(),threat_map=self.v_threat.get(),
                    av_map=self.v_av.get(),dep_map=self.v_dep.get(),
                    impact_map=self.v_impact.get(),max_depth=int(self.v_depth.get() or 30))
                result=bundle["result"]
                if not result.get("ok",False):
                    self.after(0,lambda:self._log(f"[WARN] ok=False: {result.get('reason','')}"))
                n_p=len(result.get("paths",[])); n_n=len(result.get("nodes",[]))
                self.after(0,lambda:self._log(f"[OK] {n_p} paths, {n_n} nodes"))
                if bundle.get("attack_graph_png"):
                    self.after(0,lambda:self._log(f"[OK] Attack graph PNG: {bundle['attack_graph_png']}"))
                if bundle.get("report_html"):
                    self.after(0,lambda:self._log(f"[OK] Result report HTML: {bundle['report_html']}"))
                elements=extract_elements(result)
                self.after(0,lambda:self._log(
                    f"[OK] Nodes {sum(1 for e in elements if e['type']=='node')}  "
                    f"Edges {sum(1 for e in elements if e['type']=='edge')}"))
                self._ag_result=result
                self.after(0,lambda:self._show_mapping(elements,result))
            except Exception as e:
                err=traceback.format_exc()
                self.after(0,lambda:self._log(f"[ERROR]\n{err}"))
                self.after(0,lambda:messagebox.showerror("Error",str(e)))
                self.after(0,lambda:self.lbl_status.config(text="Error"))
        threading.Thread(target=worker,daemon=True).start()
    def _show_mapping(self,elements,result):
        self.lbl_status.config(text="Property mapping…")
        dlg=AssetMapDialog(self,elements,at_data=self._at_data)
        self.wait_window(dlg)
        if not dlg.confirmed: self.lbl_status.config(text="Canceled"); return
        mapping=dlg.get_mapping(); self._mapping_cache=mapping
        out_dir=Path(self.v_out_dir.get()); out_dir.mkdir(parents=True,exist_ok=True)
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        out_json=str(out_dir/f"threat_mapping_{ts}.json"); out_csv=str(out_dir/f"threat_mapping_{ts}.csv")
        meta={"project":self.v_proj.get(),"tm7":self.v_tm7.get(),"mode":self.v_mode.get(),
              "target":self.v_target.get(),"boundary":self.v_boundary.get(),
              "path_count":len(result.get("paths",[]))}
        with open(out_json,"w",encoding="utf-8") as f:
            json.dump(build_result_json(mapping,meta),f,ensure_ascii=False,indent=2)
        with open(out_csv,"w",encoding="utf-8",newline="") as f:
            f.write(build_result_csv(mapping))
        self._log(f"[OK] JSON: {out_json}\n[OK] CSV:  {out_csv}")
        self.lbl_status.config(text=f"Done  {len(mapping)} assets")
        ResultWindow(self,mapping,out_json,out_csv,ag_result=self._ag_result)
    def _save(self):
        if not self._mapping_cache: messagebox.showinfo("Info","Please run it first."); return
        p=filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON","*.json"),("CSV","*.csv")],
            initialfile=f"threat_mapping_{datetime.now():%Y%m%d_%H%M%S}.json")
        if not p: return
        if p.endswith(".csv"):
            with open(p,"w",encoding="utf-8",newline="") as f: f.write(build_result_csv(self._mapping_cache))
        else:
            with open(p,"w",encoding="utf-8") as f:
                json.dump(build_result_json(self._mapping_cache,{}),f,ensure_ascii=False,indent=2)
        messagebox.showinfo("Save Complete",p)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--backend",default=None); args=ap.parse_args()
    try:
        import ctypes; ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception: pass
    ThreatMapperGUI(backend_script=args.backend).mainloop()

if __name__=="__main__": main()
