#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import runpy
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
LOGO_PATH = (PROJECT_ROOT / "asset" / "logo.png").resolve()

DOMAINS = {
    "automotive": {
        "label": "Automotive / Vehicle",
        "description": "Vehicle cybersecurity attack-path analysis",
        "script": "automotive/tool_attack_paths_automotive.py",
        "backend": "../backend/parse_attack_graph_automotive.py",
    },
    "ics": {
        "label": "ICS / OT",
        "description": "Industrial control system attack-path analysis",
        "script": "ics/tool_attack_paths_ics.py",
        "backend": "../backend/parse_attack_graph_ics.py",
    },
    "enterprise": {
        "label": "Enterprise IT",
        "description": "Enterprise attack-path analysis",
        "script": "enterprise/tool_attack_paths_enterprise.py",
        "backend": "../backend/parse_attack_graph_enterprise.py",
    },
}


def center_window(win: tk.Tk | tk.Toplevel, w: int, h: int) -> None:
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")


class SplashScreen(tk.Tk):
    def __init__(self, duration_ms: int = 1500):
        super().__init__()

        self.duration_ms = duration_ms
        self.logo_img = None

        self.overrideredirect(True)
        self.configure(bg="#0B1220")
        center_window(self, 720, 500)

        self._build()
        self.after(self.duration_ms, self.destroy)

    def _load_logo(self):
        if not LOGO_PATH.exists():
            return None

        try:
            from PIL import Image, ImageTk

            img = Image.open(LOGO_PATH).convert("RGBA")
            img.thumbnail((210, 210))
            return ImageTk.PhotoImage(img)
        except Exception:
            try:
                return tk.PhotoImage(file=str(LOGO_PATH))
            except Exception:
                return None

    def _build(self):
        wrap = tk.Frame(self, bg="#0B1220")
        wrap.pack(fill="both", expand=True)

        self.logo_img = self._load_logo()

        if self.logo_img:
            tk.Label(
                wrap,
                image=self.logo_img,
                bg="#0B1220",
            ).pack(pady=(42, 12))
        else:
            tk.Label(
                wrap,
                text="ThreatCraft",
                font=("Segoe UI", 28, "bold"),
                fg="white",
                bg="#0B1220",
            ).pack(pady=(72, 12))

        tk.Label(
            wrap,
            text="ThreatCraft",
            font=("Segoe UI", 22, "bold"),
            fg="white",
            bg="#0B1220",
        ).pack()

        tk.Label(
            wrap,
            text="UKC-guided LLM Attack Scenario Generation",
            font=("Segoe UI", 10),
            fg="#C9D7F2",
            bg="#0B1220",
        ).pack(pady=(6, 0))

        tk.Label(
            wrap,
            text="Automotive · ICS · Enterprise",
            font=("Segoe UI", 9),
            fg="#7DD3FC",
            bg="#0B1220",
        ).pack(pady=(3, 0))

        tk.Label(
            wrap,
            text="Loading...",
            font=("Segoe UI", 9),
            fg="#7DD3FC",
            bg="#0B1220",
        ).pack(pady=(22, 0))


class DomainSelector(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("ThreatCraft Domain Selector")
        self.geometry("720x500")
        self.resizable(False, False)
        self.configure(bg="white")

        self.selected_domain = tk.StringVar(value="automotive")
        self.result = None

        center_window(self, 720, 500)
        self._build()

    def _build(self):
        header = tk.Frame(self, bg="#1C2333", height=72)
        header.pack(fill="x")

        tk.Label(
            header,
            text="ThreatCraft",
            font=("Segoe UI", 18, "bold"),
            fg="white",
            bg="#1C2333",
        ).pack(anchor="w", padx=24, pady=(14, 0))

        tk.Label(
            header,
            text="Select the analysis domain to start",
            font=("Segoe UI", 10),
            fg="#C9D7F2",
            bg="#1C2333",
        ).pack(anchor="w", padx=24, pady=(2, 10))

        body = tk.Frame(self, bg="white")
        body.pack(fill="both", expand=True, padx=24, pady=18)

        for key, cfg in DOMAINS.items():
            row = tk.Frame(body, bg="white")
            row.pack(fill="x", pady=7)

            ttk.Radiobutton(
                row,
                text=cfg["label"],
                value=key,
                variable=self.selected_domain,
            ).pack(anchor="w")

            tk.Label(
                row,
                text=cfg["description"],
                font=("Segoe UI", 9),
                fg="#666666",
                bg="white",
            ).pack(anchor="w", padx=26, pady=(1, 0))

        btn_row = tk.Frame(self, bg="#F6F7F9")
        btn_row.pack(fill="x", side="bottom")

        tk.Button(
            btn_row,
            text="Cancel",
            font=("Segoe UI", 10),
            bg="#E5E7EB",
            fg="#111827",
            relief="flat",
            padx=18,
            pady=7,
            command=self._cancel,
        ).pack(side="right", padx=(6, 18), pady=12)

        tk.Button(
            btn_row,
            text="Start",
            font=("Segoe UI", 10, "bold"),
            bg="#1565C0",
            fg="white",
            relief="flat",
            padx=24,
            pady=7,
            command=self._start,
        ).pack(side="right", padx=6, pady=12)

    def _start(self):
        self.result = self.selected_domain.get()
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


def show_splash() -> None:
    splash = SplashScreen(duration_ms=1500)
    splash.mainloop()


def select_domain() -> str | None:
    app = DomainSelector()
    app.mainloop()
    return app.result


def run_domain(domain: str) -> None:
    cfg = DOMAINS[domain]

    script_path = (SCRIPT_DIR / cfg["script"]).resolve()
    backend_path = (SCRIPT_DIR / cfg["backend"]).resolve()
    domain_script_dir = script_path.parent

    if not script_path.exists():
        messagebox.showerror(
            "Missing file",
            f"Domain script not found:\n{script_path}",
        )
        return

    if not backend_path.exists():
        messagebox.showerror(
            "Missing backend",
            f"Backend script not found:\n{backend_path}",
        )
        return

    # Important: selected domain folder must come first.
    for p in [str(domain_script_dir), str(SCRIPT_DIR)]:
        if p in sys.path:
            sys.path.remove(p)
        sys.path.insert(0, p)

    sys.argv = [
        str(script_path),
        "--backend",
        str(backend_path),
    ]

    runpy.run_path(str(script_path), run_name="__main__")

def main():
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    show_splash()

    domain = select_domain()
    if not domain:
        return

    run_domain(domain)


if __name__ == "__main__":
    main()