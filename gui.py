#!/usr/bin/env python3
"""Desktop GUI for LAN IPv4 host discovery.

Looks like a small bench instrument: dark chassis, amber sweep lamp,
tabular results. Shared engine is scanner.py.
"""

from __future__ import annotations

import csv
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scanner import Host, ScanResult, list_ifaces, scan_lan

# Chassis palette — network bench, not a SaaS dashboard.
C_BG = "#171c22"
C_PANEL = "#212830"
C_WELL = "#10141a"
C_INK = "#e6ebe4"
C_MUTED = "#8b948c"
C_LINE = "#2c343c"
C_AMBER = "#c4922a"
C_LIVE = "#5ea882"
C_SELF = "#d9c48a"
C_GW = "#6b9ac4"
C_BTN = "#2a333c"
C_BTN_ON = "#c4922a"

UI_FONT = ("Noto Sans CJK KR", 11)
UI_FONT_SM = ("Noto Sans CJK KR", 10)
UI_FONT_BD = ("Noto Sans CJK KR", 12, "bold")
MONO = ("Ubuntu Mono", 12)
MONO_SM = ("Ubuntu Mono", 11)
TITLE_FONT = ("Noto Sans CJK KR", 18, "bold")


class ScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("LAN Sweep")
        self.geometry("1080x640")
        self.minsize(820, 480)
        self.configure(bg=C_BG)
        self._queue: queue.Queue = queue.Queue()
        self._cancel = threading.Event()
        self._busy = False
        self._result: ScanResult | None = None
        self._ifaces = []
        self._build_style()
        self._build()
        self._reload_ifaces()
        self.after(80, self._drain)

    def _build_style(self) -> None:
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("TFrame", background=C_BG)
        st.configure("Panel.TFrame", background=C_PANEL)
        st.configure("TLabel", background=C_BG, foreground=C_INK, font=UI_FONT)
        st.configure("Muted.TLabel", background=C_BG, foreground=C_MUTED, font=UI_FONT_SM)
        st.configure("Title.TLabel", background=C_BG, foreground=C_INK, font=TITLE_FONT)
        st.configure("Lamp.TLabel", background=C_BG, foreground=C_AMBER, font=UI_FONT_BD)
        st.configure("TCombobox", fieldbackground=C_WELL, background=C_PANEL, foreground=C_INK)
        st.configure(
            "Treeview",
            background=C_WELL,
            fieldbackground=C_WELL,
            foreground=C_INK,
            font=MONO,
            rowheight=28,
            borderwidth=0,
        )
        st.configure(
            "Treeview.Heading",
            background=C_PANEL,
            foreground=C_MUTED,
            font=UI_FONT_SM,
            relief="flat",
        )
        st.map("Treeview", background=[("selected", "#3a4a3c")], foreground=[("selected", C_INK)])
        st.configure(
            "Sweep.Horizontal.TProgressbar",
            troughcolor=C_WELL,
            background=C_AMBER,
            bordercolor=C_LINE,
            lightcolor=C_AMBER,
            darkcolor=C_AMBER,
        )

    def _build(self) -> None:
        head = ttk.Frame(self, style="TFrame")
        head.pack(fill="x", padx=20, pady=(16, 8))

        left = ttk.Frame(head, style="TFrame")
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="LAN Sweep", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            left,
            text="ICMP + ARP. Names from mDNS / NetBIOS when available.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        self.lamp = ttk.Label(head, text="idle", style="Lamp.TLabel")
        self.lamp.pack(side="right", padx=(12, 0))

        bar = ttk.Frame(self, style="TFrame")
        bar.pack(fill="x", padx=20, pady=(4, 8))

        ttk.Label(bar, text="Interface", style="Muted.TLabel").pack(side="left")
        self.iface_var = tk.StringVar()
        self.iface_box = ttk.Combobox(
            bar, textvariable=self.iface_var, state="readonly", width=28, font=MONO_SM
        )
        self.iface_box.pack(side="left", padx=(8, 16))

        self.scan_btn = tk.Button(
            bar,
            text="Scan",
            command=self._toggle,
            bg=C_BTN_ON,
            fg="#1a1408",
            activebackground="#d4a53c",
            activeforeground="#1a1408",
            relief="flat",
            font=UI_FONT_BD,
            padx=16,
            pady=4,
            cursor="hand2",
        )
        self.scan_btn.pack(side="left")

        self.copy_btn = tk.Button(
            bar, text="Copy IP", command=self._copy_ip, **self._ghost_btn()
        )
        self.copy_btn.pack(side="right")
        self.csv_btn = tk.Button(
            bar, text="Save CSV", command=self._save_csv, **self._ghost_btn()
        )
        self.csv_btn.pack(side="right", padx=(0, 8))

        self.progress = ttk.Progressbar(
            self, style="Sweep.Horizontal.TProgressbar", mode="determinate", maximum=100
        )
        self.progress.pack(fill="x", padx=20, pady=(0, 8))

        table_wrap = tk.Frame(self, bg=C_LINE, bd=0)
        table_wrap.pack(fill="both", expand=True, padx=20, pady=(0, 8))
        inner = tk.Frame(table_wrap, bg=C_WELL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)

        cols = ("ip", "hostname", "mac", "vendor", "method")
        self.tree = ttk.Treeview(inner, columns=cols, show="headings", selectmode="browse")
        headings = {
            "ip": "IP",
            "hostname": "Hostname",
            "mac": "MAC",
            "vendor": "Vendor",
            "method": "How",
        }
        widths = {"ip": 150, "hostname": 220, "mac": 180, "vendor": 180, "method": 140}
        for c in cols:
            self.tree.heading(c, text=headings[c], command=lambda col=c: self._sort(col))
            self.tree.column(c, width=widths[c], anchor="w")
        vsb = ttk.Scrollbar(inner, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.tag_configure("self", foreground=C_SELF)
        self.tree.tag_configure("gw", foreground=C_GW)
        self.tree.tag_configure("live", foreground=C_LIVE)
        self.tree.bind("<Double-1>", lambda _e: self._copy_ip())
        self.tree.bind("<Control-c>", lambda _e: self._copy_ip())

        foot = ttk.Frame(self, style="TFrame")
        foot.pack(fill="x", padx=20, pady=(0, 14))
        self.status = ttk.Label(
            foot,
            text="Pick an interface and press Scan.",
            style="Muted.TLabel",
        )
        self.status.pack(side="left")
        ttk.Label(
            foot,
            text="Double-click a row to copy its IP",
            style="Muted.TLabel",
        ).pack(side="right")

    def _ghost_btn(self) -> dict:
        return dict(
            bg=C_BTN,
            fg=C_INK,
            activebackground="#3a4550",
            activeforeground=C_INK,
            relief="flat",
            font=UI_FONT,
            padx=12,
            pady=4,
            cursor="hand2",
        )

    def _reload_ifaces(self) -> None:
        try:
            self._ifaces = list_ifaces()
        except Exception as exc:
            self._ifaces = []
            self.status.config(text=str(exc))
            return
        labels = [f"{i.name}  {i.cidr}  ({i.network})" for i in self._ifaces]
        self.iface_box["values"] = labels
        if labels:
            self.iface_box.current(0)

    def _current_iface(self) -> str | None:
        idx = self.iface_box.current()
        if idx < 0 or idx >= len(self._ifaces):
            return None
        return self._ifaces[idx].name

    def _toggle(self) -> None:
        if self._busy:
            self._cancel.set()
            self.lamp.config(text="stopping")
            return
        iface = self._current_iface()
        if not iface:
            messagebox.showerror("LAN Sweep", "No IPv4 interface to scan.")
            return
        self._cancel.clear()
        self._busy = True
        self.scan_btn.config(text="Stop", bg="#6b3a32", fg=C_INK, activebackground="#7a4540")
        self.lamp.config(text="sweeping")
        self.progress["value"] = 0
        self.status.config(text=f"Sweeping {iface}…")
        for item in self.tree.get_children():
            self.tree.delete(item)
        threading.Thread(target=self._worker, args=(iface,), daemon=True).start()

    def _worker(self, iface: str) -> None:
        def progress(done: int, total: int, ip: str) -> None:
            self._queue.put(("progress", done, total, ip))

        try:
            result = scan_lan(
                iface=iface,
                progress=progress,
                cancelled=self._cancel.is_set,
            )
            self._queue.put(("done", result))
        except Exception as exc:
            self._queue.put(("error", str(exc)))

    def _drain(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, done, total, ip = msg
                    pct = (100.0 * done / total) if total else 100.0
                    self.progress["value"] = pct
                    self.status.config(text=f"{done} / {total}   last {ip}")
                elif kind == "done":
                    self._finish(msg[1])
                elif kind == "error":
                    self._idle()
                    self.lamp.config(text="error")
                    self.status.config(text=msg[1])
                    messagebox.showerror("LAN Sweep", msg[1])
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _finish(self, result: ScanResult) -> None:
        self._result = result
        self._idle()
        self.lamp.config(text=f"{len(result.live)} live")
        self.progress["value"] = 100
        for item in self.tree.get_children():
            self.tree.delete(item)
        for h in result.live:
            tag = "live"
            if h.is_self:
                tag = "self"
            elif h.is_gateway:
                tag = "gw"
            self.tree.insert(
                "",
                "end",
                values=(h.ip, h.hostname, h.mac, h.vendor, h.method),
                tags=(tag,),
            )
        stopped = " (stopped early)" if self._cancel.is_set() else ""
        self.status.config(
            text=(
                f"{len(result.live)} live · {result.probed} probed · "
                f"{result.subnet} on {result.iface} · {result.elapsed_sec:.2f}s"
                f"{stopped}"
            )
        )

    def _idle(self) -> None:
        self._busy = False
        self.scan_btn.config(
            text="Scan", bg=C_BTN_ON, fg="#1a1408", activebackground="#d4a53c"
        )
        if self.lamp.cget("text") == "stopping":
            self.lamp.config(text="idle")

    def _selected_host(self) -> Host | None:
        sel = self.tree.selection()
        if not sel or not self._result:
            return None
        ip = str(self.tree.item(sel[0], "values")[0])
        for h in self._result.live:
            if h.ip == ip:
                return h
        return None

    def _copy_ip(self) -> None:
        host = self._selected_host()
        if not host:
            return
        self.clipboard_clear()
        self.clipboard_append(host.ip)
        self.status.config(text=f"Copied {host.ip}")

    def _save_csv(self) -> None:
        if not self._result or not self._result.live:
            messagebox.showinfo("LAN Sweep", "Scan first, then save.")
            return
        path = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
            initialfile="lan-sweep.csv",
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["ip", "hostname", "mac", "vendor", "method"])
            for h in self._result.live:
                w.writerow([h.ip, h.hostname, h.mac, h.vendor, h.method])
        self.status.config(text=f"Wrote {path}")

    def _sort(self, col: str) -> None:
        rows = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        if col == "ip":
            def key(item):
                try:
                    return tuple(int(x) for x in item[0].split("."))
                except ValueError:
                    return (0,)
            rows.sort(key=key)
        else:
            rows.sort(key=lambda item: item[0].lower())
        for i, (_, k) in enumerate(rows):
            self.tree.move(k, "", i)


def main() -> None:
    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
