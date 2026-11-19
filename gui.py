"""Tkinter GUI for the SHA-256 File Integrity Verification System."""
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import integrity as ig

COLORS = {ig.OK: "#2e7d32", ig.MODIFIED: "#c62828", ig.MISSING: "#ef6c00", ig.NEW: "#1565c0", ig.UNKNOWN: "#6a1b9a"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SHA-256 File Integrity Checker")
        self.geometry("900x500")
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        for text, cmd in [("Add Files…", self.add_files), ("Add Folder…", self.add_folder),
                          ("Verify All", self.verify), ("Accept Selected", self.accept),
                          ("Untrack Selected", self.untrack), ("Export Report…", self.export),
                          ("Hash a File…", self.quick_hash)]:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2)
        ttk.Style().configure("Treeview", rowheight=26)
        self.tree = ttk.Treeview(self, columns=("status", "hash", "path"), show="headings")
        for c, w in (("status", 90), ("hash", 220), ("path", 560)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w)
        for st, col in COLORS.items():
            self.tree.tag_configure(st, foreground=col)
        self.tree.pack(fill="both", expand=True, padx=6)
        self.status = tk.StringVar()
        ttk.Label(self, textvariable=self.status, padding=6).pack(fill="x")
        self.results = {}
        self.refresh()

    def guard(fn):
        def wrap(self, *a):
            try:
                return fn(self, *a)
            except ig.StoreTampered as e:
                messagebox.showerror("TAMPERING DETECTED", str(e))
            except OSError as e:
                messagebox.showerror("Error", str(e))
        return wrap

    @guard
    def refresh(self, results=None):
        self.tree.delete(*self.tree.get_children())
        entries = ig.load_store()["entries"]
        rows = {p: results.get(p, ig.OK) if results else "" for p in entries}
        rows.update({p: s for p, s in (results or {}).items() if p not in rows})
        for p, st in rows.items():
            h = entries.get(p, {}).get("sha256", "")
            self.tree.insert("", "end", iid=p, values=(st, h[:32] + ("…" if h else ""), p), tags=(st,))
        if results:
            bad = sum(s != ig.OK for s in results.values())
            self.status.set(f"{len(results) - bad}/{len(results)} intact" + (f" — {bad} PROBLEM(S)!" if bad else ""))
        else:
            self.status.set(f"{len(entries)} tracked file(s)")

    @guard
    def add_files(self):
        if f := filedialog.askopenfilenames():
            ig.generate(list(f), quiet=True)
            self.refresh()

    @guard
    def add_folder(self):
        if d := filedialog.askdirectory():
            ig.generate([d], quiet=True)
            self.refresh()

    @guard
    def verify(self):
        self.results = ig.verify(quiet=True)
        self.refresh(self.results)
        if any(s != ig.OK for s in self.results.values()):
            messagebox.showwarning("Integrity check", "Tampering detected - see highlighted files.")

    @guard
    def accept(self):
        if self.tree.selection() and messagebox.askyesno("Accept", "Re-baseline selected files as authorised?"):
            ig.update(list(self.tree.selection()))
            self.refresh()

    @guard
    def untrack(self):
        if self.tree.selection():
            ig.remove(list(self.tree.selection()))
            self.refresh()

    @guard
    def export(self):
        if not self.results:
            self.verify()
        if f := filedialog.asksaveasfilename(defaultextension=".html",
                                             filetypes=[("HTML", "*.html"), ("JSON", "*.json"), ("Text", "*.txt")]):
            ig.write_report(self.results, f)

    @guard
    def quick_hash(self):
        if f := filedialog.askopenfilename():
            messagebox.showinfo("SHA-256", f"{os.path.basename(f)}\n\n{ig.sha256_file(f)}")


if __name__ == "__main__":
    App().mainloop()
