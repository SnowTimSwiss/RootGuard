import os
import sys
import json
import stat
import pwd
import shutil
import getpass
import subprocess
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox

# -------------------------------
# Konfiguration / Pfade
# -------------------------------
CONFIG_PATH = "/etc/rootguard.json"
DEFAULT_CONFIG = {
    "users": {
        # "username": {
        #     "blocked": ["prog1", "prog2"],
        #     "mode": "deny" | "pkexec"
        # }
    },
    "scan_paths": ["/usr/bin", "/bin", "/usr/local/bin"],
    "base_block_dir": "/opt/rootguard/blocked"  # pro Nutzer: /opt/rootguard/blocked/<user>
}

ENV_HINT_LINE = "# >>> ROOTGUARD PATH >>>"
ENV_HINT_END = "# <<< ROOTGUARD PATH <<<"

# -------------------------------
# Hilfsfunktionen: Config
# -------------------------------
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

# -------------------------------
# Nutzerverwaltung
# -------------------------------
def system_users():
    """Liefert sinnvolle Login-User (UID >= 1000) plus aktuellen User."""
    users = set()
    for p in pwd.getpwall():
        try:
            if p.pw_uid >= 1000 and p.pw_dir and p.pw_shell and "nologin" not in p.pw_shell:
                users.add(p.pw_name)
        except Exception:
            continue
    users.add(getpass.getuser())
    return sorted(users)

def ensure_user_entry(cfg, user):
    if "users" not in cfg:
        cfg["users"] = {}
    if user not in cfg["users"]:
        cfg["users"][user] = {"blocked": [], "mode": "deny"}
        save_config(cfg)

# -------------------------------
# Scan / Programmliste
# -------------------------------
def scan_programs(cfg):
    """Scannt ausführbare Dateien in den konfigurierten Pfaden und
    liefert {progname: absolute_path} (erste gefundene wins)."""
    mapping = {}
    for d in cfg.get("scan_paths", []):
        if not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                p = os.path.join(d, name)
                if name in mapping:
                    continue
                try:
                    st = os.stat(p)
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(st.st_mode) and os.access(p, os.X_OK):
                    mapping[name] = p
        except PermissionError:
            continue
    return dict(sorted(mapping.items(), key=lambda kv: kv[0].lower()))

# -------------------------------
# Block-Ordner / Stub-Verwaltung
# -------------------------------
def user_block_dir(cfg, user):
    return os.path.join(cfg["base_block_dir"], user)

def ensure_block_dir(cfg, user):
    path = user_block_dir(cfg, user)
    os.makedirs(path, exist_ok=True)
    # Root-own, 755
    try:
        os.chown(path, 0, 0)
    except PermissionError:
        pass
    os.chmod(path, 0o755)
    return path

def stub_path(cfg, user, prog):
    return os.path.join(user_block_dir(cfg, user), prog)

STUB_TEMPLATE_DENY = """#!/bin/sh
# RootGuard stub: deny
app="{APP}"
if command -v zenity >/dev/null 2>&1; then
  zenity --error --title="RootGuard" --text="Das Programm '{APP}' ist für deinen Account gesperrt."
else
  echo "RootGuard: '{APP}' ist für deinen Account gesperrt."
fi
exit 126
"""

STUB_TEMPLATE_PKEXEC = """#!/bin/sh
# RootGuard stub: pkexec
app="{APP}"
real="{REAL}"
if [ ! -x "$real" ]; then
  if command -v zenity >/dev/null 2>&1; then
    zenity --error --title="RootGuard" --text="Das Zielprogramm für '{APP}' wurde nicht gefunden."
  else
    echo "RootGuard: Zielprogramm für '{APP}' wurde nicht gefunden."
  fi
  exit 127
fi
# pkexec zeigt GUI-Auth an, falls nötig:
exec pkexec "$real" "$@"
"""

def write_executable_file(path, content):
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o755)
    try:
        os.chown(path, 0, 0)  # root:root
    except PermissionError:
        pass

def create_stub(cfg, user, prog, real_path, mode):
    path = stub_path(cfg, user, prog)
    if mode == "pkexec":
        content = STUB_TEMPLATE_PKEXEC.format(APP=prog, REAL=real_path)
    else:
        content = STUB_TEMPLATE_DENY.format(APP=prog)
    write_executable_file(path, content)

def remove_stub(cfg, user, prog):
    p = stub_path(cfg, user, prog)
    if os.path.exists(p):
        os.remove(p)

# -------------------------------
# PATH-Injektion für Benutzer
# -------------------------------
def inject_path_for_user(user, block_dir):
    """
    Fügt idempotent einen PATH-Präfix in typische Login-Skripte ein.
    Bevorzugte Dateien: ~/.profile, ~/.bash_profile, ~/.bashrc
    """
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return False

    home = Path(pw.pw_dir).expanduser()
    files = [home / ".profile", home / ".bash_profile", home / ".bashrc"]

    snippet = f"""{ENV_HINT_LINE}
# RootGuard fügt den Block-Ordner an den PATH-Anfang:
if [ -d "{block_dir}" ] && ! echo "$PATH" | tr ':' '\\n' | grep -qx "{block_dir}"; then
  export PATH="{block_dir}:$PATH"
fi
{ENV_HINT_END}
"""

    changed_any = False
    for f in files:
        try:
            content = ""
            if f.exists():
                content = f.read_text(encoding="utf-8", errors="ignore")
                # Entferne alte Blöcke
                if ENV_HINT_LINE in content and ENV_HINT_END in content:
                    start = content.index(ENV_HINT_LINE)
                    end = content.index(ENV_HINT_END) + len(ENV_HINT_END)
                    content = content[:start].rstrip() + "\n" + content[end:].lstrip()
            else:
                # Stelle sicher, dass Datei existiert und dem User gehört
                f.touch()
                os.chown(str(f), pw.pw_uid, pw.pw_gid)

            new_content = (content.rstrip() + "\n\n" + snippet).lstrip("\n")
            f.write_text(new_content, encoding="utf-8")
            os.chown(str(f), pw.pw_uid, pw.pw_gid)
            changed_any = True
        except Exception as e:
            # Wir versuchen die anderen Dateien weiter
            continue
    return changed_any

# -------------------------------
# Geschäftslogik: Block/Allow
# -------------------------------
def apply_user_rules(cfg, user, program_map):
    """
    Synchronisiert Stub-Dateien gemäß Konfiguration:
    - Für alle 'blocked' Einträge: Stub anlegen (Modus beachten)
    - Für alles andere: ggf. alte Stubs entfernen
    """
    ensure_block_dir(cfg, user)
    user_cfg = cfg["users"][user]
    mode = user_cfg.get("mode", "deny")
    blocked = set(user_cfg.get("blocked", []))

    # Entferne Stubs, die nicht mehr blockiert sind
    bd = user_block_dir(cfg, user)
    for existing in os.listdir(bd):
        if existing not in blocked:
            remove_stub(cfg, user, existing)

    # Erzeuge/aktualisiere Stubs für blockierte Programme
    for prog in blocked:
        real = program_map.get(prog)
        # Falls Program inzwischen fehlt, erzeugen wir trotzdem einen Deny-Stub
        if not real:
            create_stub(cfg, user, prog, "/bin/false", "deny")
        else:
            create_stub(cfg, user, prog, real, mode)

    # PATH-Injektion sicherstellen
    inject_path_for_user(user, bd)

# -------------------------------
# GUI
# -------------------------------
class RootGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RootGuard v3 – AppLock ohne ACLs")
        self.geometry("900x600")
        self.resizable(True, True)

        # ttk-Theme
        try:
            self.style = ttk.Style(self)
            if "clam" in self.style.theme_names():
                self.style.theme_use("clam")
        except Exception:
            pass

        self.cfg = load_config()
        self.program_map = scan_programs(self.cfg)

        # State
        self.users = system_users()
        for u in self.users:
            ensure_user_entry(self.cfg, u)

        self.user_var = tk.StringVar(value=self.users[0] if self.users else getpass.getuser())
        self.mode_var = tk.StringVar(value=self.cfg["users"][self.user_var.get()]["mode"])
        self.search_var = tk.StringVar()

        # Header
        header = ttk.Frame(self, padding=10)
        header.pack(fill="x")

        ttk.Label(header, text="Benutzer:", font=("TkDefaultFont", 10, "bold")).pack(side="left")
        self.user_box = ttk.Combobox(header, values=self.users, textvariable=self.user_var, state="readonly", width=20)
        self.user_box.pack(side="left", padx=8)
        self.user_box.bind("<<ComboboxSelected>>", self.on_user_change)

        ttk.Label(header, text="Modus:", font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=(16, 4))
        self.mode_box = ttk.Combobox(header, values=["deny", "pkexec"], textvariable=self.mode_var, state="readonly", width=10)
        self.mode_box.pack(side="left")
        self.mode_box.bind("<<ComboboxSelected>>", self.on_mode_change)

        # Suche
        ttk.Label(header, text="Suche:").pack(side="left", padx=(20, 4))
        self.search_entry = ttk.Entry(header, textvariable=self.search_var, width=28)
        self.search_entry.pack(side="left")
        self.search_entry.bind("<Return>", lambda e: self.apply_filter())

        self.btn_search = ttk.Button(header, text="Filter anwenden", command=self.apply_filter)
        self.btn_search.pack(side="left", padx=6)

        # Hauptbereich
        body = ttk.Frame(self, padding=(10, 0, 10, 10))
        body.pack(fill="both", expand=True)

        # Listen + Buttons
        columns = ttk.Frame(body)
        columns.pack(fill="both", expand=True)

        left = ttk.Frame(columns)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right = ttk.Frame(columns)
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))

        ttk.Label(left, text="Erlaubt (Doppelclick = sperren)").pack(anchor="w")
        self.list_allowed = tk.Listbox(left, selectmode="extended")
        self.list_allowed.pack(fill="both", expand=True, pady=(4, 0))
        self.list_allowed.bind("<Double-1>", self.block_selected)

        mid_btns = ttk.Frame(columns)
        mid_btns.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Button(mid_btns, text="→ Sperren", command=self.block_selected).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(mid_btns, text="← Erlauben", command=self.allow_selected).grid(row=1, column=0, padx=5, pady=5)

        ttk.Label(right, text="Gesperrt (Doppelclick = erlauben)").pack(anchor="w")
        self.list_blocked = tk.Listbox(right, selectmode="extended")
        self.list_blocked.pack(fill="both", expand=True, pady=(4, 0))
        self.list_blocked.bind("<Double-1>", self.allow_selected)

        # Fußzeile / Status
        footer = ttk.Frame(self, padding=10)
        footer.pack(fill="x")
        self.status = tk.StringVar(value="Bereit.")
        ttk.Label(footer, textvariable=self.status).pack(side="left")

        self.refresh_lists()

    # ---- GUI Actions
    def on_user_change(self, event=None):
        u = self.user_var.get()
        ensure_user_entry(self.cfg, u)
        self.mode_var.set(self.cfg["users"][u].get("mode", "deny"))
        self.refresh_lists()

    def on_mode_change(self, event=None):
        u = self.user_var.get()
        self.cfg["users"][u]["mode"] = self.mode_var.get()
        save_config(self.cfg)
        # Stubs neu schreiben
        apply_user_rules(self.cfg, u, self.program_map)
        self.status.set(f"Modus für {u} auf '{self.mode_var.get()}' gesetzt.")

    def apply_filter(self):
        self.refresh_lists()

    def current_filter(self):
        q = self.search_var.get().strip().lower()
        return q

    def block_selected(self, event=None):
        user = self.user_var.get()
        sel_indices = list(self.list_allowed.curselection())
        if not sel_indices:
            return
        items = [self.list_allowed.get(i) for i in sel_indices]
        for prog in items:
            if prog not in self.cfg["users"][user]["blocked"]:
                self.cfg["users"][user]["blocked"].append(prog)
        save_config(self.cfg)
        apply_user_rules(self.cfg, user, self.program_map)
        self.refresh_lists()
        self.status.set(f"{len(items)} Programm(e) für {user} gesperrt.")

    def allow_selected(self, event=None):
        user = self.user_var.get()
        sel_indices = list(self.list_blocked.curselection())
        if not sel_indices:
            return
        items = [self.list_blocked.get(i) for i in sel_indices]
        self.cfg["users"][user]["blocked"] = [p for p in self.cfg["users"][user]["blocked"] if p not in items]
        save_config(self.cfg)
        apply_user_rules(self.cfg, user, self.program_map)
        self.refresh_lists()
        self.status.set(f"{len(items)} Programm(e) für {user} wieder erlaubt.")

    def refresh_lists(self):
        user = self.user_var.get()
        blocked_set = set(self.cfg["users"][user]["blocked"])
        q = self.current_filter()

        allowed = []
        blocked = []

        for prog in self.program_map.keys():
            if prog in blocked_set:
                blocked.append(prog)
            else:
                allowed.append(prog)

        if q:
            allowed = [p for p in allowed if q in p.lower()]
            blocked = [p for p in blocked if q in p.lower()]

        self.list_allowed.delete(0, tk.END)
        self.list_blocked.delete(0, tk.END)
        for p in allowed:
            self.list_allowed.insert(tk.END, p)
        for p in blocked:
            self.list_blocked.insert(tk.END, p)

        # Sicherheit: Block-Ordner + PATH-Injektion aktualisieren
        apply_user_rules(self.cfg, user, self.program_map)

# -------------------------------
# Main
# -------------------------------
def main():
    if os.geteuid() != 0:
        print("Bitte als root starten (sudo).")
        sys.exit(1)

    # Config anlegen, falls fehlt
    if not os.path.exists(CONFIG_PATH):
        base = DEFAULT_CONFIG.copy()
        # Vorbelegen: aktuelle scan_paths existierende filtern
        base["scan_paths"] = [p for p in DEFAULT_CONFIG["scan_paths"] if os.path.isdir(p)]
        save_config(base)

    # Basispfade sicherstellen
    cfg = load_config()
    Path(cfg["base_block_dir"]).mkdir(parents=True, exist_ok=True)
    try:
        os.chown(cfg["base_block_dir"], 0, 0)
    except PermissionError:
        pass
    os.chmod(cfg["base_block_dir"], 0o755)

    # GUI starten
    app = RootGuardApp()
    app.mainloop()

if __name__ == "__main__":
    main()
