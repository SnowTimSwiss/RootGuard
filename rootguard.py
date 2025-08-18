import os, sys, json, getpass, subprocess, shutil, stat
import tkinter as tk
from tkinter import ttk, messagebox

CONFIG_PATH = "/etc/rootguard.json"
WRAPPER_PATH = "/usr/local/bin/rg-wrapper"
AUTH_HELPER_PATH = "/usr/local/bin/rg-auth-helper"
POLKIT_POLICY_PATH = "/usr/share/polkit-1/actions/org.rootguard.authenticate.policy"
REAL_BIN_DIR = "/usr/local/bin/real"

DEFAULT_CONFIG = {"users": {}}

# -------------------------------
# Config I/O
# -------------------------------
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

def is_restricted(user, program):
    cfg = load_config()
    return program in cfg.get("users", {}).get(user, [])

# -------------------------------
# Launch logic (used by wrapper mode)
# -------------------------------
def _auth_via_polkit():
    # Löst NUR die Authentifizierung aus; startet keine App als root.
    try:
        r = subprocess.run(["pkexec", AUTH_HELPER_PATH], check=False)
        return r.returncode == 0
    except FileNotFoundError:
        # pkexec nicht gefunden
        return False

def _real_binary_path(program):
    cand = os.path.join(REAL_BIN_DIR, program)
    if os.path.exists(cand):
        return cand
    # Fallback (falls nicht geschützt): normales /usr/bin (Achtung rekursiv vermeiden)
    sys_bin = f"/usr/bin/{program}"
    if os.path.exists(sys_bin) and not os.path.islink(sys_bin):
        return sys_bin
    return cand  # kann nicht existieren; execvp wird dann fehlschlagen

def launch_program(program, args):
    user = getpass.getuser()
    # Bei „gesperrt“: Auth erzwingen, danach als Benutzer starten
    if is_restricted(user, program):
        ok = _auth_via_polkit()
        if not ok:
            print(f"[RootGuard] Authentifizierung abgebrochen/fehlgeschlagen → '{program}' wird nicht gestartet.")
            sys.exit(126)
        # Erfolgreich authentifiziert → als Benutzer starten (nicht root!)
        os.execvp(_real_binary_path(program), [program] + args)
    else:
        os.execvp(_real_binary_path(program), [program] + args)

# -------------------------------
# Protection: move real binary, symlink wrapper, patch .desktop
# -------------------------------
def protect_program(program):
    os.makedirs(REAL_BIN_DIR, exist_ok=True)
    original = f"/usr/bin/{program}"
    backup = os.path.join(REAL_BIN_DIR, program)

    # Original verschieben, falls noch nicht geschehen
    if os.path.exists(original) and not os.path.exists(backup) and not os.path.islink(original):
        try:
            os.rename(original, backup)
        except PermissionError:
            raise
        except OSError:
            # Manche Programme sind Wrapper oder alternatives Pfadlayout – ggf. kopieren
            if os.path.isfile(original):
                shutil.copy2(original, backup)
                os.remove(original)

    # Wrapper unter Originalnamen verlinken
    try:
        if os.path.islink(original) or os.path.exists(original):
            try:
                os.remove(original)
            except IsADirectoryError:
                pass
        os.symlink(WRAPPER_PATH, original)
    except Exception as e:
        print(f"[RootGuard] Konnte Symlink für {program} nicht erstellen: {e}")

    # Desktop-Icons patchen (Exec=…)
    _patch_desktop_exec(program)

def _patch_desktop_exec(program):
    desktop_dirs = [
        "/usr/share/applications",
        os.path.expanduser("~/.local/share/applications"),
    ]
    for d in desktop_dirs:
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if not name.endswith(".desktop"):
                continue
            path = os.path.join(d, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                changed = False
                for i, line in enumerate(lines):
                    if line.startswith("Exec=") and program in line:
                        # Ersetze NUR das erste Wort hinter Exec= durch den Wrapper-Aufruf.
                        # Restliche Argumente bleiben erhalten.
                        # Beispiel: Exec=firefox %u  -> Exec=/usr/local/bin/rg-wrapper firefox %u
                        exec_cmd = line.strip()[5:].strip()
                        parts = exec_cmd.split()
                        if parts and (program in parts[0] or parts[0].endswith(f"/{program}")):
                            parts[0] = f"{WRAPPER_PATH} {program}"
                            lines[i] = "Exec=" + " ".join(parts) + "\n"
                            changed = True
                if changed:
                    with open(path, "w", encoding="utf-8") as f:
                        f.writelines(lines)
            except Exception:
                continue

# -------------------------------
# Unprotect (optional utility)
# -------------------------------
def unprotect_program(program):
    original = f"/usr/bin/{program}"
    backup = os.path.join(REAL_BIN_DIR, program)
    if os.path.islink(original):
        try:
            os.remove(original)
        except Exception:
            pass
    if os.path.exists(backup):
        try:
            shutil.copy2(backup, original)
        except Exception:
            pass

# -------------------------------
# Setup: write wrapper, auth helper, polkit policy
# -------------------------------
def _write_file(path, content, mode=0o644):
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)

def initial_setup():
    # Config
    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULT_CONFIG.copy())
        os.chmod(CONFIG_PATH, 0o644)

    # Wrapper
    if not os.path.exists(WRAPPER_PATH):
        wrapper_code = f"""#!/usr/bin/env python3
import os, sys, getpass, json, subprocess
CONFIG_PATH = "{CONFIG_PATH}"
REAL_BIN_DIR = "{REAL_BIN_DIR}"
AUTH_HELPER_PATH = "{AUTH_HELPER_PATH}"

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def is_restricted(user, program):
    cfg = load_config()
    return program in cfg.get("users", {{}}).get(user, [])

def _auth():
    try:
        r = subprocess.run(["pkexec", AUTH_HELPER_PATH], check=False)
        return r.returncode == 0
    except FileNotFoundError:
        return False

def _real(program):
    p = os.path.join(REAL_BIN_DIR, program)
    if os.path.exists(p):
        return p
    sys_bin = f"/usr/bin/{{program}}"
    if os.path.exists(sys_bin) and not os.path.islink(sys_bin):
        return sys_bin
    return p

def main():
    # Wenn rg-wrapper unter Programmnamen aufgerufen wurde (Symlink),
    # ist argv[0] z.B. "/usr/bin/firefox" und program = "firefox".
    argv0 = os.path.basename(sys.argv[0])
    if argv0 and argv0 != "rg-wrapper" and argv0 != "python3":
        program = argv0
        args = sys.argv[1:]
    else:
        if len(sys.argv) < 2:
            print("Usage: rg-wrapper <program> [args...]")
            sys.exit(1)
        program = sys.argv[1]
        args = sys.argv[2:]

    user = os.getenv("SUDO_USER") or os.getenv("PKEXEC_UID") or os.getenv("USER") or "unknown"
    # getpass kann in manchen Desktop-Kontexten korrekter sein:
    try:
        import getpass as _gp
        user = _gp.getuser() or user
    except Exception:
        pass

    if is_restricted(user, program):
        if not _auth():
            print(f"[RootGuard] Authentifizierung abgebrochen → {{program}} nicht gestartet.")
            sys.exit(126)
        os.execvp(_real(program), [program] + args)
    else:
        os.execvp(_real(program), [program] + args)

if __name__ == "__main__":
    main()
"""
        _write_file(WRAPPER_PATH, wrapper_code, 0o755)

    # Auth-Helper
    if not os.path.exists(AUTH_HELPER_PATH):
        auth_helper = """#!/usr/bin/env bash
# Tut nichts außer erfolgreich als root zu laufen, um Polkit-Auth auszulösen.
exit 0
"""
        _write_file(AUTH_HELPER_PATH, auth_helper, 0o755)

    # Polkit-Policy
    if not os.path.exists(POLKIT_POLICY_PATH):
        policy = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="org.rootguard.authenticate">
    <description>RootGuard Authentication</description>
    <message>RootGuard benötigt Administrator-Rechte, um die Sperre zu überbrücken.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{AUTH_HELPER_PATH}</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
"""
        _write_file(POLKIT_POLICY_PATH, policy, 0o644)

    # Sicherstellen, dass REAL_BIN_DIR existiert
    os.makedirs(REAL_BIN_DIR, exist_ok=True)

# -------------------------------
# Program scan
# -------------------------------
def scan_programs():
    # Nur reguläre Dateien in /usr/bin anzeigen (keine Symlink-Wrapper doppelt zählen)
    programs = []
    try:
        for f in os.listdir("/usr/bin"):
            p = os.path.join("/usr/bin", f)
            if os.path.isfile(p):
                programs.append(f)
    except Exception:
        pass
    return sorted(set(programs))

# -------------------------------
# GUI
# -------------------------------
class RootGuardGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RootGuard")
        self.geometry("900x520")

        # TTK-Style etwas moderner gestalten
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TButton", padding=8)
        style.configure("TLabel", padding=4)
        style.configure("TEntry", padding=4)
        style.configure("Card.TFrame", relief="groove", borderwidth=2)
        self.configure(padx=10, pady=10)

        self.cfg = load_config()
        users = sorted(set(self.cfg.get("users", {}).keys()) | {getpass.getuser()})
        if not users:
            users = [getpass.getuser()]
        if "users" not in self.cfg:
            self.cfg["users"] = {}
        for u in users:
            self.cfg["users"].setdefault(u, [])
        save_config(self.cfg)

        # Topbar: User Auswahl + Suche
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0,10))

        ttk.Label(top, text="Benutzer").pack(side="left")
        self.user_var = tk.StringVar(value=users[0])
        self.user_cb = ttk.Combobox(top, textvariable=self.user_var, values=users, state="readonly", width=20)
        self.user_cb.pack(side="left", padx=8)
        self.user_cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_lists())

        ttk.Label(top, text="Suche").pack(side="left", padx=(20,0))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(top, textvariable=self.search_var, width=40)
        self.search_entry.pack(side="left", padx=8)
        self.search_var.trace_add("write", lambda *args: self.refresh_lists())

        # Middle: Zwei Karten (Alle / Gesperrt)
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True)

        left_card = ttk.Frame(mid, style="Card.TFrame")
        left_card.pack(side="left", fill="both", expand=True, padx=(0,8))
        ttk.Label(left_card, text="Alle Programme").pack(anchor="w")
        self.all_list = tk.Listbox(left_card, selectmode="browse")
        self.all_list.pack(fill="both", expand=True, padx=8, pady=8)

        center_btns = ttk.Frame(mid)
        center_btns.pack(side="left", fill="y", padx=4)
        self.btn_block = ttk.Button(center_btns, text="▶ Sperren →", command=self.block_selected)
        self.btn_unblock = ttk.Button(center_btns, text="← Freigeben ◀", command=self.unblock_selected)
        self.btn_block.pack(pady=(150,5))
        self.btn_unblock.pack()

        right_card = ttk.Frame(mid, style="Card.TFrame")
        right_card.pack(side="left", fill="both", expand=True, padx=(8,0))
        ttk.Label(right_card, text="Gesperrt für Benutzer").pack(anchor="w")
        self.blocked_list = tk.Listbox(right_card, selectmode="browse")
        self.blocked_list.pack(fill="both", expand=True, padx=8, pady=8)

        # Bottom-Bar: Aktionen
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", pady=(10,0))
        ttk.Button(bottom, text="Neu scannen", command=self.refresh_lists).pack(side="left")
        ttk.Button(bottom, text="Beenden", command=self.destroy).pack(side="right")

        self.refresh_lists()

    def current_user(self):
        return self.user_var.get()

    def refresh_lists(self):
        # Scan
        all_programs = scan_programs()

        # Filter
        q = (self.search_var.get() or "").strip().lower()
        if q:
            all_programs = [p for p in all_programs if q in p.lower()]

        user = self.current_user()
        blocked = set(self.cfg.get("users", {}).get(user, []))

        # Links (alle), rechts (gesperrt)
        self.all_list.delete(0, tk.END)
        self.blocked_list.delete(0, tk.END)
        for p in all_programs:
            if p in blocked:
                # Zeige gesperrte auch links (blass), aber rechts separat vollständig
                self.all_list.insert(tk.END, f"{p}  • gesperrt")
            else:
                self.all_list.insert(tk.END, p)
        for p in sorted(blocked):
            if not q or q in p.lower():
                self.blocked_list.insert(tk.END, p)

    def block_selected(self):
        user = self.current_user()
        sel = self.all_list.curselection()
        if not sel:
            return
        label = self.all_list.get(sel[0])
        prog = label.split()[0]  # vor "• gesperrt"
        if prog not in self.cfg["users"][user]:
            self.cfg["users"][user].append(prog)
            save_config(self.cfg)
            try:
                protect_program(prog)
            except Exception as e:
                messagebox.showerror("Fehler", f"Konnte {prog} nicht schützen: {e}")
        self.refresh_lists()

    def unblock_selected(self):
        user = self.current_user()
        sel = self.blocked_list.curselection()
        if not sel:
            return
        prog = self.blocked_list.get(sel[0])
        if prog in self.cfg["users"][user]:
            self.cfg["users"][user].remove(prog)
            save_config(self.cfg)
        # Hinweis: Schutz bleibt bestehen, damit andere Nutzer/Regeln greifen.
        messagebox.showinfo("Hinweis", f"{prog} ist für {user} freigegeben. Schutz (Wrapper) bleibt aktiv.")
        self.refresh_lists()

# -------------------------------
# Main
# -------------------------------
def ensure_root():
    if os.geteuid() != 0:
        print("Bitte als root ausführen (sudo).")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Wrapper-Modus: root ist NICHT nötig (wird über Symlink aufgerufen)
        prog = sys.argv[1]
        args = sys.argv[2:]
        launch_program(prog, args)
    else:
        # Setup + GUI
        ensure_root()
        initial_setup()
        # (Optional) Polkit neu laden ist normal nicht nötig; Agent im User-Desktop liefert Prompt.
        app = RootGuardGUI()
        app.mainloop()
