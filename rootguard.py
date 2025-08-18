#!/usr/bin/env python3
import os, sys, json, getpass, subprocess, shutil
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk

CONFIG_PATH = "/etc/rootguard.json"
WRAPPER_PATH = "/usr/local/bin/rg-wrapper"
REAL_BIN_DIR = "/usr/local/bin/real"

DEFAULT_CONFIG = {"users": {}}

# -------------------------------
# Config Functions
# -------------------------------
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def is_restricted(user, program):
    config = load_config()
    return program in config.get("users", {}).get(user, [])

# -------------------------------
# Wrapper Launch
# -------------------------------
def launch_program(program, args):
    user = getpass.getuser()
    if is_restricted(user, program):
        print(f"[RootGuard] '{program}' ist für {user} gesperrt. Root erforderlich...")
        subprocess.run(["pkexec", os.path.join(REAL_BIN_DIR, program)] + args)
    else:
        os.execvp(os.path.join(REAL_BIN_DIR, program), [program]+args)

# -------------------------------
# Protect Programs
# -------------------------------
def protect_program(program):
    os.makedirs(REAL_BIN_DIR, exist_ok=True)
    original = f"/usr/bin/{program}"
    backup = f"{REAL_BIN_DIR}/{program}"

    # Original verschieben, falls nicht schon geschehen
    if os.path.exists(original) and not os.path.exists(backup):
        os.rename(original, backup)

    # Wrapper unter Originalnamen
    if os.path.exists(original):
        os.remove(original)
    os.symlink(WRAPPER_PATH, original)

    # Desktop-Icons anpassen
    desktop_dirs = ["/usr/share/applications", os.path.expanduser("~/.local/share/applications")]
    for d in desktop_dirs:
        if not os.path.exists(d): continue
        for f in os.listdir(d):
            if f.endswith(".desktop"):
                path = os.path.join(d, f)
                with open(path, "r") as file:
                    lines = file.readlines()
                changed = False
                for i, line in enumerate(lines):
                    if line.startswith("Exec=") and program in line:
                        lines[i] = f"Exec={WRAPPER_PATH} {program}\n"
                        changed = True
                if changed:
                    with open(path, "w") as file:
                        file.writelines(lines)

# -------------------------------
# GUI mit automatischem Scan
# -------------------------------
def run_gui():
    config = load_config()
    users = list(config.get("users", {}).keys())
    if not users:
        users = [getpass.getuser()]
        config["users"][users[0]] = []
        save_config(config)

    def scan_programs():
        programs = sorted([f for f in os.listdir("/usr/bin") if os.path.isfile(os.path.join("/usr/bin", f))])
        return programs

    def refresh_program_list():
        user = user_var.get()
        prog_list.delete(0, tk.END)
        all_programs = scan_programs()
        for prog in all_programs:
            if prog in config["users"].get(user, []):
                prog_list.insert(tk.END, f"{prog} (gesperrt)")
            else:
                prog_list.insert(tk.END, prog)

    def add_program():
        user = user_var.get()
        selection = prog_list.curselection()
        if not selection: return
        prog_name = prog_list.get(selection[0]).replace(" (gesperrt)", "")
        if prog_name not in config["users"][user]:
            config["users"][user].append(prog_name)
            save_config(config)
            protect_program(prog_name)
            refresh_program_list()

    def remove_program():
        user = user_var.get()
        selection = prog_list.curselection()
        if not selection: return
        prog_name = prog_list.get(selection[0]).replace(" (gesperrt)", "")
        if prog_name in config["users"][user]:
            config["users"][user].remove(prog_name)
            save_config(config)
            refresh_program_list()
            messagebox.showinfo("Hinweis", f"Programm {prog_name} bleibt geschützt, Wrapper bleibt aktiv.")

    root = tk.Tk()
    root.title("RootGuard")

    tk.Label(root, text="Benutzer:").pack(pady=5)
    user_var = tk.StringVar(value=users[0])
    user_menu = ttk.Combobox(root, textvariable=user_var, values=users)
    user_menu.pack(pady=5)
    user_menu.bind("<<ComboboxSelected>>", lambda e: refresh_program_list())

    prog_list = tk.Listbox(root, height=20, width=50)
    prog_list.pack(pady=5)

    tk.Button(root, text="Programm sperren", command=add_program).pack(pady=2)
    tk.Button(root, text="Sperre aufheben", command=remove_program).pack(pady=2)

    refresh_program_list()
    root.mainloop()

# -------------------------------
# Initial Setup
# -------------------------------
def initial_setup():
    if not os.path.exists(CONFIG_PATH):
        print("Erstelle Config...")
        save_config(DEFAULT_CONFIG)

    # Wrapper schreiben
    if not os.path.exists(WRAPPER_PATH):
        print("Erstelle Wrapper...")
        wrapper_code = f"""#!/usr/bin/env python3
import sys, os, json, getpass, subprocess
CONFIG_PATH = "{CONFIG_PATH}"
REAL_BIN_DIR = "{REAL_BIN_DIR}"
def load_config():
    with open(CONFIG_PATH,"r") as f:
        return json.load(f)
def is_restricted(user, program):
    config = load_config()
    return program in config.get("users",{{}}).get(user,[])
if len(sys.argv) < 2:
    print("Usage: rg-wrapper <program> [args...]")
    sys.exit(1)
prog = sys.argv[1]
args = sys.argv[2:]
user = getpass.getuser()
if is_restricted(user, prog):
    subprocess.run(["pkexec", os.path.join(REAL_BIN_DIR, prog)]+args)
else:
    os.execvp(os.path.join(REAL_BIN_DIR, prog), [prog]+args)
"""
        with open(WRAPPER_PATH, "w") as f:
            f.write(wrapper_code)
        os.chmod(WRAPPER_PATH, 0o755)

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Wrapper-Modus
        launch_program(sys.argv[1], sys.argv[2:])
    else:
        # GUI / Setup
        if os.geteuid() != 0:
            print("Bitte als Root ausführen, um Setup durchzuführen")
            sys.exit(1)
        initial_setup()
        run_gui()
