#!/usr/bin/env python3
import os, sys, json, getpass, subprocess
import tkinter as tk
from tkinter import messagebox, ttk

CONFIG_PATH = "/etc/rootguard.json"
DEFAULT_CONFIG = {"users": {}}

# -------------------------------
# Config handling
# -------------------------------
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

# -------------------------------
# ACL Handling
# -------------------------------
def block_program(user, program):
    path = f"/usr/bin/{program}"
    if os.path.exists(path):
        subprocess.run(["setfacl", "-m", f"u:{user}:---", path], check=False)

def allow_program(user, program):
    path = f"/usr/bin/{program}"
    if os.path.exists(path):
        subprocess.run(["setfacl", "-x", f"u:{user}", path], check=False)

# -------------------------------
# GUI
# -------------------------------
def run_gui():
    config = load_config()
    current_user = getpass.getuser()
    if current_user not in config["users"]:
        config["users"][current_user] = []
        save_config(config)

    def scan_programs():
        return sorted([f for f in os.listdir("/usr/bin") if os.path.isfile(os.path.join("/usr/bin", f))])

    def refresh_lists():
        user = user_var.get()
        blocked.delete(0, tk.END)
        allowed.delete(0, tk.END)
        all_programs = scan_programs()
        user_blocked = set(config["users"].get(user, []))
        for prog in all_programs:
            if prog in user_blocked:
                blocked.insert(tk.END, prog)
            else:
                allowed.insert(tk.END, prog)

    def block_selected():
        user = user_var.get()
        sel = allowed.curselection()
        if not sel: return
        prog = allowed.get(sel[0])
        if prog not in config["users"].get(user, []):
            config["users"][user].append(prog)
            save_config(config)
            block_program(user, prog)
        refresh_lists()

    def allow_selected():
        user = user_var.get()
        sel = blocked.curselection()
        if not sel: return
        prog = blocked.get(sel[0])
        if prog in config["users"].get(user, []):
            config["users"][user].remove(prog)
            save_config(config)
            allow_program(user, prog)
        refresh_lists()

    def search(event=None):
        query = search_var.get().lower()
        for lb in [allowed, blocked]:
            for i in range(lb.size()):
                text = lb.get(i).lower()
                if query in text:
                    lb.selection_clear(0, tk.END)
                    lb.selection_set(i)
                    lb.see(i)
                    return

    root = tk.Tk()
    root.title("RootGuard v2")

    tk.Label(root, text="Benutzer auswählen:").pack(pady=5)
    users = list(config["users"].keys())
    user_var = tk.StringVar(value=current_user)
    user_menu = ttk.Combobox(root, textvariable=user_var, values=users)
    user_menu.pack(pady=5)
    user_menu.bind("<<ComboboxSelected>>", lambda e: refresh_lists())

    frame = tk.Frame(root)
    frame.pack(pady=10)

    tk.Label(frame, text="Erlaubt").grid(row=0, column=0, padx=10)
    tk.Label(frame, text="Gesperrt").grid(row=0, column=1, padx=10)

    allowed = tk.Listbox(frame, height=20, width=40)
    allowed.grid(row=1, column=0, padx=10)
    blocked = tk.Listbox(frame, height=20, width=40)
    blocked.grid(row=1, column=1, padx=10)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=5)
    tk.Button(btn_frame, text="→ Sperren", command=block_selected).grid(row=0, column=0, padx=5)
    tk.Button(btn_frame, text="← Erlauben", command=allow_selected).grid(row=0, column=1, padx=5)

    search_var = tk.StringVar()
    tk.Entry(root, textvariable=search_var).pack(pady=5)
    tk.Button(root, text="Suchen", command=search).pack()

    refresh_lists()
    root.mainloop()

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als root starten (sudo).")
        sys.exit(1)

    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULT_CONFIG)

    run_gui()
