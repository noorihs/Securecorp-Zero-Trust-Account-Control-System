
import json
import os
import sys
import getpass
import hashlib
import secrets
import requests
from datetime import datetime

BASE       = "http://localhost:5000"
USERS_FILE = "users.json"
RES_FILE   = "resources.json"
POL_FILE   = "policies.json"

# ── ANSI Colors ────────────────────────────────────────────────────────────────
G  = "\033[92m"
R  = "\033[91m"
Y  = "\033[93m"
C  = "\033[96m"
B  = "\033[1m"
D  = "\033[2m"
RS = "\033[0m"


def ok(msg):   print(f"  {G}✓  {msg}{RS}")
def err(msg):  print(f"  {R}✗  {msg}{RS}")
def info(msg): print(f"  {C}ℹ  {msg}{RS}")
def warn(msg): print(f"  {Y}⚠  {msg}{RS}")
def hdr(msg):  print(f"\n{B}{C}{'─'*56}\n  {msg}\n{'─'*56}{RS}")


# ── File Helpers ───────────────────────────────────────────────────────────────

def load_users() -> dict:
    with open(USERS_FILE) as f:
        return json.load(f)["users"]

def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump({"users": users}, f, indent=2)

def load_resources() -> dict:
    with open(RES_FILE) as f:
        return json.load(f)["resources"]

def save_resources(resources: dict):
    with open(RES_FILE, "w") as f:
        json.dump({"resources": resources}, f, indent=2)

def load_policies() -> list:
    with open(POL_FILE) as f:
        return json.load(f)["policies"]

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{password}:{salt}".encode()).hexdigest()


# ── User Commands ──────────────────────────────────────────────────────────────

def cmd_users_list():
    hdr("USER LIST")
    users = load_users()
    print(f"  {B}{'Username':<12}{'Role':<12}{'Department':<14}{'Clearance':<14}{'Location'}{RS}")
    print(f"  {'─'*62}")
    for uname, u in users.items():
        cc = {"secret": R, "confidential": Y, "public": G}.get(u.get("clearance",""), RS)
        lc = G if u.get("location") == "internal" else Y
        print(f"  {C}{uname:<12}{RS}{u['role']:<12}{u['department']:<14}"
              f"{cc}{u['clearance']:<14}{RS}{lc}{u['location']}{RS}")
    print(f"\n  Total: {len(users)} users")


def cmd_users_add():
    hdr("ADD USER")
    users = load_users()

    username = input(f"  {C}Username:{RS} ").strip().lower()
    if not username:
        err("Username cannot be empty"); return
    if username in users:
        err(f"User '{username}' already exists"); return

    role = input(f"  {C}Role (Admin/Manager/Employee):{RS} ").strip()
    if role not in ("Admin", "Manager", "Employee"):
        err("Role must be Admin, Manager, or Employee"); return

    dept = input(f"  {C}Department (HR/Finance/IT/Operations):{RS} ").strip()
    if not dept:
        err("Department cannot be empty"); return

    clearance = input(f"  {C}Clearance (public/confidential/secret):{RS} ").strip()
    if clearance not in ("public", "confidential", "secret"):
        err("Clearance must be public, confidential, or secret"); return

    location = input(f"  {C}Location (internal/external):{RS} ").strip()
    if location not in ("internal", "external"):
        err("Location must be internal or external"); return

    password = getpass.getpass(f"  {C}Password (min 8 chars):{RS} ")
    if len(password) < 8:
        err("Password must be at least 8 characters"); return

    salt  = secrets.token_hex(16)
    phash = hash_password(password, salt)
    users[username] = {
        "role": role, "department": dept,
        "clearance": clearance, "location": location,
        "salt": salt, "password_hash": phash,
    }
    save_users(users)
    ok(f"User '{username}' created ({role} / {dept} / {clearance})")


def cmd_users_delete(username: str):
    users = load_users()
    if username not in users:
        err(f"User '{username}' not found"); return
    confirm = input(f"  {Y}Delete '{username}'? (yes/no):{RS} ").strip().lower()
    if confirm != "yes":
        info("Cancelled"); return
    del users[username]
    save_users(users)
    ok(f"User '{username}' deleted")


def cmd_users_role(username: str, new_role: str):
    if new_role not in ("Admin", "Manager", "Employee"):
        err("Role must be Admin, Manager, or Employee"); return
    users = load_users()
    if username not in users:
        err(f"User '{username}' not found"); return
    old = users[username]["role"]
    users[username]["role"] = new_role
    save_users(users)
    ok(f"'{username}' role changed: {old} → {new_role}")


def cmd_users_passwd(username: str):
    users = load_users()
    if username not in users:
        err(f"User '{username}' not found"); return
    password = getpass.getpass(f"  {C}New password for '{username}':{RS} ")
    if len(password) < 8:
        err("Password must be at least 8 characters"); return
    salt = secrets.token_hex(16)
    users[username]["salt"]          = salt
    users[username]["password_hash"] = hash_password(password, salt)
    save_users(users)
    ok(f"Password updated for '{username}'")


def cmd_users_unlock(username: str):
    try:
        r = requests.post(f"{BASE}/admin/unlock/{username}", timeout=3)
        ok(f"Account '{username}' unlocked") if r.ok else err(f"Server error: {r.text}")
    except requests.ConnectionError:
        warn("Server not reachable — restart the server to reset in-memory locks")


# ── Resource Commands ──────────────────────────────────────────────────────────

def cmd_resources_list():
    hdr("RESOURCE LIST")
    res = load_resources()
    for rid, r in res.items():
        cc = {"public": G, "confidential": Y, "secret": R}.get(r["classification"], RS)
        print(f"  {C}{rid:<10}{RS}  {r['department']:<12}  "
              f"{cc}{r['classification']:<14}{RS}  {r['name']}")
    print(f"\n  Total: {len(res)} resources")


def cmd_resources_add():
    hdr("ADD RESOURCE")
    res = load_resources()

    rid = input(f"  {C}Resource ID (e.g. HR-003):{RS} ").strip().upper()
    if not rid:
        err("ID cannot be empty"); return
    if rid in res:
        err(f"Resource '{rid}' already exists"); return

    name = input(f"  {C}Name:{RS} ").strip()
    dept = input(f"  {C}Department:{RS} ").strip()
    cls  = input(f"  {C}Classification (public/confidential/secret):{RS} ").strip()
    if cls not in ("public", "confidential", "secret"):
        err("Invalid classification"); return
    data = input(f"  {C}Data/description:{RS} ").strip()

    res[rid] = {"name": name, "department": dept, "classification": cls, "data": data}
    save_resources(res)
    ok(f"Resource '{rid}' created ({dept} / {cls})")


def cmd_resources_delete(rid: str):
    res = load_resources()
    rid = rid.upper()
    if rid not in res:
        err(f"Resource '{rid}' not found"); return
    confirm = input(f"  {Y}Delete '{rid}'? (yes/no):{RS} ").strip().lower()
    if confirm != "yes":
        info("Cancelled"); return
    del res[rid]
    save_resources(res)
    ok(f"Resource '{rid}' deleted")


# ── Policy Commands ────────────────────────────────────────────────────────────

def cmd_policies_list():
    hdr("POLICY LIST")
    policies = load_policies()
    for p in policies:
        print(f"  {C}[{p['id']}]{RS}  Pri={p.get('priority','?')}  {B}{p['name']}{RS}")
        print(f"       {D}{p.get('description','')}{RS}")
    print(f"\n  Total: {len(policies)} policies")


def cmd_policies_reload():
    try:
        r = requests.post(f"{BASE}/admin/reload-policies", timeout=3)
        if r.ok:
            data = r.json()
            ok(f"Policies reloaded on server ({data.get('count','?')} policies)")
        else:
            err(f"Server error: {r.text}")
    except requests.ConnectionError:
        warn("Server not reachable — policies reload on next server restart")


# ── Security Commands ──────────────────────────────────────────────────────────

def cmd_security_status():
    hdr("SECURITY STATUS")
    try:
        r = requests.get(f"{BASE}/admin/security-status", timeout=3)
        if r.ok:
            data   = r.json()
            locked = data.get("locked_accounts", {})
            ips    = data.get("flagged_ips", {})
            if locked:
                warn(f"Locked accounts ({len(locked)}):")
                for u, d in locked.items():
                    print(f"    {R}{u}{RS}  failures={d.get('failures','?')}")
            else:
                ok("No locked accounts")
            if ips:
                warn(f"Flagged IPs ({len(ips)}):")
                for ip, count in ips.items():
                    print(f"    {Y}{ip}{RS}  {count} recent attempts")
            else:
                ok("No flagged IPs")
        else:
            err(f"Server error: {r.text}")
    except requests.ConnectionError:
        err("Server not reachable — start app.py on port 5000")


def cmd_security_reset_ip(ip: str):
    try:
        r = requests.post(f"{BASE}/admin/reset-ip", json={"ip": ip}, timeout=3)
        ok(f"IP '{ip}' unblocked") if r.ok else err(f"Server error: {r.text}")
    except requests.ConnectionError:
        err("Server not reachable")


def cmd_security_logs(n: int = 20):
    hdr(f"LAST {n} SECURITY LOGS")
    try:
        r = requests.get(f"{BASE}/admin/public-logs?n={n}", timeout=3)
        if r.ok:
            logs = r.json().get("logs", [])
            if not logs:
                info("No log entries yet")
                return
            for entry in logs:
                sev   = entry.get("severity", "INFO")
                color = {"CRITICAL": R, "WARNING": Y, "INFO": G}.get(sev, RS)
                ts    = entry.get("timestamp", "")[:19]
                event = entry.get("event", "")
                msg   = entry.get("message", "")
                print(f"  {D}{ts}{RS}  {color}{sev:<8}{RS}  {C}{event:<25}{RS}  {msg}")
        else:
            err(f"Server error: {r.text}")
    except requests.ConnectionError:
        err("Server not reachable — start app.py on port 5000")


# ── Help ───────────────────────────────────────────────────────────────────────

def show_help():
    print(f"""
{B}{C}SecureCorp Admin CLI — Commands{RS}

  {B}users list{RS}                    List all users
  {B}users add{RS}                     Add a new user (interactive)
  {B}users delete <username>{RS}       Delete a user
  {B}users role <username> <role>{RS}  Change user role
  {B}users unlock <username>{RS}       Unlock a locked account
  {B}users passwd <username>{RS}       Change password

  {B}resources list{RS}                List all resources
  {B}resources add{RS}                 Add a new resource (interactive)
  {B}resources delete <id>{RS}         Delete a resource

  {B}policies list{RS}                 List all ABAC policies
  {B}policies reload{RS}               Hot-reload policies (server must be running)

  {B}security status{RS}               Show locked accounts & flagged IPs
  {B}security reset-ip <ip>{RS}        Unblock an IP address
  {B}security logs [n]{RS}             Show last n log entries (default 20)

  {B}help{RS}                          Show this menu
  {B}exit{RS}                          Quit
""")


# ── Main REPL ──────────────────────────────────────────────────────────────────

def run():
    print(f"""
{B}{C}╔══════════════════════════════════════════════════════╗
║   SecureCorp Admin CLI                              ║
║   Dynamic user & system management                  ║
╚══════════════════════════════════════════════════════╝{RS}
  Type {B}help{RS} for commands, {B}exit{RS} to quit.
""")

    while True:
        try:
            raw = input(f"{C}securecorp>{RS} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        try:
            if cmd == "exit":
                break
            elif cmd == "help":
                show_help()

            elif cmd == "users":
                sub = args[0].lower() if args else ""
                if sub == "list":
                    cmd_users_list()
                elif sub == "add":
                    cmd_users_add()
                elif sub == "delete" and len(args) >= 2:
                    cmd_users_delete(args[1])
                elif sub == "role" and len(args) >= 3:
                    cmd_users_role(args[1], args[2])
                elif sub == "passwd" and len(args) >= 2:
                    cmd_users_passwd(args[1])
                elif sub == "unlock" and len(args) >= 2:
                    cmd_users_unlock(args[1])
                else:
                    err("Unknown users command. Type 'help' for usage.")

            elif cmd == "resources":
                sub = args[0].lower() if args else ""
                if sub == "list":
                    cmd_resources_list()
                elif sub == "add":
                    cmd_resources_add()
                elif sub == "delete" and len(args) >= 2:
                    cmd_resources_delete(args[1])
                else:
                    err("Unknown resources command. Type 'help' for usage.")

            elif cmd == "policies":
                sub = args[0].lower() if args else ""
                if sub == "list":
                    cmd_policies_list()
                elif sub == "reload":
                    cmd_policies_reload()
                else:
                    err("Unknown policies command. Type 'help' for usage.")

            elif cmd == "security":
                sub = args[0].lower() if args else ""
                if sub == "status":
                    cmd_security_status()
                elif sub == "reset-ip" and len(args) >= 2:
                    cmd_security_reset_ip(args[1])
                elif sub == "logs":
                    n = int(args[1]) if len(args) >= 2 else 20
                    cmd_security_logs(n)
                else:
                    err("Unknown security command. Type 'help' for usage.")

            else:
                err(f"Unknown command '{cmd}'. Type 'help' for usage.")

        except Exception as e:
            err(f"Error: {e}")


if __name__ == "__main__":
    run()