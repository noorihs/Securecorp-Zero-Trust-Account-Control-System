
import json
import os
import sys
import time
import hashlib
import secrets
import getpass
from datetime import datetime

# ── File Paths ─────────────────────────────────────────────────────────────────
# Same directory as app.py — flat layout, no data/ subfolder
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
M  = "\033[95m"
RS = "\033[0m"

# ── Config (mirrors config.py) ─────────────────────────────────────────────────
CLEARANCE_RANK = {"public": 0, "confidential": 1, "secret": 2}
ROLE_PERMISSIONS = {
    "Admin":    ["read", "write", "delete"],
    "Manager":  ["read", "write"],
    "Employee": ["read"],
}
ROLE_HIERARCHY = {
    "Admin":    ["Manager", "Employee"],
    "Manager":  ["Employee"],
    "Employee": [],
}
ACCESS_START = 8
ACCESS_END   = 18


# ── Data Helpers ───────────────────────────────────────────────────────────────

def load(path):
    with open(path) as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump({"users": users}, f, indent=2)

def save_resources(resources):
    with open(RES_FILE, "w") as f:
        json.dump({"resources": resources}, f, indent=2)

def hash_password(password, salt):
    return hashlib.sha256(f"{password}:{salt}".encode()).hexdigest()


# ── Policy Evaluation ──────────────────────────────────────────────────────────

def effective_permissions(role):
    perms = set(ROLE_PERMISSIONS.get(role, []))
    for r in ROLE_HIERARCHY.get(role, []):
        perms |= set(ROLE_PERMISSIONS.get(r, []))
    return perms


def evaluate(user, resource, operation, hour_override=None):
    """
    Full policy evaluation — all 5 policies.
    Returns list of {name, decision, reason} dicts.
    """
    results = []
    hour    = hour_override if hour_override is not None else datetime.now().hour
    role    = user.get("role", "")

    # ── RBAC ──────────────────────────────────────────────────────────────────
    if role not in ROLE_PERMISSIONS:
        results.append({"name": "RBAC", "decision": "DENY",
                        "reason": f"Unknown role '{role}'"})
        return results
    perms = effective_permissions(role)
    if operation not in perms:
        results.append({"name": "RBAC", "decision": "DENY",
                        "reason": f"Role '{role}' cannot '{operation}' (allowed: {sorted(perms)})"})
        return results
    results.append({"name": "RBAC", "decision": "ALLOW",
                    "reason": f"Role '{role}' has '{operation}' permission"})

    # ── POL-001 Department Isolation ──────────────────────────────────────────
    exempt = ["Admin"]
    if role in exempt:
        results.append({"name": "POL-001 Department Isolation", "decision": "ALLOW",
                        "reason": f"Role '{role}' is exempt"})
    elif user.get("department") != resource.get("department"):
        results.append({"name": "POL-001 Department Isolation", "decision": "DENY",
                        "reason": f"User dept '{user.get('department')}' ≠ "
                                  f"resource dept '{resource.get('department')}'"})
        return results
    else:
        results.append({"name": "POL-001 Department Isolation", "decision": "ALLOW",
                        "reason": f"Same department: '{user.get('department')}'"})

    # ── POL-002 Clearance Check ───────────────────────────────────────────────
    u_lvl = CLEARANCE_RANK.get(user.get("clearance", "public"), 0)
    r_lvl = CLEARANCE_RANK.get(resource.get("classification", "public"), 0)
    if u_lvl < r_lvl:
        results.append({"name": "POL-002 Clearance Check", "decision": "DENY",
                        "reason": f"Clearance '{user.get('clearance')}' (lvl {u_lvl}) "
                                  f"< classification '{resource.get('classification')}' (lvl {r_lvl})"})
        return results
    results.append({"name": "POL-002 Clearance Check", "decision": "ALLOW",
                    "reason": f"Clearance '{user.get('clearance')}' ≥ '{resource.get('classification')}'"})

    # ── POL-003 Business Hours ────────────────────────────────────────────────
    if role in exempt:
        results.append({"name": "POL-003 Business Hours", "decision": "ALLOW",
                        "reason": f"Role '{role}' exempt from time restriction"})
    elif not (ACCESS_START <= hour < ACCESS_END):
        results.append({"name": "POL-003 Business Hours", "decision": "DENY",
                        "reason": f"Hour {hour:02d}:xx outside window "
                                  f"{ACCESS_START:02d}:00–{ACCESS_END:02d}:00"})
        return results
    else:
        results.append({"name": "POL-003 Business Hours", "decision": "ALLOW",
                        "reason": f"Within business hours (hour={hour:02d})"})

    # ── POL-004 External Access ───────────────────────────────────────────────
    loc = user.get("location", "internal")
    cls = resource.get("classification", "public")
    if loc == "external" and cls in ("confidential", "secret"):
        results.append({"name": "POL-004 External Access", "decision": "DENY",
                        "reason": f"External users cannot access '{cls}' resources"})
        return results
    results.append({"name": "POL-004 External Access", "decision": "ALLOW",
                    "reason": f"Location '{loc}' allowed for '{cls}' resource"})

    # ── POL-005 Delete Restriction ────────────────────────────────────────────
    if operation == "delete" and role != "Admin":
        results.append({"name": "POL-005 Delete Restriction", "decision": "DENY",
                        "reason": f"Only Admin can delete; current role='{role}'"})
        return results
    results.append({"name": "POL-005 Delete Restriction", "decision": "ALLOW",
                    "reason": "Delete check passed"})

    return results


# ── Display Helpers ────────────────────────────────────────────────────────────

def cls():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print(f"""
{B}{C}╔══════════════════════════════════════════════════════════════╗
║       SecureCorp — Interactive Access Simulator             ║
║       Zero-Trust · RBAC · ABAC · Live Policy Evaluation     ║
╚══════════════════════════════════════════════════════════════╝{RS}""")

def sep(title=""):
    if title:
        print(f"\n{B}{C}  {'─'*20} {title} {'─'*20}{RS}")
    else:
        print(f"  {D}{'─'*56}{RS}")

def pick(prompt, options, display_fn=None):
    """Generic numbered picker. Returns chosen item or None."""
    print()
    for i, opt in enumerate(options, 1):
        label = display_fn(opt) if display_fn else str(opt)
        print(f"  {C}[{i}]{RS}  {label}")
    print(f"  {D}[0]  Cancel / back{RS}")
    while True:
        try:
            n = int(input(f"\n  {B}Your choice:{RS} ").strip())
            if n == 0:
                return None
            if 1 <= n <= len(options):
                return options[n - 1]
            print(f"  {R}Enter a number between 0 and {len(options)}{RS}")
        except (ValueError, EOFError):
            print(f"  {R}Please enter a number{RS}")

def show_user_card(uname, u):
    cc = {"secret": R, "confidential": Y, "public": G}
    lc = R if u.get("location") == "external" else G
    print(f"""
  {B}User:{RS}        {C}{uname}{RS}
  {B}Role:{RS}        {B}{u['role']}{RS}
  {B}Department:{RS}  {u['department']}
  {B}Clearance:{RS}   {cc.get(u['clearance'], RS)}{u['clearance']}{RS}
  {B}Location:{RS}    {lc}{u['location']}{RS}""")

def show_resource_card(rid, r):
    cc = {"secret": R, "confidential": Y, "public": G}
    c  = cc.get(r.get("classification", "public"), RS)
    print(f"""
  {B}Resource:{RS}       {C}{rid}{RS}
  {B}Name:{RS}           {r['name']}
  {B}Department:{RS}     {r['department']}
  {B}Classification:{RS} {c}{r['classification']}{RS}""")

def show_verdict(results):
    sep("POLICY EVALUATION")
    print()
    final = "ALLOW"
    for step in results:
        d     = step["decision"]
        icon  = f"{G}✓{RS}" if d == "ALLOW" else f"{R}✗{RS}"
        color = G if d == "ALLOW" else R
        print(f"  {icon}  {B}{step['name']}{RS}")
        print(f"     {color}{step['reason']}{RS}")
        if d == "DENY":
            final = "DENY"
            break
        print()

    sep()
    if final == "ALLOW":
        print(f"""
  {B}{G}╔══════════════════════════════════╗
  ║   ✓  ACCESS GRANTED              ║
  ╚══════════════════════════════════╝{RS}""")
    else:
        denied_by = next((s["name"] for s in results if s["decision"] == "DENY"), "policy")
        print(f"""
  {B}{R}╔══════════════════════════════════╗
  ║   ✗  ACCESS DENIED               ║
  ║      Blocked by: {denied_by:<16}║
  ╚══════════════════════════════════╝{RS}""")


# ── Flows ──────────────────────────────────────────────────────────────────────

def flow_simulate():
    while True:
        cls(); banner()
        sep("STEP 1 — SELECT USER")
        users  = load(USERS_FILE)["users"]
        unames = list(users.keys())

        def user_label(u):
            usr = users[u]
            c = {"secret": R, "confidential": Y, "public": G}.get(usr["clearance"], RS)
            l = R if usr["location"] == "external" else G
            return (f"{B}{u:<10}{RS}  role={usr['role']:<10}  "
                    f"dept={usr['department']:<12}  "
                    f"clearance={c}{usr['clearance']}{RS}  "
                    f"loc={l}{usr['location']}{RS}")

        uname = pick("Choose a user", unames, user_label)
        if uname is None:
            return
        user = users[uname]

        cls(); banner(); show_user_card(uname, user)
        sep("STEP 2 — SELECT RESOURCE")
        resources = load(RES_FILE)["resources"]
        rids = list(resources.keys())

        def res_label(rid):
            r = resources[rid]
            c = {"secret": R, "confidential": Y, "public": G}.get(r["classification"], RS)
            return (f"{B}{rid:<10}{RS}  dept={r['department']:<12}  "
                    f"class={c}{r['classification']}{RS}  {D}{r['name']}{RS}")

        rid = pick("Choose a resource", rids, res_label)
        if rid is None:
            continue
        resource = resources[rid]

        cls(); banner(); show_user_card(uname, user); show_resource_card(rid, resource)
        sep("STEP 3 — SELECT OPERATION")
        op = pick("Choose an operation", ["read", "write", "delete"])
        if op is None:
            continue

        sep("STEP 4 — TIME CONTEXT")
        cur_hour = datetime.now().hour
        print(f"\n  Current system hour: {B}{cur_hour:02d}:xx{RS}  (business hours: 08:00–18:00)")
        print(f"\n  {C}[1]{RS}  Use current time ({cur_hour:02d}:xx)")
        print(f"  {C}[2]{RS}  Override — business hours (10:00)")
        print(f"  {C}[3]{RS}  Override — after hours (22:00)")
        print(f"  {C}[4]{RS}  Enter custom hour")
        choice = input(f"\n  {B}Your choice:{RS} ").strip()
        if choice == "2":
            hour = 10
        elif choice == "3":
            hour = 22
        elif choice == "4":
            try:
                hour = int(input("  Enter hour (0-23): "))
            except ValueError:
                hour = cur_hour
        else:
            hour = cur_hour

        cls(); banner()
        show_user_card(uname, user)
        show_resource_card(rid, resource)
        print(f"\n  {B}Operation:{RS}  {M}{op.upper()}{RS}")
        print(f"  {B}Time:{RS}       {hour:02d}:xx")

        show_verdict(evaluate(user, resource, op, hour_override=hour))

        print(f"\n  {D}Press Enter to run another simulation, or Ctrl+C to go back…{RS}")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            return


def flow_add_user():
    """Add a new user then show a full access preview."""
    cls(); banner()
    sep("ADD NEW USER")
    users = load(USERS_FILE)["users"]

    username = input(f"\n  {C}Username:{RS} ").strip().lower()
    if not username:
        print(f"  {R}Username cannot be empty{RS}"); input("  Press Enter…"); return
    if username in users:
        print(f"  {R}User '{username}' already exists{RS}"); input("  Press Enter…"); return

    role = pick("Role", ["Admin", "Manager", "Employee"])
    if not role: return

    dept = pick("Department", ["HR", "Finance", "IT", "Operations"])
    if not dept: return

    clearance = pick("Clearance level", ["public", "confidential", "secret"])
    if not clearance: return

    location = pick("Location", ["internal", "external"])
    if not location: return

    try:
        password = getpass.getpass(f"\n  {C}Password (min 8 chars):{RS} ")
    except Exception:
        password = input(f"\n  {C}Password:{RS} ")

    if len(password) < 8:
        print(f"  {R}Password too short{RS}"); input("  Press Enter…"); return

    salt  = secrets.token_hex(16)
    phash = hash_password(password, salt)
    users[username] = {
        "role": role, "department": dept,
        "clearance": clearance, "location": location,
        "salt": salt, "password_hash": phash,
    }
    save_users(users)
    print(f"\n  {G}✓ User '{username}' created!{RS}")

    # Show access preview
    input(f"\n  {D}Press Enter to preview access for '{username}'…{RS}")
    cls(); banner()
    sep(f"ACCESS PREVIEW FOR '{username.upper()}'")
    show_user_card(username, users[username])

    resources = load(RES_FILE)["resources"]
    hour      = datetime.now().hour
    if not (ACCESS_START <= hour < ACCESS_END):
        hour = 10

    print(f"\n  {'Operation':<10}  {'Resource':<10}  {'Dept':<12}  {'Class':<14}  Result")
    print(f"  {'─'*68}")
    for op in ["read", "write", "delete"]:
        for rid, resource in resources.items():
            results = evaluate(users[username], resource, op, hour_override=hour)
            final   = "ALLOW" if all(r["decision"] == "ALLOW" for r in results) else "DENY"
            denied  = next((r["name"] for r in results if r["decision"] == "DENY"), "")
            icon    = f"{G}✓ ALLOW{RS}" if final == "ALLOW" else f"{R}✗ DENY {RS}"
            cc      = {"secret": R, "confidential": Y, "public": G}
            cls_c   = cc.get(resource["classification"], RS)
            note    = f"  ← {D}{denied}{RS}" if final == "DENY" else ""
            print(f"  {M}{op:<10}{RS}  {C}{rid:<10}{RS}  {resource['department']:<12}  "
                  f"{cls_c}{resource['classification']:<14}{RS}  {icon}{note}")

    input(f"\n  {D}Press Enter to go back…{RS}")


def flow_add_resource():
    """Add a new resource then show who can access it."""
    cls(); banner()
    sep("ADD NEW RESOURCE")
    resources = load(RES_FILE)["resources"]

    rid = input(f"\n  {C}Resource ID (e.g. HR-003):{RS} ").strip().upper()
    if not rid:
        print(f"  {R}ID cannot be empty{RS}"); input("  Press Enter…"); return
    if rid in resources:
        print(f"  {R}Resource '{rid}' already exists{RS}"); input("  Press Enter…"); return

    name = input(f"  {C}Name:{RS} ").strip()
    dept = pick("Department", ["HR", "Finance", "IT", "Operations"])
    if not dept: return

    classification = pick("Classification", ["public", "confidential", "secret"])
    if not classification: return

    data = input(f"  {C}Description:{RS} ").strip()
    resources[rid] = {"name": name, "department": dept,
                      "classification": classification, "data": data}
    save_resources(resources)
    print(f"\n  {G}✓ Resource '{rid}' created!{RS}")

    input(f"\n  {D}Press Enter to see who can access it…{RS}")
    cls(); banner()
    sep(f"WHO CAN ACCESS '{rid}'?")
    show_resource_card(rid, resources[rid])

    users = load(USERS_FILE)["users"]
    hour  = 10

    print(f"\n  {'User':<12}{'Role':<12}{'Dept':<14}  read    write   delete")
    print(f"  {'─'*60}")
    for uname, u in users.items():
        row = f"  {C}{uname:<12}{RS}{u['role']:<12}{u['department']:<14}  "
        for op in ["read", "write", "delete"]:
            results = evaluate(u, resources[rid], op, hour_override=hour)
            final   = "ALLOW" if all(r["decision"] == "ALLOW" for r in results) else "DENY"
            row += f"{G}✓{RS}       " if final == "ALLOW" else f"{R}✗{RS}       "
        print(row)

    input(f"\n  {D}Press Enter to go back…{RS}")


def flow_access_matrix():
    """Show full access matrix: all users × all resources × all operations."""
    cls(); banner()
    sep("FULL ACCESS MATRIX")

    users     = load(USERS_FILE)["users"]
    resources = load(RES_FILE)["resources"]

    hour = datetime.now().hour
    if not (ACCESS_START <= hour < ACCESS_END):
        hour = 10

    for rid, resource in resources.items():
        cc = {"secret": R, "confidential": Y, "public": G}
        c  = cc.get(resource["classification"], RS)
        print(f"\n  {B}{C}{rid}{RS}  {resource['department']}  "
              f"{c}{resource['classification']}{RS}  {D}{resource['name']}{RS}")
        print(f"  {'User':<12}{'Role':<12}  read    write   delete")
        print(f"  {'─'*50}")
        for uname, u in users.items():
            row = f"  {C}{uname:<12}{RS}{u['role']:<12}  "
            for op in ["read", "write", "delete"]:
                results = evaluate(u, resource, op, hour_override=hour)
                final   = "ALLOW" if all(r["decision"] == "ALLOW" for r in results) else "DENY"
                row += f"{G}✓{RS}       " if final == "ALLOW" else f"{R}✗{RS}       "
            print(row)

    print(f"\n  {D}Hour used: {hour:02d}:xx (business hours){RS}")
    input(f"\n  {D}Press Enter to go back…{RS}")


# ── Main Menu ──────────────────────────────────────────────────────────────────

def main():
    while True:
        cls(); banner()
        print(f"""
  {B}What do you want to do?{RS}

  {C}[1]{RS}  {B}Simulate access{RS}          — pick a user, resource & operation
  {C}[2]{RS}  {B}Add a new user{RS}            — create user + see what they can access
  {C}[3]{RS}  {B}Add a new resource{RS}        — create resource + see who can access it
  {C}[4]{RS}  {B}Full access matrix{RS}        — all users × all resources
  {C}[0]{RS}  {D}Exit{RS}
""")
        choice = input(f"  {B}Your choice:{RS} ").strip()
        try:
            if choice == "1":
                flow_simulate()
            elif choice == "2":
                flow_add_user()
            elif choice == "3":
                flow_add_resource()
            elif choice == "4":
                flow_access_matrix()
            elif choice == "0":
                print(f"\n  {G}Goodbye.{RS}\n")
                break
        except KeyboardInterrupt:
            continue


if __name__ == "__main__":
    main()