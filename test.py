"""
test.py — SECURE BUILD
Full test suite. Handles the 2-step MFA login automatically by
fetching the PIN from the /mfa/pending endpoint (same machine).
"""

import sys
import time
import uuid
import requests

BASE = "http://localhost:5000"

USERS = {
    "alice": "Admin@2024",
    "bob":   "Manager@2024",
    "carol": "Employee@2024",
    "dave":  "Dave@2024",
    "frank": "Frank@2024",
}

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"
INFO = "\033[93m  →\033[0m"

_results = {"passed": 0, "failed": 0}


def check(condition: bool, label: str, detail: str = ""):
    if condition:
        _results["passed"] += 1
        print(f"  {PASS}  {label}")
    else:
        _results["failed"] += 1
        print(f"  {FAIL}  {label}")
        if detail:
            print(f"         {INFO} {detail}")


def section(title: str):
    print(f"\n{'═'*64}")
    print(f"  {title}")
    print(f"{'═'*64}")


# ── MFA-aware login helpers ───────────────────────────────────────────────────

def _fetch_pin(username: str, timeout: float = 5.0) -> str | None:
    """Poll /mfa/pending until a PIN appears for this user (or timeout)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE}/mfa/pending", timeout=2)
            if r.ok:
                for entry in r.json().get("pending", []):
                    if entry["username"] == username:
                        return entry["pin"]
        except Exception:
            pass
        time.sleep(0.3)
    return None


def login(username: str, password: str) -> dict | None:
    """Full 2-step login: password → MFA PIN → TGT."""
    # Step 1
    r = requests.post(f"{BASE}/login", json={"username": username, "password": password})
    if not r.ok:
        return None
    if not r.json().get("mfa_required"):
        return r.json()   # shouldn't happen in secure build

    # Step 2 — fetch PIN from MFA channel and submit
    pin = _fetch_pin(username)
    if not pin:
        print(f"  [test] Could not retrieve MFA PIN for {username}")
        return None
    r2 = requests.post(f"{BASE}/login/mfa", json={"username": username, "pin": pin})
    return r2.json() if r2.ok else None


def get_ticket(tgt: str, service: str = "resource_server") -> dict | None:
    r = requests.post(f"{BASE}/request-ticket", json={
        "tgt": tgt,
        "service": service,
        "authenticator": {"nonce": str(uuid.uuid4()), "timestamp": time.time()},
    })
    return r.json() if r.ok else None


def resource_headers(st: str) -> dict:
    return {
        "X-Service-Ticket":          st,
        "X-Authenticator-Nonce":     str(uuid.uuid4()),
        "X-Authenticator-Timestamp": str(time.time()),
    }


def full_login(username: str) -> str | None:
    auth = login(username, USERS[username])
    if not auth:
        return None
    ticket_resp = get_ticket(auth["tgt"])
    return ticket_resp.get("service_ticket") if ticket_resp else None


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════════

def test_authentication():
    section("1 · AUTHENTICATION — Valid & Invalid Flows")

    for user, pwd in USERS.items():
        auth = login(user, pwd)
        check(auth is not None and "tgt" in auth, f"Valid login: {user}")

    # Wrong password — step 1 should fail
    r = requests.post(f"{BASE}/login", json={"username": "alice", "password": "WRONG"})
    check(r.status_code == 401, "Reject wrong password")

    # Non-existent user
    r = requests.post(f"{BASE}/login", json={"username": "nobody", "password": "x"})
    check(r.status_code == 401, "Reject unknown username")

    # Empty body
    r = requests.post(f"{BASE}/login", json={})
    check(r.status_code == 400, "Reject empty credentials")

    # MFA with wrong PIN
    r1 = requests.post(f"{BASE}/login", json={"username": "bob", "password": "Manager@2024"})
    if r1.ok and r1.json().get("mfa_required"):
        r2 = requests.post(f"{BASE}/login/mfa", json={"username": "bob", "pin": "000000"})
        check(r2.status_code == 401, "Reject wrong MFA PIN")

    auth = login("alice", USERS["alice"])
    check(auth is not None and auth["user_info"]["role"] == "Admin", "TGT carries correct role for alice")
    check("tgt_expires_in" in auth, "TGT includes expiry metadata")


def test_ticket_exchange():
    section("2 · TICKET EXCHANGE — TGT → Service Ticket")

    auth = login("bob", USERS["bob"])
    assert auth, "bob must log in"

    r = requests.post(f"{BASE}/request-ticket", json={
        "tgt": auth["tgt"],
        "service": "resource_server",
        "authenticator": {"nonce": str(uuid.uuid4()), "timestamp": time.time()},
    })
    check(r.status_code == 200 and "service_ticket" in r.json(), "Valid TGT → Service Ticket exchange")

    tampered = auth["tgt"][:-8] + "TAMPERED"
    r = requests.post(f"{BASE}/request-ticket", json={
        "tgt": tampered, "service": "resource_server",
        "authenticator": {"nonce": str(uuid.uuid4()), "timestamp": time.time()},
    })
    check(r.status_code == 401, "Reject tampered TGT")

    r = requests.post(f"{BASE}/request-ticket", json={"service": "resource_server"})
    check(r.status_code == 400, "Reject missing TGT")


def test_rbac():
    section("3 · RBAC — Role-Based Access Control")

    alice_st = full_login("alice")
    bob_st   = full_login("bob")
    carol_st = full_login("carol")

    r = requests.get(f"{BASE}/resource/IT-001", headers=resource_headers(alice_st))
    check(r.status_code == 200, "Admin can READ IT-001")

    r = requests.delete(f"{BASE}/resource/IT-002", headers=resource_headers(alice_st))
    check(r.status_code == 200, "Admin can DELETE IT-002")

    r = requests.delete(f"{BASE}/resource/FIN-002", headers=resource_headers(bob_st))
    check(r.status_code == 403, "Manager cannot DELETE (RBAC: no delete permission)")

    r = requests.post(f"{BASE}/resource", headers=resource_headers(carol_st),
                      json={"department": "HR", "classification": "public"})
    check(r.status_code == 403, "Employee cannot WRITE (RBAC: read-only role)")

    r = requests.get(f"{BASE}/resource/HR-002", headers=resource_headers(carol_st))
    check(r.status_code == 200, "Employee can READ HR-002 (own dept, public)")


def test_abac_department():
    section("4 · ABAC — POL-001 Department Isolation")

    carol_st = full_login("carol")
    frank_st = full_login("frank")

    r = requests.get(f"{BASE}/resource/FIN-002", headers=resource_headers(carol_st))
    check(r.status_code == 403, "HR Employee denied Finance resource (POL-001)")

    r = requests.get(f"{BASE}/resource/HR-001", headers=resource_headers(frank_st))
    check(r.status_code == 403, "Finance Employee denied HR resource (POL-001)")

    r = requests.get(f"{BASE}/resource/HR-002", headers=resource_headers(carol_st))
    check(r.status_code == 200, "HR Employee allowed own dept resource (POL-001 pass)")

    alice_st = full_login("alice")
    r = requests.get(f"{BASE}/resource/FIN-001", headers=resource_headers(alice_st))
    check(r.status_code == 200, "Admin exempt from department isolation (POL-001 exempt)")


def test_abac_clearance():
    section("5 · ABAC — POL-002 Clearance / Classification")

    alice_st = full_login("alice")
    bob_st   = full_login("bob")
    frank_st = full_login("frank")

    r = requests.get(f"{BASE}/resource/IT-001", headers=resource_headers(alice_st))
    check(r.status_code == 200, "Admin (secret clearance) reads secret IT-001 → ALLOW")

    r = requests.get(f"{BASE}/resource/FIN-001", headers=resource_headers(bob_st))
    check(r.status_code == 403, "Manager (confidential) denied secret FIN-001 (POL-002)")

    r = requests.get(f"{BASE}/resource/FIN-002", headers=resource_headers(frank_st))
    check(r.status_code == 200, "Finance Employee (confidential) reads confidential FIN-002 → ALLOW")


def test_abac_external():
    section("6 · ABAC — POL-004 External Access Restriction")

    dave_st = full_login("dave")
    r = requests.get(f"{BASE}/resource/OPS-001", headers=resource_headers(dave_st))
    check(r.status_code == 403, "External user denied confidential OPS-001 (POL-004)")


def test_replay_attack():
    section("7 · SECURITY — Replay Attack Detection")

    r = requests.post(f"{BASE}/demo/replay-attack")
    data = r.json()
    check(r.status_code == 200, "Replay attack demo endpoint responds")
    check(data.get("status", "").startswith("MITIGATED"), "Replay attack mitigated")
    check("BLOCKED" in data.get("step_2_replay_attempt", ""), "Second nonce use blocked")

    auth = login("bob", USERS["bob"])
    nonce = str(uuid.uuid4())
    ts    = time.time()

    r1 = requests.post(f"{BASE}/request-ticket", json={
        "tgt": auth["tgt"], "service": "resource_server",
        "authenticator": {"nonce": nonce, "timestamp": ts},
    })
    r2 = requests.post(f"{BASE}/request-ticket", json={
        "tgt": auth["tgt"], "service": "resource_server",
        "authenticator": {"nonce": nonce, "timestamp": ts},
    })
    check(r1.status_code == 200, "First (legitimate) request accepted")
    check(r2.status_code == 401 and "REPLAY" in r2.json().get("code", ""),
          "Replayed request rejected with REPLAY_DETECTED")


def test_ticket_tampering():
    section("8 · SECURITY — Ticket Tampering Detection")

    r = requests.post(f"{BASE}/demo/tamper-attack")
    data = r.json()
    check(r.status_code == 200, "Tamper demo endpoint responds")
    check(data.get("tamper_detected") is True, "Tampered ticket detected (HMAC failure)")
    check(data.get("status", "").startswith("MITIGATED"), "Tampering mitigated")

    auth = login("carol", USERS["carol"])
    st_resp = get_ticket(auth["tgt"])
    st = st_resp["service_ticket"]
    tampered_st = st[:-8] + "XXXXXXXX"

    r = requests.get(f"{BASE}/resource/HR-002", headers={
        "X-Service-Ticket": tampered_st,
        "X-Authenticator-Nonce": str(uuid.uuid4()),
        "X-Authenticator-Timestamp": str(time.time()),
    })
    check(r.status_code == 401, "Tampered service ticket rejected at Resource Server")


def test_privilege_escalation():
    section("9 · SECURITY — Privilege Escalation Prevention")

    r = requests.post(f"{BASE}/demo/privilege-escalation")
    data = r.json()
    check(r.status_code == 200, "Privilege escalation demo endpoint responds")
    check("DENY" in data.get("with_real_role", ""), "Real Employee role denied delete")
    check(data.get("status", "").startswith("MITIGATED"), "Escalation mitigated")

    carol_st = full_login("carol")
    r = requests.delete(f"{BASE}/resource/HR-001",
                        headers=resource_headers(carol_st),
                        json={"role": "Admin"})
    check(r.status_code == 403, "Forged role in request body is ignored — RBAC uses ticket role")


def test_brute_force():
    section("10 · SECURITY — Brute Force / Account Lockout")

    # Use a throwaway username so we don't lock out real test users
    target = "frank"
    # Unlock first (in case previous run left it locked)
    requests.post(f"{BASE}/admin/unlock/{target}")

    for _ in range(5):
        requests.post(f"{BASE}/login", json={"username": target, "password": "WRONGPWD"})

    r = requests.post(f"{BASE}/login", json={"username": target, "password": USERS[target]})
    check(r.status_code == 429, "Account locked after 5 failed attempts")

    # Unlock for subsequent tests
    requests.post(f"{BASE}/admin/unlock/{target}")


def test_no_ticket():
    section("11 · EDGE CASES — Missing / Expired Tickets")

    r = requests.get(f"{BASE}/resource/HR-002")
    check(r.status_code == 401, "No ticket → 401")

    r = requests.get(f"{BASE}/resource/HR-002",
                     headers={"X-Service-Ticket": "not-a-valid-ticket"})
    check(r.status_code == 401, "Garbage ticket → 401")

    carol_st = full_login("carol")
    r = requests.get(f"{BASE}/resource/NOPE-999", headers=resource_headers(carol_st))
    check(r.status_code == 404, "Non-existent resource → 404")


# ═══════════════════════════════════════════════════════════════════════════════

def run_all():
    print("\n" + "╔" + "═"*62 + "╗")
    print("║   SecureCorp Zero-Trust System — Full Test Suite (Secure)   ║")
    print("╚" + "═"*62 + "╝")

    for fn in [
        test_authentication,
        test_ticket_exchange,
        test_rbac,
        test_abac_department,
        test_abac_clearance,
        test_abac_external,
        test_replay_attack,
        test_ticket_tampering,
        test_privilege_escalation,
        test_brute_force,
        test_no_ticket,
    ]:
        try:
            fn()
        except Exception as exc:
            print(f"\033[91m  ERROR in {fn.__name__}: {exc}\033[0m")

    total  = _results["passed"] + _results["failed"]
    passed = _results["passed"]
    failed = _results["failed"]

    print(f"\n{'═'*64}")
    print(f"  Results: {passed}/{total} passed", end="")
    if failed == 0:
        print("  \033[92m— All tests passed! ✓\033[0m")
    else:
        print(f"  \033[91m— {failed} test(s) failed ✗\033[0m")
    print(f"{'═'*64}\n")
    return failed == 0


if __name__ == "__main__":
    ok = run_all()
    sys.exit(0 if ok else 1)
