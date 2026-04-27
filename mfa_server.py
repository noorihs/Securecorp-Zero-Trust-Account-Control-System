"""
mfa_server.py — MFA Terminal
Run this in a SECOND terminal alongside app.py.

This script polls the app's /mfa/pending endpoint every 2 seconds
and displays any new MFA PINs on screen — simulating a separate
out-of-band channel (e.g., SMS gateway, authenticator device, etc.).

Usage:
    Terminal 1:  python app.py
    Terminal 2:  python mfa_server.py
"""

import time
import requests

BASE    = "http://localhost:5000"
POLL_HZ = 2   # seconds between polls

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║        SecureCorp  —  MFA  Terminal                  ║
║  Waiting for authentication challenges...            ║
╚══════════════════════════════════════════════════════╝{RESET}
Polling {BASE}/mfa/pending every {POLL_HZ}s
""")


def main():
    banner()
    seen = set()

    while True:
        try:
            r = requests.get(f"{BASE}/mfa/pending", timeout=3)
            if r.ok:
                entries = r.json().get("pending", [])
                for entry in entries:
                    key = f"{entry['username']}:{entry['pin']}"
                    if key not in seen:
                        seen.add(key)
                        print(f"{BOLD}{GREEN}{'═'*54}{RESET}")
                        print(f"  {YELLOW}🔐 MFA CHALLENGE{RESET}")
                        print(f"  User    : {BOLD}{entry['username']}{RESET}")
                        print(f"  PIN     : {BOLD}{CYAN}{entry['pin']}{RESET}")
                        print(f"  Expires : {entry['expires_in']}s remaining")
                        print(f"{BOLD}{GREEN}{'═'*54}{RESET}\n")
        except requests.ConnectionError:
            print(f"  {YELLOW}[MFA] Waiting for app.py to start...{RESET}")
        except Exception as e:
            print(f"  [MFA] Error: {e}")

        time.sleep(POLL_HZ)


if __name__ == "__main__":
    main()
