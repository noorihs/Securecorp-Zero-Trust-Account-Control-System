"""
rate_limiter.py — SECURE BUILD
Fixes brute-force vulnerability:
  - Tracks failed attempts per username (account lockout after 5 failures)
  - Tracks failed attempts per IP (IP block after 20 failures in a window)
  - All counters are reset on successful login
"""

import time
from threading import Lock
from typing import Dict, Tuple


class RateLimiter:
    """
    SECURE: Real rate-limiting and account lockout.

    Account lockout:
        After MAX_FAILURES consecutive failed logins for a username,
        the account is locked for LOCKOUT_SECONDS.

    IP blocking:
        After IP_MAX_FAILURES failed logins from the same IP within
        IP_WINDOW_SECONDS, the IP is blocked for IP_BLOCK_SECONDS.
    """

    MAX_FAILURES     = 5
    LOCKOUT_SECONDS  = 300      # 5 minutes

    IP_MAX_FAILURES  = 20
    IP_WINDOW_SECONDS = 60      # sliding window
    IP_BLOCK_SECONDS = 600      # 10 minutes

    def __init__(self, **kwargs):
        # username → {failures: int, locked_until: float}
        self._accounts: Dict[str, Dict] = {}
        # ip → {timestamps: list[float], blocked_until: float}
        self._ips: Dict[str, Dict] = {}
        self._lock = Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def is_ip_blocked(self, ip: str) -> Tuple[bool, str]:
        with self._lock:
            rec = self._ips.get(ip)
            if rec and time.time() < rec.get("blocked_until", 0):
                remaining = int(rec["blocked_until"] - time.time())
                return True, f"IP temporarily blocked — try again in {remaining}s"
            return False, ""

    def is_account_locked(self, username: str) -> Tuple[bool, str]:
        with self._lock:
            rec = self._accounts.get(username)
            if rec and time.time() < rec.get("locked_until", 0):
                remaining = int(rec["locked_until"] - time.time())
                return True, f"Account locked due to too many failed attempts — try again in {remaining}s"
            return False, ""

    def record_attempt(self, ip: str, username: str, success: bool):
        with self._lock:
            if success:
                # Reset both on success
                if username in self._accounts:
                    self._accounts[username]["failures"] = 0
                    self._accounts[username]["locked_until"] = 0
                if ip in self._ips:
                    self._ips[ip]["timestamps"] = []
                    self._ips[ip]["blocked_until"] = 0
                return

            # ── Account lockout tracking ──────────────────────────────────
            if username not in self._accounts:
                self._accounts[username] = {"failures": 0, "locked_until": 0}
            rec = self._accounts[username]
            rec["failures"] += 1
            if rec["failures"] >= self.MAX_FAILURES:
                rec["locked_until"] = time.time() + self.LOCKOUT_SECONDS
                rec["failures"] = 0   # reset counter so next cycle works

            # ── IP rate-limit tracking ────────────────────────────────────
            if ip not in self._ips:
                self._ips[ip] = {"timestamps": [], "blocked_until": 0}
            ip_rec = self._ips[ip]
            now = time.time()
            # Purge old timestamps outside the sliding window
            ip_rec["timestamps"] = [
                t for t in ip_rec["timestamps"]
                if now - t < self.IP_WINDOW_SECONDS
            ]
            ip_rec["timestamps"].append(now)
            if len(ip_rec["timestamps"]) >= self.IP_MAX_FAILURES:
                ip_rec["blocked_until"] = now + self.IP_BLOCK_SECONDS
                ip_rec["timestamps"] = []

    def unlock_account(self, username: str):
        with self._lock:
            if username in self._accounts:
                self._accounts[username]["failures"] = 0
                self._accounts[username]["locked_until"] = 0

    def reset_ip(self, ip: str):
        with self._lock:
            if ip in self._ips:
                self._ips[ip]["timestamps"] = []
                self._ips[ip]["blocked_until"] = 0

    def get_status(self) -> Dict:
        with self._lock:
            now = time.time()
            locked = {
                u: {"locked_until": rec["locked_until"]}
                for u, rec in self._accounts.items()
                if now < rec.get("locked_until", 0)
            }
            flagged = {
                ip: {"blocked_until": rec["blocked_until"]}
                for ip, rec in self._ips.items()
                if now < rec.get("blocked_until", 0)
            }
            return {"locked_accounts": locked, "flagged_ips": flagged}


rate_limiter = RateLimiter()
