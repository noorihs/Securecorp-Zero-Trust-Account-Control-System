"""
security.py — SECURE BUILD
Fixes:
  1. Ticket Tampering  → Fernet (AES-128-CBC + HMAC-SHA256) instead of bare base64
  2. Replay Attack     → Nonce registry with timestamp-window enforcement
  3. Password Timing   → secrets.compare_digest instead of ==
  4. MFA              → TOTP-style 6-digit PIN stored in _pending_mfa dict
"""

import base64
import hashlib
import secrets
import time
import uuid
from threading import Lock

from cryptography.fernet import Fernet, InvalidToken


# ── Key Derivation (Fernet needs 32-byte URL-safe base64 key) ─────────────────

def _derive_fernet_key(raw_key: bytes) -> bytes:
    """Derive a 32-byte Fernet key from an arbitrary raw key via SHA-256."""
    digest = hashlib.sha256(raw_key).digest()
    return base64.urlsafe_b64encode(digest)


# ── Ticket Encryption — Fernet (SECURE) ──────────────────────────────────────

def encrypt_ticket(data: dict, key: bytes) -> str:
    """
    SECURE: Encrypts + authenticates the ticket payload with Fernet.
    Any modification to the ciphertext will raise InvalidToken on decryption.
    """
    import json
    fernet = Fernet(_derive_fernet_key(key))
    raw    = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return fernet.encrypt(raw).decode("utf-8")


def decrypt_ticket(token: str, key: bytes) -> dict:
    """
    SECURE: Fernet decryption verifies the HMAC before returning plaintext.
    Raises InvalidToken (→ caught as Exception in callers) if tampered.
    """
    import json
    fernet = Fernet(_derive_fernet_key(key))
    raw    = fernet.decrypt(token.encode("utf-8"))   # raises InvalidToken if bad
    return json.loads(raw.decode("utf-8"))


# ── Password Hashing (timing-safe compare) ───────────────────────────────────

def hash_password(password: str, salt: str) -> str:
    combined = f"{password}:{salt}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """SECURE: uses secrets.compare_digest to prevent timing attacks."""
    computed = hash_password(password, salt)
    return secrets.compare_digest(computed, stored_hash)


# ── Random Generation ─────────────────────────────────────────────────────────

def generate_session_key() -> str:
    return secrets.token_hex(32)


def generate_nonce() -> str:
    return str(uuid.uuid4())


# ── Replay Protection — SECURE ────────────────────────────────────────────────

class ReplayProtection:
    """
    SECURE: Nonces are stored with their expiry timestamp.
    A nonce seen within the time window is rejected immediately.
    Old nonces are purged on each call to avoid unbounded memory growth.
    """

    def __init__(self, window_seconds: int = 300):
        self._window = window_seconds
        self._used: dict[str, float] = {}   # nonce → expiry_time
        self._lock = Lock()

    def check_and_register(self, nonce: str, timestamp: float) -> bool:
        """
        Returns True if the nonce is fresh and not seen before (ALLOW).
        Returns False if the nonce is replayed or the timestamp is too old/future.
        """
        now = time.time()
        with self._lock:
            self._purge(now)

            # Reject timestamps outside the acceptable window
            if abs(now - timestamp) > self._window:
                return False

            # Reject already-seen nonces
            if nonce in self._used:
                return False

            # Register nonce with its expiry time
            self._used[nonce] = now + self._window
            return True

    def _purge(self, now: float):
        """Remove expired nonces to keep memory bounded."""
        expired = [n for n, exp in self._used.items() if exp < now]
        for n in expired:
            del self._used[n]

    def force_add(self, nonce: str):
        """Test helper: forcibly mark a nonce as used."""
        with self._lock:
            self._used[nonce] = time.time() + self._window


replay_protection = ReplayProtection(window_seconds=300)


# ── MFA — 6-digit PIN (OTP-style) ────────────────────────────────────────────

class MFAManager:
    """
    Simple server-side MFA.
    When a user passes password verification, a 6-digit PIN is generated
    and printed to the MFA terminal (mfa_server.py).
    The login is only completed when the user supplies the correct PIN
    within the validity window.
    """

    PIN_TTL = 120        # seconds a PIN stays valid
    PIN_DIGITS = 6

    def __init__(self):
        # username → {pin, expires_at, attempts}
        self._pending: dict[str, dict] = {}
        self._lock = Lock()

    def generate_pin(self, username: str) -> str:
        """Create a new PIN for the user and return it (to be shown on MFA terminal)."""
        pin = "".join([str(secrets.randbelow(10)) for _ in range(self.PIN_DIGITS)])
        with self._lock:
            self._pending[username] = {
                "pin":        pin,
                "expires_at": time.time() + self.PIN_TTL,
                "attempts":   0,
            }
        return pin

    def verify_pin(self, username: str, pin: str) -> tuple[bool, str]:
        """
        Returns (True, "") on success.
        Returns (False, reason) on failure.
        Invalidates the PIN after success or too many wrong attempts.
        """
        with self._lock:
            entry = self._pending.get(username)
            if not entry:
                return False, "No pending MFA challenge for this user"
            if time.time() > entry["expires_at"]:
                del self._pending[username]
                return False, "MFA PIN expired — please log in again"

            entry["attempts"] += 1
            if entry["attempts"] > 5:
                del self._pending[username]
                return False, "Too many wrong MFA attempts — please log in again"

            if not secrets.compare_digest(entry["pin"], pin.strip()):
                return False, f"Wrong PIN ({entry['attempts']}/5 attempts)"

            # Success — consume the PIN
            del self._pending[username]
            return True, ""

    def has_pending(self, username: str) -> bool:
        with self._lock:
            entry = self._pending.get(username)
            if not entry:
                return False
            if time.time() > entry["expires_at"]:
                del self._pending[username]
                return False
            return True


mfa_manager = MFAManager()
