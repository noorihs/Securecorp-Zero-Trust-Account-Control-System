
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional


class SecurityLogger:
    """
    Writes structured JSON log entries to a rotating log file
    and keeps an in-memory ring buffer for the /admin/logs endpoint.
    """

    BUFFER_SIZE = 500   # max entries in memory

    def __init__(self, log_path: str):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # File handler — one JSON object per line (NDJSON)
        self._file_logger = logging.getLogger("securecorp.security")
        self._file_logger.setLevel(logging.DEBUG)

        if not self._file_logger.handlers:
            fh = logging.FileHandler(log_path, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(message)s"))
            self._file_logger.addHandler(fh)

        # In-memory ring buffer
        self._buffer: List[Dict] = []
        self._attack_events: List[Dict] = []

    # ── Internal ────────────────────────────────────────────────────────────

    def _write(self, entry: Dict[str, Any]):
        entry.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
        self._file_logger.info(json.dumps(entry))

        # Ring buffer
        self._buffer.append(entry)
        if len(self._buffer) > self.BUFFER_SIZE:
            self._buffer.pop(0)

        # Separate attack buffer
        if entry.get("severity") in ("WARNING", "CRITICAL"):
            self._attack_events.append(entry)
            if len(self._attack_events) > self.BUFFER_SIZE:
                self._attack_events.pop(0)

    # ── Public Logging Methods ──────────────────────────────────────────────

    def log_auth_attempt(self, username: str, success: bool, ip: str = "unknown"):
        self._write({
            "event":    "AUTH_ATTEMPT",
            "severity": "INFO" if success else "WARNING",
            "username": username,
            "success":  success,
            "ip":       ip,
            "message":  f"Login {'succeeded' if success else 'FAILED'} for '{username}' from {ip}",
        })

    def log_ticket_issued(self, ticket_type: str, username: str, service: str = None):
        entry = {
            "event":       "TICKET_ISSUED",
            "severity":    "INFO",
            "ticket_type": ticket_type,
            "username":    username,
            "message":     f"{ticket_type} issued for '{username}'",
        }
        if service:
            entry["service"] = service
        self._write(entry)

    def log_ticket_invalid(self, reason: str, ip: str = "unknown"):
        self._write({
            "event":    "TICKET_INVALID",
            "severity": "WARNING",
            "reason":   reason,
            "ip":       ip,
            "message":  f"Invalid ticket presented: {reason}",
        })

    def log_access_decision(
        self, username: str, resource_id: str,
        operation: str, decision: str, reason: str
    ):
        self._write({
            "event":       "ACCESS_DECISION",
            "severity":    "INFO" if decision == "ALLOW" else "WARNING",
            "username":    username,
            "resource_id": resource_id,
            "operation":   operation,
            "decision":    decision,
            "reason":      reason,
            "message": (
                f"[{decision}] '{username}' {operation} '{resource_id}': {reason}"
            ),
        })

    def log_policy_evaluation(
        self, resource_id: str, decision: str,
        reason: str, trace: List[Dict]
    ):
        self._write({
            "event":       "POLICY_EVALUATION",
            "severity":    "INFO",
            "resource_id": resource_id,
            "decision":    decision,
            "reason":      reason,
            "trace_steps": len(trace),
            "message":     f"PDP evaluated {len(trace)} policies for '{resource_id}' → {decision}",
        })

    def log_replay_attack(self, nonce: str, username: Optional[str], ip: str):
        self._write({
            "event":    "REPLAY_ATTACK",
            "severity": "CRITICAL",
            "nonce":    nonce,
            "username": username or "unknown",
            "ip":       ip,
            "message":  f"REPLAY ATTACK DETECTED — nonce '{nonce}' reused by '{username}' from {ip}",
        })

    def log_tamper_detected(self, token_prefix: str, ip: str):
        self._write({
            "event":        "TAMPER_DETECTED",
            "severity":     "CRITICAL",
            "token_prefix": token_prefix[:30] + "...",
            "ip":           ip,
            "message":      f"TICKET TAMPERING DETECTED from {ip} — HMAC verification failed",
        })

    def log_privilege_escalation(self, username: str, claimed_role: str, real_role: str):
        self._write({
            "event":       "PRIVILEGE_ESCALATION",
            "severity":    "CRITICAL",
            "username":    username,
            "claimed_role": claimed_role,
            "real_role":   real_role,
            "message": (
                f"PRIVILEGE ESCALATION ATTEMPT — '{username}' claimed role '{claimed_role}' "
                f"(actual: '{real_role}')"
            ),
        })

    def log_suspicious(self, description: str, context: Dict = None):
        self._write({
            "event":    "SUSPICIOUS_ACTIVITY",
            "severity": "WARNING",
            "detail":   description,
            "context":  context or {},
            "message":  f"Suspicious activity: {description}",
        })

    # ── Query Methods ────────────────────────────────────────────────────────

    def get_recent_logs(self, n: int = 50) -> List[Dict]:
        return list(reversed(self._buffer[-n:]))

    def get_attack_events(self) -> List[Dict]:
        return list(reversed(self._attack_events))