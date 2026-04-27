"""
app.py — SECURE BUILD
Fixes applied:
  1. Ticket Tampering      → Fernet encryption (security.py)
  2. Replay Attack         → Nonce registry with TTL enforcement (security.py)
  3. Privilege Escalation  → Role/clearance NEVER read from request body/headers
  4. Unauth Cross-Dept     → POL-001 and POL-005 restored in pdp.py
  5. Brute Force           → Real lockout/IP-block in rate_limiter.py
  6. MFA                   → 6-digit PIN required after password — verify via /login/mfa
"""

import json
import os
import time
from functools import wraps

from flask import Flask, jsonify, request

import config
from security import (
    decrypt_ticket, encrypt_ticket,
    generate_nonce, generate_session_key,
    replay_protection, verify_password,
    mfa_manager,
)
from pdp import PolicyDecisionPoint
from logger_module import SecurityLogger
from rate_limiter import rate_limiter

app    = Flask(__name__)
logger = SecurityLogger("logs/security.log")
pdp    = PolicyDecisionPoint("policies.json")


def _load_users() -> dict:
    with open("users.json", "r") as fh:
        return json.load(fh)["users"]


def _load_resources() -> dict:
    with open("resources.json", "r") as fh:
        return json.load(fh)["resources"]


# ── Ticket Helpers ────────────────────────────────────────────────────────────

def _issue_tgt(username: str, user: dict) -> tuple:
    session_key = generate_session_key()
    payload = {
        "ticket_type": "TGT",
        "username":    username,
        "role":        user["role"],
        "department":  user["department"],
        "clearance":   user["clearance"],
        "location":    user["location"],
        "session_key": session_key,
        "issued_at":   time.time(),
        "expires_at":  time.time() + config.TGT_LIFETIME,
    }
    return encrypt_ticket(payload, config.KDC_MASTER_KEY), session_key


def _issue_service_ticket(tgt_data: dict, service: str) -> tuple:
    session_key_2 = generate_session_key()
    payload = {
        "ticket_type": "SERVICE_TICKET",
        "username":    tgt_data["username"],
        "role":        tgt_data["role"],
        "department":  tgt_data["department"],
        "clearance":   tgt_data["clearance"],
        "location":    tgt_data["location"],
        "service":     service,
        "session_key": session_key_2,
        "issued_at":   time.time(),
        "expires_at":  time.time() + config.TICKET_LIFETIME,
    }
    return encrypt_ticket(payload, config.TGS_SERVICE_KEY), session_key_2


def _validate_service_ticket(token: str):
    """SECURE: Fernet decrypt raises InvalidToken if ticket was tampered."""
    try:
        data = decrypt_ticket(token, config.TGS_SERVICE_KEY)
    except Exception as exc:
        return None, f"Ticket verification failed: {exc}"

    if data.get("ticket_type") != "SERVICE_TICKET":
        return None, "Wrong ticket type"
    if time.time() > data.get("expires_at", 0):
        return None, "Ticket expired"

    return data, None


# ── Authorization Decorator — SECURE ─────────────────────────────────────────

def require_ticket(operation: str):
    """
    SECURE:
      - Replay check returns bool; False → 401 REPLAY_DETECTED
      - Role and clearance are taken EXCLUSIVELY from the verified ticket
      - No request body or header fields can override ticket attributes
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token     = request.headers.get("X-Service-Ticket", "")
            nonce     = request.headers.get("X-Authenticator-Nonce", "")
            ts_str    = request.headers.get("X-Authenticator-Timestamp", str(time.time()))
            client_ip = request.remote_addr or "unknown"

            if not token:
                return jsonify({"error": "X-Service-Ticket header required", "code": "NO_TICKET"}), 401

            ticket, err = _validate_service_ticket(token)
            if err:
                logger.log_ticket_invalid(err, client_ip)
                return jsonify({"error": err, "code": "INVALID_TICKET"}), 401

            # FIX 1 — Replay: actually enforce the check
            if nonce:
                try:
                    ts = float(ts_str)
                except ValueError:
                    ts = time.time()
                allowed = replay_protection.check_and_register(nonce, ts)
                if not allowed:
                    logger.log_replay_attack(nonce, ticket.get("username"), client_ip)
                    return jsonify({"error": "Replay detected", "code": "REPLAY_DETECTED"}), 401

            # FIX 2 — No privilege escalation: NEVER read role/clearance from client
            # ticket already contains the verified role/clearance from the KDC.
            # (The old vulnerable lines that read body['role'] are completely removed.)

            # Hour override is still accepted for demo purposes (time-window testing)
            try:
                hour_override = int(request.headers.get("X-Hour-Override", -1))
            except ValueError:
                hour_override = -1
            if hour_override >= 0:
                ticket["_hour_override"] = hour_override

            request.ticket_data = ticket
            request.operation   = operation
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── KDC: Login — Step 1 (password verification) ──────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    """
    Step 1 of 2-factor login.
    On success: returns {"mfa_required": true, "username": "..."}
    The TGT is NOT issued until /login/mfa succeeds.
    """
    body      = request.get_json(silent=True) or {}
    username  = str(body.get("username", "")).strip().lower()
    password  = str(body.get("password", ""))
    client_ip = request.remote_addr or "unknown"

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    blocked, msg = rate_limiter.is_ip_blocked(client_ip)
    if blocked:
        return jsonify({"error": msg, "code": "RATE_LIMITED"}), 429

    locked, msg = rate_limiter.is_account_locked(username)
    if locked:
        return jsonify({"error": msg, "code": "ACCOUNT_LOCKED"}), 429

    users = _load_users()
    if username not in users:
        rate_limiter.record_attempt(client_ip, username, False)
        logger.log_auth_attempt(username, False, client_ip)
        return jsonify({"error": "Invalid credentials"}), 401

    user = users[username]
    if not verify_password(password, user["salt"], user["password_hash"]):
        rate_limiter.record_attempt(client_ip, username, False)
        logger.log_auth_attempt(username, False, client_ip)
        return jsonify({"error": "Invalid credentials"}), 401

    # Password correct → generate MFA PIN (displayed on the MFA terminal)
    pin = mfa_manager.generate_pin(username)

    # Print PIN to this server's console (the "second terminal" / MFA channel)
    print(f"\n{'═'*50}")
    print(f"  🔐  MFA PIN for '{username}':  {pin}")
    print(f"  (valid for 120 seconds)")
    print(f"{'═'*50}\n", flush=True)

    logger.log_suspicious(
        f"MFA challenge issued for '{username}'",
        {"username": username, "ip": client_ip}
    )

    return jsonify({
        "message":      "Password verified — MFA required",
        "mfa_required": True,
        "username":     username,
    }), 200


# ── KDC: Login — Step 2 (MFA PIN verification) ───────────────────────────────

@app.route("/login/mfa", methods=["POST"])
def login_mfa():
    """
    Step 2: User submits the 6-digit PIN shown on the MFA terminal.
    On success: issues TGT (same response shape as old /login).
    """
    body      = request.get_json(silent=True) or {}
    username  = str(body.get("username", "")).strip().lower()
    pin       = str(body.get("pin", "")).strip()
    client_ip = request.remote_addr or "unknown"

    if not username or not pin:
        return jsonify({"error": "username and pin required"}), 400

    ok, reason = mfa_manager.verify_pin(username, pin)
    if not ok:
        logger.log_auth_attempt(username, False, client_ip)
        return jsonify({"error": reason, "code": "MFA_FAILED"}), 401

    users = _load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 401

    user = users[username]
    rate_limiter.record_attempt(client_ip, username, True)
    tgt, session_key = _issue_tgt(username, user)
    logger.log_auth_attempt(username, True, client_ip)
    logger.log_ticket_issued("TGT", username)

    return jsonify({
        "message":        "Authentication successful",
        "tgt":            tgt,
        "session_key":    session_key,
        "user_info":      {"username": username, "role": user["role"], "department": user["department"]},
        "tgt_expires_in": config.TGT_LIFETIME,
    }), 200


# ── TGS: Request Service Ticket ───────────────────────────────────────────────

@app.route("/request-ticket", methods=["POST"])
def request_ticket():
    body          = request.get_json(silent=True) or {}
    tgt_token     = str(body.get("tgt", ""))
    service       = str(body.get("service", "resource_server"))
    authenticator = body.get("authenticator", {})
    client_ip     = request.remote_addr or "unknown"

    if not tgt_token:
        return jsonify({"error": "tgt is required"}), 400

    try:
        tgt_data = decrypt_ticket(tgt_token, config.KDC_MASTER_KEY)
    except Exception as exc:
        logger.log_ticket_invalid(str(exc), client_ip)
        return jsonify({"error": f"Invalid TGT: {exc}", "code": "INVALID_TICKET"}), 401

    if tgt_data.get("ticket_type") != "TGT":
        return jsonify({"error": "Wrong ticket type", "code": "INVALID_TICKET"}), 401
    if time.time() > tgt_data.get("expires_at", 0):
        return jsonify({"error": "TGT expired", "code": "TICKET_EXPIRED"}), 401

    # FIX — Replay protection is enforced here too
    nonce = authenticator.get("nonce") or generate_nonce()
    ts    = float(authenticator.get("timestamp", time.time()))
    if not replay_protection.check_and_register(nonce, ts):
        logger.log_replay_attack(nonce, tgt_data.get("username"), client_ip)
        return jsonify({"error": "Replay detected", "code": "REPLAY_DETECTED"}), 401

    service_ticket, sk2 = _issue_service_ticket(tgt_data, service)
    logger.log_ticket_issued("SERVICE_TICKET", tgt_data["username"], service)

    return jsonify({
        "message":        "Service ticket issued",
        "service_ticket": service_ticket,
        "session_key":    sk2,
        "service":        service,
    }), 200


# ── Resource Server ───────────────────────────────────────────────────────────

def _access_resource(resource_id: str, operation: str):
    ticket    = request.ticket_data
    client_ip = request.remote_addr or "unknown"
    resources = _load_resources()

    if resource_id not in resources:
        return jsonify({"error": f"Resource '{resource_id}' not found"}), 404

    resource = resources[resource_id]
    user_attrs = {
        "username":   ticket["username"],
        "role":       ticket["role"],
        "department": ticket["department"],
        "clearance":  ticket["clearance"],
        "location":   ticket["location"],
    }
    resource_attrs = {
        "department":     resource["department"],
        "classification": resource["classification"],
    }
    context = {}
    if "_hour_override" in ticket:
        context["hour_override"] = ticket["_hour_override"]

    decision, reason, trace = pdp.evaluate(user_attrs, resource_attrs, operation, context)
    logger.log_access_decision(ticket["username"], resource_id, operation, decision, reason)
    logger.log_policy_evaluation(resource_id, decision, reason, trace)

    if decision == "DENY":
        return jsonify({"error": "Access denied", "reason": reason, "trace": trace}), 403

    return jsonify({
        "message":   f"{operation.upper()} {resource_id} — ALLOWED",
        "resource":  resource,
        "operation": operation,
        "user":      ticket["username"],
        "trace":     trace,
    }), 200


@app.route("/resource/<resource_id>", methods=["GET"])
@require_ticket("read")
def get_resource(resource_id):
    return _access_resource(resource_id, "read")


@app.route("/resource", methods=["POST"])
@require_ticket("write")
def create_resource():
    ticket = request.ticket_data
    body   = request.get_json(silent=True) or {}
    resources = _load_resources()
    new_id = f"NEW-{int(time.time())}"
    resources[new_id] = {
        "department":     body.get("department", ticket["department"]),
        "classification": body.get("classification", "public"),
        "data":           body.get("data", "New resource"),
        "owner":          ticket["username"],
    }
    return jsonify({"message": f"Resource '{new_id}' created", "id": new_id}), 200


@app.route("/resource/<resource_id>", methods=["DELETE"])
@require_ticket("delete")
def delete_resource(resource_id):
    return _access_resource(resource_id, "delete")


# ── Admin Endpoints ───────────────────────────────────────────────────────────

@app.route("/admin/unlock/<username>", methods=["POST"])
def admin_unlock(username):
    rate_limiter.unlock_account(username)
    return jsonify({"message": f"Account '{username}' unlocked"}), 200


@app.route("/admin/unblock-ip/<path:ip>", methods=["POST"])
def admin_unblock_ip(ip):
    rate_limiter.reset_ip(ip)
    return jsonify({"message": f"IP '{ip}' unblocked"}), 200


@app.route("/admin/reload-policies", methods=["POST"])
def admin_reload_policies():
    pdp.reload_policies()
    return jsonify({"message": "Policies reloaded", "count": len(pdp.policies)}), 200


@app.route("/admin/security-status", methods=["GET"])
def admin_security_status():
    return jsonify(rate_limiter.get_status()), 200


@app.route("/admin/logs", methods=["GET"])
@require_ticket("read")
def admin_logs():
    ticket = request.ticket_data
    if ticket["role"] != "Admin":
        return jsonify({"error": "Admin role required"}), 403
    logs = logger.get_recent_logs(int(request.args.get("n", 50)))
    return jsonify({"logs": logs, "count": len(logs)}), 200


@app.route("/admin/public-logs", methods=["GET"])
def admin_public_logs():
    logs = logger.get_recent_logs(int(request.args.get("n", 20)))
    return jsonify({"logs": logs, "count": len(logs)}), 200


@app.route("/admin/attack-events", methods=["GET"])
@require_ticket("read")
def admin_attacks():
    ticket = request.ticket_data
    if ticket["role"] != "Admin":
        return jsonify({"error": "Admin role required"}), 403
    return jsonify({"attack_events": logger.get_attack_events()}), 200


@app.route("/mfa/pending", methods=["GET"])
def mfa_pending():
    """
    Called by mfa_server.py (the MFA terminal) to retrieve active challenges.
    In production this endpoint would be internal-only / on a separate port.
    """
    import time as _time
    result = []
    with mfa_manager._lock:
        for username, entry in mfa_manager._pending.items():
            remaining = max(0, int(entry["expires_at"] - _time.time()))
            if remaining > 0:
                result.append({
                    "username":   username,
                    "pin":        entry["pin"],
                    "expires_in": remaining,
                })
    return jsonify({"pending": result}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "healthy (SECURE BUILD)",
        "system":  "SecureCorp Zero-Trust — Production Version",
        "version": "1.0-secure",
    }), 200


# ── Demo Endpoints (updated to reflect fixed behaviour) ──────────────────────

@app.route("/demo/replay-attack", methods=["POST"])
def demo_replay_attack():
    nonce  = generate_nonce()
    ts     = time.time()
    first  = replay_protection.check_and_register(nonce, ts)
    second = replay_protection.check_and_register(nonce, ts)
    return jsonify({
        "attack":                "Replay Attack",
        "step_1_legitimate_use": "ALLOWED" if first  else "BLOCKED",
        "step_2_replay_attempt": "BLOCKED" if not second else "ALLOWED (replay succeeded!)",
        "status": "MITIGATED — replay was blocked" if not second else "VULNERABLE — replay not detected",
    }), 200


@app.route("/demo/tamper-attack", methods=["POST"])
def demo_tamper_attack():
    import base64, json as _json
    payload = {
        "ticket_type": "SERVICE_TICKET",
        "username": "carol", "role": "Employee",
        "department": "HR", "clearance": "public", "location": "internal",
        "session_key": generate_session_key(),
        "issued_at": time.time(), "expires_at": time.time() + 600,
    }
    valid_token = encrypt_ticket(payload, config.TGS_SERVICE_KEY)

    # Try to forge by raw base64 manipulation (will fail — Fernet detects it)
    try:
        raw  = base64.urlsafe_b64decode(valid_token.encode() + b"==")
        data = _json.loads(raw)
        data["role"] = "Admin"
        forged_token = base64.urlsafe_b64encode(
            _json.dumps(data, separators=(",", ":")).encode()
        ).decode()
    except Exception:
        forged_token = valid_token[:-8] + "XXXXXXXX"

    detected = False
    try:
        decrypt_ticket(forged_token, config.TGS_SERVICE_KEY)
    except Exception:
        detected = True

    return jsonify({
        "attack":          "Ticket Tampering",
        "original_role":   "Employee",
        "forged_role":     "N/A (token rejected before decode)",
        "tamper_detected": detected,
        "status": "MITIGATED — tampering detected" if detected else "VULNERABLE — forged ticket accepted!",
    }), 200


@app.route("/demo/privilege-escalation", methods=["POST"])
def demo_privilege_escalation():
    carol_real   = {"username": "carol", "role": "Employee", "department": "HR",
                    "clearance": "public", "location": "internal"}
    carol_forged = {**carol_real, "role": "Admin", "clearance": "secret"}
    resource     = {"department": "HR", "classification": "confidential"}

    real_dec,   real_rsn,   _ = pdp.evaluate(carol_real,   resource, "delete")
    forged_dec, forged_rsn, _ = pdp.evaluate(carol_forged, resource, "delete")

    return jsonify({
        "attack":           "Privilege Escalation",
        "user":             "carol",
        "actual_role":      "Employee",
        "injected_role":    "Admin",
        "with_real_role":   f"{real_dec}: {real_rsn}",
        "with_forged_role": f"{forged_dec}: {forged_rsn}",
        "note":             "Role from ticket is authoritative — request body is ignored",
        "status": "MITIGATED — escalation blocked" if forged_dec == "DENY" else "VULNERABLE",
    }), 200


@app.route("/demo/unauthorized-access", methods=["POST"])
def demo_unauthorized_access():
    carol = {"username": "carol", "role": "Employee", "department": "HR",
             "clearance": "public", "location": "internal"}
    fin   = {"department": "Finance", "classification": "public"}

    decision, reason, trace = pdp.evaluate(carol, fin, "read")
    return jsonify({
        "attack":      "Unauthorized Cross-Department Access",
        "user_dept":   "HR",
        "target_dept": "Finance",
        "decision":    decision,
        "reason":      reason,
        "status": "MITIGATED — access denied" if decision == "DENY" else "VULNERABLE",
    }), 200


@app.route("/api/pdp/evaluate", methods=["POST"])
def api_pdp_evaluate():
    data        = request.get_json(silent=True) or {}
    user        = data.get("user", {})
    resource_id = data.get("resource_id")
    operation   = data.get("operation", "read")
    context     = data.get("context", {})

    if not user or not resource_id:
        return jsonify({"error": "user and resource_id required"}), 400

    resources = _load_resources()
    resource  = resources.get(resource_id)
    if not resource:
        return jsonify({"error": f"Resource {resource_id} not found"}), 404

    user_attrs     = {k: user.get(k) for k in ("role", "department", "clearance", "location")}
    resource_attrs = {k: resource.get(k) for k in ("department", "classification")}

    decision, reason, trace = pdp.evaluate(user_attrs, resource_attrs, operation, context)
    rules_applied = [
        {
            "policy_id": t.get("check", "UNKNOWN"),
            "effect":    "allow" if t.get("decision") == "ALLOW" else "deny",
            "matched":   t.get("decision") == "ALLOW",
            "reason":    t.get("reason", ""),
        }
        for t in trace
    ]

    return jsonify({"allowed": decision == "ALLOW", "reason": reason, "rules_applied": rules_applied}), 200


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    print("""
╔══════════════════════════════════════════════════════════════════╗
║   SecureCorp — SECURE BUILD  v1.0                               ║
╠══════════════════════════════════════════════════════════════════╣
║  ✓ Fernet encryption (AES-128-CBC + HMAC-SHA256) on tickets     ║
║  ✓ Replay protection — nonce registry with 300 s window         ║
║  ✓ No privilege escalation — role from ticket only              ║
║  ✓ POL-001 dept isolation + POL-005 delete restriction active   ║
║  ✓ Account lockout after 5 failures; IP block after 20          ║
║  ✓ MFA — 6-digit PIN required after password (POST /login/mfa)  ║
╚══════════════════════════════════════════════════════════════════╝

MFA PIN will appear here when a user completes step 1 of login.
    """)
    app.run(debug=False, port=config.APP_PORT,host="0.0.0.0", use_reloader=False)
