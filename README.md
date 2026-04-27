# SecureCorp Zero-Trust — SECURE BUILD

## What Was Fixed

| # | Vulnerability | File | Fix Applied |
|---|--------------|------|-------------|
| 1 | **Ticket Tampering** | `security.py` | Replaced bare base64 with **Fernet** (AES-128-CBC + HMAC-SHA256). Any modification raises `InvalidToken`. |
| 2 | **Replay Attack** | `security.py` | `ReplayProtection.check_and_register()` now stores nonces with a TTL. A replayed nonce or stale timestamp returns `False` → HTTP 401 `REPLAY_DETECTED`. |
| 3 | **Privilege Escalation** | `app.py` | Removed the lines that read `role`/`clearance` from request body or `X-Role` header. Authorization attributes come exclusively from the Fernet-protected ticket. |
| 4 | **Cross-Department Access** | `pdp.py` | Restored `POL-001` (Department Isolation) and `POL-002` (Clearance Check) and `POL-005` (Delete Restriction) handlers. Unknown policy IDs now default to **DENY** (fail-secure). |
| 5 | **Brute Force** | `rate_limiter.py` | Implemented real lockout: account locked for 5 min after 5 consecutive failures; IP blocked for 10 min after 20 failures in 60 s. |
| 6 | **MFA (new)** | `security.py`, `app.py`, `mfa_server.py` | Login is now 2 steps: `POST /login` (password) → `POST /login/mfa` (6-digit PIN). The PIN is displayed on the MFA terminal (`mfa_server.py`). |

---

## How to Run

### Install dependencies
```bash
pip install flask cryptography requests
```

### Terminal 1 — Main server
```bash
python app.py
```

### Terminal 2 — MFA terminal (shows PINs)
```bash
python mfa_server.py
```

### Terminal 3 — Tests
```bash
python test.py
```

---

## MFA Login Flow

```
Client                    Server (app.py)          MFA Terminal (mfa_server.py)
  |                            |                              |
  |-- POST /login ------------>|                              |
  |   {username, password}     |                              |
  |                            |-- generate 6-digit PIN ----> displays PIN
  |<-- 200 mfa_required -------|                              |
  |                            |                              |
  |-- POST /login/mfa -------->|                              |
  |   {username, pin}          |-- verify PIN                 |
  |<-- 200 + TGT + session_key-|                              |
```

### Step 1
```bash
curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Admin@2024"}'
# → {"mfa_required": true, "username": "alice"}
```

### Step 2 (enter PIN shown on MFA terminal)
```bash
curl -s -X POST http://localhost:5000/login/mfa \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","pin":"384920"}'
# → {"tgt": "...", "session_key": "...", ...}
```

---

## Attack Scripts (now show BLOCKED)

Run any of the 5 attack scripts against the secure server — each exploit will
now be blocked and show a green `✓ BLOCKED` result:

```bash
python attack_1_replay.py
python attack_2_tampering.py
python attack_3_privilege_escalation.py
python attack_4_cross_dept.py
python attack_5_brute_force.py
```

---

## Users Reference

| Username | Role     | Dept       | Clearance    | Location | Password       |
|----------|----------|------------|--------------|----------|----------------|
| alice    | Admin    | IT         | secret       | internal | Admin@2024     |
| bob      | Manager  | Finance    | confidential | internal | Manager@2024   |
| carol    | Employee | HR         | public       | internal | Employee@2024  |
| dave     | Employee | Operations | public       | external | Dave@2024      |
| frank    | Employee | Finance    | confidential | internal | Frank@2024     |
