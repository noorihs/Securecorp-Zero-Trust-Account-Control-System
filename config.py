
# ── Cryptographic Master Keys (32 bytes each for AES-256) ────────────────────
KDC_MASTER_KEY   = b'SecureCorp-KDC-MasterKey-2024!!'   # KDC ↔ TGT
TGS_SERVICE_KEY  = b'SecureCorp-TGS-SvcKey-v1-2024!!'   # KDC ↔ Service Ticket

# ── Ticket Lifetimes ──────────────────────────────────────────────────────────
TGT_LIFETIME     = 3600   # 1 hour  (seconds)
TICKET_LIFETIME  = 600    # 10 minutes (seconds)

# ── Time-Based Access Control ─────────────────────────────────────────────────
ACCESS_START_HOUR = 8     # 08:00
ACCESS_END_HOUR   = 18    # 18:00

# ── RBAC: Role → Permitted Operations ────────────────────────────────────────
ROLE_PERMISSIONS = {
    "Admin":    ["read", "write", "delete"],
    "Manager":  ["read", "write"],
    "Employee": ["read"],
}

# ── RBAC: Role Hierarchy (key inherits all permissions of value list) ─────────
ROLE_HIERARCHY = {
    "Admin":    ["Manager", "Employee"],
    "Manager":  ["Employee"],
    "Employee": [],
}

# ── Clearance / Classification Ranking ───────────────────────────────────────
CLEARANCE_RANK = {
    "public":       0,
    "confidential": 1,
    "secret":       2,
}

# ── Server Port ───────────────────────────────────────────────────────────────
APP_PORT = 5000