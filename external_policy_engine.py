

import json
from datetime import datetime
from flask import Flask, jsonify, request
from typing import Dict, Any, List, Tuple

app_pdp = Flask(__name__)

# ── Load policies from file ───────────────────────────────────────────────────

def _load_policies(path: str = "data/policies.json") -> List[Dict]:
    try:
        with open(path) as f:
            raw = json.load(f)
        return sorted(raw.get("policies", []), key=lambda p: p.get("priority", 999))
    except Exception as e:
        print(f"[ExternalPDP] Could not load policies: {e}")
        return []


CLEARANCE_RANK = {"public": 0, "confidential": 1, "secret": 2}
ROLE_PERMISSIONS = {
    "Admin":    ["read", "write", "delete"],
    "Manager":  ["read", "write"],
    "Employee": ["read"],
}
ROLE_HIERARCHY = {
    "Admin":    ["Manager", "Employee"],
    "Manager":  ["Employee"],
    "Employee": [],
}
ACCESS_START_HOUR = 8
ACCESS_END_HOUR   = 18


# ── Policy evaluation logic ───────────────────────────────────────────────────

def _effective_permissions(role: str) -> set:
    perms = set(ROLE_PERMISSIONS.get(role, []))
    for inherited in ROLE_HIERARCHY.get(role, []):
        perms |= set(ROLE_PERMISSIONS.get(inherited, []))
    return perms


def _check_rbac(role: str, operation: str) -> Dict:
    if role not in ROLE_PERMISSIONS:
        return {"decision": "DENY", "reason": f"Unknown role: '{role}'"}
    perms = _effective_permissions(role)
    if operation not in perms:
        return {"decision": "DENY",
                "reason": f"Role '{role}' lacks '{operation}' (has: {sorted(perms)})"}
    return {"decision": "ALLOW", "reason": f"Role '{role}' has '{operation}'"}


def _pol_department(policy, user, resource, op, ctx):
    exempt = policy.get("conditions", {}).get("exempt_roles", ["Admin"])
    if user.get("role") in exempt:
        return {"decision": "ALLOW", "reason": f"Role exempt from dept isolation"}
    ud, rd = user.get("department", ""), resource.get("department", "")
    if ud != rd:
        return {"decision": "DENY",
                "reason": f"Dept isolation: user='{ud}' ≠ resource='{rd}'"}
    return {"decision": "ALLOW", "reason": f"Dept match: '{ud}'"}


def _pol_clearance(policy, user, resource, op, ctx):
    u_lvl = CLEARANCE_RANK.get(user.get("clearance", "public"), 0)
    r_lvl = CLEARANCE_RANK.get(resource.get("classification", "public"), 0)
    if u_lvl < r_lvl:
        return {"decision": "DENY",
                "reason": f"Clearance '{user.get('clearance')}' < classification '{resource.get('classification')}'"}
    return {"decision": "ALLOW", "reason": "Clearance sufficient"}


def _pol_time(policy, user, resource, op, ctx):
    exempt = policy.get("conditions", {}).get("exempt_roles", ["Admin"])
    if user.get("role") in exempt:
        return {"decision": "ALLOW", "reason": "Role exempt from time policy"}
    hour = ctx.get("hour_override", datetime.now().hour)
    if not (ACCESS_START_HOUR <= hour < ACCESS_END_HOUR):
        return {"decision": "DENY",
                "reason": f"Outside business hours (hour={hour}, window=08-18)"}
    return {"decision": "ALLOW", "reason": f"Within business hours (hour={hour})"}


def _pol_external(policy, user, resource, op, ctx):
    loc = user.get("location", "internal")
    cls = resource.get("classification", "public")
    if loc == "external" and cls in ("confidential", "secret"):
        return {"decision": "DENY",
                "reason": f"External location denied '{cls}' resource"}
    return {"decision": "ALLOW", "reason": f"Location '{loc}' OK for '{cls}'"}


def _pol_delete(policy, user, resource, op, ctx):
    if op == "delete" and user.get("role") != "Admin":
        return {"decision": "DENY",
                "reason": f"Delete restricted to Admin; role='{user.get('role')}'"}
    return {"decision": "ALLOW", "reason": "Delete check passed"}


HANDLERS = {
    "POL-001": _pol_department,
    "POL-002": _pol_clearance,
    "POL-003": _pol_time,
    "POL-004": _pol_external,
    "POL-005": _pol_delete,
}


def evaluate(user: Dict, resource: Dict, operation: str,
             ctx: Dict = None) -> Tuple[str, str, List]:
    ctx = ctx or {}
    trace = []
    policies = _load_policies()

    rbac = _check_rbac(user.get("role", ""), operation)
    trace.append({"check": "RBAC", **rbac})
    if rbac["decision"] == "DENY":
        return "DENY", rbac["reason"], trace

    for policy in policies:
        handler = HANDLERS.get(policy["id"])
        if not handler:
            trace.append({"check": policy["id"], "decision": "ALLOW", "reason": "No handler"})
            continue
        result = handler(policy, user, resource, operation, ctx)
        trace.append({"check": f"[{policy['id']}] {policy['name']}", **result})
        if result["decision"] == "DENY":
            return "DENY", result["reason"], trace

    return "ALLOW", "All policies passed", trace


# ── HTTP Endpoints ────────────────────────────────────────────────────────────

@app_pdp.route("/evaluate", methods=["POST"])
def evaluate_policy():
    """
    External PDP evaluation endpoint.
    Request:  { user, resource, operation, context? }
    Response: { decision, reason, trace }
    """
    body      = request.get_json(silent=True) or {}
    user      = body.get("user", {})
    resource  = body.get("resource", {})
    operation = body.get("operation", "read")
    ctx       = body.get("context", {})

    if not user or not resource:
        return jsonify({"error": "user and resource are required"}), 400

    decision, reason, trace = evaluate(user, resource, operation, ctx)
    return jsonify({
        "decision":  decision,
        "reason":    reason,
        "trace":     trace,
        "engine":    "SecureCorp External Policy Engine v1.0",
    }), 200


@app_pdp.route("/policies", methods=["GET"])
def list_policies():
    """List all loaded policies."""
    return jsonify({"policies": _load_policies()}), 200


@app_pdp.route("/policies/reload", methods=["POST"])
def reload_policies():
    """Hot-reload policies from disk."""
    policies = _load_policies()
    return jsonify({
        "message": f"Reloaded {len(policies)} policies",
        "count":   len(policies),
    }), 200


@app_pdp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "healthy",
        "service": "External Policy Engine",
        "policies_loaded": len(_load_policies()),
    }), 200


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║   SecureCorp External Policy Engine  — port 5001    ║
╠══════════════════════════════════════════════════════╣
║  POST /evaluate        Evaluate access request      ║
║  GET  /policies        List all policies            ║
║  POST /policies/reload Hot-reload from disk         ║
║  GET  /health          Health check                 ║
╚══════════════════════════════════════════════════════╝
    """)
    app_pdp.run(port=5001, debug=False)