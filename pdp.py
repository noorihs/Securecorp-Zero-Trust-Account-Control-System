"""
pdp.py — SECURE BUILD
Fixes:
  - Restores POL-001 (Department Isolation) handler
  - Restores POL-002 (Clearance Check) handler
  - Restores POL-005 (Delete Restriction) handler
  - No policy ever falls through to an unconditional ALLOW
"""

import json
from datetime import datetime
from typing import Tuple, List, Dict, Any
import config


class PolicyDecisionPoint:

    def __init__(self, policies_path: str):
        self.policies_path = policies_path
        self.policies: List[Dict] = []
        self._load_policies()

    def _load_policies(self):
        with open(self.policies_path, "r") as fh:
            raw = json.load(fh)
        self.policies = sorted(
            raw.get("policies", []),
            key=lambda p: p.get("priority", 999),
        )

    def reload_policies(self):
        self._load_policies()

    def evaluate(
        self,
        user_attrs: Dict[str, Any],
        resource_attrs: Dict[str, Any],
        operation: str,
        context: Dict[str, Any] = None,
    ) -> Tuple[str, str, List[Dict]]:
        ctx = context or {}
        trace: List[Dict] = []

        # Step 1: RBAC check
        rbac = self._check_rbac(user_attrs.get("role", ""), operation)
        trace.append({"check": "RBAC", **rbac})
        if rbac["decision"] == "DENY":
            return "DENY", rbac["reason"], trace

        # Step 2: ABAC policy chain
        for policy in self.policies:
            result = self._evaluate_policy(policy, user_attrs, resource_attrs, operation, ctx)
            trace.append({"check": f"[{policy['id']}] {policy['name']}", **result})
            if result["decision"] == "DENY":
                return "DENY", result["reason"], trace

        return "ALLOW", "All checks passed — access granted", trace

    # ── RBAC ──────────────────────────────────────────────────────────────────

    def _check_rbac(self, role: str, operation: str) -> Dict:
        if role not in config.ROLE_PERMISSIONS:
            return {"decision": "DENY", "reason": f"Unknown role: '{role}'"}
        perms = self._effective_permissions(role)
        if operation not in perms:
            return {
                "decision": "DENY",
                "reason": f"Role '{role}' does not have '{operation}' permission "
                          f"(effective permissions: {sorted(perms)})",
            }
        return {"decision": "ALLOW", "reason": f"Role '{role}' has '{operation}' permission"}

    def _effective_permissions(self, role: str) -> set:
        perms = set(config.ROLE_PERMISSIONS.get(role, []))
        for inherited in config.ROLE_HIERARCHY.get(role, []):
            perms |= set(config.ROLE_PERMISSIONS.get(inherited, []))
        return perms

    # ── Policy Dispatch ───────────────────────────────────────────────────────

    def _evaluate_policy(self, policy, user, resource, operation, ctx) -> Dict:
        pid = policy["id"]
        handlers = {
            "POL-001": self._pol_department_isolation,   # RESTORED
            "POL-002": self._pol_clearance,              # RESTORED
            "POL-003": self._pol_time_window,
            "POL-004": self._pol_external_access,
            "POL-005": self._pol_delete_restriction,     # RESTORED
        }
        handler = handlers.get(pid)
        if handler:
            return handler(policy, user, resource, operation, ctx)
        # Unknown policy IDs default to DENY (fail-secure)
        return {"decision": "DENY", "reason": f"Unknown policy '{pid}' — denied by default (fail-secure)"}

    # ── POL-001: Department Isolation (RESTORED) ──────────────────────────────

    def _pol_department_isolation(self, policy, user, resource, operation, ctx) -> Dict:
        exempt = policy.get("conditions", {}).get("exempt_roles", ["Admin"])
        role   = user.get("role", "")
        if role in exempt:
            return {"decision": "ALLOW", "reason": f"Role '{role}' is exempt from department isolation"}
        u_dept = user.get("department", "")
        r_dept = resource.get("department", "")
        if u_dept != r_dept:
            return {
                "decision": "DENY",
                "reason": f"Department isolation: user dept='{u_dept}' ≠ resource dept='{r_dept}'",
            }
        return {"decision": "ALLOW", "reason": f"Department match: '{u_dept}'"}

    # ── POL-002: Clearance Check (RESTORED) ──────────────────────────────────

    def _pol_clearance(self, policy, user, resource, operation, ctx) -> Dict:
        u_clr = user.get("clearance", "public")
        r_cls = resource.get("classification", "public")
        u_lvl = config.CLEARANCE_RANK.get(u_clr, 0)
        r_lvl = config.CLEARANCE_RANK.get(r_cls, 0)
        if u_lvl < r_lvl:
            return {
                "decision": "DENY",
                "reason": f"Insufficient clearance: user='{u_clr}' (lvl {u_lvl}), "
                          f"required='{r_cls}' (lvl {r_lvl})",
            }
        return {"decision": "ALLOW", "reason": f"Clearance '{u_clr}' >= classification '{r_cls}'"}

    # ── POL-003: Time Window ──────────────────────────────────────────────────

    def _pol_time_window(self, policy, user, resource, operation, ctx) -> Dict:
        conds  = policy.get("conditions", {})
        exempt = conds.get("exempt_roles", ["Admin"])
        role   = user.get("role", "")
        if role in exempt:
            return {"decision": "ALLOW", "reason": f"Role '{role}' exempt from time restrictions"}
        hour = ctx.get("hour_override", datetime.now().hour)
        if not (config.ACCESS_START_HOUR <= hour < config.ACCESS_END_HOUR):
            return {
                "decision": "DENY",
                "reason": f"Outside business hours (hour={hour:02d}, window=08-18)",
            }
        return {"decision": "ALLOW", "reason": f"Within business hours (hour={hour:02d})"}

    # ── POL-004: External Access ──────────────────────────────────────────────

    def _pol_external_access(self, policy, user, resource, operation, ctx) -> Dict:
        loc = user.get("location", "internal")
        cls = resource.get("classification", "public")
        if loc == "external" and cls in ("confidential", "secret"):
            return {
                "decision": "DENY",
                "reason": f"External location denied access to '{cls}' resource",
            }
        return {"decision": "ALLOW", "reason": f"Location '{loc}' allowed for '{cls}' resource"}

    # ── POL-005: Delete Restriction (RESTORED) ────────────────────────────────

    def _pol_delete_restriction(self, policy, user, resource, operation, ctx) -> Dict:
        if operation == "delete":
            allowed_roles = policy.get("conditions", {}).get("allowed_roles", ["Admin"])
            role = user.get("role", "")
            if role not in allowed_roles:
                return {
                    "decision": "DENY",
                    "reason": f"Delete restricted to {allowed_roles}; user role='{role}' (Separation of Duties)",
                }
        return {"decision": "ALLOW", "reason": "Delete check passed"}
