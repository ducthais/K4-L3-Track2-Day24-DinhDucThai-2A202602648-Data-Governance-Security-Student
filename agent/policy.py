"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    # Rule 1: restricted + egress -> DENY (minimum rule, always checked first)
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: restricted data with egress enabled"

    # OBO checks only apply when principal_id is provided
    if context.principal_id:
        # Load principals
        principals = _load_principals()

        # Unknown principal -> DENY
        if context.principal_id not in principals:
            return False, f"DENY: unknown principal '{context.principal_id}'"

        principal = principals[context.principal_id]

        # Check expires_at
        if context.expires_at:
            try:
                expires = datetime.fromisoformat(context.expires_at)
                now = datetime.now(timezone.utc)
                if expires <= now:
                    return False, f"DENY: session expired at {context.expires_at}"
            except ValueError:
                return False, f"DENY: invalid expires_at format '{context.expires_at}'"

        # Check purpose
        if context.request_purpose and "purposes" in principal:
            if context.request_purpose not in principal["purposes"]:
                return False, (
                    f"DENY: purpose '{context.request_purpose}' not allowed "
                    f"for principal '{context.principal_id}'"
                )

        # Compute effective scopes
        if context.requested_tool:
            allowed_tools = set(principal.get("allowed_tools", []))
            agent_scopes = set(context.agent_scopes)
            effective = allowed_tools & agent_scopes

            # If delegation_depth > 0, also intersect with parent_scopes
            if context.delegation_depth > 0:
                parent_scopes = set(context.parent_scopes)
                effective = effective & parent_scopes

            if context.requested_tool not in effective:
                return False, (
                    f"DENY: tool '{context.requested_tool}' not in effective scopes "
                    f"for principal '{context.principal_id}' "
                    f"(effective={sorted(effective)})"
                )

    return True, (
        f"ALLOW: {context.requested_tool or 'operation'} permitted — "
        f"classification={context.data_classification}, "
        f"principal={context.principal_id or 'none'}, "
        f"purpose={context.request_purpose}"
    )
