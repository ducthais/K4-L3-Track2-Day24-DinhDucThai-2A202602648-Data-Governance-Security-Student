"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from agent import ledger, tools
from agent.pii import redact
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CUSTOMERS_FILE = DATA_DIR / "customers.json"

AGENT_ID = "lab24-agent"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_at() -> str:
    """Session expires 1 hour from now."""
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def _args_hash(*args) -> str:
    """Hash of tool arguments for the ledger (no PII in raw form)."""
    serialized = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _extract_ticket_ids(docs: list[dict]) -> list[int]:
    """Extract ticket IDs from filenames (e.g., 'ticket-007.md' -> 7).
    This is the TRUSTED source — not from free text content."""
    ids = []
    pattern = re.compile(r"ticket-(\d+)\.md", re.IGNORECASE)
    for doc in docs:
        m = pattern.search(doc.get("id", ""))
        if m:
            ids.append(int(m.group(1)))
    return sorted(set(ids))


def _ticket_to_customers(ticket_ids: list[int]) -> list[str]:
    """Map ticket IDs to customer IDs using related_tickets in customers.json.
    This is the TRUSTED mapping — not from attacker-controlled text."""
    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    result = []
    for customer in customers:
        related = customer.get("related_tickets", [])
        if any(tid in related for tid in ticket_ids):
            result.append(customer["customer_id"])
    return sorted(set(result))


def _gate(
    tool_name: str,
    classification: str,
    purpose: str,
    egress: bool,
    principal_id: str,
    agent_scopes: tuple[str, ...],
    parent_scopes: tuple[str, ...],
    run_id: str,
    expires_at: str,
    ledger_path: Path,
    args_for_hash: tuple = (),
) -> tuple[bool, str]:
    """Run policy check and log to ledger. Returns (allowed, reason)."""
    ctx = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=f"{AGENT_ID}/{run_id}",
        delegation_depth=0,
        egress_enabled=egress,
        principal_id=principal_id,
        requested_tool=tool_name,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at=expires_at,
    )
    allowed, reason = check(ctx)
    decision = "allow" if allowed else "deny"

    entry = {
        "ts": _now_iso(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": tool_name,
        "args_hash": _args_hash(*args_for_hash),
        "classification": classification,
        "decision": decision,
        "reason": reason,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }
    ledger.append(entry, ledger_path)
    return allowed, reason


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"
    expires = _expires_at()

    # ── Run A: search_docs (untrusted content) ──────────────────────
    run_a_id = f"run-a-{uuid.uuid4().hex[:8]}"
    run_a_scopes = ("search_docs",)  # Run A only gets search_docs

    allowed, reason = _gate(
        tool_name="search_docs",
        classification="internal",
        purpose="summarize-tickets",
        egress=False,
        principal_id=principal_id,
        agent_scopes=run_a_scopes,
        parent_scopes=(),
        run_id=run_a_id,
        expires_at=expires,
        ledger_path=ledger_path,
        args_for_hash=(message,),
    )

    if not allowed:
        return f"Run A bị từ chối search_docs: {reason}"

    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    # Detect injection (for logging purposes only — do NOT use customer_ids from it)
    injected = llm.find_injection(combined_text)

    # Extract ticket IDs from FILENAMES only (trusted source)
    ticket_ids = _extract_ticket_ids(docs)

    # PII redact before passing anything forward
    redacted_text_docs = [{"id": d["id"], "text": redact(d["text"])} for d in docs]

    # ── Run B: read_customer (private data) ─────────────────────────
    run_b_id = f"run-b-{uuid.uuid4().hex[:8]}"
    run_b_scopes = ("search_docs", "read_customer", "http_post")

    # Map ticket IDs -> customer IDs via trusted source
    customer_ids = _ticket_to_customers(ticket_ids)

    for cid in customer_ids:
        allowed, reason = _gate(
            tool_name="read_customer",
            classification="restricted",
            purpose="support-reply",
            egress=False,
            principal_id=principal_id,
            agent_scopes=run_b_scopes,
            parent_scopes=(),
            run_id=run_b_id,
            expires_at=expires,
            ledger_path=ledger_path,
            args_for_hash=(cid,),
        )
        if allowed:
            tools.read_customer(cid)

    # ── Egress: http_post always goes through policy ────────────────
    if injected is not None:
        allowed, reason = _gate(
            tool_name="http_post",
            classification="restricted",
            purpose="reconciliation",
            egress=True,
            principal_id=principal_id,
            agent_scopes=run_b_scopes,
            parent_scopes=(),
            run_id=run_b_id,
            expires_at=expires,
            ledger_path=ledger_path,
            args_for_hash=(injected.target_url,),
        )
        # restricted + egress -> always denied by policy

    # Return summary (same observable behavior as before containment)
    return llm.summarize(redacted_text_docs)
