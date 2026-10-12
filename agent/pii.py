"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# --- Regex patterns ---

# Email: match trước để tránh bị trùng với các pattern khác
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# CCCD: đúng 12 chữ số liên tiếp, không nằm trong chuỗi số dài hơn
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

# SĐT: bắt đầu bằng 0, theo sau 9-10 chữ số (có thể có dấu cách/gạch ngang)
_PHONE_RE = re.compile(r"(?<!\d)0(?:[\s.-]?\d){9,10}(?!\d)")

# STK: 8-16 chữ số liên tiếp, phải đi kèm ngữ cảnh STK/tài khoản
_BANK_CONTEXT_RE = re.compile(
    r"(?:STK|stk|Stk|số tài khoản|so tai khoan|tài khoản|tai khoan|"
    r"chuyển khoản|chuyen khoan|account|bank)\s*[:.]?\s*(\d{8,16})(?!\d)",
    re.IGNORECASE,
)

# Standalone bank account: 13-16 chữ số (rất dài → gần chắc là STK)
_BANK_LONG_RE = re.compile(r"(?<!\d)\d{13,16}(?!\d)")


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    used_ranges: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        for s, e in used_ranges:
            if start < e and s < end:
                return True
        return False

    # 1) Email
    for m in _EMAIL_RE.finditer(text):
        s, e = m.start(), m.end()
        if not _overlaps(s, e):
            entities.append({"type": "EMAIL", "start": s, "end": e})
            used_ranges.append((s, e))

    # 2) Bank account (context-based)
    for m in _BANK_CONTEXT_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if not _overlaps(s, e):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": s, "end": e})
            used_ranges.append((s, e))

    # 3) Bank account (long standalone numbers 13-16 digits)
    for m in _BANK_LONG_RE.finditer(text):
        s, e = m.start(), m.end()
        if not _overlaps(s, e):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": s, "end": e})
            used_ranges.append((s, e))

    # 4) CCCD (12 digits)
    for m in _CCCD_RE.finditer(text):
        s, e = m.start(), m.end()
        if not _overlaps(s, e):
            entities.append({"type": "VN_CCCD", "start": s, "end": e})
            used_ranges.append((s, e))

    # 5) Phone
    for m in _PHONE_RE.finditer(text):
        raw = m.group()
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 10 or len(digits) > 11:
            continue
        s, e = m.start(), m.end()
        if not _overlaps(s, e):
            entities.append({"type": "VN_PHONE", "start": s, "end": e})
            used_ranges.append((s, e))

    # Sort by start position
    entities.sort(key=lambda ent: ent["start"])
    return entities


def redact(text: str) -> str:
    entities = detect(text)
    # Replace from end to start to preserve offsets
    for entity in sorted(entities, key=lambda e: e["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[:entity["start"]] + replacement + text[entity["end"]:]
    return text
