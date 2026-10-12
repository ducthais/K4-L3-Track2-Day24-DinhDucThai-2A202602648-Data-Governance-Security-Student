# Baseline — Checkpoint 1

1. **Agent có identity riêng mỗi run chưa?**
   Chưa. Trong `agent/loop.py`, hàm `_naive_loop()` (dòng 27–54) không tạo bất kỳ identity (agent_id, run_id) nào cho mỗi lần chạy. Không có UUID hay timestamp gắn với run. Hàm chỉ gọi thẳng `tools.search_docs()`, `llm.find_injection()`, `tools.read_customer()` và `tools.http_post()` mà không ghi nhận ai đang chạy hay run nào đang thực thi.

2. **Ai cho phép `http_post`?**
   Không ai cho phép — không có bước kiểm tra quyền nào. Trong `agent/loop.py`, hàm `_naive_loop()` dòng 44 gọi thẳng `tools.http_post(injected.target_url, {"records": collected})` mà không qua bất kỳ policy check nào. File `agent/tools.py` hàm `http_post()` (dòng 68–85) chỉ có một hard allowlist cho localhost:10024 — đây là safety net của lab, không phải authorization control. Không có `agent/policy.py` check() nào được gọi trước khi POST.

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu?**
   Không có bằng chứng audit nào. `_naive_loop()` không gọi `agent/ledger.py` — không có dòng log nào ghi lại tool call, quyết định allow/deny, hay dữ liệu đã gửi. File `agent/ledger.py` hàm `append()` và `verify()` (dòng 43–48) đều chỉ là stub `raise NotImplementedError`. Bằng chứng duy nhất là `reports/sink.log` do sink server ghi — nhưng đó là log của attacker, không phải audit trail do agent kiểm soát.
