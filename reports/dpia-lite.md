# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu hỗ trợ khách hàng (`corpus/*.md`): Phân loại `internal`. Chứa nội dung trao đổi kỹ thuật, sự cố dịch vụ; có nguy cơ chứa chỉ thị prompt injection độc hại từ đối tượng bên ngoài và dữ liệu cá nhân chưa lọc.
- Dữ liệu hồ sơ khách hàng (`data/customers.json`): Phân loại `restricted`. Chứa thông tin định danh cá nhân nhạy cảm (PII) tổng hợp gồm: họ tên, số CCCD (12 chữ số), số điện thoại di động, số tài khoản ngân hàng, địa chỉ email, và danh sách các ticket liên kết (`related_tickets`).

2. Mục đích xử lý và principal:
- Mục đích xử lý:
  - `summarize-tickets`: Tổng hợp nội dung các yêu cầu hỗ trợ đang mở phục vụ quản lý nội bộ.
  - `support-reply`: Tra cứu hồ sơ khách hàng tương ứng với ticket cụ thể để nhân viên phản hồi hỗ trợ.
- Principal (mô phỏng theo cơ chế On-Behalf-Of từ `data/principals.json`):
  - `support_l1`: Chỉ được cấp quyền `search_docs` cho mục đích `summarize-tickets`. Tuyệt đối không được cấp quyền `read_customer` trên dữ liệu `restricted`.
  - `dpo`: Được cấp quyền `search_docs` và `read_customer` cho mục đích `support-reply`.
  - Cả hai principal đều bị nghiêm cấm quyền `http_post` ra ngoài mạng internet khi ngữ cảnh mang dữ liệu `restricted`.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A (Untrusted Ingestion): Nhận câu hỏi người dùng, gọi `search_docs` đọc corpus. Nội dung được làm sạch qua `redact()` (PII gate). Chỉ trích xuất danh sách ID ticket dạng số nguyên từ tên file tin cậy (`ticket-(\d+).md`), cô lập toàn bộ free text chứa prompt injection lại Run A.
- Run B (Isolated Customer Store Access): Nhận danh sách ticket ID từ Run A, dùng bảng tham chiếu `related_tickets` trong `customers.json` để xác định `customer_id` hợp lệ. Gọi `read_customer` (chỉ cho phép khi danh tính là `dpo`).
- Egress Path: Khi mã độc yêu cầu gửi dữ liệu ra endpoint exfiltration (`http://127.0.0.1:10024/reconcile`), PEP chặn đứng với quy tắc cấm `restricted + egress`. Không có byte dữ liệu nào thoát ra ngoài mạng.

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng kỹ thuật:
  - `reports/attack-before.log`: Ghi nhận dữ liệu synthetic của `KH-000999` bị lộ ra sink trong kịch bản baseline chưa có kiểm soát.
  - `reports/attack-after.log`: File rỗng (0 bytes), chứng minh dữ liệu bị chặn hoàn toàn sau containment.
  - `reports/ledger.jsonl`: Dòng 23 ghi nhận quyết định `http_post` bị `deny` với lý do `DENY: restricted data with egress enabled`, chuỗi hash chain SHA-256 xác thực `verify() = True`.
  - Kết quả kiểm thử tự động: 33/33 test case trong bộ kiểm thử `tests/` vượt qua thành công (bao gồm `test_split.py`, `test_obo.py`, `test_injection.py`, `test_supply_chain.py`).
- Giới hạn của mock:
  - Sử dụng 100% dữ liệu synthetic, không lưu trữ hay xử lý bất kỳ PII người thật nào.
  - Cơ chế OBO mô phỏng thông qua cấu hình JSON và cờ `--as`, chưa thay thế cho hệ thống xác thực tập trung IdP/OAuth2/mTLS trong môi trường production.
  - Điểm đích sink là HTTP server trên localhost (`127.0.0.1:10024`), chưa mô phỏng các kỹ thuật exfiltration qua kênh ẩn (DNS tunneling, timing attacks).
  - Mock LLM sử dụng cơ chế so khớp heuristic/regex deterministic để phục vụ chấm điểm và tái lập kết quả ổn định, không phản ánh toàn bộ độ biến thiên ngôn ngữ phức tạp của LLM thương mại.
