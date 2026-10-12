# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`), commit sau đó `ece6ca4` đã xoá file `lab-fake-secret.txt`.
- File, rule và kết quả quét lịch sử:
  - Lệnh quét lịch sử: `gitleaks git --config .gitleaks.toml --redact --verbose .`
  - File: `lab-fake-secret.txt:1`
  - Rule ID: `lab24-synthetic-token`
  - Kết quả: Tìm thấy 1 finding (leaks found: 1, exit code 1) tại commit `1bdd849` chứa token giả tổng hợp `LAB24_FAKE_TOKEN`.
- Kết quả quét file hiện tại:
  - Lệnh: `gitleaks dir --config .gitleaks.toml .` và `pre-commit run --all-files`
  - Kết quả: Sạch (no leaks found, Passed), không có secret trong file hiện tại trên HEAD.
- Nếu đây là credential thật, cần xử lý thế nào:
  - Phải lập tức thu hồi (revoke) và rotate credential trên dịch vụ cung cấp (IAM/API provider/IdP) để vô hiệu hóa token ngay lập tức.
  - Rà soát audit log truy vết xem token đã bị khai thác trái phép hay chưa.
  - Sau khi đã rotate, mới dùng công cụ (như git-filter-repo / BFG) viết lại lịch sử git nếu cần dọn dẹp repo.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file khỏi HEAD chỉ làm file biến mất ở commit mới nhất, trong khi toàn bộ nội dung file và secret vẫn nằm nguyên vẹn trong lịch sử git object của commit `1bdd849`, bất kỳ ai clone repo đều đọc được. Xoá file không hề thu hồi hay vô hiệu hóa credential đang hoạt động.
  - Pin dependency (`requirements.lock` kèm sha256 hash) và hook `gitleaks-system` chỉ giúp ngăn chặn mã độc trong supply chain và chặn commit mới, chứ không thể tự động rotate hay vô hiệu hoá secret đã bị lộ trong quá khứ.
