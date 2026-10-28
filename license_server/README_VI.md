# DewTool License API — hướng dẫn triển khai

API này thay cho bước xác thực license offline sau khi đã deploy và cấu hình URL ở client. Key chỉ bắt đầu tính hạn ở lần kích hoạt đầu tiên, bị khóa với một `machine_id`, gửi heartbeat mỗi 30 giây và hiện online nếu heartbeat trong 100 giây gần nhất.

## 1. Tạo database Neon

1. Tạo tài khoản ở [Neon](https://console.neon.tech/) và tạo project PostgreSQL mới.
2. Mở **Connect** và sao chép connection string dạng PostgreSQL. Không đưa chuỗi này vào GitHub hoặc gửi trong chat.
3. Dùng gói miễn phí để bắt đầu; giới hạn hiện tại gồm 1 GB lưu trữ và 100 CU-giờ mỗi project/tháng. Compute tự scale về 0 khi không hoạt động.

## 2. Đưa mã server lên GitHub

1. Mở repository `hoangchan1201/license-key`, chọn **Add file → Upload files**.
2. Tải các file `app.py`, `admin_cli.py`, `requirements.txt`, `README_VI.md` từ thư mục `license_server` lên **thư mục gốc** của repository.
3. Bấm **Commit changes**. Có thể giữ repo public vì trong mã không có key hay mật khẩu.
4. Không commit database URL hoặc `LICENSE_ADMIN_TOKEN`.

## 3. Deploy API trên Render

1. Tạo tài khoản Render và chọn **New → Web Service**.
2. Kết nối repository `license-key`.
3. Để trống **Root Directory**. Chọn **Runtime: Python**, **Build Command: `pip install -r requirements.txt`**, **Start Command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`**, gói **Free**.
4. Ở phần **Environment Variables**, thêm:
   - `DATABASE_URL`: connection string lấy từ Neon.
   - `LICENSE_ADMIN_TOKEN`: tạo chuỗi bí mật dài, ngẫu nhiên và giữ riêng.
   - `LICENSE_KEY_ENCRYPTION_KEY`: sau khi cập nhật server, tạo key Fernet bằng `py -m pip install cryptography` rồi chạy `py -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`; lưu kết quả vào biến này trên Render. Giữ bí mật và sao lưu an toàn; không đổi/mất key này nếu muốn xem lại license key đầy đủ.
5. Deploy. Mở URL service kèm `/health`; phải thấy `{"ok":true,...}`. URL sẽ có dạng `https://ten-service.onrender.com`.

> Render Free có thể sleep sau 15 phút không có request; lần gọi đầu sau sleep sẽ khởi động lại. Không dùng Render Free PostgreSQL cho license lâu dài vì database miễn phí hết hạn sau 30 ngày. API service chỉ lưu dữ liệu trong Neon.

## 4. Tạo license key

Trên máy quản trị, mở PowerShell tại thư mục `license_server`:

```powershell
py admin_cli.py create --days 30 --count 1
```

Lần chạy đầu tiên, chương trình hỏi `LICENSE_ADMIN_TOKEN` rồi lưu token đã mã hóa bằng Windows cho tài khoản hiện tại. Nếu cần nhập/lưu lại token, chạy `py admin_cli.py set-token`. Lưu ý token sẽ hiện trên màn hình khi nhập. Những lần sau không cần nhập lại. URL API đã được đặt sẵn; có thể ghi đè bằng `--url` nếu đổi server. Không đưa token lên GitHub.

Key hiện ra chỉ một lần; hãy lưu an toàn rồi gửi key cho đúng người dùng. Ví dụ tạo key 7 ngày: `--days 7`. Lần kích hoạt đầu tiên mới bắt đầu tính thời hạn.

Thời hạn được chọn theo một đơn vị mỗi lần; tháng tính 30 ngày, năm tính 365 ngày. Mức hỗ trợ từ 1 giờ đến 3650 ngày:

```powershell
py admin_cli.py create --hours 3 --count 1
py admin_cli.py create --days 2 --count 1
py admin_cli.py create --weeks 2 --count 1
py admin_cli.py create --months 1 --count 1
py admin_cli.py create --years 1 --count 1
```

API trên Render phải được cập nhật/redeploy trước khi dùng `--hours`. Thời hạn tròn ngày (ngày/tuần/tháng/năm) vẫn dùng được với bản server cũ.

## 5. Xem ai đang online / thu hồi key

```powershell
py admin_cli.py list
py admin_cli.py revoke --key "DEW-..."
py admin_cli.py reset --key "DEW-..."
```

`list` hiển thị key đã che một phần, hạn và online/offline. Online nghĩa là server nhận heartbeat trong vòng 100 giây. Bản server mới mã hóa key để admin có thể xem/copy lại. Các key cũ chỉ lưu hash nên không thể khôi phục nội dung đầy đủ. `reset` xóa liên kết máy và ngày kích hoạt; lần dùng tiếp theo bắt đầu lại thời hạn, nên chỉ dùng khi cần hỗ trợ đổi máy.

Dialog **Quản lý License — Admin** cũng hỗ trợ giảm cùng một khoảng thời hạn cho một hoặc nhiều key đã chọn. Mỗi key phải còn ít nhất 1 giờ sau khi trừ; nếu bất kỳ key nào không hợp lệ hoặc không đủ thời hạn, cả lô sẽ bị từ chối. Tính năng này cần deploy phiên bản server có endpoint `/api/v1/admin/reduce` trước khi dùng.

Nút **Key miễn phí** trong License Admin tạo một lô key miễn phí chưa kích hoạt. Người dùng bấm **Get key free**, nhập mã trong ảnh CAPTCHA do server tạo và được server xác minh, sau đó server khóa key cho đúng một máy. CAPTCHA hết hạn sau 5 phút và tối đa 3 lần nhập sai. Server giới hạn tối đa 8 CAPTCHA trong 10 phút trên mỗi machine ID. Tính năng này cần deploy phiên bản server có cột `is_free`, bảng `free_key_captchas`, Pillow và các endpoint `/api/v1/free-key/captcha` cùng `/api/v1/free-key`; schema tự bổ sung khi server khởi động. Đây là CAPTCHA cơ bản để cản yêu cầu tự động đơn giản, không thay thế dịch vụ chống bot chuyên dụng.

## 6. Kết nối launcher

Sau khi `/health` hoạt động, client ở thư mục mã nguồn đã được nối tới URL Render và launcher đã chuyển sang `license_client_api`. Hãy build lại launcher để phát hành bản dùng API.

## Lưu ý

- Các key tạo bằng `keygen_offline.py` không tự có trong database API. Muốn chuyển người dùng hiện tại, cần cấp key API mới hoặc chuẩn bị quy trình nhập/migrate key có kiểm soát.
- Không nhúng `LICENSE_ADMIN_TOKEN` vào launcher. Chỉ đặt token trong Environment Variables của Render và PowerShell riêng trên máy quản trị.
- Free web service có thể khởi động chậm sau idle; khi API không truy cập được, client chưa thể xác thực key.

