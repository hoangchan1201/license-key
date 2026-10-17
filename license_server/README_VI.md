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
5. Deploy. Mở URL service kèm `/health`; phải thấy `{"ok":true,...}`. URL sẽ có dạng `https://ten-service.onrender.com`.

> Render Free có thể sleep sau 15 phút không có request; lần gọi đầu sau sleep sẽ khởi động lại. Không dùng Render Free PostgreSQL cho license lâu dài vì database miễn phí hết hạn sau 30 ngày. API service chỉ lưu dữ liệu trong Neon.

## 4. Tạo license key

Trên máy quản trị, mở PowerShell tại thư mục `license_server`:

```powershell
$env:LICENSE_API_BASE_URL = "https://ten-service.onrender.com"
$env:LICENSE_ADMIN_TOKEN = "TOKEN_BI_MAT_CUA_BAN"
py -m pip install -r requirements.txt
py admin_cli.py create --days 30 --count 1
```

Key hiện ra chỉ một lần; hãy lưu an toàn rồi gửi key cho đúng người dùng. Ví dụ tạo key 7 ngày: `--days 7`. Lần kích hoạt đầu tiên mới bắt đầu tính thời hạn.

## 5. Xem ai đang online / thu hồi key

```powershell
py admin_cli.py list
py admin_cli.py revoke --key "DEW-..."
py admin_cli.py reset --key "DEW-..."
```

`list` hiển thị key đã che một phần, hạn và online/offline. Online nghĩa là server nhận heartbeat trong vòng 100 giây. `reset` xóa liên kết máy và ngày kích hoạt; lần dùng tiếp theo bắt đầu lại thời hạn, nên chỉ dùng khi cần hỗ trợ đổi máy.

## 6. Kết nối launcher

Sau khi `/health` hoạt động, cần cập nhật `LICENSE_API_BASE_URL` trong `license_client_api.py` bằng URL Render, rồi chuyển import license ở `launcher_auto_tool.py` từ `license_client_offline` sang `license_client_api` và build lại. Chưa chuyển launcher trước khi có URL API thật, nếu không bản hiện tại sẽ không xác thực được license.

## Lưu ý

- Các key tạo bằng `keygen_offline.py` không tự có trong database API. Muốn chuyển người dùng hiện tại, cần cấp key API mới hoặc chuẩn bị quy trình nhập/migrate key có kiểm soát.
- Không nhúng `LICENSE_ADMIN_TOKEN` vào launcher. Chỉ đặt token trong Environment Variables của Render và PowerShell riêng trên máy quản trị.
- Free web service có thể khởi động chậm sau idle; khi API không truy cập được, client chưa thể xác thực key.
