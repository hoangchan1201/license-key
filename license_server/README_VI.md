# DewTool License API — hướng dẫn triển khai

API này thay cho bước xác thực license offline sau khi đã deploy và cấu hình URL ở client. Key chỉ bắt đầu tính hạn ở lần kích hoạt đầu tiên và bị khóa với một `machine_id`. Tool chỉ ghi mốc ON khi mở/xác thực và mốc OFF khi thoát bình thường; không gửi heartbeat định kỳ tới database.

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
   - `MINIMUM_CLIENT_VERSION`: phiên bản tối thiểu được phép dùng, hiện đặt `1.0.25`. Client không gửi phiên bản hoặc gửi phiên bản thấp hơn sẽ bị từ chối khi kích hoạt (HTTP 426).
5. Trước khi đặt ngưỡng bắt buộc, hãy build DewTool `1.0.25`, tải ZIP lên release `DewTool-Updates` (asset cập nhật cần đúng quy ước tên trong launcher), rồi kiểm tra bản mới chạy được. Sau đó đặt `MINIMUM_CLIENT_VERSION=1.0.25` trong Render và deploy server. Mở URL service kèm `/health`; phải thấy `{"ok":true,...}`. Bản cũ không gửi header phiên bản sẽ bị chặn khi kích hoạt.

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

`list` hiển thị key đã che một phần, hạn và online/offline. Online nghĩa là tool đã ghi mốc ON và chưa ghi mốc OFF khi thoát bình thường. Bản server mới mã hóa key để admin có thể xem/copy lại. Các key cũ chỉ lưu hash nên không thể khôi phục nội dung đầy đủ. `reset` xóa liên kết máy và ngày kích hoạt; lần dùng tiếp theo bắt đầu lại thời hạn, nên chỉ dùng khi cần hỗ trợ đổi máy.

Dialog **Quản lý License — Admin** cũng hỗ trợ giảm cùng một khoảng thời hạn cho một hoặc nhiều key đã chọn. Mỗi key phải còn ít nhất 1 giờ sau khi trừ; nếu bất kỳ key nào không hợp lệ hoặc không đủ thời hạn, cả lô sẽ bị từ chối. Tính năng này cần deploy phiên bản server có endpoint `/api/v1/admin/reduce` trước khi dùng.

Tính năng key miễn phí đã được loại bỏ. License được cấp và quản lý trực tiếp trong tab **License** của Quản trị License; ứng dụng không còn lấy key từ endpoint cấp key miễn phí.

## Key offline miễn phí 1 ngày

Endpoint `POST /api/v1/offline-free-key` ký một key offline, gắn với mã máy và có hạn 24 giờ. Endpoint này không kết nối Neon/Postgres và chỉ ghi lịch sử tạm thời (mã key, mã băm ngắn của máy, hạn dùng) vào log Render.

Trên Render, thêm biến môi trường bí mật `OFFLINE_SIGNING_PRIVATE_KEY`: nội dung chính xác của file `%APPDATA%\DewToolLicense\offline_fallback_ed25519.key` trên máy Admin. Không đưa giá trị này vào GitHub, file build, hoặc gửi cho người dùng. Khóa phải khớp với public key đã có trong `license_offline_fallback.py`; nếu không server từ chối cấp key.

## 6. Kết nối launcher

Sau khi `/health` hoạt động, client ở thư mục mã nguồn đã được nối tới URL Render và launcher đã chuyển sang `license_client_api`. Hãy build lại launcher để phát hành bản dùng API.

## Lưu ý

- Các key tạo bằng `keygen_offline.py` không tự có trong database API. Muốn chuyển người dùng hiện tại, cần cấp key API mới hoặc chuẩn bị quy trình nhập/migrate key có kiểm soát.
- Không nhúng `LICENSE_ADMIN_TOKEN` vào launcher. Chỉ đặt token trong Environment Variables của Render và PowerShell riêng trên máy quản trị.
- Free web service có thể khởi động chậm sau idle; khi API không truy cập được, client chưa thể xác thực key.
