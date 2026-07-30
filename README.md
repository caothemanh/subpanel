# Subdomain Scanner Panel

Panel web (có đăng nhập, có menu) để tìm subdomain của 1 domain, lấy IP tương ứng
và phát hiện loại CDN đang dùng — kèm lịch sử các lần quét.

## Cài đặt — chỉ 1 lệnh

```bash
sudo bash install.sh
```

Chạy lệnh trên từ trong thư mục đã giải nén (`subpanel/`). Script sẽ tự động:

1. Cài gói hệ thống cần thiết (python3, venv, ufw, curl...)
2. Copy toàn bộ project vào `/opt/subpanel`
3. Tạo virtualenv riêng + cài thư viện Python
4. Hỏi bạn đặt tên đăng nhập / mật khẩu admin (nếu chạy không tương tác, tự sinh mật khẩu ngẫu nhiên và in ra màn hình)
5. Cài `subfinder` nếu máy đã có Go (bỏ qua nếu chưa có — panel vẫn chạy tốt với crt.sh + brute-force)
6. Tạo systemd service `subpanel`, bật tự khởi động cùng hệ thống
7. Mở port 5000 trên `ufw` nếu đang bật

Sau khi chạy xong, script in ra địa chỉ truy cập + tài khoản đăng nhập.

## Các menu trong panel

| Menu | Chức năng |
|---|---|
| 🚀 **Quét mới** | Nhập domain, chọn nguồn (subfinder / brute-force wordlist), xem kết quả subdomain + IP + CDN, xuất CSV |
| 🕓 **Lịch sử quét** | Danh sách các lần quét trước đó (lưu trong SQLite), xem lại chi tiết hoặc xoá |
| 📝 **Wordlist** | Chỉnh sửa danh sách từ khoá dùng để brute-force subdomain |
| 👤 **Tài khoản** | Đổi mật khẩu đăng nhập |

## Nguồn dữ liệu tìm subdomain

- **crt.sh** — tra cứu chứng chỉ SSL đã cấp (Certificate Transparency), luôn dùng, không cần API key.
- **subfinder** (tuỳ chọn) — nếu có cài, dùng thêm để có kết quả đầy đủ hơn.
- **Brute-force wordlist** — thử các tên subdomain phổ biến, chỉnh trực tiếp trong menu Wordlist.

## Cách phát hiện CDN

1. So khớp chuỗi CNAME với dấu hiệu của các CDN phổ biến (Cloudflare, Akamai, Fastly, CloudFront, Azure CDN, Sucuri, Incapsula, BunnyCDN, v.v.)
2. Nếu IP nằm trong dải IP công bố chính thức của Cloudflare → gắn nhãn Cloudflare.
3. Nếu vẫn chưa rõ, gửi 1 request HEAD và kiểm tra header phản hồi (`Server`, `CF-RAY`, `X-Amz-Cf-Id`, `X-Served-By`...).

## Quản lý service sau khi cài

```bash
systemctl status subpanel     # xem trạng thái
systemctl restart subpanel    # khởi động lại
journalctl -u subpanel -f     # xem log realtime
```

## Bảo mật khi public ra internet

- Panel chạy HTTP thuần trên port 5000 (Flask dev server). Nếu mở ra internet công khai,
  nên đặt sau **Nginx reverse proxy + HTTPS (Let's Encrypt)** thay vì expose thẳng port 5000.
- Đổi mật khẩu mặc định ngay sau lần đăng nhập đầu tiên (menu Tài khoản).
- Chỉ nên quét domain mà bạn sở hữu hoặc được phép kiểm thử.

## Cài đặt thủ công (nếu không dùng install.sh)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
# mở http://<ip-server>:5000  (tài khoản mặc định: admin / admin123 — hãy đổi ngay)
```
