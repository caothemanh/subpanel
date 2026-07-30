# Subdomain Scanner Panel

Panel web (có đăng nhập, có menu) để tìm subdomain của 1 domain, lấy IP tương ứng
và phát hiện loại CDN đang dùng — kèm lịch sử các lần quét.

## Bước 1 — Đẩy code lên GitHub

Trong thư mục `subpanel/` (vừa giải nén), chạy:

```bash
git init
git add .
git commit -m "Subdomain Scanner Panel"
git branch -M main
git remote add origin https://github.com/caothemanh/subpanel.git
git push -u origin main
```

(Trước đó nhớ tạo repo rỗng tên `subpanel` trên GitHub — https://github.com/new — public hoặc private đều được, xem lưu ý ở cuối)

## Bước 2 — Cài đặt trên VPS chỉ bằng 1 lệnh

Mở `install.sh`, sửa 2 dòng đầu cho khớp đúng repo/nhánh của bạn (mặc định đã để sẵn `caothemanh/subpanel` nhánh `main`) rồi push lại. Sau đó trên VPS (Ubuntu), chỉ cần:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/caothemanh/subpanel/main/install.sh)"
```

Không cần tải file, không cần `cd`, không cần giải nén gì cả — script tự:

1. Cài gói hệ thống cần thiết (python3, venv, git, ufw, curl...)
2. Clone code trực tiếp từ GitHub vào `/opt/subpanel`
3. Tạo virtualenv riêng + cài thư viện Python
4. Hỏi bạn đặt tên đăng nhập / mật khẩu admin (nếu chạy không tương tác, tự sinh mật khẩu ngẫu nhiên và in ra màn hình)
5. Cài `subfinder` nếu máy đã có Go (bỏ qua nếu chưa có — panel vẫn chạy tốt với crt.sh + brute-force)
6. Tạo systemd service `subpanel`, bật tự khởi động cùng hệ thống
7. Mở port 5000 trên `ufw` nếu đang bật

Chạy lại đúng lệnh trên bất cứ lúc nào để **cập nhật lên bản mới nhất** trên GitHub — script tự `git pull` mà không mất tài khoản đăng nhập hay lịch sử quét đã lưu.

## Nếu repo GitHub để Private

Lệnh `curl` ở trên chỉ hoạt động với repo **public**. Nếu để private, cách đơn giản nhất là dùng Personal Access Token trong REPO_URL:

```bash
sudo REPO_URL="https://<TOKEN>@github.com/caothemanh/subpanel.git" bash -c "$(curl -fsSL https://raw.githubusercontent.com/caothemanh/subpanel/main/install.sh)"
```

(cần lấy được `install.sh` bằng cách khác nếu repo private, ví dụ scp file này lên VPS trước, vì `curl` không đọc được raw file của repo private nếu không có token trong URL raw.githubusercontent.com)

## Các menu trong panel

| Menu | Chức năng |
|---|---|
| 🚀 **Quét mới** | Nhập domain, chọn nguồn (subfinder / brute-force wordlist), xem kết quả subdomain + IP + CDN, xuất CSV |
| 🕓 **Lịch sử quét** | Danh sách các lần quét trước đó (lưu trong SQLite), xem lại chi tiết hoặc xoá |
| 📝 **Wordlist** | Chỉnh sửa danh sách từ khoá dùng để brute-force subdomain |
| 👤 **Tài khoản** | Đổi mật khẩu đăng nhập |

## Nguồn dữ liệu tìm subdomain

Passive (luôn bật, miễn phí, không cần API key), chạy song song:

- **crt.sh** — Certificate Transparency logs
- **HackerTarget** — hostsearch API
- **RapidDNS** — passive DNS aggregator
- **CertSpotter** — Certificate Transparency logs (nguồn thứ 2, hay bắt được cái crt.sh bỏ sót)
- **AlienVault OTX** — passive DNS
- **Anubis / JLDC** — passive DNS
- **Wayback Machine (CDX API)** — quét URL đã lưu trữ để lấy tên subdomain từng xuất hiện

Chủ động (tuỳ chọn, bật/tắt được lúc quét):

- **subfinder** — nếu máy đã cài Go và binary `subfinder`, dùng thêm để gộp kết quả.
- **Brute-force wordlist** — thử ~500 tên subdomain phổ biến có sẵn (chỉnh sửa trong menu Wordlist), có tự phát hiện DNS wildcard để lọc bớt kết quả giả.
- **Permutation** — với mỗi subdomain đã tìm được (vd `api`), tự thử thêm các biến thể môi trường phổ biến (`dev-api`, `api-dev`, `staging-api`, `api-v2`...).

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
