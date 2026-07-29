# Subdomain Scanner Panel

Panel web để tìm subdomain của 1 domain, lấy IP tương ứng và phát hiện loại CDN đang dùng.

## Nguồn dữ liệu

- **crt.sh** — tra cứu chứng chỉ SSL đã cấp (Certificate Transparency), không cần API key.
- **subfinder** (tuỳ chọn) — nếu máy đã cài `subfinder`, panel tự động dùng thêm để có kết quả đầy đủ hơn.
- **Brute-force wordlist** — thử một danh sách tên subdomain phổ biến (`wordlist.txt`, có thể chỉnh sửa/thêm dòng).

## Cách phát hiện CDN

1. So khớp chuỗi CNAME với các dấu hiệu của CDN phổ biến (Cloudflare, Akamai, Fastly, CloudFront, Azure CDN, Sucuri, Incapsula, BunnyCDN, v.v.)
2. Nếu IP nằm trong dải IP công bố chính thức của Cloudflare → gắn nhãn Cloudflare.
3. Nếu vẫn chưa rõ, gửi 1 request HEAD và kiểm tra header phản hồi (`Server`, `CF-RAY`, `X-Amz-Cf-Id`, `X-Served-By`, ...).

## Cài đặt trên Ubuntu

```bash
# 1. Cài Python & pip nếu chưa có
sudo apt update && sudo apt install -y python3 python3-pip

# 2. Copy thư mục này lên server, ví dụ /opt/subpanel
sudo mkdir -p /opt/subpanel
sudo cp -r * /opt/subpanel/
cd /opt/subpanel

# 3. Cài thư viện Python
pip3 install -r requirements.txt

# 4. (Tuỳ chọn nhưng khuyến nghị) Cài subfinder để kết quả đầy đủ hơn
#    Yêu cầu Go đã cài sẵn: https://go.dev/doc/install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp ~/go/bin/subfinder /usr/local/bin/

# 5. Chạy thử
python3 app.py
# Mở trình duyệt: http://<ip-server>:5000
```

## Chạy nền vĩnh viễn bằng systemd (khuyến nghị)

```bash
sudo cp subpanel.service /etc/systemd/system/subpanel.service
sudo systemctl daemon-reload
sudo systemctl enable --now subpanel
sudo systemctl status subpanel
```

Panel sẽ tự khởi động lại nếu bị crash và tự chạy khi server reboot.

## Mở port ra ngoài (nếu dùng UFW)

```bash
sudo ufw allow 5000/tcp
```

Nếu chạy trên VPS công khai, nên đặt sau Nginx reverse proxy + xác thực (Basic Auth hoặc IP whitelist) vì panel này không có sẵn cơ chế đăng nhập.

## Lưu ý

- Chỉ nên quét domain mà bạn sở hữu hoặc được phép kiểm thử (bug bounty trong phạm vi cho phép, hạ tầng của chính bạn, v.v.).
- Brute-force wordlist mặc định khá nhỏ để quét nhanh — có thể thay `wordlist.txt` bằng danh sách lớn hơn (ví dụ từ SecLists) để tìm được nhiều subdomain hơn, nhưng sẽ quét lâu hơn.
- crt.sh đôi khi phản hồi chậm hoặc rate-limit nếu quét quá nhiều domain liên tục — panel đã set timeout 15s cho việc này.
