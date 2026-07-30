#!/usr/bin/env bash
#
# install.sh — cài đặt Subdomain Scanner Panel chỉ bằng 1 lệnh:
#
#     sudo bash install.sh
#
# Script sẽ:
#   1. Cài các gói hệ thống cần thiết (python3, venv, pip, ufw...)
#   2. Copy toàn bộ project vào /opt/subpanel
#   3. Tạo virtualenv riêng + cài thư viện Python
#   4. Hỏi bạn tên đăng nhập / mật khẩu admin (hoặc tự sinh nếu chạy không tương tác)
#   5. Cài Go + subfinder (tuỳ chọn, để có kết quả subdomain đầy đủ hơn)
#   6. Tạo systemd service, bật tự khởi động cùng hệ thống
#   7. Mở port trên firewall (nếu dùng ufw)
#
set -euo pipefail

INSTALL_DIR="/opt/subpanel"
SERVICE_NAME="subpanel"
PORT="5000"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Script này cần chạy bằng quyền root. Hãy chạy lại: sudo bash install.sh"
  exit 1
fi

echo "=============================================="
echo "  Subdomain Scanner Panel - Trình cài đặt"
echo "=============================================="

# ---------------------------------------------------------------------------
echo ""
echo "[1/7] Cài gói hệ thống cần thiết..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ufw curl git rsync > /dev/null

# ---------------------------------------------------------------------------
echo "[2/7] Copy project vào ${INSTALL_DIR} ..."
mkdir -p "$INSTALL_DIR"
rsync -a --exclude 'venv' --exclude 'history.db' --exclude 'config.json' \
  "$SCRIPT_DIR"/ "$INSTALL_DIR"/ 2>/dev/null || cp -r "$SCRIPT_DIR"/. "$INSTALL_DIR"/

# ---------------------------------------------------------------------------
echo "[3/7] Tạo virtualenv và cài thư viện Python..."
if [[ ! -d "$INSTALL_DIR/venv" ]]; then
  python3 -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# ---------------------------------------------------------------------------
echo "[4/7] Thiết lập tài khoản đăng nhập..."
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
  if [[ -t 0 ]]; then
    read -rp "  Tên đăng nhập admin [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    while true; do
      read -rsp "  Mật khẩu admin (tối thiểu 6 ký tự): " ADMIN_PASS
      echo ""
      if [[ ${#ADMIN_PASS} -ge 6 ]]; then break; fi
      echo "  Mật khẩu quá ngắn, thử lại."
    done
  else
    ADMIN_USER="admin"
    ADMIN_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(9))')"
    echo "  Chạy không tương tác -> tự sinh mật khẩu: ${ADMIN_PASS}"
  fi

  "$INSTALL_DIR/venv/bin/python3" - "$ADMIN_USER" "$ADMIN_PASS" "$INSTALL_DIR/config.json" <<'PYEOF'
import json, secrets, sys
from werkzeug.security import generate_password_hash

username, password, path = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = {
    "secret_key": secrets.token_hex(32),
    "username": username,
    "password_hash": generate_password_hash(password),
}
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF
  echo "  Đã tạo tài khoản admin: ${ADMIN_USER}"
else
  echo "  config.json đã tồn tại -> giữ nguyên tài khoản hiện tại."
  ADMIN_USER="(giữ nguyên)"
  ADMIN_PASS="(giữ nguyên)"
fi

# ---------------------------------------------------------------------------
echo "[5/7] Cài subfinder (tuỳ chọn, giúp tìm subdomain đầy đủ hơn)..."
if ! command -v subfinder >/dev/null 2>&1; then
  if command -v go >/dev/null 2>&1; then
    GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >/dev/null 2>&1 \
      && echo "  Đã cài subfinder." \
      || echo "  Không cài được subfinder qua 'go install' — bỏ qua, panel vẫn hoạt động bình thường (dùng crt.sh + brute-force)."
  else
    echo "  Chưa có Go trên máy -> bỏ qua subfinder. Panel vẫn dùng crt.sh + brute-force wordlist."
    echo "  (Muốn cài subfinder sau: cài Go tại https://go.dev/doc/install rồi chạy"
    echo "   'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest')"
  fi
else
  echo "  subfinder đã có sẵn trên máy."
fi

# ---------------------------------------------------------------------------
echo "[6/7] Tạo và khởi động systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Subdomain Scanner Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}" > /dev/null 2>&1
sleep 2
systemctl is-active --quiet "${SERVICE_NAME}" && echo "  Service đang chạy." || {
  echo "  !! Service không khởi động được, xem log bằng: journalctl -u ${SERVICE_NAME} -e"
  exit 1
}

# ---------------------------------------------------------------------------
echo "[7/7] Mở port ${PORT} trên firewall (nếu dùng ufw)..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" > /dev/null
  echo "  Đã mở port ${PORT}/tcp trên ufw."
else
  echo "  ufw không bật hoặc không có -> bỏ qua (nhớ tự mở port ${PORT} nếu dùng firewall khác)."
fi

# ---------------------------------------------------------------------------
SERVER_IP="$(curl -s --max-time 3 https://ifconfig.me || hostname -I | awk '{print $1}')"

echo ""
echo "=============================================="
echo "  CÀI ĐẶT HOÀN TẤT"
echo "=============================================="
echo "  Truy cập panel tại : http://${SERVER_IP}:${PORT}"
echo "  Tên đăng nhập      : ${ADMIN_USER}"
echo "  Mật khẩu           : ${ADMIN_PASS}"
echo ""
echo "  Quản lý service:"
echo "    systemctl status ${SERVICE_NAME}"
echo "    systemctl restart ${SERVICE_NAME}"
echo "    journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "  Nhớ đổi mật khẩu trong menu 'Tài khoản' sau khi đăng nhập lần đầu."
echo "  Panel chạy HTTP thuần — nếu public ra internet, nên đặt sau Nginx + HTTPS."
echo "=============================================="
