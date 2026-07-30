#!/usr/bin/env python3
"""
Subdomain Scanner Panel — main Flask application.

Menus:
  - Quét mới      (/)            run a new scan
  - Lịch sử       (/history)     browse past scans, stored in SQLite
  - Chi tiết quét (/history/<id>) view stored results of one past scan
  - Wordlist      (/wordlist)    edit the brute-force wordlist
  - Tài khoản     (/account)     change the admin password
  - Đăng xuất     (/logout)

Auth: single admin account, credentials + secret key stored in config.json
(created automatically by install.sh, or on first run with a default you
should change immediately from the Tài khoản page).
"""

import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from functools import wraps

from flask import (Flask, g, jsonify, redirect, render_template, request,
                    session, url_for, flash)
from werkzeug.security import check_password_hash, generate_password_hash

import core

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_FILE = os.path.join(BASE_DIR, "history.db")

app = Flask(__name__)

# -----------------------------------------------------------------------
# Background scan jobs — in-memory job registry so a scan started from the
# web UI keeps running (and finishes) even if the user closes the tab or
# navigates elsewhere. Keyed by job_id, protected by JOBS_LOCK since jobs
# run in their own threads separate from Flask's request handling.
# -----------------------------------------------------------------------
JOBS = {}
JOBS_LOCK = threading.Lock()
JOB_MAX_AGE = 3600  # drop finished job records after 1h to bound memory use


def _set_job(job_id, **fields):
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(fields)


def _prune_old_jobs():
    now = time.time()
    with JOBS_LOCK:
        stale = [jid for jid, j in JOBS.items()
                 if j.get("status") in ("done", "error") and now - j.get("created_at", now) > JOB_MAX_AGE]
        for jid in stale:
            del JOBS[jid]


def _run_scan_job(job_id, domain, use_subfinder, use_brute, use_permutation):
    def progress(stage):
        _set_job(job_id, stage=stage)

    try:
        _set_job(job_id, status="running", stage="Đang khởi tạo...")
        result = core.run_scan(
            domain,
            use_subfinder=use_subfinder,
            use_brute=use_brute,
            use_permutation=use_permutation,
            progress_cb=progress,
        )

        cdn_count = sum(1 for r in result["results"] if r["alive"] and not r["cdn"].startswith("Không"))

        # Background thread needs its own sqlite connection (can't use flask.g here).
        conn = sqlite3.connect(DB_FILE)
        try:
            conn.execute(
                "INSERT INTO scans (domain, created_at, total, alive, cdn_count, results_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (result["domain"], int(time.time()), result["total"], result["alive"], cdn_count,
                 json.dumps(result["results"], ensure_ascii=False))
            )
            conn.commit()
        finally:
            conn.close()

        _set_job(job_id, status="done", stage="Hoàn tất", result=result)
    except Exception as e:
        _set_job(job_id, status="error", stage="Lỗi", error=str(e))


@app.template_filter("timestamp_to_str")
def timestamp_to_str(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%d/%m/%Y %H:%M")
    except Exception:
        return str(ts)


# -----------------------------------------------------------------------
# Config / bootstrap
# -----------------------------------------------------------------------
def load_config():
    if not os.path.isfile(CONFIG_FILE):
        default = {
            "secret_key": secrets.token_hex(32),
            "username": "admin",
            "password_hash": generate_password_hash("admin123"),
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(default, f, indent=2)
        print("!! Không tìm thấy config.json — đã tạo tài khoản mặc định admin/admin123.")
        print("!! Hãy đổi mật khẩu ngay trong menu 'Tài khoản' sau khi đăng nhập.")
        return default
    with open(CONFIG_FILE) as f:
        return json.load(f)


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


CONFIG = load_config()
app.secret_key = CONFIG["secret_key"]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            total INTEGER NOT NULL,
            alive INTEGER NOT NULL,
            cdn_count INTEGER NOT NULL,
            results_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


# -----------------------------------------------------------------------
# Auth helpers
# -----------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == CONFIG["username"] and check_password_hash(CONFIG["password_hash"], password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(request.args.get("next") or url_for("index"))
        flash("Sai tên đăng nhập hoặc mật khẩu", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------------------------------------------
# Main scan page
# -----------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    return render_template("scan.html", active="scan")


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    _prune_old_jobs()
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip()
    use_brute = bool(data.get("bruteforce", True))
    use_subfinder = bool(data.get("subfinder", True))
    use_permutation = bool(data.get("permutation", True))

    if not domain:
        return jsonify({"error": "Nhập tên miền cần quét"}), 400

    job_id = secrets.token_hex(8)
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "queued",
            "stage": "Đang xếp hàng...",
            "domain": domain,
            "created_at": time.time(),
        }

    thread = threading.Thread(
        target=_run_scan_job,
        args=(job_id, domain, use_subfinder, use_brute, use_permutation),
        daemon=True,
    )
    thread.start()

    return jsonify({"job_id": job_id}), 202


@app.route("/api/scan/status/<job_id>")
@login_required
def api_scan_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Không tìm thấy tiến trình quét này (có thể đã hết hạn)"}), 404
        return jsonify(dict(job))


# -----------------------------------------------------------------------
# History
# -----------------------------------------------------------------------
@app.route("/history")
@login_required
def history():
    db = get_db()
    rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 200").fetchall()
    return render_template("history.html", active="history", scans=rows)


@app.route("/history/<int:scan_id>")
@login_required
def history_detail(scan_id):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        flash("Không tìm thấy bản ghi quét này", "error")
        return redirect(url_for("history"))
    results = json.loads(row["results_json"])
    return render_template("detail.html", active="history", scan=row, results=results)


@app.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def history_delete(scan_id):
    db = get_db()
    db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db.commit()
    return redirect(url_for("history"))


# -----------------------------------------------------------------------
# Wordlist editor
# -----------------------------------------------------------------------
@app.route("/wordlist", methods=["GET", "POST"])
@login_required
def wordlist():
    if request.method == "POST":
        core.save_wordlist(request.form.get("content", ""))
        flash("Đã lưu wordlist", "success")
        return redirect(url_for("wordlist"))
    content = ""
    if os.path.isfile(core.WORDLIST_FILE):
        with open(core.WORDLIST_FILE, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    return render_template("wordlist.html", active="wordlist", content=content)


# -----------------------------------------------------------------------
# Account settings
# -----------------------------------------------------------------------
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not check_password_hash(CONFIG["password_hash"], current):
            flash("Mật khẩu hiện tại không đúng", "error")
        elif len(new_password) < 6:
            flash("Mật khẩu mới phải từ 6 ký tự trở lên", "error")
        elif new_password != confirm:
            flash("Mật khẩu xác nhận không khớp", "error")
        else:
            CONFIG["password_hash"] = generate_password_hash(new_password)
            save_config(CONFIG)
            flash("Đã đổi mật khẩu thành công", "success")
    return render_template("account.html", active="account", username=CONFIG["username"])


if __name__ == "__main__":
    port = int(os.environ.get("SUBPANEL_PORT", 9081))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
