# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from hashlib import sha256
from sqlalchemy import create_engine, text
import os, json

# ===== App init =====
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("SECRET_KEY", "change-me-please")

# ===== 資料庫設定 =====
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_PATH = os.path.join(BASE_DIR, "events.db")
DEFAULT_SQLITE_URL = f"sqlite:///{SQLITE_PATH}"
DB_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)
engine = create_engine(DB_URL, future=True, pool_pre_ping=True)

# ===== 建立資料表 =====
with engine.begin() as conn:
    conn.execute(text("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts DATETIME NOT NULL,
        client_id TEXT,
        ip_public TEXT,
        ip_internal TEXT,
        user_agent TEXT,
        vector TEXT,
        payload_sha256 TEXT,
        payload_len INTEGER,
        payload_sample TEXT,
        missed INTEGER NOT NULL
    )
    """))
    conn.execute(text("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME NOT NULL
    )
    """))

# ===== Helper =====
def safe_text_preview(b: bytes, limit=1024) -> str:
    try:
        s = b.decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
        return (s[:limit] + "…") if len(s) > limit else s
    except Exception:
        r = repr(b)
        return (r[:limit] + "…") if len(r) > limit else r

def uid_from_user_id(user_id: int) -> str:
    return f"{int(user_id):06d}"

# ===== Routes =====
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/index")
def index():
    return render_template("index.html")

# ========== 登入/註冊 ==========
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        msg = request.args.get("msg")
        return render_template("register.html", error=msg)

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    if not username or not password:
        return render_template("register.html", error="請輸入帳號與密碼")

    pw_hash = generate_password_hash(password)
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO users (username, password_hash, created_at)
                VALUES (:u, :p, :t)
            """), {"u": username, "p": pw_hash, "t": datetime.utcnow()})
    except Exception:
        return render_template("register.html", error="此帳號已被使用")

    session["user"] = username
    return redirect(url_for("index"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        msg = request.args.get("msg")
        return render_template("login.html", error=msg)

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, username, password_hash FROM users WHERE username=:u"), {"u": username}).mappings().first()

    if not row or not check_password_hash(row["password_hash"], password):
        return render_template("login.html", error="帳號或密碼錯誤")

    session["user"] = row["username"]
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# ========== Agent 下載 ==========
@app.route("/download_agent")
def download_agent():
    if not session.get("user"):
        return redirect(url_for("login", next=request.path, msg="請先登入才能下載"))

    with engine.begin() as conn:
        user_row = conn.execute(text("SELECT id FROM users WHERE username=:u"), {"u": session["user"]}).mappings().first()
    if not user_row:
        return "使用者不存在", 404

    uid = uid_from_user_id(user_row["id"])
    platform = (request.args.get("platform") or "windows").lower()
    if platform == "linux":
        stored_name = "agent-linux"
        ext = ""
    else:
        stored_name = "agent.exe"
        ext = ".exe"

    downloads_dir = os.path.join(app.root_path, "downloads")
    file_path = os.path.join(downloads_dir, stored_name)
    if not os.path.exists(file_path):
        return "檔案不存在", 404

    download_name = f"agent_{uid}{ext}"
    resp = make_response(send_from_directory(downloads_dir, stored_name, as_attachment=True))
    resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
    return resp

# ========== 接收 Agent 傳來的封包 ==========
@app.route("/report", methods=["POST"])
def report():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify(ok=False, error="Invalid JSON"), 400

    now = datetime.utcnow()
    ip_public = request.headers.get("X-Forwarded-For") or request.remote_addr
    ua = request.headers.get("User-Agent", "")

    row = {
        "ts": now,
        "client_id": data.get("client_id") or data.get("name") or "",
        "ip_public": data.get("ip_public") or data.get("public_ip") or ip_public,
        "ip_internal": data.get("ip_internal") or data.get("ip") or "",
        "user_agent": ua,
        "vector": data.get("vector"),
        "payload_sha256": None,
        "payload_len": None,
        "payload_sample": None,
        "missed": 1
    }

    if "payload" in data or "os" in data or "data" in data:
        payload_raw = data.get("payload") or data.get("os") or data.get("data")
        payload_bytes = str(payload_raw).encode("utf-8", errors="ignore")
        row["payload_sha256"] = sha256(payload_bytes).hexdigest()
        row["payload_len"] = len(payload_bytes)
        row["payload_sample"] = safe_text_preview(payload_bytes)

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO events (ts, client_id, ip_public, ip_internal, user_agent,
                                vector, payload_sha256, payload_len, payload_sample, missed)
            VALUES (:ts, :client_id, :ip_public, :ip_internal, :user_agent,
                    :vector, :payload_sha256, :payload_len, :payload_sample, :missed)
        """), row)

    return jsonify(ok=True, ts=now.isoformat()+"Z")

# ========== View ==========
@app.route("/view", methods=["GET", "POST"])
def view():
    if request.method == "POST":
        try:
            raw_bytes = request.get_data(cache=False, as_text=False) or b""
            ua = request.headers.get("User-Agent", "")
            ip_public = request.headers.get("X-Forwarded-For") or request.remote_addr
            now = datetime.utcnow()

            try:
                parsed = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
            except Exception:
                parsed = None

            if isinstance(parsed, dict):
                row = {
                    "ts": now,
                    "client_id": parsed.get("client_id") or parsed.get("name") or "",
                    "ip_public": parsed.get("ip_public") or parsed.get("public_ip") or ip_public,
                    "ip_internal": parsed.get("ip_internal") or parsed.get("ip") or "",
                    "user_agent": ua,
                    "vector": parsed.get("vector"),
                    "payload_sha256": None,
                    "payload_len": None,
                    "payload_sample": None,
                    "missed": 1
                }
                if "payload" in parsed or "os" in parsed or "data" in parsed:
                    payload_raw = parsed.get("payload") or parsed.get("os") or parsed.get("data")
                    payload_bytes = str(payload_raw).encode("utf-8", errors="ignore")
                    row["payload_sha256"] = sha256(payload_bytes).hexdigest()
                    row["payload_len"] = len(payload_bytes)
                    row["payload_sample"] = safe_text_preview(payload_bytes)
            else:
                row = {
                    "ts": now,
                    "client_id": "",
                    "ip_public": ip_public,
                    "ip_internal": "",
                    "user_agent": ua,
                    "vector": None,
                    "payload_sha256": sha256(raw_bytes).hexdigest() if raw_bytes else None,
                    "payload_len": len(raw_bytes) if raw_bytes else None,
                    "payload_sample": safe_text_preview(raw_bytes) if raw_bytes else None,
                    "missed": 1
                }

            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO events (ts, client_id, ip_public, ip_internal, user_agent,
                                        vector, payload_sha256, payload_len, payload_sample, missed)
                    VALUES (:ts, :client_id, :ip_public, :ip_internal, :user_agent,
                            :vector, :payload_sha256, :payload_len, :payload_sample, :missed)
                """), row)

        except Exception as e:
            app.logger.exception("Error handling /view POST: %s", e)
        return "OK", 200

    if not session.get("user"):
        return redirect(url_for("login", msg="請先登入才能查看事件清單"))

    username = session["user"]
    with engine.begin() as conn:
        if username == "jie":
            rows = conn.execute(text("SELECT * FROM events ORDER BY ts DESC LIMIT 500")).mappings().all()
        else:
            user_row = conn.execute(text("SELECT id FROM users WHERE username=:u"), {"u": username}).mappings().first()
            uid = uid_from_user_id(user_row["id"]) if user_row else username
            rows = conn.execute(text("SELECT * FROM events WHERE client_id=:c ORDER BY ts DESC LIMIT 500"), {"c": uid}).mappings().all()

    return render_template("view.html", rows=rows)

# 健康檢查
@app.route("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
