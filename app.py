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

# ===== 專題動機 =====
@app.route("/motivation")
def motivation():
    return render_template("motivation.html")

# ===== 使用者清單（僅管理員 jie 可見） =====
@app.route("/users")
def users_list():
    if not session.get("user"):
        return redirect(url_for("login", msg="請先登入才能查看使用者清單"))

    # 只允許管理員 jie 存取
    if session["user"] != "jie":
        return "權限不足，僅管理員可查看。", 403

    with engine.begin() as conn:
        users = conn.execute(text("SELECT id, username, password_hash, created_at FROM users ORDER BY id ASC")).mappings().all()

    return render_template("users.html", users=users)

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
@app.route("/report", methods=["POST"])
def report():
    try:
        # 嘗試解析中繼站轉送的 JSON
        raw = request.get_data(as_text=True)
        print("=== Received from relay ===")
        print(raw[:500])  # 印前500字防止過長
        data = json.loads(raw)
        print("Decoded JSON:", data)
    except Exception as e:
        return jsonify(ok=False, error=f"JSON decode failed: {e}"), 400

    # 取得基本欄位
    now = datetime.utcnow()
    ip_public = request.headers.get("X-Forwarded-For") or request.remote_addr
    ua = request.headers.get("User-Agent", "")

    # 自動容錯的取值
    def g(*keys, default=""):
        for k in keys:
            if k in data:
                return data[k]
        return default

    row = {
        "ts": now,
        "client_id": g("client_id", "name", "id", default=""),
        "ip_public": g("ip_public", "public_ip", default=ip_public),
        "ip_internal": g("ip_internal", "internal_ip", "ip", default=""),
        "user_agent": ua,
        "vector": g("vector", "method", "type", default="relay"),
        "payload_sha256": None,
        "payload_len": None,
        "payload_sample": None,
        "missed": 1
    }

    # 嘗試從資料中提取 payload 或系統資訊
    payload_raw = g("payload", "os", "data", default=None)
    if payload_raw:
        payload_bytes = str(payload_raw).encode("utf-8", errors="ignore")
        row["payload_sha256"] = sha256(payload_bytes).hexdigest()
        row["payload_len"] = len(payload_bytes)
        # 簡短樣本文字
        sample = str(payload_raw)
        if len(sample) > 80:
            sample = sample[:77] + "..."
        row["payload_sample"] = sample

    # 寫入資料庫
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO events (ts, client_id, ip_public, ip_internal, user_agent,
                                    vector, payload_sha256, payload_len, payload_sample, missed)
                VALUES (:ts, :client_id, :ip_public, :ip_internal, :user_agent,
                        :vector, :payload_sha256, :payload_len, :payload_sample, :missed)
            """), row)
        print(f"[Render] ✅ Insert success: {row['client_id']}, {row['ip_public']}")
    except Exception as e:
        print("[Render Error] DB insert failed:", e)
        return jsonify(ok=False, error=str(e)), 500

    return jsonify(ok=True, ts=now.isoformat() + "Z")


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
# ===== 清除事件 =====
@app.route("/clear", methods=["POST"])
def clear():
    if not session.get("user"):
        return redirect(url_for("login", next="/view", msg="請先登入才能清除事件"))

    scope  = request.form.get("scope", "all")
    vector = (request.form.get("vector") or "").strip()
    client = (request.form.get("client") or "").strip()

    with engine.begin() as conn:
        if scope == "filtered" and (vector or client):
            q = "DELETE FROM events WHERE 1=1"
            p = {}
            if vector:
                q += " AND vector = :vector"
                p["vector"] = vector
            if client:
                q += " AND client_id = :client"
                p["client"] = client
            conn.execute(text(q), p)
        else:
            conn.execute(text("DELETE FROM events"))
    return redirect(url_for("view"))

# 健康檢查
@app.route("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
