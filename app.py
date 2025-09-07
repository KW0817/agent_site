# app.py
from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from hashlib import sha256
from sqlalchemy import create_engine, text
import os, json

# ===== App init (只初始化一次，並設定 static) =====
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("SECRET_KEY", "change-me-please")  # 請改成環境變數

# ===== 資料庫設定（優先用 DATABASE_URL；fallback 為 SQLite） =====
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_PATH = os.path.join(BASE_DIR, "events.db")
DEFAULT_SQLITE_URL = f"sqlite:///{SQLITE_PATH}"
DB_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)

engine = create_engine(DB_URL, future=True, pool_pre_ping=True)

# 啟動時建立資料表
with engine.begin() as conn:
    # 事件表
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
    # 使用者表
    conn.execute(text("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME NOT NULL
    )
    """))

# ===== 登入保護（全域） =====
# 公開端點：不需登入
PUBLIC_ENDPOINTS = {
    "login",
    "register",
    "logout",
    "health",
    "report",
    "static",
}

@app.before_request
def require_login_globally():
    """
    規則：
      - 若已登入：通過
      - 若 endpoint 在 PUBLIC_ENDPOINTS：通過
      - 若是 /view 且 method=POST（讓 agent 送特殊封包）：通過
      - 其他一律要求登入，導向 /login?next=...
    """
    ep = request.endpoint  # 可能為 None（404 時）
    if ep is None:
        return  # 交給 Flask 預設處理

    # 已登入則放行
    if session.get("user"):
        return

    # 公開端點放行
    if ep in PUBLIC_ENDPOINTS:
        return

    # 允許 /view 的 POST（匿名上報）
    if ep == "view" and request.method == "POST":
        return

    # 其他皆需登入
    next_url = request.full_path if request.query_string else request.path
    return redirect(url_for("login", next=next_url))

# ===== 下載檔案（需要登入） =====
@app.route("/downloads/<path:filename>")
def download_file(filename):
    downloads_dir = os.path.join(app.root_path, "downloads")
    return send_from_directory(downloads_dir, filename, as_attachment=True)

# ===== Agent 回報（公開） =====
@app.route("/report", methods=["POST"])
def report():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify(ok=False, error="Invalid JSON"), 400

    # 相容舊鍵名
    if isinstance(data, dict) and "name" in data and "ip" in data:
        data = {
            "client_id": data.get("name") or "",
            "ip_internal": data.get("ip") or "",
            "ip_public": data.get("public_ip") or "",
            "user_agent": request.headers.get("User-Agent", "agent/mini-1.0"),
            "vector": "SIMPLE-TEST",
            "payload": data.get("os") or ""
        }

    now = datetime.utcnow()
    client_id   = (data.get("client_id") or "").strip()[:128]
    ip_public   = (data.get("ip_public") or request.headers.get("X-Forwarded-For") or request.remote_addr or "").strip()[:64]
    ip_internal = (data.get("ip_internal") or "").strip()[:64]
    user_agent  = (data.get("user_agent") or request.headers.get("User-Agent") or "").strip()[:256]
    vector      = (data.get("vector") or "UNKNOWN").strip()[:64]

    payload_raw = data.get("payload", "")
    if isinstance(payload_raw, (dict, list)):
        payload_raw = json.dumps(payload_raw, ensure_ascii=False)
    payload_bytes = str(payload_raw).encode("utf-8", errors="ignore")
    payload_hash  = sha256(payload_bytes).hexdigest()
    payload_len   = len(payload_bytes)
    sample        = payload_bytes[:1024].decode("utf-8", errors="replace")

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO events (ts, client_id, ip_public, ip_internal, user_agent, vector,
                                payload_sha256, payload_len, payload_sample, missed)
            VALUES (:ts, :client_id, :ip_public, :ip_internal, :user_agent, :vector,
                    :payload_sha256, :payload_len, :payload_sample, 1)
        """), {
            "ts": now, "client_id": client_id, "ip_public": ip_public, "ip_internal": ip_internal,
            "user_agent": user_agent, "vector": vector, "payload_sha256": payload_hash,
            "payload_len": payload_len, "payload_sample": sample
        })

    return jsonify(ok=True, ts=now.isoformat()+"Z", payload_sha256=payload_hash)

# ===== 首頁（需登入） =====
@app.route("/")
def index():
    return render_template("index.html")

# ===== 檢視頁：GET 需登入；POST 允許匿名上報特徵封包 =====
@app.route("/view", methods=["GET", "POST"])
def view():
    if request.method == "POST":
        try:
            raw = request.get_data(cache=False, as_text=False) or b""
            ua  = request.headers.get("User-Agent", "")
            app.logger.info(f"/view POST received: len={len(raw)}, UA={ua}")
        except Exception:
            pass
        return "OK", 200

    vector = (request.args.get("vector") or "").strip()
    client = (request.args.get("client") or "").strip()

    query = """
        SELECT id, ts, client_id, ip_public, ip_internal, vector, payload_sha256, payload_len
        FROM events WHERE 1=1
    """
    params = {}
    if vector:
        query += " AND vector = :vector"; params["vector"] = vector
    if client:
        query += " AND client_id = :client"; params["client"] = client
    query += " ORDER BY ts DESC LIMIT 500"

    with engine.begin() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return render_template("view.html", rows=rows, vector=vector, client=client)

# ===== 近24小時統計（需登入） =====
@app.route("/api/stats")
def api_stats():
    since = datetime.utcnow() - timedelta(days=1)
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT vector, COUNT(*) AS cnt
            FROM events
            WHERE ts >= :since
            GROUP BY vector
            ORDER BY cnt DESC
        """), {"since": since}).mappings().all()
    return jsonify(rows=[dict(r) for r in rows])

# ===== 清除事件（需登入） =====
@app.route("/clear", methods=["POST"])
def clear():
    scope  = request.form.get("scope", "all")          # all / filtered
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

    return redirect(url_for("view", vector=vector if scope=="filtered" else None,
                                   client=client if scope=="filtered" else None))

# ===== 使用者：註冊 / 登入 / 登出（公開頁面） =====
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", error=None)

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
    # 註冊成功後帶回 next（若存在）
    next_url = request.args.get("next") or request.form.get("next") or url_for("index")
    return redirect(next_url)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    if not username or not password:
        return render_template("login.html", error="請輸入帳號與密碼")

    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, username, password_hash
            FROM users
            WHERE username = :u
        """), {"u": username}).mappings().first()

    if not row or not check_password_hash(row["password_hash"], password):
        return render_template("login.html", error="帳號或密碼錯誤")

    session["user"] = row["username"]
    # 登入成功後帶回 next（若存在）
    next_url = request.args.get("next") or request.form.get("next") or url_for("index")
    return redirect(next_url)

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# ===== 健康檢查（公開） =====
@app.route("/health")
def health():
    return jsonify(status="ok")

# ===== 主程式 =====
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5050")))
