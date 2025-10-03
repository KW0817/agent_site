from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from hashlib import sha256
from sqlalchemy import create_engine, text
import os, json, re

# ===== App init =====
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("SECRET_KEY", "change-me-please")

# ===== 資料庫設定 =====
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_PATH = os.path.join(BASE_DIR, "events.db")
DEFAULT_SQLITE_URL = f"sqlite:///{SQLITE_PATH}"
DB_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)

engine = create_engine(DB_URL, future=True, pool_pre_ping=True)

# 啟動時建立資料表（events, users）
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

# -------- helper functions ----------
def safe_text_preview(b: bytes, limit=1024) -> str:
    if not b:
        return ""
    try:
        s = b.decode("utf-8", errors="replace")
        s = s.replace("\r", "\\r").replace("\n", "\\n")
        return (s[:limit] + "…") if len(s) > limit else s
    except Exception:
        r = repr(b)
        return (r[:limit] + "…") if len(r) > limit else r

# zero-pad id to 6 digits
def uid_from_user_id(user_id: int) -> str:
    try:
        return f"{int(user_id):06d}"
    except Exception:
        return "000000"

# ------------------------------------

# ===== 入口頁 =====
@app.route("/")
def home():
    return render_template("home.html")

# ===== 首頁 =====
@app.route("/index")
def index():
    return render_template("index.html")

# ===== 專題動機 =====
@app.route("/motivation")
def motivation():
    return render_template("motivation.html")

# ===== 下載 agent：回傳帶 UID 的檔名（需登入） =====
@app.route("/download_agent")
def download_agent():
    if not session.get("user"):
        return redirect(url_for("login", next=request.path, msg="請先登入才能下載"))

    with engine.begin() as conn:
        user_row = conn.execute(text("SELECT id FROM users WHERE username = :u"), {"u": session["user"]}).mappings().first()
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

# ===== Agent 回報（公開） =====
@app.route("/report", methods=["POST"])
def report():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify(ok=False, error="Invalid JSON"), 400

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
    sample        = safe_text_preview(payload_bytes, limit=1024)

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

# ===== 檢視事件清單 =====
@app.route("/view", methods=["GET", "POST"])
def view():
    if request.method == "POST":
        try:
            raw_bytes = request.get_data(cache=False, as_text=False) or b""
            ua = request.headers.get("User-Agent", "") or ""
            parsed_json = None
            try:
                parsed_json = json.loads(raw_bytes.decode('utf-8', errors='ignore'))
            except Exception:
                parsed_json = None

            now = datetime.utcnow()
            if isinstance(parsed_json, dict):
                client_id   = (parsed_json.get("client_id") or parsed_json.get("name") or "").strip()[:128]
                ip_public   = (parsed_json.get("ip_public") or parsed_json.get("public_ip") or request.headers.get("X-Forwarded-For") or request.remote_addr or "").strip()[:64]
                ip_internal = (parsed_json.get("ip_internal") or parsed_json.get("ip") or "").strip()[:64]
                user_agent  = (parsed_json.get("user_agent") or ua)[:256]
                vector      = (parsed_json.get("vector") or "JSON")[:64]
                payload_field = parsed_json.get("payload") or parsed_json.get("os") or parsed_json.get("data") or ""
                if isinstance(payload_field, (dict, list)):
                    payload_field = json.dumps(payload_field, ensure_ascii=False)
                payload_bytes = str(payload_field).encode("utf-8", errors="ignore")
            else:
                payload_bytes = raw_bytes
                client_id = request.args.get("client") or ""
                ip_public = request.headers.get("X-Forwarded-For") or request.remote_addr or ""
                ip_internal = ""
                user_agent = ua or "unknown"
                vector = "RAW"

            payload_hash = sha256(payload_bytes).hexdigest()
            payload_len = len(payload_bytes)
            sample = safe_text_preview(payload_bytes, limit=1024)

            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO events (ts, client_id, ip_public, ip_internal, user_agent, vector,
                                        payload_sha256, payload_len, payload_sample, missed)
                    VALUES (:ts, :client_id, :ip_public, :ip_internal, :user_agent, :vector,
                            :payload_sha256, :payload_len, :payload_sample, 1)
                """), {
                    "ts": now,
                    "client_id": (client_id or "")[:128],
                    "ip_public": (ip_public or "")[:64],
                    "ip_internal": (ip_internal or "")[:64],
                    "user_agent": (user_agent or "")[:256],
                    "vector": (vector or "RAW")[:64],
                    "payload_sha256": payload_hash,
                    "payload_len": payload_len,
                    "payload_sample": sample
                })
            app.logger.info(f"/view POST stored: client={client_id} vec={vector} len={payload_len}")
        except Exception as e:
            app.logger.exception("Error handling /view POST: %s", e)
        return "OK", 200

    if not session.get("user"):
        return redirect(url_for("login", next=request.full_path or request.path, msg="請先登入才能查看事件清單"))

    username = session["user"]
    vector = (request.args.get("vector") or "").strip()

    if username == "jie":
        query = """
            SELECT id, ts, client_id, ip_public, ip_internal, vector, payload_sha256, payload_len, payload_sample
            FROM events
            ORDER BY ts DESC LIMIT 500
        """
        params = {}
    else:
        with engine.begin() as conn:
            user_row = conn.execute(text("SELECT id FROM users WHERE username = :u"), {"u": username}).mappings().first()
        uid = uid_from_user_id(user_row["id"]) if user_row else username
        query = """
            SELECT id, ts, client_id, ip_public, ip_internal, vector, payload_sha256, payload_len, payload_sample
            FROM events
            WHERE client_id = :client
        """
        params = {"client": uid}
        if vector:
            query += " AND vector = :vector"
            params["vector"] = vector
        query += " ORDER BY ts DESC LIMIT 500"

    with engine.begin() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return render_template("view.html", rows=rows, vector=vector, client=username)

# ===== 近24小時統計 =====
@app.route("/api/stats")
def api_stats():
    if not session.get("user"):
        return jsonify(error="請先登入"), 401

    username = session["user"]
    since = datetime.utcnow() - timedelta(days=1)

    with engine.begin() as conn:
        if username == "jie":
            rows = conn.execute(text("""
                SELECT vector, COUNT(*) AS cnt
                FROM events
                WHERE ts >= :since
                GROUP BY vector
                ORDER BY cnt DESC
            """), {"since": since}).mappings().all()
        else:
            user_row = conn.execute(text("SELECT id FROM users WHERE username = :u"), {"u": username}).mappings().first()
            uid = uid_from_user_id(user_row["id"]) if user_row else username
            rows = conn.execute(text("""
                SELECT vector, COUNT(*) AS cnt
                FROM events
                WHERE ts >= :since AND client_id = :client
                GROUP BY vector
                ORDER BY cnt DESC
            """), {"since": since, "client": uid}).mappings().all()

    return jsonify(rows=[dict(r) for r in rows])

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

# ===== 註冊 =====
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

# ===== 登入 =====
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        msg = request.args.get("msg")
        return render_template("login.html", error=msg)

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
    return redirect(url_for("index"))

# ===== 登出 =====
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# ===== 管理員查看所有使用者 =====
@app.route("/users")
def users_list():
    if not session.get("user"):
        return redirect(url_for("login", msg="請先登入"))
    if session["user"] != "jie":
        return "你沒有權限查看這個頁面", 403

    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, username, password_hash, created_at
            FROM users
            ORDER BY created_at DESC
        """)).mappings().all()

    return render_template("users.html", users=rows)

# ===== 健康檢查 =====
@app.route("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
