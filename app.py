# app.py
from flask import Flask, request, render_template, send_from_directory, jsonify
from datetime import datetime, timedelta
from hashlib import sha256
from sqlalchemy import create_engine, text
import os, json

app = Flask(__name__)

# ======================
# 資料庫設定
# 預設 SQLite；要用 MySQL/PG，設定環境變數 DATABASE_URL 即可：
#   MySQL: mysql+pymysql://user:pass@host:3306/db?charset=utf8mb4
#   Postgres: postgresql+psycopg2://user:pass@host:5432/db
# ======================
DB_URL = os.getenv("DATABASE_URL", "sqlite:///events.db")
engine = create_engine(DB_URL, future=True)

# 建表（若不存在）
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

# ==============
# 靜態下載
# ==============
@app.route("/downloads/<path:filename>")
def download_file(filename):
    downloads_dir = os.path.join(app.root_path, "downloads")
    return send_from_directory(downloads_dir, filename, as_attachment=True)

# ==============
# Agent 回報端點
# ==============
@app.route("/report", methods=["POST"])
def report():
    # 解析 JSON
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify(ok=False, error="Invalid JSON"), 400

    # 兼容你舊版的鍵名（name/ip/public_ip/os...）
    if isinstance(data, dict) and "name" in data and "ip" in data:
        data = {
            "client_id": data.get("name") or "",
            "ip_internal": data.get("ip") or "",
            "ip_public": data.get("public_ip") or "",
            "user_agent": request.headers.get("User-Agent", "agent/mini-1.0"),
            "vector": "SIMPLE-TEST",
            "payload": data.get("os") or ""
        }

    # 正式欄位
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

    missed = 1  # 能送達就表示對方環境未攔截

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO events (
                ts, client_id, ip_public, ip_internal, user_agent, vector,
                payload_sha256, payload_len, payload_sample, missed
            ) VALUES (
                :ts, :client_id, :ip_public, :ip_internal, :user_agent, :vector,
                :payload_sha256, :payload_len, :payload_sample, :missed
            )
        """), {
            "ts": now, "client_id": client_id, "ip_public": ip_public, "ip_internal": ip_internal,
            "user_agent": user_agent, "vector": vector, "payload_sha256": payload_hash,
            "payload_len": payload_len, "payload_sample": sample, "missed": missed
        })

    return jsonify(ok=True, ts=now.isoformat()+"Z", payload_sha256=payload_hash)

# ==============
# 首頁
# ==============
@app.route("/")
def index():
    return render_template("index.html")

# ==========================
# 檢視頁（GET+POST 皆可）
# - GET：顯示事件清單（可用 ?vector=&client= 篩選）
# - POST：給 Agent/WinINet 發特徵封包用，回 200
# ==========================
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
        query += " AND vector = :vector"
        params["vector"] = vector
    if client:
        query += " AND client_id = :client"
        params["client"] = client

    query += " ORDER BY ts DESC LIMIT 500"

    with engine.begin() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return render_template("view.html", rows=rows, vector=vector, client=client)

# ==========================
# 近 24 小時統計（依向量）
# ==========================
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

# 健康檢查
@app.route("/health")
def health():
    return jsonify(status="ok")

# 本機測試時可直接啟動（Render 會用 gunicorn server:app）
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))
    app.run(host="0.0.0.0", port=port)
