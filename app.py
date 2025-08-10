from flask import Flask, request, render_template, send_from_directory, jsonify
from datetime import datetime, timedelta
from hashlib import sha256
from sqlalchemy import create_engine, text
import os, json

app = Flask(__name__)

# 資料庫：預設 SQLite；要改 MySQL 時設定 DATABASE_URL 環境變數
# MySQL 範例：mysql+pymysql://user:pass@host:3306/dbname?charset=utf8mb4
DB_URL = os.getenv("DATABASE_URL", "sqlite:///events.db")
engine = create_engine(DB_URL, future=True)

# 建表
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

# 下載檔案
@app.route("/downloads/<path:filename>")
def download_file(filename):
    downloads_dir = os.path.join(app.root_path, "downloads")
    return send_from_directory(downloads_dir, filename, as_attachment=True)

# Agent 回報
@app.route("/report", methods=["POST"])
def report():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify(ok=False, error="Invalid JSON"), 400

    now = datetime.utcnow()
    client_id = (data.get("client_id") or "").strip()[:128]
    ip_public = (data.get("ip_public") or request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:64]
    ip_internal = (data.get("ip_internal") or "").strip()[:64]
    user_agent = (data.get("user_agent") or request.headers.get("User-Agent") or "").strip()[:256]
    vector = (data.get("vector") or "UNKNOWN").strip()[:64]

    payload_raw = data.get("payload", "")
    if isinstance(payload_raw, (dict, list)):
        payload_raw = json.dumps(payload_raw, ensure_ascii=False)
    payload_bytes = str(payload_raw).encode("utf-8", errors="ignore")
    payload_hash = sha256(payload_bytes).hexdigest()
    payload_len = len(payload_bytes)
    sample = payload_bytes[:1024].decode("utf-8", errors="replace")

    missed = 1  # 能送達即視為「漏攔截」

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO events (ts, client_id, ip_public, ip_internal, user_agent, vector,
                                payload_sha256, payload_len, payload_sample, missed)
            VALUES (:ts, :client_id, :ip_public, :ip_internal, :user_agent, :vector,
                    :payload_sha256, :payload_len, :payload_sample, :missed)
        """), {
            "ts": now, "client_id": client_id, "ip_public": ip_public, "ip_internal": ip_internal,
            "user_agent": user_agent, "vector": vector, "payload_sha256": payload_hash,
            "payload_len": payload_len, "payload_sample": sample, "missed": missed
        })

    return jsonify(ok=True, ts=now.isoformat()+"Z", payload_sha256=payload_hash)

# 首頁與檢視
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/view")
def view():
    vector = (request.args.get("vector") or "").strip()
    client = (request.args.get("client") or "").strip()
    q = "SELECT id, ts, client_id, ip_public, ip_internal, vector, payload_sha256, payload_len FROM events WHERE 1=1"
    p = {}
    if vector:
        q += " AND vector = :vector"; p["vector"] = vector
    if client:
        q += " AND client_id = :client"; p["client"] = client
    q += " ORDER BY ts DESC LIMIT 500"
    with engine.begin() as conn:
        rows = conn.execute(text(q), p).mappings().all()
    return render_template("view.html", rows=rows, vector=vector, client=client)

# 近24小時統計
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
