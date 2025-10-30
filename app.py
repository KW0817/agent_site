# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, render_template_string
from sqlalchemy import create_engine, text
from datetime import datetime
from hashlib import sha256
import os, json

app = Flask(__name__)

# ===== 資料庫設定 =====
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_PATH = os.path.join(BASE_DIR, "events.db")
DEFAULT_SQLITE_URL = f"sqlite:///{SQLITE_PATH}"
DB_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)
engine = create_engine(DB_URL, future=True, pool_pre_ping=True)

# ===== 自動建立資料表 =====
def ensure_table():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP,
            client_id TEXT,
            ip_public TEXT,
            ip_internal TEXT,
            user_agent TEXT,
            vector TEXT,
            payload_sha256 TEXT,
            payload_len INTEGER,
            payload_sample TEXT,
            missed INTEGER
        )
        """))
ensure_table()

# ===== /report：接收中繼站或 Agent =====
@app.route("/report", methods=["POST"])
def report():
    try:
        raw = request.get_data(as_text=True)
        print("\n=== Received /report ===")
        print(raw[:500])  # 印前500字
        data = json.loads(raw)
    except Exception as e:
        return jsonify(ok=False, error=f"JSON decode failed: {e}"), 400

    now = datetime.utcnow()
    ip_public = request.headers.get("X-Forwarded-For") or request.remote_addr
    ua = request.headers.get("User-Agent", "")

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

    payload_raw = g("payload", "os", "data", default=None)
    if payload_raw:
        payload_bytes = str(payload_raw).encode("utf-8", errors="ignore")
        row["payload_sha256"] = sha256(payload_bytes).hexdigest()
        row["payload_len"] = len(payload_bytes)
        sample = str(payload_raw)
        if len(sample) > 80:
            sample = sample[:77] + "..."
        row["payload_sample"] = sample

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO events (ts, client_id, ip_public, ip_internal, user_agent,
                                    vector, payload_sha256, payload_len, payload_sample, missed)
                VALUES (:ts, :client_id, :ip_public, :ip_internal, :user_agent,
                        :vector, :payload_sha256, :payload_len, :payload_sample, :missed)
            """), row)
        print(f"[Render] ✅ Insert success: {row['client_id']} {row['ip_public']}")
    except Exception as e:
        print("[Render Error] DB insert failed:", e)
        return jsonify(ok=False, error=str(e)), 500

    return jsonify(ok=True, ts=now.isoformat() + "Z")

# ===== /view：顯示事件 =====
@app.route("/view")
def view():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT * FROM events ORDER BY ts DESC LIMIT 500")).mappings().all()

    html = """
    <!DOCTYPE html>
    <html lang="zh-Hant">
    <head>
      <meta charset="UTF-8">
      <title>漏攔截事件清單</title>
      <style>
        body{margin:0;padding:24px;font-family:Arial,sans-serif;background:#f7f7f7;}
        .wrap{max-width:1100px;margin:0 auto;background:#fff;border-radius:12px;
              padding:20px 24px;box-shadow:0 0 10px rgba(0,0,0,.06);}
        table{width:100%;border-collapse:collapse;margin-top:12px;}
        th,td{border-bottom:1px solid #eee;padding:8px 6px;text-align:left;font-size:14px;}
        th{background:#fafafa;}
      </style>
    </head>
    <body>
    <div class="wrap">
      <h2>漏攔截事件清單</h2>
      <table>
        <thead>
          <tr>
            <th>時間(UTC)</th><th>Client ID</th><th>Public IP</th>
            <th>Internal IP</th><th>User-Agent</th><th>Vector</th>
            <th>Payload Hash</th><th>Length</th>
          </tr>
        </thead>
        <tbody>
          {% for r in rows %}
          <tr>
            <td>{{ r.ts }}</td>
            <td>{{ r.client_id }}</td>
            <td>{{ r.ip_public }}</td>
            <td>{{ r.ip_internal }}</td>
            <td>{{ r.user_agent }}</td>
            <td>{{ r.vector or '' }}</td>
            <td>{{ r.payload_sha256 or '' }}</td>
            <td>{{ r.payload_len or '' }}</td>
          </tr>
          {% else %}
          <tr><td colspan="8">尚無資料</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows)

# ===== Debug routes =====
@app.route("/debug_events")
def debug_events():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT COUNT(*) AS n FROM events")).mappings().first()
        return f"事件總數: {rows['n']}"

@app.route("/debug_tables")
def debug_tables():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';")).fetchall()
    return "<br>".join([r[0] for r in rows]) or "無資料表"

@app.route("/init_db")
def init_db():
    ensure_table()
    return "資料表 events 已建立或已存在"

# ===== 啟動 Flask =====
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
