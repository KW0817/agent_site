from flask import Flask, request, render_template, send_from_directory, jsonify
import mysql.connector
from datetime import datetime, timedelta
import os

app = Flask(__name__)

db_config = {
    "host": "interchange.proxy.rlwy.net",
    "port": 10000,
    "user": "root",
    "password": "HoqhkLPJdxgzSCjaUCnrYdQvwOeaFxXm",
    "database": "railway"
}

@app.route("/templates/1")
def agent_detail():
    return render_template("1.html")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory('downloads', filename, as_attachment=True)

@app.route('/report', methods=['POST'])
def report():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON data received"}), 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        timestamp = (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        sql = """
            INSERT INTO agent_data (timestamp, hostname, local_ip, public_ip, os_info)
            VALUES (%s, %s, %s, %s, %s)
        """
        values = (
            timestamp,
            data.get("name"),
            data.get("ip"),
            data.get("public_ip"),
            data.get("os_info")  
        )
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ 資料寫入成功")
        return jsonify({"status": "success"}), 200

    except Exception as e:
        print("❌ 資料寫入失敗:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))

