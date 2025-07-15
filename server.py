from flask import Flask, request, jsonify
import pymysql
from datetime import datetime
import pytz

app = Flask(__name__)

db_config = {
    "host": "interchange.proxy.rlwy.net",
    "port": 3306,
    "user": "root",
    "password": "HoqhkLPJdxgzSCjaUCnrYdQvwOeaFxXm",
    "database": "railway"
}

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    hostname = data.get("name", "unknown")
    local_ip = data.get("ip", "unknown")
    public_ip = data.get("public_ip", "unknown")
    os_info = data.get("os", "unknown")

    taiwan_time = datetime.now(pytz.timezone("Asia/Taipei")).strftime('%Y-%m-%d %H:%M:%S')

    try:
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        sql = "INSERT INTO agent_data(hostname, local_ip, public_ip, os_info, created_at) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(sql, (hostname, local_ip, public_ip, os_info, taiwan_time))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
