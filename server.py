from app import app
import os

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))   # 本機5050；雲端會給 PORT
    app.run(host="0.0.0.0", port=port)
