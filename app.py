@app.route("/view", methods=["GET", "POST"])
def view():
    # 供 Agent/WinINet 送特徵封包用：回 200 OK
    if request.method == "POST":
        try:
            raw = request.get_data(cache=False, as_text=False) or b""
            ua = request.headers.get("User-Agent", "")
            app.logger.info(f"/view POST received: len={len(raw)}, UA={ua}")
        except Exception:
            pass
        return "OK", 200

    # ===== 以下維持原本 GET 顯示清單頁 =====
    vector = (request.args.get("vector") or "").strip()
    client = (request.args.get("client") or "").strip()

    query = "SELECT id, ts, client_id, ip_public, ip_internal, vector, payload_sha256, payload_len FROM events WHERE 1=1"
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
