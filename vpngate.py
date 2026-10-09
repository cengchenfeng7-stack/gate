def check_one(node, session):
    url = WORKER_CHECK_URL + "vpn:vpn@" + f"{node['host']}:{node['port']}"

    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"

    try:
        r = session.get(
            url,
            timeout=CHECK_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (gate-checker)"},
            verify=False,
        )
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            print(f"❌ HTTP 错误 -> {url[:80]} | 状态码: {r.status_code} | 响应: {r.text[:200]}")
            return out

        try:
            j = r.json()
        except ValueError as e:
            out["error"] = f"Invalid JSON from worker: {e}"
            out["worker_error"] = True
            print(f"❌ JSON 解析错误 -> {url[:80]} | 响应: {r.text[:200]}")
            return out

        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        print(f"❌ 异常错误 -> {url[:80]} | 错误: {str(exc)[:150]}")
        return out
