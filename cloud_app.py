# -*- coding: utf-8 -*-
"""
نسخة السحابة (Render) من لوحة الراوتر.

الفكرة: الراوتر على شبكة البيت، فالسيرفر السحابي مايقدرش يوصله.
- السحابة بتخدم نفس الواجهة (PAGE) وبتخزّن آخر حالة وصلت من الوكيل المحلي.
- وكيل محلي (router_agent.py) على جهاز المالك بيسحب الأوامر من هنا وينفّذها
  على الراوتر ويرجّع النتيجة.
- مفيش أي باسورد راوتر على السحابة: بيانات الدخول بتفضل على جهاز المالك بس.

المتغيرات (Render):
  PORT            — بيديه Render
  AGENT_KEY       — مفتاح سري بين السحابة والوكيل (إجباري)
  DASH_PASS       — باسورد اللوحة (Basic auth). إجباري للرابط العام
  DASH_USER       — افتراضي admin
"""
import hashlib, hmac, http.server, json, os, secrets, sys, threading, time
from datetime import datetime
from urllib.parse import parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from router_tool import PAGE, VERSION, redact   # نفس الواجهة (ملف واحد للـ UI)

PORT = int(os.environ.get("PORT", "8080"))
AGENT_KEY = (os.environ.get("AGENT_KEY") or "").strip()
DASH_PASS = (os.environ.get("DASH_PASS") or "").strip()
DASH_USER = (os.environ.get("DASH_USER") or "admin").strip()
CMD_TIMEOUT = float(os.environ.get("CMD_TIMEOUT", "75"))
SECRET = (AGENT_KEY + "|" + DASH_PASS + "|rd").encode()
COOKIE = "rd_auth"

ST = {
    # توكن ثابت (مشتق من السر) عشان الـ restart ميكسرش صفحة مفتوحة
    "token": hmac.new(SECRET, b"ui-token", hashlib.sha256).hexdigest()[:24],
    "snapshot": None, "snap_ts": 0.0,
    "speed": {"ok": False, "stale": True, "rx": 0, "tx": 0, "hist": []}, "speed_ts": 0.0,
    "events": [], "file": [],
    "cmds": [], "results": {}, "seq": 0,
    "agent_ts": 0.0, "agent_host": "",
}
LK = threading.Lock()
RESULT_EV = threading.Condition(LK)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def agent_alive():
    return (time.time() - ST["agent_ts"]) < 12 if ST["agent_ts"] else False


def offline_status():
    return {"router_ok": False, "ts": now_str(),
            "error": "الوكيل المحلي مش متصل بالسحابة. اتأكد إن جهازك مفتوح وبيشغّل router_agent.py.",
            "tech": "agent offline", "devices": [], "counts": {"online": 0, "total": 0, "blocked": 0},
            "me_ips": [], "me_macs": [], "auth": {"username": "", "has_password": False,
                                                 "logged_in": False, "router_ok": False},
            "public_ip": "", "agent": {"online": False}}


def get_status():
    with LK:
        snap = ST["snapshot"]
        age = round(time.time() - ST["snap_ts"], 1) if ST["snap_ts"] else None
        alive = agent_alive()
    if not snap:
        d = offline_status()
        return d
    d = dict(snap)
    d["agent"] = {"online": alive, "age": age, "host": ST["agent_host"]}
    if not alive:
        d["router_ok"] = False
        d["error"] = "الوكيل المحلي اتأخر في الرد — آخر تحديث قبل %s ثانية." % age
        d["tech"] = "agent stale"
    return d


def get_speed():
    with LK:
        d = dict(ST["speed"] or {})
        ts = ST["speed_ts"]
    d["age"] = round(time.time() - ts, 1) if ts else None
    d["stale"] = (not ts) or (time.time() - ts) > 12
    d["agent"] = agent_alive()
    return d


def enqueue(name, data):
    with LK:
        ST["seq"] += 1
        cid = ST["seq"]
        ST["cmds"].append({"id": cid, "name": name, "data": data or {}})
    return cid


def wait_result(cid, timeout=CMD_TIMEOUT):
    end = time.time() + timeout
    with LK:
        while cid not in ST["results"]:
            left = end - time.time()
            if left <= 0:
                return None
            RESULT_EV.wait(min(left, 1.0))
        return ST["results"].pop(cid)


LOGIN_HTML = r"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
<title>دخول لوحة الراوتر</title>
<style>
:root{--bg:#070b12;--card:#101828;--line:#1e2b44;--line2:#2b3d5e;--tx:#e9eff9;--mut:#8395b5;--mut2:#5c6f90;
--acc:#4f8cff;--bad:#ff5d6e;--ok:#22c97b}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;color:var(--tx);
background:radial-gradient(900px 420px at 80% -10%,rgba(79,140,255,.16),transparent 60%),
           radial-gradient(700px 340px at 10% 0%,rgba(34,201,123,.07),transparent 58%),var(--bg);
font:14px/1.6 "Segoe UI",Tahoma,Arial,sans-serif}
.card{width:min(430px,96vw);background:linear-gradient(180deg,#101828,#0d1524);border:1px solid var(--line);
border-radius:18px;padding:26px 24px;box-shadow:0 20px 60px rgba(0,0,0,.55)}
.logo{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;margin:0 auto 14px;
background:linear-gradient(145deg,#2f6ae0,#59a0ff);box-shadow:0 8px 22px rgba(47,106,224,.45)}
h1{margin:0 0 4px;font-size:18px;text-align:center}
p.sub{margin:0 0 18px;text-align:center;color:var(--mut2);font-size:12.5px}
label{display:block;color:var(--mut);font-size:12.5px;margin-bottom:7px}
input{width:100%;font:inherit;background:#0b1424;color:var(--tx);border:1px solid var(--line);
border-radius:12px;padding:12px 14px;letter-spacing:1px}
input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.18)}
button{width:100%;font:inherit;font-weight:600;color:#fff;border:0;border-radius:12px;padding:12px;
margin-top:14px;cursor:pointer;background:linear-gradient(180deg,#3a72d8,#2a5cc0);box-shadow:0 6px 18px rgba(47,106,224,.35)}
button:hover{filter:brightness(1.08)}
.err{background:#2a1220;border:1px solid #8a3a48;color:#ffb3bd;border-radius:11px;padding:10px 12px;
font-size:12.5px;margin-bottom:14px}
.note{margin-top:16px;padding-top:14px;border-top:1px solid var(--line);color:var(--mut2);font-size:12px;line-height:1.8}
.note b{color:var(--mut)}
.note code{font-family:Consolas,monospace;direction:ltr;unicode-bidi:isolate;color:#bcd6ff}
</style></head><body>
<div class="card">
  <div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.9"
      stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="13.5" width="19" height="7" rx="2.2"/>
      <path d="M6.5 17h.01M10 17h.01"/><path d="M12 10V6.6"/><path d="M8.4 7.4a6 6 0 0 1 7.2 0"/>
      <path d="M6.1 4.6a9.5 9.5 0 0 1 11.8 0"/></svg></div>
  <h1>لوحة تحكم الراوتر</h1>
  <p class="sub">ده باسورد اللوحة (حماية الموقع) — مش باسورد الراوتر</p>
  __ERR__
  <form method="POST" action="/login">
    <label for="p">باسورد اللوحة</label>
    <input id="p" name="pass" type="password" autocomplete="current-password" placeholder="••••••••••••" autofocus>
    <button type="submit">دخول</button>
  </form>
  <div class="note">
    <b>ملاحظة:</b> باسورد الراوتر (admin) بتكتبه <b>جوّه اللوحة</b> في صندوق «الدخول للراوتر» —
    ومحفوظ بالفعل فمش هيتطلب منك.<br>
    اسم المستخدم هنا ثابت: <code>admin</code>
  </div>
</div></body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    server_version = "RouterCloud"

    def log_message(self, fmt, *a):
        pass

    # ---------- base ----------
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(b)
        except Exception:
            pass

    def _authed(self):
        """جلسة اللوحة بكوكي موقّع (بدل نافذة Basic auth اللي بتلخبط)."""
        if not DASH_PASS:
            return True
        sig = hmac.new(SECRET, b"admin", hashlib.sha256).hexdigest()[:40]
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == COOKIE and v.strip() == sig:
                    return True
        return False

    def _login_page(self, err=False):
        html = LOGIN_HTML.replace("__ERR__", '<div class="err">الباسورد غلط. جرب تاني.</div>' if err else "")
        self._send(200, html, "text/html; charset=utf-8")

    def _do_login(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        pw = (parse_qs(raw).get("pass") or [""])[0]
        if DASH_PASS and hmac.compare_digest(pw.strip(), DASH_PASS):
            sig = hmac.new(SECRET, b"admin", hashlib.sha256).hexdigest()[:40]
            self._send(303, "", "text/plain", {
                "Location": "/",
                "Set-Cookie": "%s=%s; Path=/; HttpOnly; Max-Age=2592000; SameSite=Lax" % (COOKIE, sig)})
        else:
            self._login_page(True)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    # ---------- agent ----------
    def _agent_ok(self):
        return bool(AGENT_KEY) and self.headers.get("X-Agent-Key") == AGENT_KEY

    def _agent_poll(self):
        data = self._body()
        with LK:
            ST["agent_ts"] = time.time()
            ST["agent_host"] = str(data.get("host") or "")[:40]
            if data.get("status"):
                ST["snapshot"] = data["status"]
                ST["snap_ts"] = time.time()
            if data.get("speed"):
                ST["speed"] = data["speed"]
                ST["speed_ts"] = time.time()
            if data.get("events") is not None:
                ST["events"] = data["events"][-250:]
            if data.get("file") is not None:
                ST["file"] = data["file"][-160:]
            cmds = ST["cmds"]
            ST["cmds"] = []
        return {"ok": True, "commands": cmds, "token_ok": True}

    def _agent_result(self):
        data = self._body()
        cid = data.get("id")
        with LK:
            ST["agent_ts"] = time.time()
            if cid is not None:
                ST["results"][cid] = data.get("result") or {"ok": False, "error": "رد فاضي"}
                if len(ST["results"]) > 60:
                    for k in list(ST["results"])[:20]:
                        ST["results"].pop(k, None)
            RESULT_EV.notify_all()
        return {"ok": True}

    # ---------- http ----------
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/healthz":
            return self._send(200, {"ok": True, "agent": agent_alive(), "v": VERSION})
        if p == "/login":
            return self._login_page()
        if p == "/agent/poll":
            if not self._agent_ok():
                return self._send(403, {"ok": False, "error": "agent key"})
            return self._send(200, self._agent_poll())
        if not self._authed():
            return self._send(303, "", "text/plain", {"Location": "/login"})
        if p in ("/", "/index.html"):
            return self._send(200, PAGE.replace("__TOKEN__", ST["token"]).replace("__VERSION__", VERSION),
                              "text/html; charset=utf-8")
        if self.headers.get("X-Token") != ST["token"]:
            return self._send(403, {"ok": False, "error": "token"})
        if p.startswith("/api/ping"):
            d = get_status()
            return self._send(200, {"router_ok": d.get("router_ok"), "public_ip": d.get("public_ip") or "",
                                    "ts": now_str(), "agent": d.get("agent")})
        if p.startswith("/api/status"):
            return self._send(200, get_status())
        if p.startswith("/api/speed"):
            return self._send(200, get_speed())
        if p.startswith("/api/log"):
            with LK:
                evs = list(ST["events"])
                fl = list(ST["file"]) if "file=1" in self.path else None
            out = {"seq": len(evs), "events": evs}
            if fl is not None:
                out["file"] = [redact(x) for x in fl]
            return self._send(200, out)
        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        if p == "/login":
            return self._do_login()
        if p == "/agent/poll":
            if not self._agent_ok():
                return self._send(403, {"ok": False, "error": "agent key"})
            return self._send(200, self._agent_poll())
        if p == "/agent/result":
            if not self._agent_ok():
                return self._send(403, {"ok": False, "error": "agent key"})
            return self._send(200, self._agent_result())
        if not self._authed():
            return self._send(303, "", "text/plain", {"Location": "/login"})
        if self.headers.get("X-Token") != ST["token"]:
            return self._send(403, {"ok": False, "error": "token"})
        if not p.startswith("/api/"):
            return self._send(404, {"ok": False, "error": "not found"})
        if not agent_alive():
            return self._send(200, {"ok": False,
                                    "error": "الوكيل المحلي مش متصل. شغّل router_agent.py على جهازك.",
                                    "tech": "agent offline"})
        name = p.rsplit("/", 1)[-1]
        data = self._body()
        cid = enqueue(name, data)
        res = wait_result(cid)
        if res is None:
            return self._send(200, {"ok": False, "error": "الوكيل المحلي اتأخر في الرد.",
                                    "tech": "command timeout after %ss" % int(CMD_TIMEOUT)})
        return self._send(200, res)


class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if not AGENT_KEY:
        print("!! AGENT_KEY مش متظبط — الوكيل مش هيقدر يتصل (وبنولّده عشوائي للاختبار المحلي)")
    print("RouterCloud v%s on 0.0.0.0:%d  (agent=%s, auth=%s)" %
          (VERSION, PORT, "on" if AGENT_KEY else "off", "on" if DASH_PASS else "off"), flush=True)
    srv = Srv(("0.0.0.0", PORT), H)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()