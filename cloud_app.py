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
import base64, http.server, json, os, secrets, sys, threading, time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from router_tool import PAGE, VERSION, redact   # نفس الواجهة (ملف واحد للـ UI)

PORT = int(os.environ.get("PORT", "8080"))
AGENT_KEY = (os.environ.get("AGENT_KEY") or "").strip()
DASH_PASS = (os.environ.get("DASH_PASS") or "").strip()
DASH_USER = (os.environ.get("DASH_USER") or "admin").strip()
CMD_TIMEOUT = float(os.environ.get("CMD_TIMEOUT", "75"))

ST = {
    "token": secrets.token_urlsafe(18),
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
        if not DASH_PASS:
            return True
        want = "Basic " + base64.b64encode(("%s:%s" % (DASH_USER, DASH_PASS)).encode()).decode()
        if self.headers.get("Authorization") == want:
            return True
        self._send(401, "مطلوب باسورد اللوحة", "text/plain; charset=utf-8",
                   {"WWW-Authenticate": 'Basic realm="router"'})
        return False

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
        if p == "/agent/poll":
            if not self._agent_ok():
                return self._send(403, {"ok": False, "error": "agent key"})
            return self._send(200, self._agent_poll())
        if not self._authed():
            return
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
        if p == "/agent/poll":
            if not self._agent_ok():
                return self._send(403, {"ok": False, "error": "agent key"})
            return self._send(200, self._agent_poll())
        if p == "/agent/result":
            if not self._agent_ok():
                return self._send(403, {"ok": False, "error": "agent key"})
            return self._send(200, self._agent_result())
        if not self._authed():
            return
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