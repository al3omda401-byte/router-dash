# -*- coding: utf-8 -*-
"""
الوكيل المحلي للوحة الراوتر.

بيشتغل على جهاز المالك (اللي على شبكة الراوتر) وبيوصل بالسحابة (cloud_app.py)
وياخد منها الأوامر، ينفّذها على الراوتر محليًا، ويرجّع النتيجة + الحالة اللحظية.

التشغيل:
    set CLOUD_URL=https://xxx.onrender.com
    set AGENT_KEY=xxxxx
    python router_agent.py
"""
import json, os, socket, sys, threading, time, traceback, urllib.error, urllib.request
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import router_tool as rt

CLOUD = (os.environ.get("CLOUD_URL") or "").rstrip("/")
KEY = (os.environ.get("AGENT_KEY") or "").strip()
INTERVAL = float(os.environ.get("AGENT_INTERVAL", "1.2"))
STATUS_EVERY = float(os.environ.get("STATUS_EVERY", "8"))
FILE_EVERY = 12

cfg = rt.load_config()
state = rt.State(cfg)
STATUS = {"ts": 0.0, "data": None}
STATUS_LK = threading.Lock()
SENT_SEQ = [0]
LAST_FILE = [0.0]
_POLL = [0]


def log(msg):
    print("%s %s" % (datetime.now().strftime("%H:%M:%S"), msg), flush=True)


def auth_info():
    return {"username": cfg["username"], "has_password": bool(cfg["password"]),
            "logged_in": bool(state.router.logged_in), "router_ok": bool(state.router_ok)}


def build_status():
    """نفس شكل /api/status بالظبط (عشان الواجهة ماتفرقش)."""
    base = {"ts": rt.now_str(), "me_ips": sorted(rt.local_ips(cfg["ip"])),
            "me_macs": sorted(rt.own_macs(cfg["ip"])), "auth": auth_info()}
    if not cfg["password"]:
        base.update({"router_ok": False, "error": "لازم تدخل يوزر وباسورد الراوتر الأول.",
                     "tech": "no credentials", "devices": [], "macfilter": None,
                     "counts": {"online": 0, "offline": 0, "total": 0, "blocked": 0}, "public_ip": ""})
        return base
    with state.lock:
        try:
            devs = state.router.devices()
            mf = None
            try:
                mf = state.router.macfilter()
                mf.pop("token", None)
            except rt.RouterError as e:
                rt.event("warn", "قراءة قايمة الحظر فشلت", e.tech)
            online = sum(1 for d in devs if d["status"] == "Online")
            state.router_ok = True
            base.update({"router_ok": True, "devices": devs, "macfilter": mf,
                         "counts": {"online": online, "offline": len(devs) - online,
                                    "total": len(devs), "blocked": len((mf or {}).get("entries") or [])}})
        except rt.RouterError as e:
            state.router_ok = False
            base.update({"router_ok": False, "error": e.ar, "tech": e.tech, "devices": [],
                         "counts": {"online": 0, "offline": 0, "total": 0, "blocked": 0}})
        except Exception as e:
            state.router_ok = False
            rt.log(traceback.format_exc())
            base.update({"router_ok": False, "error": "خطأ غير متوقع في البرنامج.", "tech": repr(e), "devices": []})
    base["public_ip"] = rt.public_ip()
    return base


def status_loop():
    while True:
        try:
            d = build_status()
            with STATUS_LK:
                STATUS["data"] = d
                STATUS["ts"] = time.time()
        except Exception:
            rt.log(traceback.format_exc())
        time.sleep(STATUS_EVERY)


def events_tail():
    with rt.EVENT_LOCK:
        evs = list(rt.EVENTS[-250:])
        seq = rt.EVENT_SEQ[0]
    _POLL[0] += 1
    # كل 25 دورة بنبعت القايمة كاملة تاني (لو السحابة اتعملت لها restart بترجع فاضية)
    if seq == SENT_SEQ[0] and _POLL[0] % 25 != 0:
        return None
    SENT_SEQ[0] = seq
    return evs


def file_tail():
    if time.time() - LAST_FILE[0] < 40:
        return None
    LAST_FILE[0] = time.time()
    try:
        with open(rt.LOG_PATH, encoding="utf-8", errors="replace") as f:
            return [x.rstrip("\n") for x in f.readlines()[-160:]]
    except OSError:
        return []


def http_json(url, body=None, headers=None, timeout=40):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", "User-Agent": "router-agent/%s" % rt.VERSION}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


# ---------------------------------------------------------------- commands
def cmd_login(d):
    user = str(d.get("username") or "").strip() or "admin"
    pw = str(d.get("password") or "")
    if not pw:
        return {"ok": False, "error": "اكتب باسورد الراوتر."}
    cfg["username"] = user
    cfg["password"] = pw
    with state.lock:
        state.router = rt.Router(cfg)
        try:
            where = state.router.login()
        except rt.RouterError as e:
            state.router_ok = False
            rt.event("err", "فشل تسجيل الدخول للراوتر", "%s | %s" % (e.ar, e.tech or "-"))
            cfg["password"] = ""
            rt.save_credentials(cfg)
            return {"ok": False, "error": e.ar, "tech": e.tech}
        state.router_ok = True
    saved = d.get("save") and rt.save_credentials(cfg)
    rt.event("ok", "تم تسجيل الدخول للراوتر", "%s | %s" % (user, where))
    return {"ok": True, "message": "تم تسجيل الدخول للراوتر" + (" واتحفظت البيانات." if saved else "."),
            "auth": auth_info()}


def cmd_logout(d):
    with state.lock:
        state.router.logged_in = False
        state.router._close()
        state.router.jar = {}
        state.router_ok = False
    if d.get("forget"):
        cfg["password"] = ""
        rt.save_credentials(cfg)
    rt.event("info", "تم تسجيل الخروج من الراوتر")
    return {"ok": True, "message": "تم تسجيل الخروج.", "auth": auth_info()}


def cmd_action(name, d):
    r = state.router
    mac = str(d.get("mac", "")).lower()
    if name in ("block", "unblock") and not rt.MAC_RE.match(mac):
        return {"ok": False, "error": "عنوان MAC غير صالح."}
    if name in ("block", "unblock") and not cfg["password"]:
        return {"ok": False, "error": "لازم تسجّل الدخول للراوتر الأول."}
    t0 = time.time()
    with state.lock:
        try:
            old_ip = ""
            if name == "redial":
                old_ip = rt.public_ip()
                msg = r.redial()
            elif name == "reboot":
                msg = r.reboot()
            elif name == "block":
                me_ips = rt.local_ips(cfg["ip"]) | set()
                mine = rt.own_macs(cfg["ip"])
                dev = next((x for x in r.devices() if x["mac"] == mac), None)
                if ((dev and dev["ip"] in me_ips) or mac in mine) and not d.get("confirm_self"):
                    return {"ok": False, "error": "ده جهازك إنت. لو حظرته هتفصل عن الراوتر.",
                            "tech": "self-block needs confirmation"}
                msg = r.block(mac, str(d.get("name", "")))
            elif name == "unblock":
                msg = r.unblock(mac)
            elif name == "enable_filter":
                msg = r.enable_blacklist()
            else:
                return {"ok": False, "error": "أمر غير معروف."}
            return {"ok": True, "message": msg, "old_ip": old_ip, "secs": round(time.time() - t0, 1)}
        except rt.RouterError as e:
            rt.event("err", "%s — فشل" % rt.ACTION_LABEL.get(name, name), "%s | %s" % (e.ar, e.tech or "-"))
            return {"ok": False, "error": e.ar, "tech": e.tech}
        except Exception as e:
            rt.log(traceback.format_exc())
            return {"ok": False, "error": "خطأ غير متوقع في البرنامج.", "tech": repr(e)}


def run_command(c):
    name = c.get("name")
    d = c.get("data") or {}
    log("cmd %s #%s" % (name, c.get("id")))
    try:
        if name == "login":
            return cmd_login(d)
        if name == "logout":
            return cmd_logout(d)
        return cmd_action(name, d)
    except Exception as e:
        rt.log(traceback.format_exc())
        return {"ok": False, "error": "خطأ غير متوقع في الوكيل.", "tech": repr(e)}


# ---------------------------------------------------------------- main loop
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if not CLOUD or not KEY:
        print("لازم CLOUD_URL و AGENT_KEY.")
        return 2
    log("agent -> %s (كل %.1s)" % (CLOUD, INTERVAL))
    threading.Thread(target=rt.speed_sampler, args=(state,), daemon=True).start()
    threading.Thread(target=status_loop, daemon=True).start()
    threading.Thread(target=rt.watchdog, args=(state,), daemon=True).start()
    fails = 0
    while True:
        with STATUS_LK:
            snap = STATUS["data"]
        body = {"host": socket.gethostname(), "speed": rt.speed_snapshot()}
        if snap:
            body["status"] = snap
        evs = events_tail()
        if evs is not None:
            body["events"] = evs
        ft = file_tail()
        if ft is not None:
            body["file"] = ft
        try:
            resp = http_json(CLOUD + "/agent/poll", body, {"X-Agent-Key": KEY}, timeout=30)
            fails = 0
            for c in (resp.get("commands") or []):
                res = run_command(c)
                try:
                    http_json(CLOUD + "/agent/result", {"id": c.get("id"), "result": res},
                              {"X-Agent-Key": KEY}, timeout=25)
                except Exception as e:
                    log("result post fail: %r" % e)
        except urllib.error.HTTPError as e:
            fails += 1
            if fails in (1, 5) or fails % 50 == 0:
                log("cloud HTTP %s (محاولة %d)" % (e.code, fails))
            time.sleep(3)
            continue
        except Exception as e:
            fails += 1
            if fails in (1, 5) or fails % 50 == 0:
                log("cloud unreachable: %r (محاولة %d)" % (e, fails))
            time.sleep(3)
            continue
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        sys.exit(0)