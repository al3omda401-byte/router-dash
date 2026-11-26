# -*- coding: utf-8 -*-
"""
لوحة تحكم راوتر Huawei DN8245V-56 (WE).  بايثون فقط، من غير أي مكتبات خارجية.
تشغيل:  python router_tool.py            (يفتح اللوحة)
        python router_tool.py --selftest (فحص الاتصال وتسجيل الدخول)
        python router_tool.py --diagnose (يكتب ملف diagnostics.txt)
غير مجرّب على الراوتر الحقيقي: اتبنى على طريقة عمل واجهة هواوي المعروفة.
"""
import base64, configparser, getpass, http.client, http.server, ipaddress, json, os, re
import secrets, socket, ssl, subprocess, sys, threading, time, traceback, urllib.request, webbrowser
from datetime import datetime

VERSION = "2.0"
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.ini")
LOG_PATH = os.path.join(HERE, "router_tool.log")
DIAG_PATH = os.path.join(HERE, "diagnostics.txt")
LOG_LOCK = threading.Lock()


def log(msg):
    line = "%s %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    with LOG_LOCK:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


# ---------------------------------------------------------------- سجل الأحداث (للّوحة)
EVENTS = []
EVENT_SEQ = [0]
EVENT_LAST = [("", 0.0)]
EVENT_LOCK = threading.Lock()


def event(level, text, tech=""):
    """يسجّل حدث في الذاكرة (للّوحة) + في ملف السجل، مع منع تكرار نفس الرسالة."""
    now = time.time()
    with EVENT_LOCK:
        lvl, last_ts = EVENT_LAST[0]
        if lvl == level and last_ts and now - last_ts < 90 and EVENTS and EVENTS[-1]["text"] == text:
            return
        EVENT_SEQ[0] += 1
        EVENTS.append({
            "id": EVENT_SEQ[0],
            "ts": datetime.now().strftime("%H:%M:%S"),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "level": level,
            "text": text,
            "tech": tech or "",
        })
        del EVENTS[:-400]
        EVENT_LAST[0] = (level, now)
    log(("[%s] %s" % (level, text)) + ((" | " + tech) if tech else ""))


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- قياس السرعة اللحظية
SPEED = {
    "ok": False, "stale": True, "rx": 0.0, "tx": 0.0,
    "rx_raw": 0.0, "tx_raw": 0.0,
    "rx_total": 0, "tx_total": 0,
    "domain": "", "ts": 0.0, "last_ok": 0.0, "err": "", "samples": 0,
    "hist": [], "line": {}, "line_ts": 0.0,
}
SPEED_LOCK = threading.Lock()
SPEED_INTERVAL = 2.0
LINE_EVERY = 15


def speed_snapshot():
    with SPEED_LOCK:
        d = dict(SPEED)
        d["age"] = round(time.time() - d["last_ok"], 1) if d["last_ok"] else None
        d["stale"] = (time.time() - d["last_ok"]) > SPEED_INTERVAL * 4 if d["last_ok"] else True
        return d


def speed_sampler(state, interval=SPEED_INTERVAL, stop=None):
    """يقرا عدّادات الراوتر كل ثانيتين ويحسب السرعة الفعلية (من غير ما يسحب أي سرعة).

    ملاحظة مهمة: أي فشل في القراءة مايصفّرش القيم — بيسيب آخر قراءة صحيحة
    ويعلّمها "قديمة" عشان اللوحة ماتبانش صفر بالغلط.
    """
    prev = None
    rounds = 0
    while True:
        if stop is not None and stop.is_set():
            return
        if state.cfg["password"]:
            with state.lock:
                try:
                    rx, tx, _tot, dom = state.router.wan_stats()
                    err = ""
                except RouterError as e:
                    rx = tx = 0
                    dom = ""
                    err = e.ar
                except Exception as e:
                    rx = tx = 0
                    dom = ""
                    err = repr(e)
                    log(traceback.format_exc())
                line = None
                if rounds % LINE_EVERY == 0:
                    try:
                        line = state.router.dsl_line()
                    except RouterError:
                        line = None
                    except Exception:
                        line = None
            now = time.time()
            rounds += 1
            if err:
                with SPEED_LOCK:
                    SPEED["ok"] = False
                    SPEED["err"] = err
            else:
                raw_rx = raw_tx = 0.0
                if prev:
                    dt = now - prev[0]
                    if dt > 0 and rx >= prev[1] and tx >= prev[2]:
                        raw_rx = (rx - prev[1]) / dt
                        raw_tx = (tx - prev[2]) / dt
                prev = (now, rx, tx)
                with SPEED_LOCK:
                    a = 0.5 if SPEED["samples"] else 1.0
                    SPEED["rx"] = SPEED["rx"] * (1 - a) + raw_rx * a
                    SPEED["tx"] = SPEED["tx"] * (1 - a) + raw_tx * a
                    SPEED["rx_raw"], SPEED["tx_raw"] = raw_rx, raw_tx
                    SPEED["rx_total"], SPEED["tx_total"] = rx, tx
                    SPEED["domain"] = dom
                    SPEED["ok"] = True
                    SPEED["err"] = ""
                    SPEED["ts"] = now
                    SPEED["last_ok"] = now
                    SPEED["samples"] += 1
                    SPEED["hist"].append([round(SPEED["rx"]), round(SPEED["tx"])])
                    del SPEED["hist"][:-90]
                    if line:
                        SPEED["line"] = line
                        SPEED["line_ts"] = now
        if stop is None:
            time.sleep(interval)
        elif stop.wait(interval):
            return


class RouterError(Exception):
    """خطأ برسالة عربية جاهزة للعرض."""
    def __init__(self, ar, tech=""):
        Exception.__init__(self, ar)
        self.ar = ar
        self.tech = tech


# ---------------------------------------------------------------- config
def load_config():
    cp = configparser.ConfigParser(interpolation=None)
    if not os.path.exists(CONFIG_PATH):
        raise RouterError("ملف config.ini مش موجود جنب البرنامج.")
    cp.read(CONFIG_PATH, encoding="utf-8-sig")
    s = cp["router"] if cp.has_section("router") else {}
    d = cp["dashboard"] if cp.has_section("dashboard") else {}
    cfg = {
        "ip": (s.get("ip", "192.168.1.1") or "192.168.1.1").strip(),
        "username": (s.get("username", "admin") or "admin").strip(),
        "password": s.get("password", "") or "",
        "scheme": (s.get("scheme", "auto") or "auto").strip().lower(),
        "port": (s.get("port", "") or "").strip(),
        "language": (s.get("language", "english") or "english").strip(),
        "host": (d.get("host", "127.0.0.1") or "127.0.0.1").strip(),
        "dash_port": int((d.get("port", "8080") or "8080").strip()),
        "dash_password": d.get("password", "") or "",
        "open_browser": (d.get("open_browser", "yes") or "yes").strip().lower() in ("yes", "true", "1"),
    }
    env_pw = os.environ.get("ROUTER_PASSWORD")
    if env_pw:
        cfg["password"] = env_pw
    return cfg


def ensure_password(cfg):
    if not cfg["password"]:
        print("الباسورد مش مكتوب في config.ini. اكتبه هنا (مش هيظهر على الشاشة ومش هيتحفظ):")
        cfg["password"] = getpass.getpass("Password: ")
    if not cfg["password"]:
        raise RouterError("لازم باسورد الراوتر. اكتبه في config.ini أو لما البرنامج يسأل.")


def save_credentials(cfg):
    """يحفظ اليوزر والباسورد في config.ini — تعديل سطري بس، من غير ما يلمس باقي الملف."""
    try:
        with open(CONFIG_PATH, encoding="utf-8-sig") as f:
            text = f.read()
    except OSError:
        return False

    def put(txt, key, val):
        pat = re.compile(r"(?mi)^([ \t]*%s[ \t]*=[ \t]*).*$" % re.escape(key))
        if pat.search(txt):
            return pat.sub(lambda m: m.group(1) + val, txt, count=1)
        return txt

    before = text
    text = put(text, "username", cfg["username"])
    text = put(text, "password", cfg["password"])
    if not re.search(r"(?mi)^[ \t]*password[ \t]*=", text):
        text = re.sub(r"(?mi)^([ \t]*username[ \t]*=.*)$", lambda m: m.group(1) + "\npassword = " + cfg["password"], text, count=1)
    if text == before:
        return False
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    except OSError:
        return False
    return True


def watchdog(state, interval=20):
    """يخلّي الاتصال بالراوتر حي: يجدّد الجلسة، وأول ما الراوتر/النت يرجع يتوصّل لوحده."""
    fails = 0
    while True:
        time.sleep(interval)
        if not state.cfg["password"]:
            continue
        with state.lock:
            r = state.router
            up = False
            try:
                r.connect()
                up = True
                if not r.logged_in:
                    r.login()
            except RouterError:
                up = False
                r.logged_in = False
            except Exception:
                up = False
                log(traceback.format_exc())
            state.router_ok = up
        if up:
            if fails:
                event("ok", "الاتصال بالراوتر رجع تلقائيًا بعد انقطاع")
            fails = 0
        else:
            fails += 1
            if fails in (2, 5) or fails % 25 == 0:
                event("warn", "مستني الراوتر/النت يرجع… (محاولة %d)" % fails,
                      "الجلسة هتتجدّد لوحدها أول ما يرجع")


# ---------------------------------------------------------------- parsing
QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
HEX_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")


def unhex(s):
    s = HEX_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return s.replace('\\"', '"').replace("\\\\", "\\")


def extract_token(html):
    pats = [
        r'id=["\']hwonttoken["\'][^>]*value=["\']([0-9a-zA-Z]+)["\']',
        r'value=["\']([0-9a-zA-Z]+)["\'][^>]*id=["\']hwonttoken["\']',
        r'name=["\']onttoken["\'][^>]*value=["\']([0-9a-zA-Z]+)["\']',
        r'value=["\']([0-9a-zA-Z]+)["\'][^>]*name=["\']onttoken["\']',
        r'name=["\']x\.X_HW_Token["\'][^>]*value=["\']([0-9a-zA-Z]+)["\']',
        r'hwonttoken[^>]{0,200}?value=["\']([0-9a-zA-Z]+)["\']',
    ]
    for p in pats:
        m = re.search(p, html)
        if m:
            return m.group(1)
    return ""


def looks_like_login_page(text):
    return ("txt_Username" in text) or ("txt_Password" in text)


# الراوتر بيرجّع 403 + صفحة "Waiting..." فيها pageName='/' لما الجلسة تنتهي.
EXPIRED_RE = re.compile(r"pageName\s*=\s*['\"]/['\"]|top\.location\.replace\(\s*['\"]/['\"]\s*\)")


def looks_like_expired(text):
    text = text or ""
    if looks_like_login_page(text):
        return True
    return bool(EXPIRED_RE.search(text))


def session_invalid(status, text):
    """الجلسة انتهت أو محتاجة تسجيل دخول تاني."""
    return status in (401, 403) or looks_like_expired(text)



_OUI = None
TYPE_HINTS = [
    (("apple",), "آيفون/ماك/أبل"), (("samsung",), "سامسونج (موبايل/تلفزيون)"),
    (("xiaomi", "redmi", "huawei", "honor", "oppo", "vivo", "oneplus", "realme", "motorola", "nokia", "google", "infinix", "tecno", "transsion"), "موبايل"),
    (("intel", "dell", "hewlett", "hp ", "lenovo", "asus", "acer", "msi", "micro-star", "gigabyte", "realtek", "liteon", "azurewave", "murata", "foxconn", "hon hai", "wistron", "quanta", "compal", "microsoft", "killer", "qualcomm", "mediatek", "ralink", "broadcom"), "كمبيوتر/لابتوب"),
    (("lg ", "sony", "tcl", "hisense", "roku", "vizio", "panasonic", "philips"), "تلفزيون/ترفيه"),
    (("espressif", "tuya", "shenzhen", "hangzhou", "sonoff", "ezviz", "hikvision", "dahua", "amazon", "ring"), "جهاز ذكي/كاميرا"),
    (("tp-link", "tplink", "d-link", "netgear", "zte", "tenda", "mikrotik", "ubiquiti", "altobeam", "cisco", "linksys"), "شبكة/راوتر/أكسس بوينت"),
    (("sony interactive", "nintendo", "microsoft xbox", "valve"), "جيمنج"),
]


def load_oui():
    global _OUI
    if _OUI is None:
        _OUI = {}
        try:
            with open(os.path.join(HERE, "oui.txt"), encoding="utf-8") as f:
                for line in f:
                    k, _, v = line.strip().partition("|")
                    if k:
                        _OUI[k] = v
        except OSError:
            pass
    return _OUI


def vendor_info(mac):
    """بيرجّع (الشركة, النوع المتوقع, هل MAC عشوائي)"""
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return "", "", False
    random_mac = bool(first & 2)
    if random_mac:
        return "", "موبايل (MAC عشوائي للخصوصية)", True
    v = load_oui().get(mac.replace(":", "")[:6].upper(), "")
    t = ""
    low = v.lower()
    for keys, label in TYPE_HINTS:
        if any(k in low for k in keys):
            t = label
            break
    return v, t, False


def local_ips(router_ip):
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((router_ip, 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            ips.add(ip)
    except OSError:
        pass
    return {i for i in ips if not i.startswith("127.")}


def own_mac():
    try:
        import uuid
        n = uuid.getnode()
        if (n >> 40) & 1:
            return ""
        return ":".join("%02x" % ((n >> s) & 255) for s in range(40, -1, -8))
    except Exception:
        return ""


ARP_RE = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")
_NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_ARP_CACHE = {"ts": 0.0, "value": []}
_MAC_CACHE = {"ts": 0.0, "value": []}


def arp_pairs():
    """(IP, MAC) من جدول ARP بتاع النظام — متكاشة 60 ثانية ومن غير نافذة."""
    now = time.time()
    if _ARP_CACHE["ts"] and now - _ARP_CACHE["ts"] < 60:
        return list(_ARP_CACHE["value"])
    out = []
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8,
                             encoding="utf-8", errors="replace", creationflags=_NO_WIN)
        text = (res.stdout or "") + "\n" + (res.stderr or "")
    except Exception:
        return out
    for ip, mac in ARP_RE.findall(text):
        out.append((ip, mac.replace("-", ":").lower()))
    _ARP_CACHE["ts"] = time.time()
    _ARP_CACHE["value"] = out
    return out


def local_mac_list():
    """كل MACs كروت الشبكة على الجهاز (ويندوز: getmac). متكاشة + من غير نافذة."""
    now = time.time()
    if _MAC_CACHE["ts"] and now - _MAC_CACHE["ts"] < 60:
        return set(_MAC_CACHE["value"])
    out = set()
    try:
        if os.name == "nt":
            res = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=8,
                                 encoding="utf-8", errors="replace", creationflags=_NO_WIN)
            for m in re.findall(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", res.stdout or ""):
                out.add(m.replace("-", ":").lower())
    except Exception:
        pass
    _MAC_CACHE["ts"] = time.time()
    _MAC_CACHE["value"] = sorted(out)
    return out


def own_macs(router_ip=None):
    """كل عناوين MAC بتاعة أجهزتنا (مش uuid لوحده — ده بيغلط على ويندوز)."""
    macs = set(local_mac_list())
    m = own_mac()
    if m:
        macs.add(m.lower())
    try:
        ips = local_ips(router_ip) if router_ip else set()
    except Exception:
        ips = set()
    for ip, mac in arp_pairs():
        if ip in ips:
            macs.add(mac)
    return macs


def is_private_ip(s):
    try:
        return ipaddress.ip_address(s).is_private
    except ValueError:
        return False


def split_args(s):
    out, cur, q, esc = [], [], None, False
    for ch in s:
        if q:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            cur.append(ch)
        elif ch == ",":
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    res = []
    for a in out:
        if len(a) >= 2 and a[0] in "\"'" and a[-1] == a[0]:
            a = unhex(a[1:-1])
        res.append(a)
    return res


def balanced_calls(text, name_re=r"\w+"):
    """كل new X(...) مع الأقواس المتوازنة. بيرجّع [(الاسم, النص الداخلي)]"""
    out = []
    for m in re.finditer(r"new\s+(%s)\s*\(" % name_re, text):
        i, depth, q, esc = m.end(), 1, None, False
        while i < len(text) and depth:
            ch = text[i]
            if q:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == q:
                    q = None
            elif ch in "\"'":
                q = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        out.append((m.group(1), text[m.end(): i - 1]))
    return out


# ترتيب الحقول الحقيقي في فيرمواير DN8245V-56 لو تعريف الكلاس مش موجود في الصفحة
DEFAULT_USERDEV = ["Domain", "IpAddr", "MacAddr", "Port", "IpType", "DevType", "DevStatus", "PortType",
                   "Time", "HostName", "IPv4Enabled", "IPv6Enabled", "DeviceType", "UserDevAlias",
                   "UserSpecifiedDeviceType", "LeaseTimeRemaining"]


def parse_userdev(text):
    """يقرأ صفحات الأجهزة: function X(...){this.MacAddr=...} + new X(...)."""
    props = {}
    for m in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)\s*\{(.*?)\}", text, re.S):
        body = m.group(3)
        if "this.MacAddr" not in body:
            continue
        params = [p.strip() for p in m.group(2).split(",")]
        pm = {}
        for a, b in re.findall(r"this\.(\w+)\s*=\s*(\w+)", body):
            if b in params:
                pm[a] = params.index(b)
        props[m.group(1)] = pm
    rows = []
    for name, argstr in balanced_calls(text):
        a = split_args(argstr)
        macs = [x for x in a if MAC_RE.match(x)]
        if not macs:
            continue
        pm = props.get(name)
        if not pm:
            if len(a) < 8 or any("new " in x for x in a[:4]):
                continue
            pm = {k: i for i, k in enumerate(DEFAULT_USERDEV)}

        def g(k):
            i = pm.get(k)
            return a[i] if i is not None and i < len(a) else ""
        mac = g("MacAddr").lower().replace("-", ":")
        if not MAC_RE.match(mac):
            mac = macs[0].lower().replace("-", ":")
        ip = g("IpAddr") or next((x for x in a if is_v4(x)), "")
        host, alias = g("HostName"), g("UserDevAlias")
        nm = alias if alias not in ("", "--") else (host if host not in ("", "--") else "")
        st = g("DevStatus") or next((x for x in a if x.lower() in ("online", "offline")), "")
        rows.append({"name": nm, "type": g("DevType") or g("PortType"), "ip": ip, "mac": mac,
                     "status": st or "Online", "iface": g("PortType"), "raw_len": len(a)})
    return rows


def parse_devices(text):
    rows = parse_userdev(text)
    if rows:
        return _merge(rows)
    return _merge(_parse_old(text))


def _merge(rows):
    by_mac = {}
    for r in rows:
        key = r["mac"] or r["name"]
        cur = by_mac.get(key)
        if cur is None or (r["ip"] and not cur["ip"] and is_v4(r["ip"])) or (cur["ip"] and not is_v4(cur["ip"]) and is_v4(r["ip"])):
            by_mac[key] = r
    for v in by_mac.values():
        if not v["name"]:
            v["name"] = v["ip"] or v["mac"]
    return list(by_mac.values())


def is_v4(s):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s or ""))


def _parse_old(text):
    rows = []
    for call in re.findall(r"stUserDevInfoPTVDF\(([^)]*)\)", text):
        args = [unhex(a) for a in QUOTED_RE.findall(call)]
        if len(args) < 4:
            continue
        mac = next((a for a in args if MAC_RE.match(a)), "")
        ip = next((a for a in args if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", a)), "")
        status = next((a for a in args if a.lower() in ("online", "offline")), "")
        name = args[0]
        rows.append({
            "name": name, "type": args[1] if len(args) > 1 else "", "ip": ip,
            "mac": mac.lower().replace("-", ":"), "status": status,
            "iface": args[6] if len(args) > 6 else "", "raw_len": len(args),
        })
    return rows


# ---------------------------------------------------------------- router client
class Router:
    """جلسة واحدة على اتصال TCP واحد (توكن تسجيل الدخول مربوط بالاتصال)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.conn = None
        self.scheme = None
        self.jar = {}
        self.logged_in = False
        self._last_login = 0.0
        self._login_hist = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # شهادة الراوتر self-signed، وده طبيعي
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ctx.minimum_version = ssl.TLSVersion.TLSv1
        except Exception:
            pass
        self.ctx = ctx

    # --- low level
    def _candidates(self):
        c = self.cfg
        if c["scheme"] in ("http", "https"):
            port = int(c["port"]) if c["port"] else (443 if c["scheme"] == "https" else 80)
            return [(c["scheme"], port)]
        return [("https", 443), ("http", 80)]

    def _open(self, scheme, port):
        if scheme == "https":
            return http.client.HTTPSConnection(self.cfg["ip"], port, timeout=15, context=self.ctx)
        return http.client.HTTPConnection(self.cfg["ip"], port, timeout=15)

    def _close(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        self.conn = None

    def connect(self):
        """يلاقي أول بورت شغال. بيرجّع وصف الاتصال."""
        self._close()
        last = None
        for scheme, port in self._candidates():
            try:
                s = socket.create_connection((self.cfg["ip"], port), timeout=6)
                s.close()
            except OSError as e:
                last = e
                log("tcp %s:%s فشل: %s" % (self.cfg["ip"], port, e))
                continue
            self.conn = self._open(scheme, port)
            self.scheme = (scheme, port)
            return "%s://%s:%s" % (scheme, self.cfg["ip"], port)
        raise RouterError(
            "مش قادر أوصل للراوتر على %s. اتأكد إن الكمبيوتر متوصل بشبكة الراوتر (واي فاي أو كابل) "
            "وإن العنوان في config.ini صح." % self.cfg["ip"], str(last))

    def _cookie_header(self):
        return "; ".join("%s=%s" % (k, v) for k, v in self.jar.items())

    def request(self, method, path, body=None, headers=None, timeout=None, retry=True):
        if self.conn is None:
            self.connect()
        h = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) router-dashboard/" + VERSION,
            "Accept": "text/html,*/*;q=0.8",
            "Connection": "keep-alive",
            "Referer": "%s://%s/" % (self.scheme[0], self.cfg["ip"]),
        }
        if self.jar:
            h["Cookie"] = self._cookie_header()
        if headers:
            h.update(headers)
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if timeout:
            self.conn.timeout = timeout
            if self.conn.sock:
                self.conn.sock.settimeout(timeout)
        try:
            self.conn.request(method, path, body=data, headers=h)
            resp = self.conn.getresponse()
            raw = resp.read()
        except (http.client.HTTPException, ConnectionError, socket.timeout, ssl.SSLError, OSError) as e:
            self._close()
            if retry and isinstance(e, (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError,
                                        ConnectionAbortedError, ConnectionRefusedError,
                                        http.client.CannotSendRequest, http.client.BadStatusLine)):
                self.connect()
                return self.request(method, path, body, headers, timeout, retry=False)
            raise RouterError("الاتصال بالراوتر انقطع أو اتأخر (%s)." % type(e).__name__, "%s %s: %r" % (method, path, e))
        for sc in resp.msg.get_all("Set-Cookie") or []:
            first = sc.split(";", 1)[0]
            if "=" in first:
                k, v = first.split("=", 1)
                self.jar[k.strip()] = v
        if resp.getheader("Connection", "").lower() == "close":
            self._close()
        text = raw.decode("utf-8", "replace").lstrip("\ufeff")
        return resp.status, resp, text

    # --- login
    def login(self):
        c = self.cfg
        self.logged_in = False
        gap = 1.5 - (time.time() - self._last_login)
        if gap > 0:
            time.sleep(gap)   # ما نضربش الراوتر بمحاولات دخول ورا بعض
        where = self.connect()
        self.jar = {}
        st, _, _ = self.request("GET", "/")
        if st >= 500:
            raise RouterError("صفحة الراوتر الرئيسية رجّعت خطأ %s." % st)
        st, _, tok = self.request("POST", "/asp/GetRandCount.asp", body="")
        if st != 200 or not tok.strip():
            st, _, tok = self.request("GET", "/asp/GetRandCount.asp")
        m = re.search(r"[0-9a-zA-Z]{8,}", tok or "")
        if st != 200 or not m:
            raise RouterError("الراوتر ماردّش بتوكن تسجيل الدخول. ممكن الموديل أو الفيرمواير مختلف. شغّل --diagnose وابعتلي الملف.",
                              "GetRandCount status=%s len=%s" % (st, len(tok or "")))
        token = m.group(0)
        form = "UserName=%s&PassWord=%s&Language=%s&x.X_HW_Token=%s" % (
            urlq(c["username"]), urlq(base64.b64encode(c["password"].encode()).decode()), c["language"], token)
        self.jar = {"Cookie": "body:Language:%s:id=-1" % c["language"]}
        st, _, text = self.request("POST", "/login.cgi", body=form)
        got_sid = "sid=" in self.jar.get("Cookie", "")
        if looks_like_login_page(text) or not got_sid:
            self.jar = {}
            low = text.lower()
            if "lock" in low or "wait" in low or "frequent" in low:
                raise RouterError("الراوتر قفل تسجيل الدخول مؤقتًا بعد محاولات كتير. استنى دقيقتين تلاتة وجرب تاني (ومتحاولش كتير).", "login locked")
            if "already" in low or "another" in low:
                raise RouterError("فيه مستخدم تاني داخل على لوحة الراوتر دلوقتي. اقفل أي صفحة راوتر مفتوحة في متصفح أو موبايل واستنى دقيقتين.", "login: other session")
            raise RouterError("تسجيل الدخول فشل. غالبًا اسم المستخدم أو الباسورد غلط في config.ini، أو الحساب اتقفل مؤقتًا. "
                              "متكررش المحاولة كتير عشان الراوتر ميقفلش عليك.", "login status=%s sid=%s" % (st, got_sid))
        self.logged_in = True
        self._last_login = time.time()
        self._login_hist.append(self._last_login)
        log("login ok via %s" % where)
        return where

    def _ensure(self):
        if not self.logged_in or self.conn is None:
            self.login()

    def _revive(self, why=""):
        """تسجيل دخول جديد بعد انتهاء الجلسة — بحد أقصى 6 محاولات في الدقيقة."""
        now = time.time()
        self._login_hist = [t for t in self._login_hist if now - t < 60]
        if len(self._login_hist) >= 6:
            log("متخطي إعادة الدخول (محاولات كتير في دقيقة) — %s" % why)
            return False
        gap = 3.0 - (now - self._last_login)
        if gap > 0:
            time.sleep(gap)
        self.login()
        return True

    def get(self, path):
        self._ensure()
        st, _, text = self.request("GET", path)
        if session_invalid(st, text):
            event("warn", "الجلسة انتهت — بعيد تسجيل الدخول", "GET %s status=%s" % (path.split("?")[0], st))
            if not self._revive("GET %s" % path):
                raise RouterError("الجلسة بتتقفل فورًا. ممكن مستخدم تاني داخل على لوحة الراوتر.",
                                  "relogin skipped GET %s status=%s" % (path.split("?")[0], st))
            st, _, text = self.request("GET", path)
            if session_invalid(st, text):
                raise RouterError("الجلسة بتتقفل فورًا. ممكن مستخدم تاني داخل على لوحة الراوتر.",
                                  "relogin loop GET %s status=%s" % (path.split("?")[0], st))
        return st, text

    def post(self, path, body, referer=None, timeout=None, token_page=None, extra_headers=None):
        """تنفيذ أمر. لو الجلسة انتهت بنجدّدها ونجيب توكن جديد ونعيد المحاولة مرة واحدة."""
        self._ensure()
        hdr = {"Referer": referer} if referer else None
        if extra_headers:
            hdr = dict(hdr or {})
            hdr.update(extra_headers)
        st, _, text = self.request("POST", path, body=body, headers=hdr, timeout=timeout)
        if not session_invalid(st, text):
            return st, text
        event("warn", "الجلسة انتهت قبل تنفيذ الأمر — بعيد المحاولة", "POST %s status=%s" % (path.split("?")[0], st))
        if self._revive("POST %s" % path) and token_page:
            _, page = self.get(token_page)
            tok = extract_token(page)
            if tok:
                body = re.sub(r"(x\.X_HW_Token=)[^&]*", lambda m: m.group(1) + tok, body)
                st, _, text = self.request("POST", path, body=body, headers=hdr, timeout=timeout)
                if not session_invalid(st, text):
                    return st, text
        raise RouterError("الراوتر رفض الأمر (الجلسة أو التوكن اتغيروا). دوس الزرار تاني — لو اتكرر شغّل --diagnose.",
                          "post %s status=%s" % (path.split("?")[0], st))

    # --- features
    DEV_PATHS = [("POST", "/html/bbsp/common/GetLanUserDevInfo.asp"),
                 ("GET", "/html/bbsp/common/GetLanUserDevInfo.asp"),
                 ("POST", "/html/bbsp/userdevinfo/getuserdevinfo.asp"),
                 ("GET", "/html/bbsp/userdevinfo/userdevinfo.asp")]
    DHCP_PATH = "/html/bbsp/common/GetLanUserDhcpInfo.asp"

    def _fetch(self, method, path):
        self._ensure()
        body = "" if method == "POST" else None
        st, _, text = self.request(method, path, body=body)
        if session_invalid(st, text):
            event("warn", "الجلسة انتهت — بعيد تسجيل الدخول", "%s %s status=%s" % (method, path.split("?")[0], st))
            if self._revive("%s %s" % (method, path)):
                st, _, text = self.request(method, path, body=body)
        return st, text

    def devices(self):
        tried = []
        devs = []
        for round_no in (0, 1):
            for method, path in self.DEV_PATHS:
                st, text = self._fetch(method, path)
                devs = parse_devices(text) if st == 200 else []
                tried.append("%s %s=%s/%d" % (method, path.rsplit("/", 1)[-1], st, len(text)))
                if devs:
                    break
            if devs:
                break
            if round_no == 0:
                event("warn", "قايمة الأجهزة رجعت فاضية — بحاول تاني", " ".join(tried[-4:]))
                try:
                    if not self._revive("devices"):
                        break
                except RouterError:
                    break
        if not devs:
            raise RouterError("مقدرتش أقرا قايمة الأجهزة. شكل الصفحة مختلف عن المتوقع. شغّل --diagnose وابعتلي الملف.",
                              "devices: " + " ".join(tried[-8:]))
        try:
            st, text = self._fetch("POST", self.DHCP_PATH)
            leases = {d["mac"]: d for d in parse_devices(text)} if st == 200 else {}
            lease_names = {}
            if st == 200:
                for _n, argstr in balanced_calls(text):
                    a = split_args(argstr)
                    mac = next((x.lower().replace("-", ":") for x in a if MAC_RE.match(x)), "")
                    if not mac:
                        continue
                    cands = [x for x in a if x and not x.startswith("InternetGatewayDevice.") and not MAC_RE.match(x) and not is_v4(x)
                             and x not in ("--", "Online", "Offline", "DHCP", "Static") and not re.match(r"^[\d:.\-/ ]+$", x)
                             and re.search(r"[A-Za-z\u0600-\u06FF]", x) and len(x) <= 40 and ":" not in x]
                    if cands:
                        lease_names[mac] = cands[0]
            for d in devs:
                if d["name"] in (d["mac"], d["ip"], "") and d["mac"] in lease_names:
                    d["name"] = lease_names[d["mac"]]
            for d in devs:
                l = leases.get(d["mac"])
                if l:
                    if not is_v4(d["ip"]) and is_v4(l["ip"]):
                        d["ip"] = l["ip"]
                    if d["name"] in (d["mac"], d["ip"], "") and l["name"] not in (l["mac"], l["ip"], ""):
                        d["name"] = l["name"]
        except RouterError:
            pass
        for d in devs:
            v, t, rnd = vendor_info(d["mac"])
            d["vendor"] = v
            d["random_mac"] = rnd
            if not d.get("type") or d["type"] in ("--", "Phone", "PC", "LAN", "WIFI"):
                d["type_guess"] = t or d.get("type", "")
            else:
                d["type_guess"] = d["type"]
            if d["name"] in (d["mac"], d["ip"], ""):
                d["name"] = v or ("جهاز (%s)" % d["mac"][-8:])
                d["name_guessed"] = True
        return devs

    MF = "/html/bbsp/macfilter/macfilter.asp"

    def macfilter(self):
        st, text = self.get(self.MF)
        en = re.search(r"var\s+enableFilter\s*=\s*['\"](\d)['\"]", text)
        mode = re.search(r"var\s+Mode\s*=\s*['\"](\d)['\"]", text)
        if not en or not mode:
            raise RouterError("صفحة حظر الأجهزة (MAC Filter) شكلها مختلف عن المتوقع. شغّل --diagnose وابعتلي الملف.",
                              "macfilter parse fail status=%s len=%s" % (st, len(text)))
        entries = []
        for m in re.finditer(r"stMacFilter\s*\(([^)]*)\)", text):
            a = split_args(m.group(1))
            if len(a) >= 2 and MAC_RE.match(a[1] or ""):
                alias = a[2] if len(a) > 2 else ""
                entries.append({"domain": a[0], "mac": a[1].lower().replace("-", ":"),
                                "alias": "" if alias in ("--",) else alias})
        return {"enabled": en.group(1) == "1", "mode": "blacklist" if mode.group(1) == "0" else "whitelist",
                "entries": entries, "token": extract_token(text)}

    def _mf_post(self, kind, dom, data):
        url = "/html/bbsp/macfilter/%s.cgi?x=%s&RequestFile=html/bbsp/macfilter/macfilter.asp" % (kind, dom)
        return self.post(url, data, referer="%s://%s%s" % (self.scheme[0], self.cfg["ip"], self.MF),
                         token_page=self.MF)

    def block(self, mac, alias=""):
        mac = mac.lower()
        s = self.macfilter()
        if s["mode"] != "blacklist":
            raise RouterError("حظر الأجهزة عندك على وضع القايمة البيضاء (whitelist) وده بيأثر على الكل. مش هغيّره من نفسي. غيّره يدويًا من الراوتر لو عايز.")
        if not s["enabled"]:
            raise RouterError("خاصية الحظر مقفولة على الراوتر. فعّلها الأول من الزرار فوق (هتأثر بس على المحظورين).")
        if any(e["mac"] == mac for e in s["entries"]):
            return "الجهاز محظور بالفعل."
        if not s["token"]:
            raise RouterError("مقدرتش ألاقي توكن الأمان في صفحة الحظر. شغّل --diagnose.")
        self._mf_post("add", "InternetGatewayDevice.X_HW_Security.MacFilter",
                      "x.SourceMACAddress=%s&x.DeviceAlias=%s&x.X_HW_Token=%s" % (urlq(mac), urlq(alias[:30]), s["token"]))
        s2 = self.macfilter()
        if not any(e["mac"] == mac for e in s2["entries"]):
            raise RouterError("بعتّ أمر الحظر بس الجهاز مظهرش في قايمة الحظر. الراوتر ممكن رفضه.", "block verify failed")
        event("ok", "تم حظر جهاز", "%s (%s)" % (mac_mask(mac), alias or "-"))
        return "تم حظر الجهاز."

    def unblock(self, mac):
        mac = mac.lower()
        s = self.macfilter()
        e = next((x for x in s["entries"] if x["mac"] == mac), None)
        if not e:
            return "الجهاز مش في قايمة الحظر أصلًا."
        self._mf_post("del", "InternetGatewayDevice.X_HW_Security.MacFilter",
                      "%s=&x.X_HW_Token=%s" % (urlq(e["domain"]), s["token"]))
        s2 = self.macfilter()
        if any(x["mac"] == mac for x in s2["entries"]):
            raise RouterError("بعتّ أمر فك الحظر بس الجهاز لسه في القايمة.", "unblock verify failed")
        event("ok", "تم فك حظر جهاز", mac_mask(mac))
        return "تم فك الحظر."

    def enable_blacklist(self):
        s = self.macfilter()
        if s["mode"] == "whitelist" and s["enabled"]:
            raise RouterError("الراوتر على القايمة البيضاء حاليًا (بيسمح بس للأجهزة المسجلة). مش هغيّره عشان مايفصلش الأجهزة التانية.")
        if s["enabled"] and s["mode"] == "blacklist":
            return "الحظر شغال بالفعل."
        self.post("/html/bbsp/macfilter/set.cgi?x=InternetGatewayDevice.X_HW_Security&RequestFile=html/bbsp/macfilter/macfilter.asp",
                  "x.MacFilterRight=1&x.MacFilterPolicy=0&x.X_HW_Token=%s" % s["token"],
                  referer="%s://%s%s" % (self.scheme[0], self.cfg["ip"], self.MF), token_page=self.MF)
        s2 = self.macfilter()
        if not (s2["enabled"] and s2["mode"] == "blacklist"):
            raise RouterError("حاولت أفعّل الحظر والراوتر مااستجابش.", "enable verify failed")
        event("ok", "تم تفعيل خاصية الحظر (قايمة سوداء)")
        return "تم تفعيل خاصية الحظر (قايمة سوداء، محدش اتحظر لسه)."

    REBOOT_PAGES = ["/html/ssmp/devmanage/e8cdevicemanormal.asp", "/html/ssmp/devmanage/devmanage.asp",
                    "/html/ssmp/devmanage/e8cdevicemanage.asp", "/html/ssmp/devmanage/devicemanage.asp", "/html/ssmp/reset/reset.asp",
                    "/html/ssmp/reboot/reboot.asp", "/html/ssmp/restart/restart.asp"]
    RESET_RE = re.compile(r"set\.cgi\?x=([\w.]*ResetBoard)[^'\"\s]*?RequestFile=([\w/.]+)")

    def scan_menu_paths(self):
        """يدور في index.asp والـ scripts اللي بيحمّلها على أي صفحة html/ssmp أو html/bbsp."""
        paths = []
        try:
            st, idx = self.get("/index.asp")
        except RouterError:
            return paths
        srcs = re.findall(r"src=[\"']([^\"']+\.(?:js|asp))[^\"']*[\"']", idx)
        texts = [idx]
        for s in srcs[:25]:
            if s.startswith("http"):
                continue
            s = s if s.startswith("/") else "/" + s.lstrip("./")
            try:
                st2, t2 = self.get(s)
                if st2 == 200:
                    texts.append(t2)
            except RouterError:
                continue
        for t in texts:
            for p in re.findall(r"html/(?:ssmp|bbsp)/[\w/]+\.asp", t):
                p = "/" + p
                if p not in paths:
                    paths.append(p)
        return paths

    def find_reboot(self):
        """يدور على صفحة الريستارت الحقيقية في الفيرمواير. بيرجّع (مسار الصفحة, توكن, رابط الأمر)."""
        cands = list(self.REBOOT_PAGES)
        for p in self.scan_menu_paths():
            if re.search(r"reset|reboot|restart|devmanage|devicema", p, re.I) and p not in cands:
                cands.append(p)
        seen = []
        for p in cands:
            st, text = self.get(p)
            seen.append("%s=%s" % (p.rsplit("/", 1)[-1], st))
            if st != 200:
                continue
            m = self.RESET_RE.search(text)
            tok = extract_token(text)
            if m and tok:
                dirp = p.rsplit("/", 1)[0]
                return p, tok, "%s/set.cgi?x=%s&RequestFile=%s" % (dirp, m.group(1), m.group(2))
            if "ResetBoard" in text and tok:
                dirp = p.rsplit("/", 1)[0]
                return p, tok, "%s/set.cgi?x=InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard&RequestFile=%s" % (dirp, p.lstrip("/"))
        raise RouterError("مالقيتش صفحة إعادة التشغيل في الراوتر (الفيرمواير مختلف). شغّل --diagnose وابعتلي الملف. "
                          "في الوقت ده ممكن تعمل الريستارت من صفحة الراوتر نفسها.", "reboot pages: " + " ".join(seen))

    def reboot(self):
        path, tok, url = self.find_reboot()
        event("info", "ببعت أمر إعادة تشغيل الراوتر", path)
        try:
            self.post(url, "x.X_HW_Token=%s" % tok,
                      referer="%s://%s%s" % (self.scheme[0], self.cfg["ip"], path), timeout=6, token_page=path)
        except RouterError as e:
            # الراوتر بيقطع الاتصال وهو بيعمل ريستارت، ده نجاح مش فشل
            if "انقطع" not in e.ar:
                raise
        self.logged_in = False
        self._close()
        event("ok", "اتبعت أمر إعادة التشغيل")
        return "اتبعت أمر إعادة التشغيل. الراوتر هيفصل حوالي دقيقتين لحد ما يرجع."

    WAN_PAGE = "/html/bbsp/wan/wan.asp"
    DOM_RE = re.compile(r"InternetGatewayDevice\.WANDevice\.\d+\.WANConnectionDevice\.\d+\.WAN(?:PPP|IP)Connection\.\d+")

    # إعادة تشغيل خط الـ DSL — دي الحاجة اللي زرار "تجديد الـ IP" في الراوتر بيعملها
    DSL_PAGE = "/html/ssmp/deviceinfo/dslinfo.asp"
    DSL_RE = re.compile(r"[\"']([^\"']*resetdsl\.cgi[^\"']*)[\"']")
    WAN_MON = "/html/bbsp/common/wanStateMonitor.asp"
    START_LOAD = "/html/ssmp/common/StartFileLoad.asp"

    # عدّادات البايتات الحقيقية لكل اتصال WAN (من نفس صفحة الراوتر)
    WAN_STATS_PAGE = "/html/bbsp/waninfo/waninfo_tedata.asp"
    DSL_INFO_RE = re.compile(
        r'new\s+DSLInfo\(\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*"(\d+)"\s*,\s*"(\d+)"'
        r'\s*,\s*"(\d+)"\s*,\s*"(\d+)"')
    WANSTAT_RE = re.compile(
        r'new\s+WANStats\(\s*"([^"]+)"\s*,\s*"(\d+)"\s*,\s*"(\d+)"\s*,\s*"(\d+)"\s*,\s*"(\d+)"'
        r'\s*,\s*"(\d+)"\s*,\s*"(\d+)"\s*,\s*"(\d+)"\s*,\s*"(\d+)"\s*\)')

    def wan_stats(self):
        """عدّادات البايتات الحقيقية من الراوتر: (rx_bytes, tx_bytes, domain)."""
        st, text = self.get(self.WAN_STATS_PAGE)
        if st != 200:
            raise RouterError("مقدرتش أقرا عدّادات الترافيك من الراوتر.", "wan stats status=%s" % st)
        body = unhex(text)
        best = None
        for m in self.WANSTAT_RE.finditer(body):
            dom = m.group(1)
            vals = [int(x) for x in m.groups()[1:]]
            tx_b, rx_b = vals[1], vals[5]
            tot = tx_b + rx_b
            if best is None or tot > best[2]:
                best = (rx_b, tx_b, tot, dom)
        if best is None:
            raise RouterError("الفيرمواير مابيرجّعش عدّادات الـ WAN بالشكل المعروف. شغّل --diagnose.",
                              "WANStats parse fail len=%s" % len(body))
        return best

    def wan_state(self):
        """رقم حالة الـ WAN اللحظي اللي الراوتر بيرجّعه (للتشخيص والسجل)."""
        try:
            st, _, text = self.request("GET", "%s?_=%d" % (self.WAN_MON, int(time.time() * 1000)), retry=False,
                                       headers={"X-Requested-With": "XMLHttpRequest"})
            if st == 200:
                m = re.search(r"-?\d+", text or "")
                return m.group(0) if m else ""
        except RouterError:
            pass
        return ""

    def dsl_line(self):
        """سرعة خط الـ DSL الحقيقية (كيلوبت/ث) — مرجع نقارن بيه الاستهلاك اللحظي."""
        st, text = self.get(self.DSL_PAGE)
        if st != 200:
            raise RouterError("مقدرتش أقرا سرعة الخط من صفحة الراوتر.", "dsl line status=%s" % st)
        body = unhex(text)
        best = None
        for m in self.DSL_INFO_RE.finditer(body):
            dom, status, up, down, upmax, downmax = m.groups()
            if best is None or int(down) > best["down_kbps"]:
                best = {"domain": dom, "status": status, "up_kbps": int(up), "down_kbps": int(down),
                        "up_max_kbps": int(upmax), "down_max_kbps": int(downmax)}
        if best is None:
            raise RouterError("الفيرمواير مابيرجّعش سرعة الخط بالشكل المعروف. شغّل --diagnose.",
                              "DSLInfo parse fail len=%s" % len(body))
        return best

    def find_dsl_reset(self):
        """بيرجّع (صفحة معلومات الخط, التوكن, رابط أمر إعادة تشغيل الخط) — كله متقرّي من الفيرمواير."""
        import posixpath
        cands = [self.DSL_PAGE]
        for p in self.scan_menu_paths():
            if re.search(r"dslinfo|deviceinfo|dsl", p, re.I) and p not in cands:
                cands.append(p)
        seen = []
        for p in cands[:8]:
            try:
                st, text = self.get(p)
            except RouterError as e:
                seen.append("%s=%s" % (p.rsplit("/", 1)[-1], e.tech or "err"))
                continue
            seen.append("%s=%s" % (p.rsplit("/", 1)[-1], st))
            if st != 200:
                continue
            tok = extract_token(text)
            m = self.DSL_RE.search(text)
            if not tok or not m:
                continue
            ref = unhex(m.group(1))
            if ref.startswith("/"):
                url = ref
            else:
                url = posixpath.normpath(posixpath.join(p.rsplit("/", 1)[0], ref))
                if not url.startswith("/"):
                    url = "/" + url
            return p, tok, url
        raise RouterError("مالقيتش أمر إعادة تشغيل خط الـ DSL في الفيرمواير. شغّل --diagnose وابعتلي الملف.",
                          "dsl pages: " + " ".join(seen))

    def redial(self):
        """إعادة تشغيل خط الـ DSL (زي زرار الراوتر بالظبط) — الشركة بتدّي IP جديد بعدها غالبًا."""
        page, tok, url = self.find_dsl_reset()
        before = self.wan_state()
        event("info", "إعادة تشغيل خط الـ DSL", "حالة الخط قبل: %s" % (before or "?"))
        try:   # مؤشر "جاري التحميل" اللي بتستخدمه صفحة الراوتر نفسها (مش إلزامي)
            self.request("GET", self.START_LOAD, retry=False)
        except RouterError:
            pass
        ajax = {"X-Requested-With": "XMLHttpRequest", "Origin": "%s://%s" % (self.scheme[0], self.cfg["ip"])}
        self.post(url, "&x.X_HW_Token=%s" % tok,
                  referer="%s://%s%s" % (self.scheme[0], self.cfg["ip"], page),
                  timeout=25, token_page=page, extra_headers=ajax)
        event("ok", "اتبعت أمر إعادة تشغيل الخط (DSL)", url)
        return ("اتبعت أمر إعادة تشغيل خط الـ DSL (نفس اللي بيعمله زرار تجديد الـ IP في الراوتر). "
                "الخط هيفصل دقيقة أو اتنين، وبعدها اللوحة هتقولك الـ IP الجديد.")

    def wan_sources(self):
        """صفحات الـ WAN اللي فيها تعريفات الاتصالات (للتشخيص)."""
        import posixpath
        st, text = self.get(self.WAN_PAGE)
        texts = [("wan.asp", HEX_RE.sub(lambda m: chr(int(m.group(1), 16)), text))]
        refs = re.findall(r"[\"']([\w./-]*[Ww]an[\w./-]*\.asp)[\"'?]", text) + re.findall(r"url\s*:\s*[\"']([^\"']+\.asp)", text)
        seen = set()
        for ref in refs:
            if ref in seen or ref.endswith("wan.asp"):
                continue
            seen.add(ref)
            p = ref if ref.startswith("/") else posixpath.normpath(posixpath.join("/html/bbsp/wan", ref))
            for method in ("GET", "POST"):
                try:
                    st2, t2 = self._fetch(method, p)
                except RouterError:
                    continue
                if st2 == 200 and self.DOM_RE.search(t2):
                    texts.append((p.rsplit("/", 1)[-1], HEX_RE.sub(lambda m: chr(int(m.group(1), 16)), t2)))
                    break
            if len(seen) > 12:
                break
        return texts

    def devices_raw(self):
        self._ensure()
        st, _, text = self.request("POST", "/html/bbsp/userdevinfo/getuserdevinfo.asp", body="")
        return st, text

    def raw_page(self, path):
        try:
            st, text = self.get(path)
            return st, text
        except RouterError as e:
            return 0, "ERROR: " + (e.tech or e.ar)


# ---------------------------------------------------------------- helpers
def urlq(s):
    from urllib.parse import quote
    return quote(s, safe="")


def mac_mask(mac):
    p = mac.split(":")
    return ":".join(p[:2] + ["xx"] * 3 + p[-1:]) if len(p) == 6 else "xx"


ACTION_LABEL = {"block": "حظر جهاز", "unblock": "فك حظر جهاز", "redial": "تجديد الـ IP",
                "reboot": "إعادة تشغيل الراوتر", "enable_filter": "تفعيل الحظر"}


_IP_LOCK = threading.Lock()
_IP_STATE = {"value": "", "ts": 0.0, "busy": False}


def public_ip(max_age=4.0):
    """الـ IP العام. فيه كاش قصير + منع نداءات متزامنة عشان اللوحة ما تتعلقش."""
    now = time.time()
    with _IP_LOCK:
        if _IP_STATE["value"] and now - _IP_STATE["ts"] < max_age:
            return _IP_STATE["value"]
        if _IP_STATE["busy"]:
            return _IP_STATE["value"]
        _IP_STATE["busy"] = True
    try:
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
                with urllib.request.urlopen(req, timeout=3) as r:
                    v = r.read().decode("utf-8", "replace").strip()
                if re.match(r"^[0-9a-fA-F:.]{3,45}$", v):
                    with _IP_LOCK:
                        _IP_STATE["value"] = v
                        _IP_STATE["ts"] = time.time()
                    return v
            except Exception:
                continue
        return _IP_STATE["value"]
    finally:
        with _IP_LOCK:
            _IP_STATE["busy"] = False


SECRET_PATTERNS = [
    (re.compile(r"(?i)((?:pass\w*|pwd|secret|key|username|account|sn|loid)['\"]?\s*[:=,]\s*['\"])([^'\"]*)"), r"\1<مخفي>"),
    (re.compile(r'"[^"\n]*@[^"\n]*"'), '"<مخفي>"'),
    (re.compile(r"(?i)(hwonttoken|onttoken)([^>]{0,120}?value=['\"])[0-9a-zA-Z]+"), r"\1\2<token>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<token>"),
]


def redact(text):
    for pat, rep in SECRET_PATTERNS:
        text = pat.sub(rep, text)
    return re.sub(r"(?i)\b([0-9a-f]{2}):([0-9a-f]{2}):[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:([0-9a-f]{2})\b", r"\1:\2:xx:xx:xx:\3", text)


# ---------------------------------------------------------------- self test / diagnose
def selftest(cfg, out):
    ok = True

    def step(name, fn):
        nonlocal ok
        try:
            res = fn()
            out("[ نجح ] %s%s" % (name, (" - " + res) if res else ""))
            event("ok", "فحص: %s" % name, res or "")
            return True
        except RouterError as e:
            ok = False
            out("[ فشل ] %s\n        السبب: %s\n        تفاصيل فنية: %s" % (name, e.ar, e.tech or "-"))
            event("err", "فحص: %s" % name, "%s | %s" % (e.ar, e.tech or "-"))
        except Exception as e:
            ok = False
            out("[ فشل ] %s\n        خطأ غير متوقع: %r" % (name, e))
            event("err", "فحص: %s" % name, repr(e))
            log(traceback.format_exc())
        return False

    r = Router(cfg)
    out("== فحص الاتصال بالراوتر %s ==" % cfg["ip"])
    if not step("1) الوصول للراوتر", lambda: r.connect()):
        out("\nالنتيجة: مفيش اتصال بالراوتر. اتأكد إنك على شبكته.")
        return False, r
    if not step("2) تسجيل الدخول", lambda: r.login()):
        out("\nالنتيجة: تسجيل الدخول فشل، باقي الفحوصات اتوقفت (عشان الراوتر ميقفلش عليك).")
        return False, r
    step("3) قايمة الأجهزة", lambda: "%d جهاز" % len(r.devices()))
    step("4) صفحة الحظر (MAC Filter)", lambda: (lambda s: "شغالة=%s الوضع=%s محظور=%d" % (s["enabled"], s["mode"], len(s["entries"])))(r.macfilter()))
    step("5) صفحة إعادة التشغيل (قراءة بس، مفيش ريستارت)", lambda: (lambda x: x[0])(r.find_reboot()))
    step("6) أمر إعادة تشغيل الخط DSL (قراءة بس)", lambda: (lambda x: x[2])(r.find_dsl_reset()))
    step("7) قراءة حالة الخط (WAN)", lambda: "الحالة = %s" % (r.wan_state() or "غير معروفة"))
    out("\nالنتيجة: %s" % ("كل حاجة شغالة." if ok else "فيه خطوات فشلت. شغّل --diagnose وابعتلي diagnostics.txt."))
    return ok, r


def diagnose(cfg):
    lines = []

    def out(s):
        print(s)
        lines.append(s)

    out("Router dashboard v%s  |  %s  |  python %s  |  %s" % (VERSION, datetime.now().isoformat(timespec="seconds"), sys.version.split()[0], sys.platform))
    out("router=%s scheme=%s user_set=%s password_set=%s" % (cfg["ip"], cfg["scheme"], bool(cfg["username"]), bool(cfg["password"])))
    ok, r = selftest(cfg, out)
    if r.logged_in:
        try:
            menu = r.scan_menu_paths()
            out("\n----- صفحات ظاهرة في index.asp وscripts (%d) -----\n%s" % (len(menu), "\n".join(menu[:200])))
        except Exception as e:
            out("menu scan: %r" % e)
        try:
            for src, wt in r.wan_sources():
                lines = []
                for name, call in balanced_calls(wt):
                    if r.DOM_RE.search(call):
                        lines.append(redact(call.replace("\n", " "))[:400])
                out("\n----- مصدر WAN: %s (%d bytes) - استدعاءات فيها اتصالات: %d -----\n%s" % (src, len(wt), len(lines), "\n".join(lines[:40])))
        except Exception as e:
            out("wan: %r" % e)
        for method, p in (("POST", "/html/bbsp/common/GetLanUserDevInfo.asp"), ("POST", "/html/bbsp/common/GetLanUserDhcpInfo.asp"),
                          ("GET", "/html/bbsp/userdevinfo/userdevinfo.asp")):
            try:
                st, t = r._fetch(method, p)
            except Exception as e:
                st, t = 0, repr(e)
            out("\n----- %s %s  (status %s, %d bytes) -----\n%s" % (method, p, st, len(t), redact(HEX_RE.sub(lambda m: chr(int(m.group(1), 16)), t))[:6000]))
        for p in ("/html/ssmp/devmanage/e8cdevicemanormal.asp",):
            st, text = r.raw_page(p)
            out("\n----- %s  (status %s, %d bytes) -----" % (p, st, len(text)))
            out(redact(HEX_RE.sub(lambda m: chr(int(m.group(1), 16)), text))[:9000])
    try:
        out("\n----- آخر سطور السجل -----")
        with open(LOG_PATH, encoding="utf-8") as f:
            out("".join(f.readlines()[-40:]))
    except OSError:
        pass
    with open(DIAG_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\nاتكتب الملف: %s\nراجعه سريعًا قبل ما تبعته (فيه أسماء الأجهزة؛ الباسوردات والتوكنز بتتخفى تلقائيًا)." % DIAG_PATH)


# ---------------------------------------------------------------- dashboard
PAGE = r"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>لوحة تحكم الراوتر</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='9' fill='none' stroke='%234f8cff' stroke-width='2'/%3E%3Ccircle cx='12' cy='12' r='3' fill='%234f8cff'/%3E%3C/svg%3E">
<style>
:root{
  --bg:#070b12; --card:#101828; --card2:#131d31; --line:#1e2b44; --line2:#2b3d5e;
  --tx:#e9eff9; --mut:#8395b5; --mut2:#5c6f90;
  --acc:#4f8cff; --acc2:#7ba8ff; --ok:#22c97b; --bad:#ff5d6e; --warn:#f2b13c; --info:#57c8ff;
  --r:16px; --sh:0 14px 36px rgba(0,0,0,.45);
  --mono:"Cascadia Mono",Consolas,"Courier New",monospace;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;color:var(--tx);display:flex;flex-direction:column;min-height:100vh;background:
  radial-gradient(1100px 480px at 86% -10%,rgba(79,140,255,.15),transparent 62%),
  radial-gradient(820px 400px at 4% 0%,rgba(34,201,123,.07),transparent 58%),
  var(--bg);
  font:14px/1.55 "Segoe UI",Tahoma,Arial,sans-serif;-webkit-font-smoothing:antialiased;overflow-y:scroll}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#233149;border-radius:9px;border:3px solid transparent;background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background:#31456b;background-clip:content-box}
.ic{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round;flex:none}
.ic.sm{width:15px;height:15px}
.spin{width:15px;height:15px;border:2px solid rgba(255,255,255,.22);border-top-color:var(--acc2);border-radius:50%;
  display:inline-block;animation:rot .75s linear infinite;flex:none}
.spin.big{width:22px;height:22px;border-width:3px}
@keyframes rot{to{transform:rotate(360deg)}}
.skel{display:inline-block;height:13px;border-radius:7px;vertical-align:middle;color:transparent;min-width:52px;
  background-color:#16203a;
  background-image:linear-gradient(90deg,#16203a 25%,#22304e 45%,#16203a 65%);
  background-size:320% 100%;animation:shim 1.5s ease-in-out infinite}
@keyframes shim{0%{background-position:120% 0}100%{background-position:-120% 0}}
@keyframes fadeup{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes pop{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:none}}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(34,201,123,.55)}70%{box-shadow:0 0 0 7px rgba(34,201,123,0)}100%{box-shadow:0 0 0 0 rgba(34,201,123,0)}}

/* ---------- header ---------- */
header{position:sticky;top:0;z-index:40;backdrop-filter:blur(14px);
  background:linear-gradient(180deg,rgba(9,13,21,.94),rgba(9,13,21,.82));border-bottom:1px solid var(--line)}
.hwrap{max-width:1180px;margin:auto;padding:12px 18px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.brand{display:flex;gap:11px;align-items:center;min-width:230px}
.logo{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;color:#fff;
  background:linear-gradient(145deg,#2f6ae0,#59a0ff);box-shadow:0 6px 18px rgba(47,106,224,.45)}
.brand h1{margin:0;font-size:16.5px;letter-spacing:.2px}
.brand small{color:var(--mut2);font-size:11.5px;display:block;margin-top:1px}
.tabs{display:flex;gap:4px;background:#0d1523;border:1px solid var(--line);border-radius:12px;padding:4px}
.tab{position:relative;border:0;background:transparent;color:var(--mut);font:inherit;font-size:13.5px;
  padding:7px 14px;border-radius:9px;cursor:pointer;display:flex;gap:7px;align-items:center;transition:.16s}
.tab:hover{color:var(--tx);background:#152034}
.tab.on{background:linear-gradient(180deg,#2b4f96,#22407c);color:#fff;box-shadow:0 3px 12px rgba(47,106,224,.35)}
.tab .badge{background:var(--bad);color:#fff;border-radius:99px;font-size:11px;padding:0 6px;min-width:18px;text-align:center}
.tab .badge[hidden]{display:none}
.chips{display:flex;gap:9px;align-items:center;margin-inline-start:auto;flex-wrap:wrap}
.chip{display:flex;gap:8px;align-items:center;background:#0e1727;border:1px solid var(--line);
  border-radius:11px;padding:7px 12px;font-size:13px;min-height:38px}
.chip .k{color:var(--mut2);font-size:11.5px;letter-spacing:.4px}
.chip b{font-weight:600}
.chip .v{font-family:var(--mono);direction:ltr;unicode-bidi:isolate;font-size:13px}

/* ---------- live speed ---------- */
.chip.spd{gap:9px;padding-inline:12px 14px}
.chip.spd .dot{background:var(--ok);animation:pulse 2s infinite}
.chip.spd.dead .dot{background:var(--bad);animation:none}
.spdrow{display:inline-flex;align-items:baseline;gap:5px;direction:ltr;unicode-bidi:isolate}
.spdrow .dl{color:var(--ok)}.spdrow .ul{color:var(--acc2)}
.spdrow .ic{align-self:center;transform:translateY(1px)}
.spdv{font-family:var(--mono);font-size:14px;font-weight:700;min-width:46px;text-align:right;
  display:inline-block;transition:color .2s}
.spdu{font-size:10.5px;color:var(--mut2);letter-spacing:.3px}
.spddiv{width:1px;height:16px;background:var(--line2)}
@media(max-width:900px){.chip.spd{order:9}}

/* ---------- live speed card ---------- */
.spdgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:14px}
.spdbox{background:linear-gradient(180deg,var(--card2),#0f1727);border:1px solid var(--line);border-radius:13px;
  padding:12px 14px;position:relative;overflow:hidden}
.spdbox:before{content:"";position:absolute;inset-inline-start:0;top:0;bottom:0;width:3px;background:var(--acc)}
.spdbox.dl:before{background:var(--ok)}.spdbox.ul:before{background:var(--acc2)}.spdbox.tot:before{background:var(--warn)}
.spdbox .k{color:var(--mut);font-size:12px;margin-bottom:4px}
.spdbox .big{display:flex;align-items:baseline;gap:6px;direction:ltr;unicode-bidi:isolate}
.spdbox .big b{font-family:var(--mono);font-size:23px;font-weight:700;letter-spacing:.5px}
.spdbox.dl .big b{color:var(--ok)}.spdbox.ul .big b{color:var(--acc2)}
.spdbox .big span{font-size:11.5px;color:var(--mut2)}
#spdchart{width:100%;height:90px;display:block;border-radius:12px;background:#0a1120;border:1px solid var(--line)}
.spdlegend{display:flex;gap:16px;align-items:center;margin-top:9px;font-size:12px;color:var(--mut2);flex-wrap:wrap}
.spdlegend i{display:inline-block;width:10px;height:3px;border-radius:2px;margin-inline-end:5px}
.spdlegend .lg-ok i{background:var(--ok)}.spdlegend .lg-ul i{background:var(--acc2)}
.spdlegend .lg-line{margin-inline-start:auto;font-family:var(--mono);direction:ltr;unicode-bidi:isolate}
.dot{width:9px;height:9px;border-radius:50%;background:var(--mut2);flex:none}
.dot.ok{background:var(--ok);animation:pulse 2.4s infinite}
.dot.bad{background:var(--bad)}
.dot.wait{background:var(--warn)}
.icobtn{width:38px;height:38px;border-radius:11px;border:1px solid var(--line);background:#0e1727;color:var(--mut);
  display:grid;place-items:center;cursor:pointer;transition:.16s}
.icobtn:hover{color:#fff;border-color:var(--line2);background:#132038}
.icobtn.on{color:#fff;border-color:var(--acc)}
.icobtn.spinning .ic{animation:rot .9s linear infinite}

/* ---------- layout ---------- */
main{flex:1 0 auto;max-width:1180px;width:100%;margin:0 auto;padding:18px 18px 70px;display:grid;gap:16px;align-content:start}

/* ---------- footer ---------- */
footer{flex:none;border-top:1px solid var(--line);margin-top:14px;
  background:linear-gradient(180deg,rgba(11,16,26,0),rgba(9,13,21,.75));padding:20px 18px 24px}
footer .fin{max-width:1180px;margin:auto;display:flex;align-items:center;justify-content:center;gap:14px;flex-wrap:wrap}
footer .frule{flex:1;height:1px;max-width:180px;
  background:linear-gradient(90deg,transparent,rgba(120,150,200,.35),transparent)}
footer .fbrand{display:inline-flex;align-items:center;gap:9px;font-size:12.5px;color:var(--mut2);
  letter-spacing:.5px;direction:ltr;unicode-bidi:isolate;white-space:nowrap}
footer .fbrand .ic{width:15px;height:15px;color:var(--acc2);opacity:.9}
footer .fbrand b{font-weight:700;font-size:13.5px;letter-spacing:.3px;
  background:linear-gradient(90deg,#8fb6ff,#d3e3ff 45%,#7ba8ff);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:#bcd6ff}
footer .fver{font-family:var(--mono);font-size:11px;color:#41536f}
@media(max-width:720px){footer .frule{display:none}}
.card{background:linear-gradient(180deg,var(--card),#0e1625);border:1px solid var(--line);border-radius:var(--r);
  box-shadow:var(--sh);animation:fadeup .28s ease both}
.card>.head{display:flex;gap:12px;align-items:center;padding:14px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.card>.head h2{margin:0;font-size:15px;display:flex;gap:9px;align-items:center}
.card>.head .sub{color:var(--mut2);font-size:12.5px}
.card>.body{padding:16px 18px}
.grid-tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media(max-width:1080px){.grid-tiles{grid-template-columns:repeat(2,1fr)}}
@media(max-width:520px){.grid-tiles{grid-template-columns:1fr}}
.tile{background:linear-gradient(180deg,var(--card2),#0f1727);border:1px solid var(--line);border-radius:14px;
  padding:14px 15px;display:flex;gap:13px;align-items:center;position:relative;overflow:hidden}
.tile:before{content:"";position:absolute;inset-inline-start:0;top:0;bottom:0;width:3px;background:var(--acc);opacity:.85}
.tile.ok:before{background:var(--ok)}.tile.bad:before{background:var(--bad)}.tile.warn:before{background:var(--warn)}
.tile .tico{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:#152038;color:var(--acc2)}
.tile.ok .tico{color:var(--ok);background:#10281f}.tile.bad .tico{color:var(--bad);background:#2a1220}
.tile.warn .tico{color:var(--warn);background:#2a2110}
.tile .k{color:var(--mut);font-size:12px;margin-bottom:3px}
.tile .v{font-size:16px;font-weight:700;letter-spacing:.2px}
.tile .v.mono{font-family:var(--mono);direction:ltr;unicode-bidi:isolate;font-size:15px}
.tile .n{color:var(--mut2);font-size:11.5px;margin-top:2px}

/* ---------- buttons ---------- */
.btn{font:inherit;font-size:13.5px;color:#fff;background:linear-gradient(180deg,#3a72d8,#2a5cc0);border:1px solid #3f74dc;
  border-radius:11px;padding:10px 16px;cursor:pointer;display:inline-flex;gap:8px;align-items:center;justify-content:center;
  transition:.16s;white-space:nowrap}
.btn:hover{filter:brightness(1.09)}
.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.48;cursor:not-allowed;filter:grayscale(.35)}
.btn.red{background:linear-gradient(180deg,#e14a5c,#b93144);border-color:#e35a6a}
.btn.ghost{background:#131d30;border-color:var(--line2);color:var(--tx)}
.btn.ghost:hover{background:#19243a}
.btn.sm{padding:7px 12px;font-size:12.5px;border-radius:9px}
.btn.wide{padding:12px 20px}
.row{display:flex;gap:11px;flex-wrap:wrap;align-items:center}
.hint{color:var(--mut2);font-size:12.5px;line-height:1.7;margin:12px 0 0}

/* ---------- banner ---------- */
#banner{display:none;gap:12px;align-items:flex-start;padding:13px 16px;border-radius:13px;animation:pop .2s ease both}
#banner.show{display:flex}
#banner.bad{background:linear-gradient(180deg,#2c1120,#230d19);border:1px solid #7d2a3c}
#banner.warn{background:#2a2110;border:1px solid #7a5a1c}
#banner .bt{font-weight:700;margin-bottom:3px}
.tech{font-family:var(--mono);font-size:11.5px;color:var(--mut2);direction:ltr;unicode-bidi:isolate;text-align:left;margin-top:6px;
  word-break:break-word;opacity:.9}

/* ---------- table ---------- */
.tools{display:flex;gap:11px;align-items:center;flex-wrap:wrap;padding:13px 18px;border-bottom:1px solid var(--line)}
.search{position:relative;flex:1;min-width:210px;max-width:340px}
.search .ic{position:absolute;inset-inline-start:11px;top:50%;transform:translateY(-50%);color:var(--mut2)}
.search input{width:100%;font:inherit;background:#0b1424;color:var(--tx);border:1px solid var(--line);
  border-radius:11px;padding:9px 38px 9px 12px}
.search input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.16)}
.switch{position:relative;display:flex;gap:9px;align-items:center;cursor:pointer;color:var(--mut);font-size:13px;user-select:none}
.switch input{position:absolute;opacity:0;pointer-events:none;width:0;height:0}
.sw{width:42px;height:24px;border-radius:99px;background:#25334c;border:1px solid #2c3b57;position:relative;
  transition:background .18s ease,border-color .18s ease;flex:none}
.sw:after{content:"";position:absolute;top:2px;inset-inline-start:2px;width:18px;height:18px;border-radius:50%;
  background:#93a6c6;box-shadow:0 1px 3px rgba(0,0,0,.45);
  transition:inset-inline-start .2s ease,background .2s ease}
.switch input:checked+.sw{background:linear-gradient(180deg,#3a72d8,#2a5cc0);border-color:#3f74dc}
.switch input:checked+.sw:after{inset-inline-start:calc(100% - 20px);background:#fff}
.switch:hover .sw{background:#2e3f5e}
.switch:hover input:checked+.sw{background:linear-gradient(180deg,#4480e6,#2f66d0)}
.switch input:focus-visible+.sw{box-shadow:0 0 0 3px rgba(79,140,255,.35)}
.switch input:disabled+.sw{opacity:.5;cursor:not-allowed}

/* ---------- login ---------- */
.loginrow{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}
.fld{display:grid;gap:6px;flex:1;min-width:180px;max-width:290px}
.fld span{color:var(--mut);font-size:12px}
.fld input{font:inherit;background:#0b1424;color:var(--tx);border:1px solid var(--line);border-radius:11px;
  padding:10px 12px;width:100%}
.fld input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.16)}
.loginrow .switch{align-self:center;margin-bottom:6px;white-space:nowrap}
.logindone{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:13.5px;color:var(--mut)}
.logindone .okp{color:var(--ok);font-weight:700;display:inline-flex;gap:7px;align-items:center}
.umin{font-family:var(--mono);direction:ltr;unicode-bidi:isolate;color:var(--tx)}
.counts{color:var(--mut2);font-size:12.5px;margin-inline-start:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.tablewrap{overflow:auto;max-height:min(58vh,640px)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13.5px}
thead th{position:sticky;top:0;z-index:2;background:#0f1a2c;color:var(--mut);font-weight:600;font-size:12.5px;
  text-align:right;padding:11px 12px;border-bottom:1px solid var(--line)}
tbody td{padding:11px 12px;border-bottom:1px solid #16223a;vertical-align:middle}
tbody tr{transition:background .15s}
tbody tr:hover{background:#131f34}
tbody tr.mine{background:linear-gradient(90deg,rgba(79,140,255,.11),transparent 70%)}
tbody tr.mine:hover{background:#15243d}
tbody tr.blocked{background:linear-gradient(90deg,rgba(255,93,110,.09),transparent 70%)}
tbody tr:last-child td{border-bottom:0}
.dev{display:flex;gap:11px;align-items:center;min-width:190px}
.dev .dic{width:34px;height:34px;border-radius:10px;background:#16223a;display:grid;place-items:center;font-size:17px;flex:none}
.dev .dn{font-weight:600;display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.dev .dv{color:var(--mut2);font-size:11.5px;margin-top:2px}
.tag{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line2);color:var(--mut);background:#131d30}
.tag.me{color:#bcd6ff;border-color:#3a63ad;background:#16233c}
.mono{font-family:var(--mono);direction:ltr;unicode-bidi:isolate;font-size:12.5px;color:#c8d6f0}
.mac{cursor:pointer}
.mac:hover{color:var(--acc2);text-decoration:underline dotted}
.state{display:inline-flex;gap:7px;align-items:center;font-size:12.5px;white-space:nowrap}
.state.on{color:var(--ok)}.state.off{color:var(--mut2)}.state.blk{color:var(--bad);font-weight:700}
.empty{padding:34px 18px;text-align:center;color:var(--mut2)}
.empty .ic{width:34px;height:34px;color:#2b3d5e;margin-bottom:8px}
.skelrow td{padding:13px 12px}
.skelrow .skel{height:12px}

/* ---------- log ---------- */
.loglist{max-height:min(62vh,660px);overflow:auto;padding:10px 12px;display:grid;gap:7px;background:#0a1120;
  border-top:1px solid var(--line)}
.litem{display:flex;gap:10px;align-items:flex-start;padding:9px 11px;border-radius:10px;background:#0f1a2c;
  border:1px solid #182541}
.litem.new{animation:fadeup .25s ease both}
.litem .lt{font-family:var(--mono);font-size:11.5px;color:var(--mut2);padding-top:2px;flex:none}
.litem .ltag{font-size:11px;padding:1px 8px;border-radius:99px;flex:none;border:1px solid;margin-top:1px}
.litem .lmsg{flex:1;font-size:13px;word-break:break-word}
.litem.lvl-ok{border-color:#1c4a35}.litem.lvl-ok .ltag{color:#7ff0b6;border-color:#2b7a55;background:#102a1f}
.litem.lvl-err{border-color:#5c2230}.litem.lvl-err .ltag{color:#ff9aa6;border-color:#8a3a48;background:#2a121c}
.litem.lvl-warn .ltag{color:#ffd28a;border-color:#7a5a1c;background:#2a2110}
.litem.lvl-info .ltag{color:#a9d8ff;border-color:#2c5891;background:#122238}
.litem .tech{margin-top:4px}
.chipsbar{display:flex;gap:7px;flex-wrap:wrap;align-items:center;padding:12px 18px;border-bottom:1px solid var(--line)}
.fchip{font:inherit;font-size:12.5px;border:1px solid var(--line);background:#0f1a2c;color:var(--mut);border-radius:99px;
  padding:6px 13px;cursor:pointer;transition:.16s}
.fchip:hover{color:var(--tx);border-color:var(--line2)}
.fchip.on{background:#1f3d78;border-color:#3a63ad;color:#fff}
.rawfile{margin:0;padding:14px 16px;font-family:var(--mono);font-size:11.8px;direction:ltr;text-align:left;
  background:#0a1120;color:#a9bad8;max-height:min(62vh,660px);overflow:auto;white-space:pre-wrap;word-break:break-all}

/* ---------- progress ---------- */
#prog{position:fixed;inset-inline:0;bottom:0;z-index:60;padding:14px 18px;pointer-events:none}
#prog .pcard{max-width:1180px;margin:auto;background:linear-gradient(180deg,#132038,#0d1626);border:1px solid var(--line2);
  border-radius:15px;padding:14px 18px;box-shadow:0 -10px 40px rgba(0,0,0,.55);display:none;gap:13px;align-items:center;
  pointer-events:auto;animation:pop .22s ease both}
#prog.show .pcard{display:flex}
#prog .pinfo{flex:1;min-width:0}
#prog .ptitle{font-weight:700;display:flex;gap:10px;align-items:center;justify-content:space-between}
#prog .psecs{font-family:var(--mono);color:var(--mut2);font-size:12px}
.bar{height:6px;border-radius:99px;background:#1c2a44;margin-top:9px;overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,#2f6ae0,#5fd0ff);
  transition:width .5s ease}

/* ---------- toasts ---------- */
#toasts{position:fixed;inset-inline-start:18px;bottom:18px;z-index:80;display:grid;gap:10px;max-width:min(420px,92vw)}
.toast{display:flex;gap:11px;align-items:flex-start;background:#121d31;border:1px solid var(--line2);border-radius:13px;
  padding:12px 14px;box-shadow:0 12px 34px rgba(0,0,0,.5);animation:fadeup .22s ease both}
.toast.ok{border-color:#2b7a55}.toast.bad{border-color:#8a3a48}.toast.info{border-color:#2c5891}.toast.warn{border-color:#7a5a1c}
.toast .tmsg{flex:1;font-size:13px}
.toast .tx{background:none;border:0;color:var(--mut2);cursor:pointer;font-size:15px;line-height:1;padding:2px}

/* ---------- modal ---------- */
#modal{position:fixed;inset:0;z-index:90;background:rgba(4,7,12,.72);backdrop-filter:blur(3px);display:none;
  place-items:center;padding:18px}
#modal.show{display:grid}
.mbox{width:min(460px,96vw);background:linear-gradient(180deg,#13203a,#0f1828);border:1px solid var(--line2);
  border-radius:18px;padding:20px;box-shadow:0 24px 60px rgba(0,0,0,.6);animation:pop .2s ease both}
.mbox h3{margin:0 0 8px;font-size:16.5px;display:flex;gap:10px;align-items:center}
.mbox p{margin:0;color:var(--mut);font-size:13.5px;line-height:1.75;white-space:pre-line}
.mbox .mact{display:flex;gap:10px;justify-content:flex-start;margin-top:18px;flex-wrap:wrap}
.hidden{display:none!important}
.center{display:grid;place-items:center;gap:10px;padding:40px 18px;color:var(--mut2);text-align:center}
@media(max-width:720px){
  .hide-sm{display:none!important}
  .brand{min-width:0}
  .chips{width:100%}
  main{padding:14px 12px 100px}
  .card>.head,.card>.body,.tools,.chipsbar{padding-inline:14px}
}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-router" viewBox="0 0 24 24"><rect x="2.5" y="13.5" width="19" height="7" rx="2.2"/><path d="M6.5 17h.01M10 17h.01"/><path d="M12 10V6.6"/><path d="M8.4 7.4a6 6 0 0 1 7.2 0"/><path d="M6.1 4.6a9.5 9.5 0 0 1 11.8 0"/></symbol>
<symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.6 2.6 3.9 5.6 3.9 9S14.6 18.4 12 21c-2.6-2.6-3.9-5.6-3.9-9S9.4 5.6 12 3z"/></symbol>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3l7.5 3v5.2c0 4.7-3.1 8.6-7.5 9.8-4.4-1.2-7.5-5.1-7.5-9.8V6L12 3z"/><path d="M9.2 12.2l2 2 3.6-3.9"/></symbol>
<symbol id="i-power" viewBox="0 0 24 24"><path d="M12 3.5v8"/><path d="M6.4 6.9a7.5 7.5 0 1 0 11.2 0"/></symbol>
<symbol id="i-refresh" viewBox="0 0 24 24"><path d="M4.2 10.5a8 8 0 0 1 13.4-4.1l2.1 2"/><path d="M19.8 13.5a8 8 0 0 1-13.4 4.1l-2.1-2"/><path d="M19.9 4.6v3.8h-3.8"/><path d="M4.1 19.4v-3.8h3.8"/></symbol>
<symbol id="i-bolt" viewBox="0 0 24 24"><path d="M13.4 2.5L5.6 13.2h5.1l-.9 8.3 8.2-11.1h-5.4z"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="10.8" cy="10.8" r="6.8"/><path d="M15.9 15.9L21 21"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="11.5" height="11.5" rx="2.3"/><path d="M15 6.2A2.3 2.3 0 0 0 12.8 3.5H5.8A2.3 2.3 0 0 0 3.5 5.8v7A2.3 2.3 0 0 0 6.2 15"/></symbol>
<symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6.5h13M8 12h13M8 17.5h13"/><circle cx="3.6" cy="6.5" r="1.3"/><circle cx="3.6" cy="12" r="1.3"/><circle cx="3.6" cy="17.5" r="1.3"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 3.4L21.4 20H2.6L12 3.4z"/><path d="M12 9.4v5"/><path d="M12 17.6h.01"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M4.5 12.6l5 5L19.5 6.6"/></symbol>
<symbol id="i-down" viewBox="0 0 24 24"><path d="M12 3.5v12"/><path d="M7 10.5l5 5 5-5"/><path d="M4.5 20.5h15"/></symbol>
<symbol id="i-up" viewBox="0 0 24 24"><path d="M12 20.5v-12"/><path d="M7 13.5l5-5 5 5"/><path d="M4.5 3.5h15"/></symbol>
<symbol id="i-users" viewBox="0 0 24 24"><circle cx="9.2" cy="8.4" r="3.6"/><path d="M2.8 20c0-3.5 2.9-6 6.4-6s6.4 2.5 6.4 6"/><path d="M16.4 5.2a3.4 3.4 0 0 1 0 6.5"/><path d="M18 14.6c2.1.7 3.4 2.6 3.4 5"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.8h.01"/></symbol>
<symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.8"/><path d="M4.6 20.5c0-4 3.3-6.6 7.4-6.6s7.4 2.6 7.4 6.6"/></symbol>
<symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15.6" r="3.9"/><path d="M10.9 13.1L20 4"/><path d="M16.6 7.4l2.4 2.4"/><path d="M14.2 9.8l2.2 2.2"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="4.5" y="10.4" width="15" height="10.1" rx="2.4"/><path d="M8.2 10.4V7.8a3.8 3.8 0 0 1 7.6 0v2.6"/></symbol>
<symbol id="i-trash" viewBox="0 0 24 24"><path d="M4.5 7h15"/><path d="M9.5 7V4.8h5V7"/><path d="M6.5 7l1 13h9l1-13"/></symbol>
</defs></svg>

<header>
  <div class="hwrap">
    <div class="brand">
      <div class="logo"><svg class="ic" style="width:21px;height:21px"><use href="#i-router"></use></svg></div>
      <div><h1>لوحة تحكم الراوتر</h1><small>Huawei DN8245V-56 / WE</small></div>
    </div>
    <div class="tabs">
      <button class="tab on" id="tab-home" onclick="go('home')"><svg class="ic sm"><use href="#i-router"></use></svg> الرئيسية</button>
      <button class="tab" id="tab-log" onclick="go('log')"><svg class="ic sm"><use href="#i-list"></use></svg> السجل <span class="badge" id="logbadge" hidden>0</span></button>
    </div>
    <div class="chips">
      <div class="chip" id="chip-router"><span class="spin"></span><span>بفحص الاتصال</span></div>
      <div class="chip spd" id="chip-speed" title="السرعة اللحظية من عدّادات الراوتر (كل البيت)">
        <span class="dot wait" id="spd-dot"></span>
        <span class="spdrow"><svg class="ic sm dl"><use href="#i-down"></use></svg>
          <b class="spdv" id="spd-dl">—</b><span class="spdu">Mbps</span></span>
        <span class="spddiv"></span>
        <span class="spdrow"><svg class="ic sm ul"><use href="#i-up"></use></svg>
          <b class="spdv" id="spd-ul">—</b><span class="spdu">Mbps</span></span>
      </div>
      <div class="chip"><span class="k">IP</span><span class="v" id="chip-ip"><span class="skel" style="width:96px"></span></span></div>
      <button class="icobtn" id="b-refresh" onclick="loadStatus()" title="تحديث البيانات"><svg class="ic"><use href="#i-refresh"></use></svg></button>
    </div>
  </div>
</header>

<main>
  <div id="banner"><svg class="ic"><use href="#i-alert"></use></svg><div style="flex:1"><div class="bt"></div><div class="bb"></div><div class="tech"></div></div></div>

  <div class="card" id="logincard">
    <div class="head">
      <h2><svg class="ic"><use href="#i-lock"></use></svg> الدخول للراوتر</h2>
      <span class="sub" id="authstate">بيتأكد…</span>
      <div class="row hidden" id="authacts" style="margin-inline-start:auto">
        <button class="btn sm ghost" id="b-change" onclick="showLogin(true)">تغيير البيانات</button>
        <button class="btn sm ghost" onclick="doLogout(false)">خروج</button>
        <button class="btn sm ghost" onclick="doLogout(true)">خروج + مسح الباسورد</button>
      </div>
    </div>

    <div class="body" id="loginbody">
      <div class="loginrow">
        <label class="fld"><span>اسم المستخدم</span>
          <input id="u" autocomplete="username" spellcheck="false" placeholder="admin"></label>
        <label class="fld"><span>الباسورد</span>
          <input id="p" type="password" autocomplete="current-password" placeholder="••••••••"></label>
        <label class="switch"><input type="checkbox" id="save" checked><span class="sw"></span> احفظ البيانات</label>
        <button class="btn" id="b-login" onclick="doLogin()"><svg class="ic"><use href="#i-key"></use></svg> دخول</button>
      </div>
      <p class="hint" id="loginhint">اكتب بيانات لوحة الراوتر مرة واحدة — لو علّمت على «احفظ البيانات» هتتخزن في
        <span class="umin">config.ini</span> عندك والبرنامج هيدخل لوحده كل مرة.</p>
    </div>

    <div class="body hidden" id="logindone">
      <div class="logindone">
        <span class="okp"><svg class="ic sm"><use href="#i-check"></use></svg> متصل بالراوتر</span>
        <span>الحساب: <b class="umin" id="luser">admin</b></span>
        <span id="lpwsaved"></span>
        <span>· الجلسة بتتجدّد لوحدها، ولو النت قطع بيرجع يتوصّل أول ما يرجع</span>
      </div>
    </div>
  </div>

  <div id="view-home" style="display:grid;gap:16px">
    <div class="grid-tiles" id="tiles"></div>

    <div class="card">
      <div class="head">
        <h2><svg class="ic"><use href="#i-wifi"></use></svg> سرعة الإنترنت (لحظي)</h2>
        <span class="sub">قياس حقيقي من عدّادات الراوتر — بدون أي سحب للسرعة</span>
        <span class="sub" id="spdline" style="margin-inline-start:auto"></span>
      </div>
      <div class="body">
        <div class="spdgrid">
          <div class="spdbox dl"><div class="k">نزول (Download)</div>
            <div class="big"><b id="spd-dl2">—</b><span>Mbps</span></div></div>
          <div class="spdbox ul"><div class="k">رفع (Upload)</div>
            <div class="big"><b id="spd-ul2">—</b><span>Mbps</span></div></div>
          <div class="spdbox tot"><div class="k">إجمالي مستهلك من آخر تشغيل للخط</div>
            <div class="big"><b id="spd-tot">—</b><span>GB</span></div></div>
        </div>
        <canvas id="spdchart"></canvas>
        <div class="spdlegend">
          <span class="lg-ok"><i></i> نزول</span>
          <span class="lg-ul"><i></i> رفع</span>
          <span id="spdstate"></span>
          <span class="lg-line" id="spdline2"></span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="head">
        <h2><svg class="ic"><use href="#i-bolt"></use></svg> الإنترنت والراوتر</h2>
        <span class="sub">تحكم مباشر</span>
      </div>
      <div class="body">
        <div class="row">
          <button class="btn wide" id="b-redial" data-gate onclick="doRedial()"><svg class="ic"><use href="#i-refresh"></use></svg> تجديد الـ IP (إعادة تشغيل الخط)</button>
          <button class="btn red wide" id="b-reboot" data-gate onclick="doReboot()"><svg class="ic"><use href="#i-power"></use></svg> إعادة تشغيل الراوتر كله</button>
          <span class="hidden" id="lockhint" style="color:var(--warn);font-size:12.5px;display:inline-flex;gap:7px;align-items:center">
            <svg class="ic sm"><use href="#i-lock"></use></svg> التحكم مقفول لحد ما يتم الدخول للراوتر
          </span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="head">
        <h2><svg class="ic"><use href="#i-users"></use></svg> الأجهزة المتصلة</h2>
        <span class="sub" id="mfstate"></span>
        <button class="btn sm ghost hidden" id="b-mf" data-gate style="margin-inline-start:auto" onclick="doEnableFilter()">تفعيل خاصية الحظر</button>
      </div>
      <div class="tools">
        <div class="search">
          <svg class="ic sm"><use href="#i-search"></use></svg>
          <input id="q" placeholder="ابحث بالاسم أو الـ IP أو الـ MAC أو الشركة" oninput="renderDevices()">
        </div>
        <label class="switch"><input type="checkbox" id="onl" checked onchange="renderDevices()"><span class="sw"></span> المتصل فقط</label>
        <div class="counts" id="counts"></div>
      </div>
      <div class="tablewrap">
        <table>
          <thead><tr>
            <th>الجهاز</th><th class="hide-sm">IP</th><th>MAC</th><th class="hide-sm">الشركة / النوع</th><th>الحالة</th><th></th>
          </tr></thead>
          <tbody id="tb"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="view-log" style="display:none;gap:16px">
    <div class="card">
      <div class="head">
        <h2><svg class="ic"><use href="#i-list"></use></svg> سجل الأحداث</h2>
        <span class="sub" id="logsub"></span>
        <div class="row" style="margin-inline-start:auto">
          <button class="btn sm ghost" id="b-logfile" onclick="toggleFile()">ملف السجل</button>
          <button class="btn sm ghost" onclick="copyLog()"><svg class="ic sm"><use href="#i-copy"></use></svg> نسخ</button>
          <button class="btn sm ghost" onclick="clearLog()"><svg class="ic sm"><use href="#i-trash"></use></svg> تصفية العرض</button>
        </div>
      </div>
      <div class="chipsbar" id="logfilters">
        <button class="fchip on" data-f="all" onclick="setFilter('all')">الكل</button>
        <button class="fchip" data-f="err" onclick="setFilter('err')">أخطاء</button>
        <button class="fchip" data-f="warn" onclick="setFilter('warn')">تحذيرات</button>
        <button class="fchip" data-f="ok" onclick="setFilter('ok')">نجاح</button>
        <button class="fchip" data-f="info" onclick="setFilter('info')">معلومات</button>
        <label class="switch" style="margin-inline-start:auto"><input type="checkbox" id="autoscroll" checked><span class="sw"></span> تتبع الأحدث</label>
      </div>
      <div class="loglist" id="loglist"><div class="center"><span class="spin big"></span> بجيب السجل…</div></div>
      <pre class="rawfile hidden" id="logfile"></pre>
    </div>
  </div>
</main>

<footer>
  <div class="fin">
    <span class="frule"></span>
    <span class="fbrand">
      <svg class="ic"><use href="#i-bolt"></use></svg>
      <span>powered by <b>Mr-3omDa</b></span>
    </span>
    <span class="frule"></span>
  </div>
  <div style="text-align:center;margin-top:9px">
    <span class="fver">Router Dashboard v__VERSION__</span>
  </div>
</footer>

<div id="prog"><div class="pcard">
  <span class="spin big"></span>
  <div class="pinfo">
    <div class="ptitle"><span id="ptitle"></span><span class="psecs" id="psecs"></span></div>
    <div class="bar"><i id="pbar"></i></div>
    <div id="psub" style="color:var(--mut2);font-size:12.5px;margin-top:6px"></div>
  </div>
</div></div>

<div id="toasts"></div>

<div id="modal"><div class="mbox">
  <h3><svg class="ic" id="micon"><use href="#i-alert"></use></svg><span id="mtitle"></span></h3>
  <p id="mbody"></p>
  <div class="mact">
    <button class="btn" id="mok"></button>
    <button class="btn ghost" id="mcancel">إلغاء</button>
  </div>
</div></div>

<script>
var T='__TOKEN__';
var $=function(s){return document.querySelector(s)};
var api=async function(p,b){var r=await fetch(p,{method:b?'POST':'GET',cache:'no-store',
  headers:{'X-Token':T,'Content-Type':'application/json'},body:b?JSON.stringify(b):null});
  if(r.status===403)throw new Error('token');return await r.json()};
var sleep=function(ms){return new Promise(function(r){setTimeout(r,ms)})};
var esc=function(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})};

var D=[],MF=null,MEIPS=[],MEMACS=[],ROUTER=null,IP='',STATE=null,LOADING=true,BUSY=false,INFLIGHT=false;
var AUTH={},FORMOPEN=false;
var LOG=[],LOGSEQ=0,LOGFILE=null,SHOWFILE=false,FILTER='all',BADGE=0,SEEN=0,TAB='home',LOGKEY='',NEWIDS={};

/* ================= helpers ================= */
function go(t){
  TAB=t;
  $('#view-home').style.display=t==='home'?'grid':'none';
  $('#view-log').style.display=t==='log'?'grid':'none';
  $('#tab-home').classList.toggle('on',t==='home');
  $('#tab-log').classList.toggle('on',t==='log');
  if(t==='log'){SEEN=LOGSEQ;BADGE=0;updBadge();loadLog(true);renderLog()}
}
function updBadge(){var b=$('#logbadge');b.hidden=!BADGE;b.textContent=BADGE>99?'99+':BADGE}
function banner(kind,title,body,tech){
  var el=$('#banner');
  if(!kind){el.className='';return}
  el.className='show '+kind;
  el.querySelector('.bt').textContent=title||'';
  el.querySelector('.bb').textContent=body||'';
  el.querySelector('.tech').textContent=tech||'';
}
function toast(msg,kind,tech){
  if(!msg)return;
  kind=kind||'info';
  var el=document.createElement('div');el.className='toast '+kind;
  var ic=kind==='ok'?'check':kind==='bad'?'alert':kind==='warn'?'alert':'info';
  var col=kind==='ok'?'ok':kind==='bad'?'bad':kind==='warn'?'warn':'info';
  el.innerHTML='<svg class="ic" style="color:var(--'+col+')"><use href="#i-'+ic+'"></use></svg>'+
    '<div class="tmsg">'+esc(msg)+(tech?'<div class="tech">'+esc(tech)+'</div>':'')+'</div>'+
    '<button class="tx">&times;</button>';
  el.querySelector('.tx').onclick=function(){el.remove()};
  $('#toasts').append(el);
  setTimeout(function(){el.remove()},kind==='bad'?11000:6000);
}
function ask(o){
  return new Promise(function(res){
    $('#mtitle').textContent=o.title||'تأكيد';
    $('#mbody').textContent=o.body||'';
    $('#mok').textContent=o.ok||'تنفيذ';
    $('#mok').className='btn'+(o.danger?' red':'');
    $('#micon').innerHTML='<use href="#i-'+(o.danger?'alert':'info')+'"></use>';
    var m=$('#modal');
    m.classList.add('show');
    setTimeout(function(){$('#mok').focus()},30);
    function done(v){
      m.classList.remove('show');
      $('#mok').onclick=null;$('#mcancel').onclick=null;m.onclick=null;document.onkeydown=null;res(v);
    }
    $('#mok').onclick=function(){done(true)};
    $('#mcancel').onclick=function(){done(false)};
    m.onclick=function(e){if(e.target===m)done(false)};
    document.onkeydown=function(e){
      if(e.key==='Escape')done(false);
      else if(e.key==='Enter'){e.preventDefault();done(true)}
    };
  });
}
function prog(o){
  $('#prog').classList.add('show');
  if(o.title!==undefined)$('#ptitle').textContent=o.title;
  if(o.sub!==undefined)$('#psub').textContent=o.sub;
  if(o.pct!==undefined)$('#pbar').style.width=Math.max(0,Math.min(100,o.pct))+'%';
  if(o.secs!==undefined)$('#psecs').textContent=o.secs;
}
function progHide(){$('#prog').classList.remove('show')}
function setBusy(b){
  BUSY=b;
  document.querySelectorAll('#tb button').forEach(function(e){if(b)e.disabled=true});
  gateUI();
}
function gateUI(){
  var on=(ROUTER===true)&&!BUSY;
  document.querySelectorAll('[data-gate]').forEach(function(e){e.disabled=!on});
  document.querySelectorAll('#tb button[data-act]').forEach(function(e){e.disabled=!on});
  var lk=$('#lockhint');
  if(lk)lk.classList.toggle('hidden',ROUTER===true);
}
function spinIn(btn,on){
  var b=typeof btn==='string'?$(btn):btn;
  if(!b||!b.appendChild)return;
  var sp=b.querySelector('.spin');
  if(on&&!sp){sp=document.createElement('span');sp.className='spin';b.appendChild(sp)}
  if(!on&&sp)sp.remove();
}

/* ================= status ================= */
async function loadStatus(){
  if(BUSY||INFLIGHT)return;
  INFLIGHT=true;LOADING=true;
  var rb=$('#b-refresh');rb.classList.add('spinning');
  try{
    var s=await api('/api/status');
    STATE=s;ROUTER=!!s.router_ok;IP=s.public_ip||'';
    if(s.auth)AUTH=s.auth;
    if(s.devices)D=s.devices;
    if(s.macfilter!==undefined)MF=s.macfilter;
    MEIPS=s.me_ips||[];MEMACS=s.me_macs||[];
    banner(null);
    if(!s.router_ok)banner('bad','الراوتر مش متصل',s.error||'مفيش اتصال بالراوتر',s.tech||'');
  }catch(e){
    ROUTER=false;
    banner('bad','مش قادر أكلم برنامج اللوحة','اتأكد إن نافذة البرنامج لسه مفتوحة.','');
  }finally{
    LOADING=false;INFLIGHT=false;rb.classList.remove('spinning');renderAll();
  }
}
function renderAll(){renderChips();renderTiles();renderDevices();renderFilter();renderAuth();gateUI()}

/* ================= auth ================= */
function renderAuth(){
  var loading=(ROUTER===null);
  var connected=(ROUTER===true);
  var saved=!!AUTH.has_password;
  var uEl=$('#u');
  if(uEl&&!uEl.value)uEl.value=AUTH.username||'admin';
  var pEl=$('#p');
  if(pEl)pEl.placeholder=saved?'•••••••• (محفوظ عندك)':'باسورد الراوتر';
  $('#authstate').textContent=loading?'بيتأكد…'
    :(connected?('متصل بحساب '+(AUTH.username||'admin'))
    :(saved?'فيه بيانات محفوظة — بستنى الراوتر':'مش متسجل دخول'));
  var showForm=(!loading)&&((!connected)||FORMOPEN);
  $('#loginbody').classList.toggle('hidden',!showForm);
  $('#logindone').classList.toggle('hidden',loading||!connected||FORMOPEN);
  $('#authacts').classList.toggle('hidden',!connected);
  $('#luser').textContent=AUTH.username||'admin';
  $('#lpwsaved').textContent=saved?'(الباسورد محفوظ)':'(الباسورد مش محفوظ)';
  $('#loginhint').textContent=saved
    ?'البيانات محفوظة عندك، والبرنامج بيدخل لوحده كل مرة. لو رفض الراوتر الدخول غيّر الباسورد هنا.'
    :'اكتب بيانات لوحة الراوتر مرة واحدة — لو علّمت على «احفظ البيانات» هتتخزن في config.ini عندك.';
}
async function doLogin(){
  var u=($('#u').value||'').trim()||'admin', p=$('#p').value||'';
  if(!p){toast('اكتب باسورد الراوتر','warn');$('#p').focus();return}
  var b=$('#b-login');setBusy(true);spinIn(b,true);
  try{
    var r=await api('/api/login',{username:u,password:p,save:$('#save').checked});
    if(r&&r.ok){
      toast(r.message,'ok');$('#p').value='';FORMOPEN=false;
      AUTH=r.auth||{};await loadStatus();
    }else toast((r&&r.error)||'فشل تسجيل الدخول','bad',(r&&r.tech)||'');
  }catch(e){toast('مش قادر أكلم برنامج اللوحة','bad')}
  finally{spinIn(b,false);setBusy(false)}
}
async function doLogout(forget){
  if(!await ask({title:forget?'خروج ومسح الباسورد':'تسجيل الخروج',
    body:forget?'هخرج من جلسة الراوتر وهمسح الباسورد المحفوظ من عندك.':'هخرج من جلسة الراوتر، وهتحتاج تكتب الباسورد تاني.',
    ok:'خروج',danger:true}))return;
  try{
    var r=await api('/api/logout',{forget:!!forget});
    toast((r&&r.message)||'تم تسجيل الخروج',(r&&r.ok)?'ok':'bad');
    AUTH=(r&&r.auth)||{};
  }catch(e){toast('مش قادر أكلم برنامج اللوحة','bad')}
  FORMOPEN=true;await loadStatus();
}
function showLogin(open){FORMOPEN=open;renderAuth();if(open)setTimeout(function(){$('#p').focus()},60)}

function renderChips(){
  var c=$('#chip-router');
  if(ROUTER===true)c.innerHTML='<span class="dot ok"></span><b>الراوتر متصل</b>';
  else if(ROUTER===false)c.innerHTML='<span class="dot bad"></span><b>الراوتر مش متصل</b>';
  else c.innerHTML='<span class="spin"></span><span>بفحص الاتصال</span>';
  var i=$('#chip-ip');
  if(IP){i.textContent=IP;i.classList.add('mono')}
  else if(LOADING){i.innerHTML='<span class="skel" style="width:96px"></span>'}
  else{i.textContent='غير معروف'}
}
function tile(icon,k,v,n,cls,mono){
  return '<div class="tile '+(cls||'')+'"><div class="tico"><svg class="ic"><use href="#'+icon+'"></use></svg></div>'+
    '<div><div class="k">'+esc(k)+'</div><div class="v'+(mono?' mono':'')+'">'+v+'</div>'+
    (n?'<div class="n">'+esc(n)+'</div>':'')+'</div></div>';
}
function renderTiles(){
  if(LOADING&&ROUTER===null){
    var sk='<span class="skel" style="width:82px;height:15px"></span>';
    $('#tiles').innerHTML=tile('i-router','حالة الراوتر',sk,'')+tile('i-globe','عنوان الإنترنت (IP)',sk,'')+
      tile('i-users','الأجهزة المتصلة',sk,'')+tile('i-shield','خاصية الحظر',sk,'');
    return;
  }
  var c=(STATE&&STATE.counts)||{};
  var t1=ROUTER===true?{c:'ok',v:'متصل'}:{c:'bad',v:'غير متصل'};
  var t2=IP?{c:'ok',v:IP,mono:true}:{c:'warn',v:'غير معروف'};
  var on=c.online||0,tot=c.total||0;
  var t3={c:on>0?'ok':'',v:on+' جهاز',n:'من إجمالي '+tot+' في قايمة الراوتر'};
  var t4;
  if(MF&&MF.enabled&&MF.mode==='blacklist')t4={c:'ok',v:'شغالة',n:(c.blocked||0)+' جهاز محظور'};
  else if(MF&&MF.enabled)t4={c:'warn',v:'قايمة بيضاء',n:'الراوتر بيسمح للمسجلين بس'};
  else t4={c:'warn',v:'مقفولة',n:'الحظر مش مفعّل على الراوتر'};
  $('#tiles').innerHTML=tile('i-router','حالة الراوتر',t1.v,'',t1.c)+
    tile('i-globe','عنوان الإنترنت (IP)',t2.v,'',t2.c,t2.mono)+
    tile('i-users','الأجهزة المتصلة',t3.v,t3.n,t3.c)+
    tile('i-shield','خاصية الحظر',t4.v,t4.n,t4.c);
}
function renderFilter(){
  var st=$('#mfstate'),bt=$('#b-mf');
  if(!MF){st.textContent='';bt.classList.add('hidden');return}
  if(MF.enabled&&MF.mode==='blacklist'){st.textContent='الحظر شغال (قايمة سوداء)';bt.classList.add('hidden')}
  else if(MF.enabled){st.textContent='الراوتر على القايمة البيضاء — الحظر من هنا مقفول';bt.classList.add('hidden')}
  else{st.textContent='خاصية الحظر مقفولة على الراوتر';bt.classList.remove('hidden')}
}

/* ================= devices ================= */
function isMe(d){return (d.ip&&MEIPS.indexOf(d.ip)>=0)||(d.mac&&MEMACS.indexOf(d.mac)>=0)}
function iconFor(d){
  if(d.random_mac)return '📱';
  var s=((d.vendor||'')+' '+(d.type_guess||'')+' '+(d.iface||'')).toLowerCase();
  if(/تلفزيون|tv|roku|vizio/.test(s))return '📺';
  if(/موبايل|phone|android|apple|samsung|xiaomi|oppo|vivo/.test(s))return '📱';
  if(/كمبيوتر|laptop|desktop|intel|dell|lenovo|hp|acer|asus|msi/.test(s))return '💻';
  if(/كاميرا|ذكي|iot|espressif|tuya|hikvision|dahua/.test(s))return '📷';
  if(/شبكة|router|access|tplink|tp-link|d-link|zte|altobeam/.test(s))return '📶';
  return '🔌';
}
function renderDevices(){
  var tb=$('#tb');if(!tb)return;
  if(LOADING&&!D.length){
    tb.innerHTML='<tr class="skelrow"><td colspan="6"><span class="skel" style="width:60%"></span></td></tr>'+
                 '<tr class="skelrow"><td colspan="6"><span class="skel" style="width:45%"></span></td></tr>'+
                 '<tr class="skelrow"><td colspan="6"><span class="skel" style="width:72%"></span></td></tr>';
    $('#counts').innerHTML='<span class="spin"></span> بجيب الأجهزة';
    return;
  }
  var q=($('#q').value||'').trim().toLowerCase();
  var mfE=(MF&&MF.entries)||[];
  var bl={};mfE.forEach(function(e){bl[e.mac]=e});
  var rows=D.slice();
  mfE.forEach(function(e){
    if(!rows.some(function(d){return d.mac===e.mac}))
      rows.push({name:e.alias||'(محظور — مش متصل)',ip:'',mac:e.mac,type:'',status:'Offline'});
  });
  var onl=$('#onl').checked;
  rows=rows.filter(function(d){
    var hay=(d.name+' '+(d.ip||'')+' '+(d.mac||'')+' '+(d.vendor||'')+' '+(d.type_guess||'')).toLowerCase();
    if(q&&hay.indexOf(q)<0)return false;
    if(onl&&d.status!=='Online'&&!bl[d.mac])return false;
    return true;
  });
  rows.sort(function(a,b){
    var am=isMe(a)?1:0,bm=isMe(b)?1:0;if(am!==bm)return bm-am;
    var ab=bl[a.mac]?1:0,bb=bl[b.mac]?1:0;if(ab!==bb)return ab-bb;
    var ao=a.status==='Online'?1:0,bo=b.status==='Online'?1:0;if(ao!==bo)return bo-ao;
    return (a.name||'').localeCompare(b.name||'');
  });
  var oncount=rows.filter(function(d){return d.status==='Online'}).length;
  var cnt='<span class="state on"><span class="dot ok"></span>'+oncount+' متصل</span>'+
    '<span>|</span> معروض '+rows.length+' من '+D.length;
  if(mfE.length)cnt+='<span>|</span><span class="state blk">'+mfE.length+' محظور</span>';
  $('#counts').innerHTML=cnt;
  if(!rows.length){
    var emsg=(ROUTER!==true)?'الراوتر مش متصل — بعد الدخول هتظهر الأجهزة هنا':'مفيش أجهزة مطابقة للفلتر الحالي';
    tb.innerHTML='<tr><td colspan="6"><div class="empty"><svg class="ic"><use href="#i-users"></use></svg>'+
      '<div>'+esc(emsg)+'</div></div></td></tr>';
    return;
  }
  var html='';
  rows.forEach(function(d){
    var blocked=!!bl[d.mac],mine=isMe(d);
    var kind=[d.vendor,d.type_guess||d.iface].filter(Boolean).join(' · ');
    var dv=mine?'جهازك — الكمبيوتر اللي فاتح اللوحة':([d.iface,kind].filter(Boolean).join(' · ')||'—');
    var st=blocked?'<span class="state blk"><svg class="ic sm"><use href="#i-shield"></use></svg>محظور</span>'
      :(d.status==='Online'?'<span class="state on"><span class="dot ok"></span>متصل</span>'
      :'<span class="state off"><span class="dot"></span>غير متصل</span>');
    html+='<tr class="'+(mine?'mine ':'')+(blocked?'blocked':'')+'">'+
      '<td><div class="dev"><div class="dic">'+iconFor(d)+'</div><div>'+
        '<div class="dn">'+esc(d.name||d.mac||'جهاز')+(mine?'<span class="tag me">جهازك</span>':'')+'</div>'+
        '<div class="dv">'+esc(dv)+'</div>'+
      '</div></div></td>'+
      '<td class="hide-sm mono">'+esc(d.ip||'—')+'</td>'+
      '<td><span class="mono mac" title="اضغط للنسخ" data-mac="'+esc(d.mac)+'">'+esc(d.mac||'—')+'</span></td>'+
      '<td class="hide-sm" style="color:var(--mut)">'+esc(kind||'—')+'</td>'+
      '<td>'+st+'</td>'+
      '<td><button class="btn sm '+(blocked?'ghost':'red')+'" data-mac="'+esc(d.mac)+'" data-name="'+esc(d.name||'')+
        '" data-act="'+(blocked?'unblock':'block')+'"'+(d.mac?'':' disabled')+'>'+
        (blocked?'فك الحظر':'حظر')+'</button></td></tr>';
  });
  tb.innerHTML=html;
  tb.querySelectorAll('button[data-act]').forEach(function(b){b.onclick=function(){onRowAction(b)}});
  tb.querySelectorAll('.mac').forEach(function(b){
    b.onclick=function(){
      var m=b.dataset.mac;
      if(navigator.clipboard&&m)navigator.clipboard.writeText(m);
      toast('اتنسخ الـ MAC: '+m,'info');
    };
  });
  gateUI();
}
function onRowAction(btn){
  var mac=btn.dataset.mac,name=btn.dataset.name,act=btn.dataset.act;
  if(act==='unblock')return doUnblock(mac,name,btn);
  var mine=(MEMACS.indexOf(mac)>=0)||D.some(function(d){return d.mac===mac&&d.ip&&MEIPS.indexOf(d.ip)>=0});
  if(mine)return doSelfBlock(mac,name,btn);
  ask({title:'حظر الجهاز',body:'هتحظر "'+(name||mac)+'" من الإنترنت عن طريق الراوتر.\nتقدر تفك الحظر من نفس القايمة في أي وقت.',
       ok:'حظر',danger:true}).then(function(v){if(v)doBlock(mac,name,false,btn)});
}
function doSelfBlock(mac,name,btn){
  ask({title:'تحذير: ده جهازك إنت',body:'الجهاز ده هو اللي فاتح اللوحة دلوقتي. لو حظرته هتفصل عن الراوتر\nومش هتقدر تفك الحظر إلا بإعادة تشغيل الراوتر.',ok:'فاهم، كمل',danger:true})
  .then(function(v){
    if(!v)return;
    ask({title:'تأكيد أخير',body:'متأكد 100% إنك عايز تحظر جهازك إنت ('+(name||mac)+')؟',ok:'أيوه احظره',danger:true})
    .then(function(v2){if(v2)doBlock(mac,name,true,btn)});
  });
}

/* ================= actions ================= */
async function callAction(name,extra,btn){
  setBusy(true);spinIn(btn,true);
  try{
    var r=await api('/api/'+name,extra||{});
    if(r&&r.ok){toast(r.message,'ok');return r}
    toast((r&&r.error)||'فشل تنفيذ الأمر','bad',(r&&r.tech)||'');
    return r;
  }catch(e){
    toast('مش قادر أكلم برنامج اللوحة','bad');
    return null;
  }finally{
    spinIn(btn,false);setBusy(false);
  }
}
async function doBlock(mac,name,self,btn){
  var r=await callAction('block',{mac:mac,name:name,confirm_self:!!self},btn);
  if(r&&r.ok)loadStatus();
}
async function doUnblock(mac,name,btn){
  if(!await ask({title:'فك الحظر',body:'هفك الحظر عن "'+(name||mac)+'" وأرجّعه للإنترنت.',ok:'فك الحظر'}))return;
  var r=await callAction('unblock',{mac:mac},btn);
  if(r&&r.ok)loadStatus();
}
async function doEnableFilter(){
  if(!await ask({title:'تفعيل خاصية الحظر',body:'هفعّل قايمة الحظر (الوضع الأسود) على الراوتر.\nمحدش هيتأثر غير الأجهزة اللي تحظرها بنفسك.',ok:'تفعيل'}))return;
  var r=await callAction('enable_filter',{},'#b-mf');
  if(r&&r.ok)loadStatus();
}
async function doRedial(){
  if(BUSY||ROUTER!==true)return;
  if(!await ask({title:'تجديد الـ IP',body:'هبعت أمر إعادة تشغيل خط الـ DSL — نفس اللي زرار تجديد الـ IP في صفحة الراوتر بيعمله بالظبط.\nالإنترنت هيفصل دقيقة أو اتنين لحد ما الخط يرجع، والعنوان الجديد مش مضمون (بيعتمد على الشركة).',ok:'تجديد الـ IP'}))return;
  var old=IP;
  var r=await callAction('redial',{},'#b-redial');
  if(!r||!r.ok){progHide();return}
  var t0=Date.now(),stable=0,last='';
  prog({title:'خط الـ DSL بيعمل إعادة تشغيل',sub:'الـ IP قبل التجديد: '+(old||'غير معروف'),pct:5,secs:'0s'});
  for(var i=0;i<75;i++){
    await sleep(4000);
    var secs=Math.round((Date.now()-t0)/1000);
    prog({pct:Math.min(94,5+i*1.3),secs:secs+'s',sub:'بستنى الخط يرجع — الـ IP قبل التجديد: '+(old||'غير معروف')});
    try{
      var p=await api('/api/ping');
      if(p.router_ok&&p.public_ip){
        if(p.public_ip===last)stable++;else{last=p.public_ip;stable=1}
        var changed=old&&last!==old;
        if(changed||stable>=2){
          IP=last;progHide();renderAll();
          if(changed)toast('الـ IP اتغير: '+old+' ← '+last,'ok');
          else toast('الإنترنت رجع. الـ IP: '+last+(old?' (نفس العنوان القديم)':''),'info');
          loadStatus();return;
        }
      }
    }catch(e){}
  }
  progHide();toast('الإنترنت لسه مرجعش. استنى شوية أو اعمل إعادة تشغيل كاملة للراوتر.','bad');
}
async function doReboot(){
  if(BUSY||ROUTER!==true)return;
  if(!await ask({title:'إعادة تشغيل الراوتر كله',body:'الراوتر هيفصل بالكامل حوالي دقيقتين والإنترنت هيقطع (كل الأجهزة).\nاللوحة هتفضل مستنية لحد ما الراوتر يرجع لوحده.',ok:'إعادة التشغيل',danger:true}))return;
  var r=await callAction('reboot',{},'#b-reboot');
  if(!r||!r.ok){progHide();return}
  var t0=Date.now(),down=false;
  prog({title:'الراوتر بيعمل إعادة تشغيل',sub:'بستنى الراوتر يفصل…',pct:5,secs:'0s'});
  for(var i=0;i<85;i++){
    await sleep(3000);
    var secs=Math.round((Date.now()-t0)/1000);
    var pct=down?Math.min(96,45+i*1.1):Math.min(44,5+i*3);
    prog({pct:pct,secs:secs+'s',sub:down?'الراوتر فصل فعلاً — بستنى يرجع…':'بستنى الراوتر يفصل…'});
    try{
      var p=await api('/api/ping');
      if(!down){
        if(p.router_ok)continue;      // لسه شغال، أمر الإعادة لسه مأثرش
        down=true;
        prog({sub:'الراوتر فصل فعلاً — بستنى يرجع…'});
      }else if(p.router_ok){
        progHide();
        toast('الراوتر رجع بعد '+secs+' ثانية. الـ IP الحالي: '+(p.public_ip||'لسه بياخد عنوان'),'ok');
        await sleep(1500);loadStatus();return;
      }
    }catch(e){}
  }
  progHide();toast('الراوتر اتأخر أكتر من 4 دقايق. اتأكد من لمبات الراوتر.','bad');
}

/* ================= log ================= */
async function loadLog(withFile){
  try{
    var j=await api('/api/log'+(withFile?'?file=1':''));
    var evs=j.events||[];
    if(!LOG.length)LOG=evs.slice();
    else{
      var known={};LOG.forEach(function(e){known[e.id]=1});
      evs.forEach(function(e){if(!known[e.id]){LOG.push(e);NEWIDS[e.id]=1}});
      if(LOG.length>600)LOG=LOG.slice(-600);
    }
    LOGSEQ=j.seq||LOGSEQ;
    if(withFile&&j.file)LOGFILE=j.file;
    renderLog();
  }catch(e){}
}
function setFilter(f){
  FILTER=f;
  $('#logfilters').querySelectorAll('.fchip').forEach(function(b){b.classList.toggle('on',b.dataset.f===f)});
  renderLog();
}
function renderLog(){
  var list=$('#loglist');if(!list)return;
  var items=LOG.filter(function(e){return FILTER==='all'||e.level===FILTER});
  var last=items.length?items[items.length-1].id:0;
  var key=FILTER+'|'+items.length+'|'+last+'|'+BADGE;
  $('#logsub').textContent=LOG.length?('آخر '+LOG.length+' حدث'):'لسه مفيش أحداث';
  if(key===LOGKEY)return;
  LOGKEY=key;
  if(!items.length){
    list.innerHTML='<div class="center"><svg class="ic" style="width:30px;height:30px"><use href="#i-list"></use></svg>'+
      '<div>'+(LOG.length?'مفيش أحداث مطابقة للفلتر':'لسه مفيش أحداث — أي عملية أو خطأ هيظهر هنا فورًا')+'</div></div>';
    return;
  }
  var near=list.scrollHeight-list.scrollTop-list.clientHeight<70;
  var tagName={ok:'نجح',err:'خطأ',warn:'تحذير',info:'معلومة'};
  var t=items.slice().reverse();
  list.innerHTML=t.map(function(e){
    return '<div class="litem lvl-'+esc(e.level)+(NEWIDS[e.id]?' new':'')+'"><span class="lt">'+esc(e.ts)+'</span>'+
      '<span class="ltag">'+esc(tagName[e.level]||e.level)+'</span>'+
      '<div class="lmsg">'+esc(e.text)+(e.tech?'<div class="tech">'+esc(e.tech)+'</div>':'')+'</div></div>';
  }).join('');
  NEWIDS={};
  if($('#autoscroll').checked&&near)list.scrollTop=0;
  if(TAB==='log'){SEEN=Math.max(SEEN,LOGSEQ);BADGE=0;updBadge()}
  else{BADGE=LOG.filter(function(e){return e.id>SEEN&&e.level==='err'}).length;updBadge()}
}
async function toggleFile(){
  SHOWFILE=!SHOWFILE;
  $('#b-logfile').classList.toggle('on',SHOWFILE);
  if(SHOWFILE){
    await loadLog(true);
    $('#loglist').classList.add('hidden');
    var f=$('#logfile');f.classList.remove('hidden');
    f.textContent=(LOGFILE||[]).join('\n')||'ملف السجل فاضي.';
    f.scrollTop=f.scrollHeight;
  }else{
    $('#loglist').classList.remove('hidden');$('#logfile').classList.add('hidden');
  }
}
function copyLog(){
  var txt=SHOWFILE?(LOGFILE||[]).join('\n')
    :LOG.map(function(e){return e.ts+' ['+e.level+'] '+e.text+(e.tech?' | '+e.tech:'')}).join('\n');
  if(!txt)return toast('مفيش حاجة للنسخ','warn');
  if(navigator.clipboard)navigator.clipboard.writeText(txt).then(
    function(){toast('اتنسخ السجل','ok')},function(){toast('النسخ مش متاح في المتصفح ده','warn')});
  else toast('النسخ مش متاح في المتصفح ده','warn');
}
function clearLog(){LOG=[];LOGKEY='';NEWIDS={};renderLog();toast('اتصفّى العرض المحلي (ملف السجل على الجهاز زي ما هو)','info')}

/* ================= live speed ================= */
var SPD={rx:0,tx:0,rxV:0,txV:0,ok:false,stale:true,age:null,hist:[],line:{},rxT:0,txT:0};
function spdFmt(bps){
  var bits=bps*8,u='Mbps',v=0;
  if(bits>=1000000){v=bits/1000000;return {v:v>=100?v.toFixed(0):v.toFixed(2),u:'Mbps'}}
  if(bits>=1000){return {v:(bits/1000).toFixed(0),u:'Kbps'}}
  return {v:'0',u:'bps'};
}
function setTxt(id,txt){var e=document.getElementById(id);if(e)e.textContent=txt}
function paintSpeed(){
  var a=spdFmt(SPD.rxV),b=spdFmt(SPD.txV);
  setTxt('spd-dl',a.v); setTxt('spd-ul',b.v);
  setTxt('spd-dl2',a.v); setTxt('spd-ul2',b.v);
  var du=document.querySelectorAll('.spdu');
  if(du[0])du[0].textContent=a.u;
  if(du[1])du[1].textContent=b.u;
  var big=document.querySelectorAll('.spdbox .big span');
  if(big[0])big[0].textContent=a.u;
  if(big[1])big[1].textContent=b.u;
  var tot=(SPD.rxT+SPD.txT)/1073741824;
  setTxt('spd-tot',tot>=1?tot.toFixed(2):(tot*1024).toFixed(0));
  var tspan=document.querySelector('.spdbox.tot .big span');
  if(tspan)tspan.textContent=tot>=1?'GB':'MB';
  var chip=$('#chip-speed');
  if(chip)chip.classList.toggle('dead',!SPD.ok||SPD.stale);
  var lg=$('#spdline2');
  if(lg){
    if(SPD.line&&SPD.line.down_kbps)
      lg.textContent='سرعة الخط: '+(SPD.line.down_kbps/1000).toFixed(1)+' / '+(SPD.line.up_kbps/1000).toFixed(2)+' Mbps (Down/Up)';
    else lg.textContent='';
  }
  var ls=$('#spdline');
  if(ls){
    var s=SPD.line&&SPD.line.status?('حالة الخط: '+SPD.line.status):'';
    if(SPD.line&&SPD.line.down_max_kbps)s+=' · أقصى سرعة ممكنة للخط: '+(SPD.line.down_max_kbps/1000).toFixed(1)+' Mbps';
    ls.textContent=s;
  }
  var st=$('#spdstate');
  if(st)st.textContent=(!SPD.ok)?('⏸ القياس واقف دلوقتي'+(SPD.err?(' — '+SPD.err):'')):(SPD.stale?'⏸ آخر قياس قديم':'● قياس حي كل ثانيتين');
}
function drawChart(){
  var c=$('#spdchart'); if(!c)return;
  var dpr=window.devicePixelRatio||1;
  var w=c.clientWidth||600, h=90;
  if(!w)return;
  if(c.width!==Math.round(w*dpr)||c.height!==Math.round(h*dpr)){c.width=Math.round(w*dpr);c.height=Math.round(h*dpr);}
  var g=c.getContext('2d'); g.setTransform(dpr,0,0,dpr,0,0); g.clearRect(0,0,w,h);
  var hist=(SPD.hist||[]).slice(-90);
  g.strokeStyle='#16223a'; g.lineWidth=1;
  for(var k=1;k<4;k++){var yy=Math.round(h*k/4)+.5;g.beginPath();g.moveTo(0,yy);g.lineTo(w,yy);g.stroke();}
  if(hist.length<2)return;
  var max=1;
  hist.forEach(function(p){max=Math.max(max,p[0],p[1])});
  max*=1.2;
  function plot(idx,color,fill){
    var pts=hist.map(function(p,i){
      var x=w-(hist.length<2?0:(i/(hist.length-1))*(w-2))-1;
      var y=h-3-(Math.min(p[idx],max)/max)*(h-12);
      return [x,y];
    });
    if(fill){
      g.beginPath(); g.moveTo(pts[0][0],h);
      pts.forEach(function(q){g.lineTo(q[0],q[1])});
      g.lineTo(pts[pts.length-1][0],h); g.closePath();
      var gr=g.createLinearGradient(0,0,0,h); gr.addColorStop(0,fill); gr.addColorStop(1,'rgba(0,0,0,0)');
      g.fillStyle=gr; g.fill();
    }
    g.beginPath();
    pts.forEach(function(q,i){i?g.lineTo(q[0],q[1]):g.moveTo(q[0],q[1])});
    g.strokeStyle=color; g.lineWidth=1.7; g.lineJoin='round'; g.stroke();
  }
  plot(0,'#22c97b','rgba(34,201,123,.25)');
  plot(1,'#7ba8ff','rgba(123,168,255,.14)');
}
async function loadSpeed(){
  if(document.hidden)return;
  try{
    var s=await api('/api/speed');
    SPD.ok=!!s.ok; SPD.stale=!!s.stale;
    if(s.ok){
      SPD.rx=s.rx||0; SPD.tx=s.tx||0;
      SPD.rxT=s.rx_total||0; SPD.txT=s.tx_total||0;
      SPD.hist=s.hist||[];
    } else { SPD.err=(s.err||'').slice(0,60); }
    if(s.line&&s.line.down_kbps)SPD.line=s.line;
  }catch(e){SPD.ok=false;SPD.stale=true}
  if(SPD.ok){SPD.rxV=SPD.rx;SPD.txV=SPD.tx}
  paintSpeed();drawChart();
}
setInterval(function(){
  if(document.hidden)return;
  var t1=SPD.ok?SPD.rx:0,t2=SPD.ok?SPD.tx:0;
  SPD.rxV+=(t1-SPD.rxV)*0.4; SPD.txV+=(t2-SPD.txV)*0.4;
  if(Math.abs(SPD.rxV-t1)<400)SPD.rxV=t1;
  if(Math.abs(SPD.txV-t2)<400)SPD.txV=t2;
  paintSpeed();
},1000);
window.addEventListener('resize',function(){setTimeout(drawChart,120)});

/* ================= boot ================= */
setInterval(function(){if(document.hidden)return;if(TAB==='home')loadStatus()},15000);
setInterval(function(){if(document.hidden)return;loadLog(SHOWFILE)},4000);
document.addEventListener('visibilitychange',function(){if(!document.hidden)loadStatus()});
renderAll();
loadStatus();
loadLog(true);
loadSpeed();
setInterval(function(){if(!document.hidden)loadSpeed()},4000);
</script>
</body>
</html>"""


class State:
    def __init__(self, cfg):
        self.cfg = cfg
        self.router = Router(cfg)
        self.lock = threading.Lock()
        self.token = secrets.token_urlsafe(24)
        self.started = time.time()
        self.router_ok = False


def make_handler(state):
    cfg = state.cfg
    dash_auth = ("Basic " + base64.b64encode(("admin:" + cfg["dash_password"]).encode()).decode()) if cfg["dash_password"] else None

    class H(http.server.BaseHTTPRequestHandler):
        server_version = "RouterDash"

        def log_message(self, fmt, *a):
            pass

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
            self.wfile.write(b)

        def _host_ok(self):
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            if host == "localhost":
                return True
            try:
                ipaddress.ip_address(host)
                return True
            except ValueError:
                return False

        def _authed(self):
            if not self._host_ok():
                self._send(403, {"ok": False, "error": "Host غير مسموح"})
                return False
            if dash_auth and self.headers.get("Authorization") != dash_auth:
                self._send(401, "مطلوب باسورد اللوحة (اسم المستخدم admin)", "text/plain; charset=utf-8",
                           {"WWW-Authenticate": 'Basic realm="router"'})
                return False
            return True

        def do_GET(self):
            if not self._authed():
                return
            if self.path in ("/", "/index.html"):
                return self._send(200, PAGE.replace("__TOKEN__", state.token).replace("__VERSION__", VERSION),
                                  "text/html; charset=utf-8")
            if not self.headers.get("X-Token") == state.token:
                return self._send(403, {"ok": False, "error": "token"})
            if self.path.startswith("/api/ping"):
                return self._send(200, self._ping())
            if self.path.startswith("/api/status"):
                return self._send(200, self._status())
            if self.path.startswith("/api/log"):
                return self._send(200, self._log("file=1" in self.path))
            if self.path.startswith("/api/speed"):
                return self._send(200, speed_snapshot())
            self._send(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            if not self._authed():
                return
            if self.headers.get("X-Token") != state.token:
                return self._send(403, {"ok": False, "error": "token"})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                data = {}
            name = self.path.rsplit("/", 1)[-1]
            if name == "login":
                return self._send(200, self._login(data))
            if name == "logout":
                return self._send(200, self._logout(data))
            self._send(200, self._action(name, data))

        def _ping(self):
            ok = False
            was = state.router_ok
            with state.lock:
                try:
                    state.router.connect()
                    ok = True
                except RouterError:
                    ok = False
                state.router_ok = ok
            if ok and not was:
                event("ok", "الراوتر رجع للاتصال")
            return {"router_ok": ok, "public_ip": public_ip() if ok else "", "ts": now_str(),
                    "uptime": int(time.time() - state.started)}

        def _log(self, with_file=False):
            with EVENT_LOCK:
                evs = list(EVENTS[-250:])
                seq = EVENT_SEQ[0]
            out = {"seq": seq, "events": evs}
            if with_file:
                try:
                    with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()[-160:]
                    out["file"] = [redact(x.rstrip("\n")) for x in lines]
                except OSError:
                    out["file"] = []
            return out

        def _auth_info(self):
            return {"username": cfg["username"], "has_password": bool(cfg["password"]),
                    "logged_in": bool(state.router.logged_in), "router_ok": bool(state.router_ok)}

        def _status(self):
            me = self.client_address[0]
            ips = local_ips(cfg["ip"])
            if not me.startswith("127.") and me != "::1":
                ips.add(me)
            info = {"ts": now_str(), "me_ips": sorted(ips), "me_macs": sorted(own_macs(cfg["ip"])),
                    "uptime": int(time.time() - state.started), "auth": self._auth_info()}
            if not cfg["password"]:
                info.update({"router_ok": False, "error": "لازم تدخل يوزر وباسورد الراوتر الأول.",
                             "tech": "no credentials"})
                info["public_ip"] = ""
                return info
            with state.lock:
                try:
                    devs = state.router.devices()
                    mf = None
                    try:
                        mf = state.router.macfilter()
                        mf.pop("token", None)
                    except RouterError as e:
                        event("warn", "قراءة قايمة الحظر فشلت", e.tech)
                    online = sum(1 for d in devs if d["status"] == "Online")
                    blocked = len((mf or {}).get("entries") or [])
                    state.router_ok = True
                    info.update({"router_ok": True, "devices": devs, "macfilter": mf,
                                 "counts": {"online": online, "offline": len(devs) - online,
                                            "total": len(devs), "blocked": blocked}})
                except RouterError as e:
                    state.router_ok = False
                    event("err", "تحديث الحالة", "%s | %s" % (e.ar, e.tech or "-"))
                    info.update({"router_ok": False, "error": e.ar, "tech": e.tech})
                except Exception as e:
                    state.router_ok = False
                    log(traceback.format_exc())
                    event("err", "خطأ غير متوقع في البرنامج", repr(e))
                    info.update({"router_ok": False, "error": "خطأ غير متوقع في البرنامج.", "tech": repr(e)})
            info["auth"] = self._auth_info()
            info["public_ip"] = public_ip()
            return info

        def _login(self, data):
            user = str(data.get("username") or "").strip() or "admin"
            pw = str(data.get("password") or "")
            if not pw:
                return {"ok": False, "error": "اكتب باسورد الراوتر."}
            cfg["username"] = user
            cfg["password"] = pw
            with state.lock:
                state.router = Router(cfg)
                try:
                    where = state.router.login()
                except RouterError as e:
                    state.router_ok = False
                    event("err", "فشل تسجيل الدخول للراوتر", "%s | %s" % (e.ar, e.tech or "-"))
                    return {"ok": False, "error": e.ar, "tech": e.tech}
                state.router_ok = True
            saved = ""
            if data.get("save"):
                saved = " واتحفظوا في config.ini." if save_credentials(cfg) else " (مقدرتش أحفظهم في config.ini)."
            event("ok", "تم تسجيل الدخول للراوتر", "%s | %s%s" % (user, where, saved))
            return {"ok": True, "message": "تم تسجيل الدخول للراوتر" + (" واتحفظت البيانات." if saved else "."),
                    "saved": bool(saved), "auth": self._auth_info()}

        def _logout(self, data):
            with state.lock:
                state.router.logged_in = False
                state.router._close()
                state.router.jar = {}
                state.router_ok = False
            if data.get("forget"):
                cfg["password"] = ""
                save_credentials(cfg)
                event("info", "اتمسح الباسورد المحفوظ")
            event("info", "تم تسجيل الخروج من الراوتر")
            return {"ok": True, "message": "تم تسجيل الخروج.", "auth": self._auth_info()}

        def _action(self, name, data):
            r = state.router
            mac = str(data.get("mac", "")).lower()
            if name in ("block", "unblock") and not MAC_RE.match(mac):
                return {"ok": False, "error": "عنوان MAC غير صالح."}
            if not cfg["password"]:
                return {"ok": False, "error": "لازم تسجّل الدخول للراوتر الأول (يوزر وباسورد).", "tech": "no credentials"}
            t0 = time.time()
            with state.lock:
                try:
                    old_ip = ""
                    if name == "redial":
                        old_ip = public_ip()
                        msg = r.redial()
                    elif name == "reboot":
                        msg = r.reboot()
                    elif name == "block":
                        me_ips = local_ips(cfg["ip"])
                        ca = self.client_address[0]
                        if not ca.startswith("127.") and ca != "::1":
                            me_ips.add(ca)
                        mine_macs = own_macs(cfg["ip"])
                        dev = next((d for d in r.devices() if d["mac"] == mac), None)
                        is_me = (dev and dev["ip"] in me_ips) or mac in mine_macs
                        if is_me and not data.get("confirm_self"):
                            return {"ok": False, "error": "ده جهازك إنت. لو حظرته هتفصل عن الراوتر ومش هتقدر تفتح اللوحة تفك الحظر. مأكدتش الحظر.", "tech": "self-block needs confirmation"}
                        msg = r.block(mac, str(data.get("name", "")))
                    elif name == "unblock":
                        msg = r.unblock(mac)
                    elif name == "enable_filter":
                        msg = r.enable_blacklist()
                    else:
                        return {"ok": False, "error": "أمر غير معروف."}
                    if name not in ("redial", "reboot"):
                        event("ok", "%s — تم" % ACTION_LABEL.get(name, name), mac_mask(mac) if mac else "")
                    return {"ok": True, "message": msg, "old_ip": old_ip, "secs": round(time.time() - t0, 1)}
                except RouterError as e:
                    event("err", "%s — فشل" % ACTION_LABEL.get(name, name), "%s | %s" % (e.ar, e.tech or "-"))
                    return {"ok": False, "error": e.ar, "tech": e.tech}
                except Exception as e:
                    log(traceback.format_exc())
                    event("err", "%s — خطأ غير متوقع" % ACTION_LABEL.get(name, name), repr(e))
                    return {"ok": False, "error": "خطأ غير متوقع في البرنامج.", "tech": repr(e)}
    return H


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    args = sys.argv[1:]
    try:
        cfg = load_config()
        if "--selftest" in args:
            ensure_password(cfg)
            ok, _ = selftest(cfg, print)
            return 0 if ok else 1
        if "--diagnose" in args:
            ensure_password(cfg)
            diagnose(cfg)
            return 0
        state = State(cfg)
        if cfg["host"] not in ("127.0.0.1", "localhost", "::1") and not cfg["dash_password"]:
            raise RouterError("أنت فاتح اللوحة للشبكة (host غير 127.0.0.1) من غير باسورد للوحة. حط password في قسم [dashboard] في config.ini.")
        if cfg["password"]:
            print("بفحص الاتصال بالراوتر الأول...")
            ok, _ = selftest(cfg, print)
            if not ok:
                print("\nفيه مشكلة في الفحص فوق. اللوحة هتفتح برضه، وأول ما الراوتر يرجع هتتوصّل لوحدها.")
        else:
            print("مفيش باسورد محفوظ. افتح اللوحة واكتب اليوزر والباسورد من صندوق الدخول (وممكن تعلم على \"احفظ\" لو عايز تنحفظ).")
        srv = http.server.ThreadingHTTPServer((cfg["host"], cfg["dash_port"]), make_handler(state))
        url = "http://%s:%d/" % ("127.0.0.1" if cfg["host"] in ("0.0.0.0", "") else cfg["host"], cfg["dash_port"])
        print("\nاللوحة شغالة على: %s\nسيب النافذة دي مفتوحة. للإغلاق: Ctrl+C أو اقفل النافذة." % url)
        event("info", "اللوحة اشتغلت", url)
        threading.Thread(target=watchdog, args=(state,), daemon=True).start()
        threading.Thread(target=speed_sampler, args=(state,), daemon=True).start()
        if cfg["open_browser"]:
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nتم الإغلاق.")
        return 0
    except RouterError as e:
        print("\nخطأ: %s" % e.ar)
        if e.tech:
            print("(تفاصيل فنية: %s)" % e.tech)
        return 1
    except OSError as e:
        print("\nمقدرتش أشغّل اللوحة (%s). لو البورت مشغول غيّر port في config.ini." % e)
        return 1


if __name__ == "__main__":
    code = main()
    if os.name == "nt" and code:
        try:
            input("\nاضغط Enter للإغلاق...")
        except EOFError:
            pass
    sys.exit(code)
