"""Fixtures shared by several test modules, so no test module imports another (#71)."""
import base64
import json
import os
import pathlib
import random
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import hearth.main
from hearth import collectors, crypto, mesh, store


# ---- a database in memory, and two client MACs (from test_router_usage)
MAC_A, MAC_B = "1c:f6:4c:5e:00:01", "60:cf:84:5e:00:02"


def mem_db():
    c = sqlite3.connect(":memory:")
    c.executescript(store.SCHEMA)
    for col in ("vendor", "friendly", "model"):  # added by init_db's migration in real installs
        c.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT")
    return c


# ---- a scripted TP-Link Deco (from test_mesh)
MAIN, OFFICE, LOUNGE = "20:e1:5d:5e:00:03", "20:e1:5d:5e:00:04", "20:e1:5d:5e:00:05"
PC, SERVER, SHIELD = "60:cf:84:5e:00:02", "50:eb:f6:5e:00:06", "48:b0:2d:5e:00:07"
b64 = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731

DEVICE_LIST = {"device_list": [
    {"mac": "20-E1-5D-5E-00-04", "device_ip": "192.168.1.237", "nickname": b64("Office"), "role": "slave",
     "parent_device_id": "AB12", "connection_type": ["band5", "band6"], "signal_level": {"band5": "2", "band6": "3"},
     "group_status": "connected", "device_model": "BE9300"},
    {"mac": "20-E1-5D-5E-00-03", "device_ip": "192.168.1.231", "nickname": b64("Bedroom"), "role": "master",
     "device_id": "AB12", "group_status": "connected"},
    {"mac": "20-E1-5D-5E-00-05", "device_ip": "192.168.1.163", "nickname": b64("Living Room"), "role": "slave",
     "parent_device_id": "AB12", "connection_type": ["wired"], "group_status": "connected"},
    "junk", {"no": "mac"},
]}

class FakeConn:
    """Stands in for http.client.HTTPSConnection: a scripted Deco."""
    cert = b"certificate-A"

    def __init__(self, deco):
        self.deco = deco
        self.sock = mock.Mock()
        self.sock.getpeercert.return_value = FakeConn.cert

    def connect(self):
        pass

    def request(self, method, path, body, headers):
        self.deco.sent.append(body)
        self._reply = self.deco.answer(path, body)

    def getresponse(self):
        r = mock.Mock(status=200)
        r.read.return_value = json.dumps(self._reply).encode()
        r.headers.get_all.return_value = ["sysauth=abc; path=/"]
        return r

    def close(self):
        pass


class FakeDeco:
    """Speaks the Deco login: RSA keys we hold the private half of, AES session from the sign."""
    P = 0xF7E75FDC469067FFDC4E847C51F452DF
    Q = 0xE85CED54AF57E53E092113E62F436F4F

    def __init__(self, password):
        self.n, self.d = self.P * self.Q, pow(65537, -1, (self.P - 1) * (self.Q - 1))
        self.password, self.sent, self.key = password, [], None

    def _rsa_decrypt(self, hexs):
        k = (self.n.bit_length() + 7) // 8
        out = b""
        for i in range(0, len(hexs), k * 2):
            block = pow(int(hexs[i:i + k * 2], 16), self.d, self.n).to_bytes(k, "big")
            out += block[block.index(b"\x00", 2) + 1:]
        return out.decode()

    def answer(self, path, body):
        body = body.decode()
        if path.endswith("form=keys"):
            return {"result": {"password": [format(self.n, "x"), "10001"]}}
        if path.endswith("form=auth"):
            return {"result": {"key": [format(self.n, "x"), "10001"], "seq": 100}}
        from urllib.parse import parse_qs
        form = parse_qs(body)
        sign = dict(p.split("=", 1) for p in self._rsa_decrypt(form["sign"][0]).split("&"))
        key, iv = sign["k"].encode(), sign["i"].encode()
        req = json.loads(crypto.aes_cbc_decrypt(key, iv, base64.b64decode(form["data"][0])))
        if path.endswith("form=login"):
            ok = self._rsa_decrypt(req["params"]["password"]) == self.password
            reply = {"error_code": 0, "result": {"stok": "abc123"}} if ok else {"error_code": -5002}
        elif "form=device_list" in path:
            reply = {"error_code": 0, "result": DEVICE_LIST}
        else:
            reply = {"error_code": 0, "result": {"client_list": [
                {"mac": "60-CF-84-5E-00-02", "ip": "192.168.1.228", "online": True, "connection_type": "wired"}]
                if req["params"]["device_mac"] == getattr(self, "pc_unit", "20-E1-5D-5E-00-04") else []}}
        return {"data": base64.b64encode(crypto.aes_cbc_encrypt(key, iv, json.dumps(reply).encode())).decode()}

def snapshot():
    nodes = mesh.link_parents(mesh.parse_nodes(DEVICE_LIST))
    return {"ts": 0, "nodes": nodes, "clients": [
        {"mac": SERVER, "ip": "192.168.1.60", "node": OFFICE, "link": "wired"},
        {"mac": PC, "ip": "192.168.1.228", "node": OFFICE, "link": "wired"},
        {"mac": SHIELD, "ip": "192.168.1.137", "node": LOUNGE, "link": "wired"}]}


# ---- the mesh loop against the scripted Deco (from test_mesh_trust)
HOST = "192.168.1.231"

def run_mesh_loop(test, change, readings=2, each=None):
    """mesh_loop with the real client against the scripted Deco: a first reading with certificate
    A, then `change(fake)` runs and the loop reads `readings - 1` more times; `each(fake, n)`, if
    given, runs after every reading n (from 1). Cleanups go on `test`. Returns
    (database, the events waited on, the safe_arp mock)."""
    db = mem_db()
    test.addCleanup(db.close)
    fd, pw = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write("DECO_PASSWORD=s3cret\n")
    test.addCleanup(os.remove, pw)
    FakeConn.cert = b"certificate-A"
    test.addCleanup(setattr, FakeConn, "cert", b"certificate-A")
    test.addCleanup(mesh.TRUSTED.clear)
    stop, waits, fake = threading.Event(), [], FakeDeco("s3cret")

    def fake_wait(stop_, event, timeout, **kw):
        waits.append(event)
        if len(waits) == 1:
            change(fake)
        if each:
            each(fake, len(waits))
        if len(waits) < readings:
            return "event"
        stop.set()
        return "stop"
    with mock.patch.object(collectors, "store", wraps=store) as st, \
            mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)), \
            mock.patch.object(collectors.mesh, "find_candidates", return_value=[HOST]), \
            mock.patch.object(collectors, "safe_arp", return_value={HOST: MAIN}) as arp, \
            mock.patch.object(collectors.router, "credentials_path", return_value=pw), \
            mock.patch.object(collectors, "log"), \
            mock.patch.object(collectors, "wait_either", side_effect=fake_wait), \
            mock.patch.multiple(collectors, ROUTER_MIN_REFRESH_GAP_S=0):
        st.db.return_value = db
        collectors.mesh_loop(stop)
    return db, waits, arp


# ---- the dashboard's source (from test_net_web)
def strip_comments(text):
    """JavaScript/CSS comments removed, so the source checks below can't be satisfied (or
    tripped) by text in a comment. A `//` counts as a comment only at the start of a line or
    after whitespace, which leaves URLs like "http://..." in strings alone."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(^|[ \t])//[^\n]*", r"\1", text, flags=re.M)


_DASHBOARD_JS = pathlib.Path(hearth.main.__file__).parent.parent / "dashboard.js"


def page_code():
    """The dashboard - its markup (dashboard.html) and script (dashboard.js) - comments removed."""
    root = pathlib.Path(hearth.main.__file__).parent.parent
    return strip_comments("\n".join((root / f).read_text(encoding="utf-8") for f in ("dashboard.html", "dashboard.js")))


# ---- timing series for the topology tests (from test_topology)
GW = "gateway"


def make_series(spec, seconds=1800, step=5, seed=1, events=()):
    """spec: {target: (floor_ms, spread_ms)}. events: [(start_s, dur_s, {targets}, extra_ms|None)]
    None = packet loss. Devices and router are sampled on the same 5 s ticks."""
    rnd = random.Random(seed)
    out = {}
    for t, (floor, spread) in spec.items():
        rows = []
        for i in range(0, seconds, step):
            rtt = floor + rnd.random() * spread
            for start, dur, who, extra in events:
                if t in who and start <= i < start + dur:
                    rtt = None if extra is None else rtt + extra
            rows.append((1_000_000 + i, rtt))
        out[t] = rows
    return out


def spikes_every(n, who, every=90, dur=10, extra=120):
    return [(30 + k * every, dur, who, extra) for k in range(n)]


# ---- running pieces of dashboard.js in node, against a small stand-in for the browser (#111)
NODE = shutil.which("node")
needs_node = unittest.skipUnless(NODE, "node isn't installed")

# document.querySelector gives one stand-in element per selector (hidden, textContent,
# innerHTML - counting writes - and click listeners); localStorage can be made to throw, as
# when a browser blocks storage; location.hash is settable
JS_DOM = r"""
const _els={};
function _el(sel){
  const e={sel,hidden:false,textContent:"",value:"",checked:false,writes:0,_html:"",_on:{},
    addEventListener(t,f){(this._on[t]=this._on[t]||[]).push(f)},
    click(){(this._on.click||[]).forEach(f=>f({preventDefault(){}}))},
    // runs the listeners and waits for them (an async submit handler finishes first)
    dispatch(t){return Promise.all((this._on[t]||[]).map(f=>f({preventDefault(){}})))}};
  Object.defineProperty(e,"innerHTML",{get(){return this._html},set(v){this._html=String(v);this.writes++}});
  return e;
}
const document={querySelector:s=>_els[s]||(_els[s]=_el(s))};
let _store={}, _storageBlocked=false;
const localStorage={
  getItem(k){if(_storageBlocked)throw new Error("blocked");return Object.prototype.hasOwnProperty.call(_store,k)?_store[k]:null},
  setItem(k,v){if(_storageBlocked)throw new Error("blocked");_store[k]=String(v)}};
const location={hash:""};
// fetch records each request (its JSON body parsed) and answers with _reply
let _fetches=[], _reply={status:200,body:{}};
async function fetch(url,opt={}){
  _fetches.push({url,method:opt.method||"GET",body:opt.body?JSON.parse(opt.body):null});
  return {ok:_reply.status<400,status:_reply.status,json:async()=>_reply.body};
}
"""


def js_defs(*starts):
    """Top-level statements of dashboard.js (comments removed), each found by how its first line
    starts (e.g. "const esc=", "function readHash(") and running to just before the next line at
    the left margin - so a multi-line constant or a whole function comes with it."""
    lines = strip_comments(_DASHBOARD_JS.read_text(encoding="utf-8")).split("\n")
    out = []
    for s in starts:
        i = next((n for n, line in enumerate(lines) if line.startswith(s)), None)
        if i is None:
            raise AssertionError(f"dashboard.js has no top-level {s!r}")
        j = i + 1
        while j < len(lines) and (not lines[j] or lines[j][0] in " \t}])"):
            j += 1
        out.append("\n".join(lines[i:j]))
    return "\n".join(out)


def run_js(code, expr):
    """Run `code` in node, then print JSON.stringify(expr) - awaited if it's a promise; the
    parsed result."""
    script = (f"{code}\nPromise.resolve().then(async()=>({expr})).then(v=>console.log(JSON.stringify(v)),"
              f"e=>{{console.error(e);process.exit(1)}});")
    out = subprocess.run([NODE or "node", "-e", script], capture_output=True, text=True, encoding="utf-8", timeout=30)
    if out.returncode:
        raise AssertionError(f"node failed:\n{out.stderr[-2000:]}")
    return json.loads(out.stdout)
