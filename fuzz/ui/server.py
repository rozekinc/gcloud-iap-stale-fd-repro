"""Tiny results server: tails results/{A,B}.jsonl, serves the page and /api/state.

Listens on 0.0.0.0 inside its container; compose publishes it on 127.0.0.1 only.
"""
import collections
import http.server
import json
import os
import sys
import threading
import time

sys.path.insert(0, "/fuzz/inject")
import cgstats  # noqa: E402

RESULTS = os.environ.get("FUZZ_RESULTS", "/results")
CONTROL = os.environ.get("FUZZ_CONTROL", "/control/intensity.json")
LEVELS = ("low", "medium", "high")
ALLOWED_HOSTS = ("127.0.0.1:8099", "localhost:8099")
HERE = os.path.dirname(os.path.abspath(__file__))
STRIP = 500
CHUNK = 1 << 20


def read_control():
  c = {"running": False, "level": "low"}
  try:
    with open(CONTROL) as f:
      saved = json.load(f)
    c["running"] = bool(saved.get("running"))
    if saved.get("level") in LEVELS:
      c["level"] = saved["level"]
  except (OSError, ValueError):
    pass
  return c


def write_control(c):
  tmp = CONTROL + ".tmp"
  with open(tmp, "w") as f:
    json.dump(dict(c, t=time.time()), f)
  os.replace(tmp, CONTROL)


def read_stats():
  out = {}
  for name in ("A", "B", "UI"):
    try:
      with open(os.path.join(RESULTS, name + ".stats.json")) as f:
        out[name] = json.load(f)
    except (OSError, ValueError):
      out[name] = None
  return out


def clear_results():
  now = time.time()
  for s in SIDES.values():
    try:
      with open(s.path, "r+b") as f:
        f.truncate(0)
    except FileNotFoundError:
      pass
    # The harness logs which code it loaded only at startup; keep that.
    patched, delay_ms = s.patched, s.delay_ms
    s.reset()
    s.patched, s.delay_ms = patched, delay_ms
    # An iteration still in flight at Stop finishes after the clear; drop it.
    s.cleared_at = now


class Side(object):

  def __init__(self, name):
    self.name = name
    self.path = os.path.join(RESULTS, name + ".jsonl")
    self.cleared_at = 0
    self.reset()

  def reset(self):
    self.pos = 0
    self.partial = b""
    self.iters = self.fails = self.errors = self.stale = 0
    self.first_t = self.last_t = self.last_fail_t = None
    self.last_fail = None
    self.last_err = None
    self.starts = 0
    self.patched = None
    self.delay_ms = None
    self.strip = collections.deque(maxlen=STRIP)
    self.recent = collections.deque()

  def poll(self):
    try:
      size = os.path.getsize(self.path)
    except OSError:
      return
    if size < self.pos:
      self.reset()
    with open(self.path, "rb") as f:
      f.seek(self.pos)
      while True:
        data = f.read(CHUNK)
        if not data:
          break
        self.pos += len(data)
        lines = (self.partial + data).split(b"\n")
        self.partial = lines.pop()
        for line in lines:
          try:
            self.add(json.loads(line))
          except (ValueError, AttributeError):
            pass

  def per_min(self, now):
    while self.recent and self.recent[0] < now - 60:
      self.recent.popleft()
    return len(self.recent)

  def add(self, r):
    t = r.get("t")
    if t is not None and t < self.cleared_at:
      return
    if r.get("start"):
      self.starts += 1
      self.patched = r.get("patched")
      self.delay_ms = r.get("delay_ms")
      return
    if self.first_t is None:
      self.first_t = t
    self.last_t = t
    if r.get("ok") is None:
      self.errors += 1
      self.last_err = r.get("err")
      self.strip.append({"s": "e", "i": r.get("i"), "t": t})
      return
    self.iters += 1
    if t is not None and t >= time.time() - 60:
      self.recent.append(t)
    if r.get("fd") and r["fd"] != "socket":
      self.stale += 1
    if r["ok"]:
      self.strip.append({"s": "o", "i": r.get("i"), "t": t})
    else:
      self.fails += 1
      self.last_fail_t = t
      self.last_fail = r
      self.strip.append({"s": "f", "i": r.get("i"), "t": t})

  def state(self):
    return {
        "name": self.name, "patched": self.patched, "delay_ms": self.delay_ms,
        "starts": self.starts, "iters": self.iters, "fails": self.fails,
        "errors": self.errors, "stale": self.stale,
        "first_t": self.first_t, "last_t": self.last_t,
        "last_fail_t": self.last_fail_t, "last_fail": self.last_fail,
        "last_err": self.last_err, "strip": list(self.strip),
        "per_min": self.per_min(time.time()),
    }


SIDES = {n: Side(n) for n in ("A", "B")}
LOCK = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
  timeout = 10

  def log_message(self, *args):
    pass

  def send(self, code, ctype, body):
    self.send_response(code)
    self.send_header("Content-Type", ctype)
    self.send_header("Cache-Control", "no-store")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def do_GET(self):
    if self.headers.get("Host") not in ALLOWED_HOSTS:
      self.send(403, "text/plain", b"forbidden")
    elif self.path == "/api/state":
      with LOCK:
        for s in SIDES.values():
          s.poll()
        body = json.dumps({"now": time.time(), "control": read_control(),
                           "containers": read_stats(),
                           "sides": [s.state() for s in SIDES.values()]})
      self.send(200, "application/json", body.encode())
    elif self.path in ("/", "/index.html"):
      with open(os.path.join(HERE, "index.html"), "rb") as f:
        self.send(200, "text/html; charset=utf-8", f.read())
    else:
      self.send(404, "text/plain", b"not found")

  def do_POST(self):
    # JSON content type forces a CORS preflight, and the Host check stops DNS
    # rebinding, so only this page can drive the fuzz.
    if (self.path != "/api/control"
        or self.headers.get("Host") not in ALLOWED_HOSTS
        or self.headers.get("Content-Type") != "application/json"):
      self.send(403, "text/plain", b"forbidden")
      return
    try:
      n = max(0, min(int(self.headers.get("Content-Length", "0")), 256))
      req = json.loads(self.rfile.read(n))
    except ValueError:
      req = {}
    if not isinstance(req, dict):
      req = {}
    with LOCK:
      c = read_control()
      action = req.get("action")
      if action == "start":
        c["running"] = True
      elif action == "stop":
        c["running"] = False
      elif action == "level" and req.get("level") in LEVELS:
        c["level"] = req["level"]
      elif action == "clear" and not c["running"]:
        clear_results()
      else:
        self.send(400, "text/plain", b"bad request")
        return
      write_control(c)
    self.send(200, "application/json", json.dumps(c).encode())


if __name__ == "__main__":
  cgstats.start(os.path.join(RESULTS, "UI.stats.json"))
  http.server.ThreadingHTTPServer(("0.0.0.0", 8099), Handler).serve_forever()
