"""Drives gcloud's own IAP tunnel websocket against the fake relay, forever.

Each iteration: open a tunnel (IapTunnelWebSocket, the code
`compute start-iap-tunnel` uses), let data flow, arm the read delay, call the
tunnel's own Close() from the main thread while the reader sits in the SSL
read, reopen the configs DB through config_sqlite_store, then check the DB.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time

sys.path[:0] = ["/google-cloud-sdk/lib", "/google-cloud-sdk/lib/third_party"]

import cgstats  # noqa: E402
import fuzz_inject as inj  # noqa: E402  (also loaded by sitecustomize)

from googlecloudsdk.api_lib.compute import iap_tunnel_lightweight_websocket as lw  # noqa: E402
from googlecloudsdk.api_lib.compute import iap_tunnel_websocket  # noqa: E402
from googlecloudsdk.api_lib.compute import iap_tunnel_websocket_utils as utils  # noqa: E402
from googlecloudsdk.core import config  # noqa: E402
from googlecloudsdk.core import config_sqlite_store  # noqa: E402
from googlecloudsdk.core import log  # noqa: E402

SIDE = os.environ.get("SIDE", "?")
OUT = os.environ.get("FUZZ_OUT", "/results/%s.jsonl" % SIDE)
PORT = int(os.environ.get("FUZZ_RELAY_PORT", "8443"))
HEX_BYTES = 64
CONTROL = os.environ.get("FUZZ_CONTROL", "/control/intensity.json")
# level -> (pause between iterations s, background opener sleep s); None = paused.
LEVELS = {
    "paused": None,
    "low": (2.0, 0.05),
    "medium": (0.2, 0.005),
    "high": (0.0, 0.001),
}
opener_stop = threading.Event()
# Idle until Start is pressed in the UI.
_control = {"mtime": None, "level": "paused"}


def current_level():
  """Start/stop + intensity from the UI; re-read only when the file changes."""
  try:
    mtime = os.stat(CONTROL).st_mtime
  except OSError:
    return "paused"
  if mtime != _control["mtime"]:
    _control["mtime"] = mtime
    try:
      with open(CONTROL) as f:
        c = json.load(f)
      level = c.get("level")
      if not c.get("running"):
        _control["level"] = "paused"
      elif level in LEVELS:
        _control["level"] = level
    except (OSError, ValueError):
      pass
  return _control["level"]


def touch_db(i):
  store = config_sqlite_store.GetConfigStore()
  store.Set("fuzz_attr", "v%d" % i)
  store.Get("fuzz_attr")


def opener_loop():
  """Background cache opener: gcloud property store get/set in a tight loop."""
  i = 0
  while not opener_stop.is_set():
    pace = LEVELS[current_level()]
    if pace is None:
      time.sleep(1)
      continue
    i += 1
    try:
      touch_db(i)
    except Exception:  # pylint: disable=broad-except
      pass  # a corrupted DB raises here too; the main loop counts it
    time.sleep(pace[1])


def check_db(path):
  """Returns (ok, detail dict)."""
  try:
    with open(path, "rb") as f:
      head = f.read(4096)
  except FileNotFoundError:
    return True, {}
  detail = {}
  tls_at = head.find(b"\x17\x03\x03")
  if tls_at >= 0:
    detail["tls_off"] = tls_at
  if not head.startswith(b"SQLite format 3\0") and head:
    detail["bad_magic"] = True
  try:
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
      res = con.execute("PRAGMA quick_check").fetchone()[0]
    finally:
      con.close()
    if res != "ok":
      detail["quick_check"] = res[:120]
  except sqlite3.DatabaseError as e:
    detail["quick_check"] = str(e)[:120]
  if detail:
    detail["head_hex"] = head[:HEX_BYTES].hex()
    return False, detail
  return True, {}


def remove_db(path):
  for suffix in ("", "-journal", "-wal", "-shm"):
    try:
      os.remove(path + suffix)
    except FileNotFoundError:
      pass


def wait_port():
  for _ in range(200):
    try:
      socket.create_connection(("127.0.0.1", PORT), 0.2).close()
      return
    except OSError:
      time.sleep(0.05)
  raise SystemExit("relay did not start")


def one_iteration(i, target, db_path):
  got_data = threading.Event()
  closed = threading.Event()

  def on_data(_data):
    got_data.set()

  ws = iap_tunnel_websocket.IapTunnelWebSocket(
      target, lambda: "dummy-token", on_data, closed.set,
      user_agent="fdrace-fuzz", conn_id=i)
  # Built before Close(): its constructor runs CREATE TABLE in a short-lived
  # connection, which must not take the freed fd.
  store = config_sqlite_store.GetConfigStore()
  t0 = time.monotonic()
  inj.in_read.clear()
  inj.last_fd_kind[0] = ""
  try:
    ws.InitiateConnection()
    if not got_data.wait(5):
      raise RuntimeError("no data from relay")
    inj.armed.set()
    if not inj.in_read.wait(5):
      raise RuntimeError("reader never entered SSL read")
  except BaseException:
    inj.armed.clear()
    ws.Close()
    raise
  helper = ws._websocket_helper  # pylint: disable=protected-access
  reader = helper and helper._receiving_thread  # pylint: disable=protected-access
  ws.Close()
  # Hold the DB open via gcloud's own cursor until the reader exits, so the
  # freed fd number is the DB during the delayed read.
  try:
    with store._cursor as cur:  # pylint: disable=protected-access
      cur.Execute("SELECT value FROM config WHERE config_attr = ?",
                  ("fuzz_attr",)).fetchone()
      if reader:
        reader.join(5)
  except Exception:  # pylint: disable=broad-except
    if reader:  # a corrupted DB can raise before the join; check_db records it
      reader.join(5)
  ok, detail = check_db(db_path)
  rec = {"t": round(time.time(), 3), "side": SIDE, "i": i, "ok": ok,
         "fd": inj.last_fd_kind[0],
         "ms": round((time.monotonic() - t0) * 1000, 1)}
  if not ok:
    rec.update(detail)
    remove_db(db_path)
  return rec


def main():
  log.SetVerbosity(None)
  cgstats.start(os.path.join(os.path.dirname(OUT), "%s.stats.json" % SIDE))
  patched = hasattr(lw.IapLightWeightWebsocket, "_release_socket")
  relay = subprocess.Popen([sys.executable, "-I", "/fuzz/relay.py"])
  wait_port()
  os.environ["CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"] = os.path.join(
      os.environ.get("FUZZ_CERT_DIR", "/state/certs"), "ca.pem")
  target = utils.IapTunnelTargetInfo(
      project="fuzz-project", zone="fuzz-zone-a", instance="fuzz-vm",
      interface="nic0", port=22, url_override="wss://localhost:%d" % PORT,
      proxy_info=None, network=None, region=None, host=None, dest_group=None,
      cloud_run_args=None)
  touch_db(0)
  db_path = config.Paths().config_db_path.format("default")
  out = open(OUT, "a", buffering=1)
  out.write(json.dumps({"t": round(time.time(), 3), "side": SIDE,
                        "start": True, "patched": patched,
                        "delay_ms": inj.DELAY * 1000,
                        "db": os.path.basename(db_path)}) + "\n")
  threading.Thread(target=opener_loop, daemon=True).start()
  i = 0
  try:
    while True:
      level = current_level()
      pace = LEVELS[level]
      if pace is None:
        time.sleep(1)
        continue
      time.sleep(pace[0])
      i += 1
      try:
        touch_db(i)  # the DB must exist with content for a stale read to hit it
      except sqlite3.DatabaseError:
        remove_db(db_path)
      try:
        rec = one_iteration(i, target, db_path)
      except Exception as e:  # pylint: disable=broad-except
        rec = {"t": round(time.time(), 3), "side": SIDE, "i": i, "ok": None,
               "err": ("%s: %s" % (type(e).__name__, e))[:200]}
        time.sleep(0.2)
      rec["lv"] = level
      out.write(json.dumps(rec) + "\n")
      if relay.poll() is not None:
        raise SystemExit("relay died")
  finally:
    opener_stop.set()
    relay.kill()


if __name__ == "__main__":
  main()
