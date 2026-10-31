"""Writes this container's own cgroup v2 stats (usage and caps) for the UI.

Read from inside the container, so the UI needs no docker socket.
"""
import json
import os
import threading
import time

CG = "/sys/fs/cgroup"


def _read(name):
  try:
    with open(os.path.join(CG, name)) as f:
      return f.read().strip()
  except OSError:
    return None


def _int(name):
  v = _read(name)
  return int(v) if v and v.isdigit() else None


def _cpu_usec():
  for line in (_read("cpu.stat") or "").splitlines():
    k, _, v = line.partition(" ")
    if k == "usage_usec":
      return int(v)
  return None


def _cpu_cap():
  quota, _, period = (_read("cpu.max") or "max").partition(" ")
  if quota == "max" or not period:
    return None
  return int(quota) / int(period)


def _mem_events():
  ev = {}
  for line in (_read("memory.events") or "").splitlines():
    k, _, v = line.partition(" ")
    ev[k] = int(v)
  return ev


def _loop(path, every):
  last = (time.monotonic(), _cpu_usec())
  while True:
    time.sleep(every)
    now, usec = time.monotonic(), _cpu_usec()
    cpu = None
    if usec is not None and last[1] is not None:
      cpu = (usec - last[1]) / ((now - last[0]) * 1e6)
    last = (now, usec)
    mem_max = _read("memory.max")
    snap = {
        "t": time.time(),
        "cpu": cpu,  # cores used over the interval
        "cpu_cap": _cpu_cap(),
        "mem": _int("memory.current"),
        "mem_peak": _int("memory.peak"),
        "mem_max": int(mem_max) if mem_max and mem_max.isdigit() else None,
        "pids": _int("pids.current"),
        "pids_max": _int("pids.max"),
        "oom_kills": _mem_events().get("oom_kill"),
    }
    tmp = path + ".tmp"
    try:
      with open(tmp, "w") as f:
        json.dump(snap, f)
      os.replace(tmp, path)
    except OSError:
      pass


def start(path, every=2.0):
  threading.Thread(target=_loop, args=(path, every), daemon=True).start()
