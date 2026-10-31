"""Delays the next non-main-thread C SSL read when armed, after Python's
closed-socket checks and before OpenSSL uses its fd. Identical in A and B."""
import os
import ssl
import stat
import threading
import time

DELAY = float(os.environ.get("FUZZ_READ_DELAY_MS", "40")) / 1000

armed = threading.Event()
in_read = threading.Event()
# Filled after the delayed read: "socket", "file:<mode>", "closed" or "".
last_fd_kind = [""]


def _fd_kind(fd):
  try:
    mode = os.fstat(fd).st_mode
  except OSError:
    return "closed"
  if stat.S_ISSOCK(mode):
    return "socket"
  return "file:%o" % stat.S_IFMT(mode)


class _SslObjProxy(object):
  __slots__ = ("_o", "_fd")

  def __init__(self, obj, fd):
    object.__setattr__(self, "_o", obj)
    object.__setattr__(self, "_fd", fd)

  def __getattr__(self, name):
    return getattr(self._o, name)

  def __setattr__(self, name, value):
    setattr(self._o, name, value)

  def read(self, *args):
    if armed.is_set() and threading.current_thread() is not threading.main_thread():
      armed.clear()
      in_read.set()
      time.sleep(DELAY)
      last_fd_kind[0] = _fd_kind(self._fd)
    return self._o.read(*args)


_orig_wrap = ssl.SSLContext._wrap_socket


def _wrap_socket(self, sock, *args, **kwargs):
  return _SslObjProxy(_orig_wrap(self, sock, *args, **kwargs), sock.fileno())


ssl.SSLContext._wrap_socket = _wrap_socket
