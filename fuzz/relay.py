"""Fake IAP relay on 127.0.0.1 (stdlib only, run with python -I).

Speaks just enough of relay.tunnel.cloudproxy.app over TLS + WebSocket:
CONNECT_SUCCESS_SID once, then a DATA frame every few ms so the client's
reader thread keeps entering SSL reads. Client frames are drained; a close
frame ends the connection.
"""
import base64
import hashlib
import os
import select
import socket
import ssl
import struct
import sys
import threading
import time

PORT = int(os.environ.get("FUZZ_RELAY_PORT", "8443"))
CERT_DIR = os.environ.get("FUZZ_CERT_DIR", "/state/certs")
CA = os.path.join(CERT_DIR, "ca.pem")
CERT = os.path.join(CERT_DIR, "server.pem")
KEY = os.path.join(CERT_DIR, "server-priv.pem")
DATA_EVERY = float(os.environ.get("FUZZ_DATA_EVERY_MS", "5")) / 1000
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TAG_CONNECT_SUCCESS_SID = 0x0001
TAG_DATA = 0x0004


def ws_frame(payload, opcode=0x2):
  n = len(payload)
  if n < 126:
    hdr = struct.pack("!BB", 0x80 | opcode, n)
  elif n < 65536:
    hdr = struct.pack("!BBH", 0x80 | opcode, 126, n)
  else:
    hdr = struct.pack("!BBQ", 0x80 | opcode, 127, n)
  return hdr + payload


def recv_exact(s, n):
  buf = b""
  while len(buf) < n:
    chunk = s.recv(n - len(buf))
    if not chunk:
      raise EOFError
    buf += chunk
  return buf


def read_frame(s):
  b0, b1 = recv_exact(s, 2)
  opcode = b0 & 0x0F
  n = b1 & 0x7F
  if n == 126:
    n = struct.unpack("!H", recv_exact(s, 2))[0]
  elif n == 127:
    n = struct.unpack("!Q", recv_exact(s, 8))[0]
  mask = recv_exact(s, 4) if b1 & 0x80 else b"\0\0\0\0"
  data = bytes(c ^ mask[i % 4] for i, c in enumerate(recv_exact(s, n)))
  return opcode, data


def handle(raw, ctx):
  try:
    s = ctx.wrap_socket(raw, server_side=True)
  except (ssl.SSLError, OSError):
    raw.close()
    return
  try:
    req = b""
    while b"\r\n\r\n" not in req:
      chunk = s.recv(4096)
      if not chunk:
        return
      req += chunk
    key = b""
    for line in req.split(b"\r\n"):
      if line.lower().startswith(b"sec-websocket-key:"):
        key = line.split(b":", 1)[1].strip()
    accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
    s.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
              b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Protocol: relay.tunnel.cloudproxy.app\r\n"
              b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    sid = b"fuzz-sid"
    s.sendall(ws_frame(struct.pack("!HI", TAG_CONNECT_SUCCESS_SID, len(sid)) + sid))
    payload = os.urandom(64)
    data = ws_frame(struct.pack("!HI", TAG_DATA, len(payload)) + payload)
    while True:
      r, _, _ = select.select([s], [], [], DATA_EVERY)
      if r or s.pending():
        opcode, body = read_frame(s)
        if opcode == 0x8:
          try:
            s.sendall(ws_frame(body[:2], 0x8))
          except OSError:
            pass
          return
        continue
      s.sendall(data)
  except (EOFError, OSError, ssl.SSLError, ValueError):
    pass
  finally:
    try:
      s.close()
    except OSError:
      pass


def make_certs():
  """Throwaway CA + localhost leaf, written to tmpfs."""
  import datetime
  import ipaddress
  from cryptography import x509
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import ec
  from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

  now = datetime.datetime.now(datetime.timezone.utc)
  days = datetime.timedelta(days=3650)
  ca_priv = ec.generate_private_key(ec.SECP256R1())
  ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fdrace-fuzz-ca")])
  ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_priv.public_key())
  ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_priv.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + days)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(ca_ski, critical=False)
        .sign(ca_priv, hashes.SHA256()))
  leaf_priv = ec.generate_private_key(ec.SECP256R1())
  leaf = (x509.CertificateBuilder()
          .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
          .issuer_name(ca_name).public_key(leaf_priv.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + days)
          .add_extension(x509.SubjectAlternativeName([
              x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_priv.public_key()), critical=False)
          .sign(ca_priv, hashes.SHA256()))
  pem = serialization.Encoding.PEM
  os.makedirs(os.path.dirname(CERT), exist_ok=True)
  with open(CA, "wb") as f:
    f.write(ca.public_bytes(pem))
  with open(CERT, "wb") as f:
    f.write(leaf.public_bytes(pem))
  with open(KEY, "wb") as f:
    f.write(leaf_priv.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))


def main():
  make_certs()
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  ctx.load_cert_chain(CERT, KEY)
  srv = socket.socket()
  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  srv.bind(("127.0.0.1", PORT))
  srv.listen(64)
  print("relay listening", PORT, file=sys.stderr, flush=True)
  while True:
    raw, _ = srv.accept()
    threading.Thread(target=handle, args=(raw, ctx), daemon=True).start()


if __name__ == "__main__":
  main()
