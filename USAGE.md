# Usage

Pull `gcr.io/google.com/cloudsdktool/google-cloud-cli:590.0.1-alpine` first; nothing else is fetched.

```sh
make up     # start A + B + UI (idle), then open http://127.0.0.1:8099
make down   # remove the containers; results stay in results/
```

The UI controls everything else:

- **Start / Stop**: stopped containers idle.
- **Intensity**: Low (one iteration about every 2 s per side), Medium, High (up to each cap). Applies from the next
  iteration.
- **Clear results**: only while stopped.
- **Container panel**: CPU, memory, peak memory, pids and OOM kills against each cap, read from each container's own
  cgroup (no docker socket).
- **A / B columns**: iterations, rate, failures, stale-fd reads, last 500 iterations, and the first 64 bytes of the
  last corrupted DB.
- **Banner**: red if B fails; green only once A has failed and B has not.

## Caps

| container | CPU | memory (no swap) | pids | network |
|---|---|---|---|---|
| A, B | `FUZZ_CPUS` (default 1) | `FUZZ_MEM` (default 512m) | 256 | none |
| UI | 0.25 | 128m | 64 | 127.0.0.1:8099 only |

Example: `FUZZ_CPUS=0.5 FUZZ_MEM=256m make up`.

## What runs

- **A**: stock gcloud 590.0.1. **B**: the same image plus the patched `iap_tunnel_lightweight_websocket.py`
  (`fuzz/patched/`). Each side logs whether the patch is loaded.
- **Relay** (`fuzz/relay.py`): a fake IAP relay on each container's loopback (TLS 1.3, WebSocket,
  `relay.tunnel.cloudproxy.app` subprotocol), throwaway CA, dummy token.
- **Harness** (`fuzz/harness.py`), per iteration, using gcloud's own `IapTunnelWebSocket`:
  1. Connect and receive data.
  2. Arm the read delay.
  3. Call `Close()` while the reader is in the SSL read.
  4. Open `default_configs.db` through gcloud's `_SqlCursor` and hold it until the reader exits.
  5. Run `PRAGMA quick_check` and scan the first 4 KiB for `17 03 03`.
- **Injection** (`fuzz/inject/fuzz_inject.py`, same on both sides): the armed read waits `FUZZ_READ_DELAY_MS`
  (default 40) after Python's closed-socket checks, before OpenSSL uses its fd. No `googlecloudsdk` code is touched.

Expected: A gets `SQLit` + `17 03 03 00 13` + 19 bytes written into the DB; B's fd stays a socket.

Not covered: `workstations start-tcp-tunnel`.
