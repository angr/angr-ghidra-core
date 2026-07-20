"""Long-lived angr decompiler server.

Starting a fresh Python + angr process for every Ghidra decompile is expensive:
interpreter startup, imports, and a cold whole-image CFG each time. Instead the
native launcher starts this daemon once and proxies each Ghidra `decompile`
invocation to it over a local socket. One socket connection is exactly one
protocol session (what a single stdio core would have handled), so the existing
`AngrCore` runs unchanged over the connection's streams. All sessions share the
whole-image CFG cache and a single decompile lock (angr is not thread-safe), so
warm functions are served without rebuilding and Ghidra's parallel decompile
processes are serialized rather than racing.

The server exits after `idle_timeout` seconds with no active connections, so it
disappears shortly after Ghidra is closed and never lingers indefinitely.

Transport: a Unix domain socket on Linux/macOS; on Windows, a localhost TCP
socket guarded by a random token file (Unix sockets are not dependable across
Windows versions). The launcher and server agree on the path/port via the same
config the launcher already reads.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import time

from ..ghidra_wire.server import ServerTransport
from .angr_core import AngrCore
from .imagecache import DEFAULT_MAX_SIZE, ImageCache

log = logging.getLogger("angr_ghidra_core")

DEFAULT_IDLE = 600  # seconds with zero connections before the server exits


class AngrServer:
    def __init__(self, listen_sock: socket.socket, *, idle_timeout: float = DEFAULT_IDLE,
                 max_size: int = DEFAULT_MAX_SIZE):
        self._sock = listen_sock
        self._idle_timeout = idle_timeout
        self._image_cache = ImageCache(max_size=max_size)
        self._decompile_lock = threading.Lock()  # angr is not thread-safe
        self._active = 0
        self._cv = threading.Condition()
        self._last_active = time.monotonic()
        self._stop = False

    def serve_forever(self) -> None:
        idle = threading.Thread(target=self._idle_watch, daemon=True)
        idle.start()
        self._sock.settimeout(1.0)
        while not self._stop:
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _idle_watch(self) -> None:
        with self._cv:
            while not self._stop:
                if self._active == 0:
                    idle_for = time.monotonic() - self._last_active
                    remaining = self._idle_timeout - idle_for
                    if remaining <= 0:
                        log.info("idle for %.0fs; shutting down", idle_for)
                        self._stop = True
                        break
                    self._cv.wait(timeout=remaining)
                else:
                    self._cv.wait(timeout=1.0)
        try:
            self._sock.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        with self._cv:
            self._active += 1
        rfile = conn.makefile("rb", buffering=0)
        wfile = conn.makefile("wb", buffering=0)
        try:
            transport = ServerTransport(rfile, wfile)
            AngrCore(transport, image_cache=self._image_cache,
                     decompile_lock=self._decompile_lock).serve()
        except Exception:
            log.exception("session ended with an error")
        finally:
            for f in (rfile, wfile):
                try:
                    f.close()
                except OSError:
                    pass
            try:
                conn.close()
            except OSError:
                pass
            with self._cv:
                self._active -= 1
                self._last_active = time.monotonic()
                self._cv.notify_all()


def _bind_unix(path: str) -> socket.socket:
    # a stale socket file from a crashed server would block binding
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o600)
    s.listen(64)
    return s


def _bind_tcp(token_path: str) -> socket.socket:
    import secrets

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(64)
    port = s.getsockname()[1]
    token = secrets.token_hex(16)
    d = os.path.dirname(token_path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = token_path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(f"{port}\n{token}\n")
    os.replace(tmp, token_path)  # atomic publish so the launcher never reads a half-written file
    return s


def main(argv=None) -> int:
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr, format="[angr-server] %(message)s")
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)

    argv = list(sys.argv[1:] if argv is None else argv)
    # --socket PATH (unix) | --tcp TOKENFILE (windows); --idle SECONDS
    socket_path = os.environ.get("ANGR_GHIDRA_SERVER_SOCKET")
    token_path = None
    idle = float(os.environ.get("ANGR_GHIDRA_SERVER_IDLE", DEFAULT_IDLE))
    try:
        max_size = int(os.environ.get("ANGR_GHIDRA_CFG_MAX_SIZE", DEFAULT_MAX_SIZE))
    except ValueError:
        max_size = DEFAULT_MAX_SIZE
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--socket":
            socket_path = argv[i + 1]; i += 2
        elif a == "--tcp":
            token_path = argv[i + 1]; i += 2
        elif a == "--idle":
            idle = float(argv[i + 1]); i += 2
        else:
            i += 1

    if token_path:
        listen = _bind_tcp(token_path)
        log.info("listening on tcp (token %s), idle %.0fs", token_path, idle)
    elif socket_path:
        listen = _bind_unix(socket_path)
        log.info("listening on %s, idle %.0fs", socket_path, idle)
    else:
        log.error("no --socket or --tcp given")
        return 2

    server = AngrServer(listen, idle_timeout=idle, max_size=max_size)
    try:
        server.serve_forever()
    finally:
        if socket_path:
            try:
                os.unlink(socket_path)
            except OSError:
                pass
        if token_path:
            try:
                os.unlink(token_path)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
