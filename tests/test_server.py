"""The long-lived server: multiple socket sessions share one whole-image CFG
cache and produce output identical to the stdio core, and it idles out."""

import os
import socket
import threading
import time

import pytest

from angr_ghidra_core.core.server_daemon import AngrServer
from angr_ghidra_core.ghidra_wire import ids
from angr_ghidra_core.ghidra_wire.client import DecompClient
from angr_ghidra_core.ghidra_wire.dump import parse_tree
from angr_ghidra_core.harness.oracle import PypcodeOracle
from angr_ghidra_core.harness.session import ANGR_CORE, DecompSession
from angr_ghidra_core.ghidra_wire.packed import PackedEncoder
from angr_ghidra_core.ghidra_wire.clang import render_c, split_decompile_response

FAUXWARE = "/workspace/binaries/tests/x86_64/fauxware"
SPACE_RAM = 4

pytestmark = pytest.mark.skipif(
    not (os.path.exists(FAUXWARE) and os.path.exists(ANGR_CORE[1])),
    reason="core or test binary not available")


def _decompile_over_socket(sock_path, func_addr):
    """Open one protocol session to the server over a fresh connection and
    decompile one function; return its C text."""
    oracle = PypcodeOracle(FAUXWARE)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(sock_path)
    rfile = c.makefile("rb", buffering=0)
    wfile = c.makefile("wb", buffering=0)
    client = DecompClient(None, oracle, streams=(rfile, wfile))
    try:
        client.register_program(oracle.pspec(), oracle.cspec(), oracle.tspec(),
                                oracle.coretypes())
        client.set_action("decompile", "")
        client.set_action("", "tree")
        client.set_action("", "c")
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_RAM)
        enc.write_unsigned(ids.ATTRIB_OFFSET, func_addr)
        enc.close_element(ids.ELEM_ADDR)
        payload = client.decompile_at(enc)
        roots = parse_tree(payload)
    
        return payload
    finally:
        client.close()
        c.close()


def _addr(name):
    o = PypcodeOracle(FAUXWARE)
    return next(f for f in o.functions.values() if f.name == name).addr


@pytest.fixture
def server(tmp_path):
    sock_path = str(tmp_path / "srv.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sock_path)
    s.listen(16)
    srv = AngrServer(s, idle_timeout=3600, max_size=500 * 1024)
    os.environ["ANGR_GHIDRA_CACHE"] = str(tmp_path / "cache")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield sock_path, srv
    srv._stop = True
    with srv._cv:
        srv._cv.notify_all()


def test_two_sessions_share_image_cache(server):
    sock_path, srv = server
    main_a = _addr("main")
    auth_a = _addr("authenticate")

    # session 1 builds the whole-image CFG
    p1 = _decompile_over_socket(sock_path, main_a)
    assert p1 and b"main" in p1
    assert len(srv._image_cache._mem) == 1, "one image should be cached"

    # session 2 (new connection) reuses it -- no new image entry
    p2 = _decompile_over_socket(sock_path, auth_a)
    assert p2 and b"authenticate" in p2
    assert len(srv._image_cache._mem) == 1, "second session must reuse the cache"


def test_server_output_matches_stdio_core(server):
    sock_path, _srv = server
    main_a = _addr("main")
    server_payload = _decompile_over_socket(sock_path, main_a)

    os.environ["ANGR_GHIDRA_NO_IMAGE_CACHE"] = "1"
    try:
        s = DecompSession(FAUXWARE, core=ANGR_CORE)
        stdio_c = s.decompile("main").c
        s.close()
    finally:
        os.environ.pop("ANGR_GHIDRA_NO_IMAGE_CACHE", None)

    roots = parse_tree(server_payload)
    model, markup = split_decompile_response(roots)
    server_c = render_c(markup)
    assert server_c == stdio_c


BOMB = "/workspace/binaries/tests/x86_64/bomb"


@pytest.mark.skipif(not os.path.exists(BOMB), reason="bomb binary not available")
def test_size_gate_falls_back_on_missplit(tmp_path):
    """A function whose whole-image extent differs from Ghidra's must fall back
    to the scoped path rather than emit a mis-split (degenerate) body. bomb's
    phase_2 is one such case: the whole-image CFG recovers it two bytes short."""
    os.environ["ANGR_GHIDRA_CACHE"] = str(tmp_path / "cache")
    try:
        s = DecompSession(BOMB, core=ANGR_CORE)     # image mode (default)
        image_c = s.decompile("phase_2").c
        s.close()

        os.environ["ANGR_GHIDRA_NO_IMAGE_CACHE"] = "1"
        s = DecompSession(BOMB, core=ANGR_CORE)     # scoped mode
        scoped_c = s.decompile("phase_2").c
        s.close()
    finally:
        os.environ.pop("ANGR_GHIDRA_NO_IMAGE_CACHE", None)

    # the gate made image mode defer to scoped -> identical, full-body output
    assert image_c == scoped_c
    assert "read_six_numbers" in image_c  # not a degenerate 'void phase_2(void)'


def test_idle_timeout_exits():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    import tempfile
    d = tempfile.mkdtemp()
    path = os.path.join(d, "idle.sock")
    s.bind(path)
    s.listen(4)
    srv = AngrServer(s, idle_timeout=0.5)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(1.5)
    assert srv._stop, "server should have exited after the idle timeout"
