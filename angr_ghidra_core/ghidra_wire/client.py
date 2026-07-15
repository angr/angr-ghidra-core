"""Client side of the decompiler protocol: plays the role of Ghidra's Java
DecompileProcess/DecompInterface, driving a core process (the real C++ one or
our angr-backed one) and servicing its callback queries from an oracle.
"""

from __future__ import annotations

import subprocess

from . import ids
from .framing import (
    BYTES_END,
    BYTES_START,
    COMMAND_END,
    COMMAND_START,
    EXCEPTION_END,
    EXCEPTION_START,
    ERROR_START,
    QUERY_RESPONSE_END,
    QUERY_RESPONSE_START,
    QUERY_START,
    RESPONSE_END,
    RESPONSE_START,
    STRING_END,
    STRING_START,
    WARNING_START,
    WARNING_END,
    BurstReader,
    BurstWriter,
    ProtocolError,
)
from .packed import PackedDecoder, PackedEncoder


class CoreException(Exception):
    """Exception raised by the core process (burst 10/11)."""

    def __init__(self, extype: str, message: str):
        super().__init__(f"{extype}: {message}")
        self.extype = extype
        self.message = message


class DecompClient:
    """Drive one decompiler core process."""

    def __init__(self, exe_path, oracle, trace=None):
        """exe_path: path to the core binary, or a list (argv) for a wrapped core
        (e.g. ["python", "bin/angr-decompile"]).
        oracle: object with query_<name>(decoder) -> reply methods.
        trace: optional callable(direction: str, kind: str, payload) for logging."""
        argv = [exe_path] if isinstance(exe_path, str) else list(exe_path)
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.reader = BurstReader(self.proc.stdout)
        self.writer = BurstWriter(self.proc.stdin)
        self.oracle = oracle
        self.trace = trace or (lambda *a: None)
        self.arch_id: str | None = None
        self.error_message: str | None = None

    # ------------------------------------------------------------------ I/O

    def _send_command(self, *params: str | bytes | PackedEncoder) -> None:
        self.writer.write_marker(COMMAND_START)
        for p in params:
            if isinstance(p, PackedEncoder):
                self.writer.write_string_stream(p.to_bytes())
            else:
                self.writer.write_string_stream(p)
        self.writer.write_marker(COMMAND_END)
        self.writer.flush()

    def _read_query_param(self) -> bytes:
        code = self.reader.read_to_burst()
        if code != STRING_START:
            raise ProtocolError(f"Expected string stream in query, got burst {code}")
        payload, code = self.reader.read_payload()
        if code != STRING_END:
            raise ProtocolError(f"Unterminated query string stream (burst {code})")
        return payload

    def _read_response(self) -> bytes:
        """Mirror of DecompileProcess.readResponse: service queries until burst 7."""
        self.error_message = None
        # readToResponse: skip odd codes until 6 (or exception 10)
        while True:
            code = self.reader.read_to_burst()
            if code & 1:
                continue
            if code == EXCEPTION_START:
                self._raise_exception()
            if code == RESPONSE_START:
                break
            raise ProtocolError(f"Alignment error: burst {code} before response")

        main = bytearray()
        current: bytearray | None = None
        code = self.reader.read_to_burst()
        while code != RESPONSE_END:
            if code == QUERY_START:
                self._service_query()
            elif code == EXCEPTION_START:
                self._raise_exception()
            elif code == STRING_START:  # 14: main output
                current = main
            elif code == STRING_END:  # 15
                current = None
            elif code == ERROR_START:  # 16
                if current is not None:
                    # error arrived before the main output finished: discard partial
                    main.clear()
                current = bytearray()
            elif code == ERROR_START + 1:  # 17
                if current is not main:
                    self.error_message = current.decode("utf-8", "replace") or None
                current = None
            elif code == WARNING_START:  # 18
                payload, end = self.reader.read_payload()
                if end != WARNING_END:
                    raise ProtocolError("Bad warning frame")
                self.trace("core", "warning", payload.decode("utf-8", "replace"))
                continue
            else:
                raise ProtocolError(f"Alignment error: burst {code} in response")
            if current is None:
                code = self.reader.read_to_burst()
            else:
                payload, code = self.reader.read_payload()
                current.extend(payload)
        return bytes(main)

    def _raise_exception(self):
        extype = self._read_query_param().decode("utf-8", "replace")
        message = self._read_query_param().decode("utf-8", "replace")
        self.reader.read_to_burst()  # exception terminator
        raise CoreException(extype, message)

    # ------------------------------------------------------------- queries

    QUERY_NAMES = {
        ids.ELEM_COMMAND_ISNAMEUSED: "isnameused",
        ids.ELEM_COMMAND_GETBYTES: "getbytes",
        ids.ELEM_COMMAND_GETCALLFIXUP: "getcallfixup",
        ids.ELEM_COMMAND_GETCALLMECH: "getcallmech",
        ids.ELEM_COMMAND_GETCALLOTHERFIXUP: "getcallotherfixup",
        ids.ELEM_COMMAND_GETCODELABEL: "getcodelabel",
        ids.ELEM_COMMAND_GETCOMMENTS: "getcomments",
        ids.ELEM_COMMAND_GETCPOOLREF: "getcpoolref",
        ids.ELEM_COMMAND_GETDATATYPE: "getdatatype",
        ids.ELEM_COMMAND_GETEXTERNALREF: "getexternalref",
        ids.ELEM_COMMAND_GETMAPPEDSYMBOLS: "getmappedsymbols",
        ids.ELEM_COMMAND_GETNAMESPACEPATH: "getnamespacepath",
        ids.ELEM_COMMAND_GETPCODE: "getpcode",
        ids.ELEM_COMMAND_GETPCODEEXECUTABLE: "getpcodeexecutable",
        ids.ELEM_COMMAND_GETREGISTER: "getregister",
        ids.ELEM_COMMAND_GETREGISTERNAME: "getregistername",
        ids.ELEM_COMMAND_GETSTRINGDATA: "getstringdata",
        ids.ELEM_COMMAND_GETTRACKEDREGISTERS: "gettrackedregisters",
        ids.ELEM_COMMAND_GETUSEROPNAME: "getuseropname",
    }

    def _service_query(self) -> None:
        payload = self._read_query_param()
        decoder = PackedDecoder(payload)
        command_id = decoder.open_element()
        name = self.QUERY_NAMES.get(command_id)
        self.trace("core", "query", name or command_id)
        try:
            if name is None:
                raise ValueError(f"Unsupported decompiler query {command_id}")
            handler = getattr(self.oracle, "query_" + name)
            reply = handler(decoder)
        except Exception as e:  # pass any oracle failure down to the core
            self.writer.write_marker(EXCEPTION_START)
            self.writer.write_string_stream(type(e).__name__)
            self.writer.write_string_stream(str(e))
            self.writer.write_marker(EXCEPTION_END)
        else:
            self.writer.write_marker(QUERY_RESPONSE_START)
            if isinstance(reply, PackedEncoder):
                if not reply.is_empty():
                    self.writer.write_string_stream(reply.to_bytes())
            elif isinstance(reply, bool):
                self.writer.write_string_stream(b"t" if reply else b"f")
            elif isinstance(reply, bytes):
                if reply:
                    self.writer.write_byte_stream(reply)
            elif isinstance(reply, tuple):
                # pre-encoded byte-stream payload (getStringData): raw doubled bytes
                self.writer.stream.write(bytes([0, 0, 1, BYTES_START]))
                self.writer.stream.write(reply[0])
                self.writer.stream.write(bytes([0, 0, 1, BYTES_END]))
            elif isinstance(reply, str):
                self.writer.write_string_stream(reply)
            elif reply is None:
                pass  # empty query response
            else:
                raise TypeError(f"Bad oracle reply type {type(reply)}")
            self.writer.write_marker(QUERY_RESPONSE_END)
        self.writer.flush()
        self.reader.read_to_burst()  # query terminator (QUERY_END)

    # ------------------------------------------------------------ commands

    def register_program(self, pspec: str, cspec: str, tspec: str, coretypes: str) -> str:
        self._send_command("registerProgram", pspec, cspec, tspec, coretypes)
        self.arch_id = self._read_response().decode()
        return self.arch_id

    def deregister_program(self) -> int:
        self._send_command("deregisterProgram", self.arch_id)
        return int(self._read_response().decode())

    def set_action(self, action: str, printconfig: str = "") -> bool:
        self._send_command("setAction", self.arch_id, action, printconfig)
        return self._read_response() == b"t"

    def set_options(self, options: PackedEncoder) -> bool:
        self._send_command("setOptions", self.arch_id, options)
        return self._read_response() == b"t"

    def decompile_at(self, addr_encoder: PackedEncoder) -> bytes:
        self._send_command("decompileAt", self.arch_id, addr_encoder)
        return self._read_response()

    def flush_native(self) -> int:
        self._send_command("flushNative", self.arch_id)
        return int(self._read_response().decode())

    def close(self) -> None:
        try:
            if self.arch_id is not None and self.proc.poll() is None:
                self.deregister_program()
        except Exception:
            pass
        finally:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            self.proc.terminate()
            self.proc.wait(timeout=5)
