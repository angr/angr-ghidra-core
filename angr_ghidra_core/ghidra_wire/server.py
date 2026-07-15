"""Server side of the decompiler protocol: plays the role of the C++ `decompile`
process. Reads commands from Ghidra (stdin), issues callback queries (stdout),
and returns command responses — mirroring ghidra_process.cc / ghidra_arch.cc.
"""

from __future__ import annotations

from .framing import (
    BYTES_END,
    BYTES_START,
    COMMAND_END,
    COMMAND_START,
    ERROR_END,
    ERROR_START,
    EXCEPTION_END,
    EXCEPTION_START,
    QUERY_END,
    QUERY_RESPONSE_END,
    QUERY_RESPONSE_START,
    QUERY_START,
    RESPONSE_END,
    RESPONSE_START,
    STRING_END,
    STRING_START,
    BurstReader,
    BurstWriter,
    ProtocolError,
    decode_byte_stream,
)
from .packed import PackedEncoder


class CallbackException(Exception):
    """Raised when Ghidra answers a callback query with an exception frame."""


class ServerTransport:
    """Framing for the core side of the pipe."""

    def __init__(self, in_stream, out_stream):
        self.reader = BurstReader(in_stream)
        self.writer = BurstWriter(out_stream)

    def read_command(self) -> tuple[str, list[bytes]]:
        """Block for the next command. Returns (name, params) where params are the
        raw string-stream payloads following the command name (archId, etc.).
        Raises EOFError when the pipe closes."""
        try:
            code = self.reader.read_to_burst()
        except ProtocolError:
            raise EOFError
        if code != COMMAND_START:
            raise ProtocolError(f"Expected command start, got burst {code}")
        params: list[bytes] = []
        while True:
            code = self.reader.read_to_burst()
            if code == COMMAND_END:
                break
            if code != STRING_START:
                raise ProtocolError(f"Expected string stream in command, got {code}")
            payload, end = self.reader.read_payload()
            if end != STRING_END:
                raise ProtocolError("Unterminated command string stream")
            params.append(payload)
        if not params:
            raise ProtocolError("Command with no name")
        return params[0].decode("utf-8"), params[1:]

    # ---- issuing callback queries (core -> Ghidra) ----

    def query(self, encoder: PackedEncoder):
        """Send a callback query and return (kind, payload):
        kind is 'string' (packed reply), 'bytes' (hex-doubled reply, decoded),
        or None (empty reply)."""
        self.writer.write_marker(QUERY_START)
        self.writer.write_string_stream(encoder.to_bytes())
        self.writer.write_marker(QUERY_END)
        self.writer.flush()

        code = self.reader.read_to_burst()
        if code == EXCEPTION_START:
            raise CallbackException(self._read_exception())
        if code != QUERY_RESPONSE_START:
            raise ProtocolError(f"Expected query response, got burst {code}")

        kind = None
        payload = None
        code = self.reader.read_to_burst()
        if code == STRING_START:
            payload, end = self.reader.read_payload()
            if end != STRING_END:
                raise ProtocolError("Unterminated query response string")
            kind = "string"
            code = self.reader.read_to_burst()
        elif code == BYTES_START:
            raw, end = self.reader.read_payload()
            if end != BYTES_END:
                raise ProtocolError("Unterminated query response bytes")
            payload = decode_byte_stream(raw)
            kind = "bytes"
            code = self.reader.read_to_burst()
        if code != QUERY_RESPONSE_END:
            raise ProtocolError(f"Expected query response end, got burst {code}")
        return kind, payload

    def _read_exception(self) -> str:
        parts = []
        for _ in range(2):  # type string, message string
            code = self.reader.read_to_burst()
            if code != STRING_START:
                break
            payload, _ = self.reader.read_payload()
            parts.append(payload.decode("utf-8", "replace"))
        self.reader.read_to_burst()  # exception terminator
        return ": ".join(p for p in parts if p)

    # ---- command responses (core -> Ghidra) ----
    #
    # Ordering mirrors GhidraCommand::doit: the response-start marker (6) is
    # written BEFORE the command body runs, so any callback queries the body
    # issues are seen by Ghidra inside its response-reading loop. The main
    # output (14/15) and error frame (16/17) are written after the body, then
    # the response-end marker (7).

    def begin_response(self) -> None:
        self.writer.write_marker(RESPONSE_START)
        self.writer.flush()

    def end_response(self, payload: bytes | str | None, error: str = "") -> None:
        if payload is not None:
            data = payload.encode("utf-8") if isinstance(payload, str) else payload
            self.writer.write_marker(STRING_START)
            self.writer.stream.write(data)
            self.writer.write_marker(STRING_END)
        # error frame is always written (may be empty), matching GhidraCommand::sendResult
        self.writer.write_marker(ERROR_START)
        if error:
            self.writer.stream.write(error.encode("utf-8"))
        self.writer.write_marker(ERROR_END)
        self.writer.write_marker(RESPONSE_END)
        self.writer.flush()
