"""Burst framing for the Ghidra <-> decompiler byte stream.

A burst marker is one-or-more 0x00 bytes, then 0x01, then a code byte:
  2/3   command open/close          (Ghidra -> core)
  4/5   query open/close            (core -> Ghidra callback)
  6/7   command response open/close (core -> Ghidra)
  8/9   query response open/close   (Ghidra -> core)
  10/11 exception open/close
  12/13 byte stream open/close
  14/15 string stream open/close
  16/17 error message open/close    (core -> Ghidra, inside command response)
  18/19 warning message open/close

Payload bytes are always non-zero (packed encoding / UTF-8 text / hex-doubled
bytes), so a 0x00 unambiguously starts the next marker.
"""

from __future__ import annotations

COMMAND_START = 2
COMMAND_END = 3
QUERY_START = 4
QUERY_END = 5
RESPONSE_START = 6
RESPONSE_END = 7
QUERY_RESPONSE_START = 8
QUERY_RESPONSE_END = 9
EXCEPTION_START = 10
EXCEPTION_END = 11
BYTES_START = 12
BYTES_END = 13
STRING_START = 14
STRING_END = 15
ERROR_START = 16
ERROR_END = 17
WARNING_START = 18
WARNING_END = 19


def marker(code: int) -> bytes:
    return bytes([0, 0, 1, code])


class ProtocolError(IOError):
    pass


class BurstReader:
    """Incremental reader over a blocking binary file object (e.g. process stdout)."""

    def __init__(self, stream):
        self.stream = stream

    def _read1(self) -> int:
        b = self.stream.read(1)
        if not b:
            raise ProtocolError("Stream closed (process died?)")
        return b[0]

    def read_to_burst(self) -> int:
        """Skip to the next burst marker and return its code (DecompileProcess.readToBurst)."""
        while True:
            cur = self._read1()
            while cur > 0:  # skip payload bytes
                cur = self._read1()
            while cur == 0:  # skip zero padding
                cur = self._read1()
            if cur == 1:
                return self._read1()
            # else: desynchronized non-zero byte; keep scanning

    def read_payload(self) -> tuple[bytes, int]:
        """Read payload bytes up to the next burst marker; return (payload, code).

        Mirrors readToBuffer: accumulates non-zero bytes, consumes the marker.
        """
        out = bytearray()
        while True:
            cur = self._read1()
            while cur > 0:
                out.append(cur)
                cur = self._read1()
            while cur == 0:
                cur = self._read1()
            if cur == 1:
                code = self._read1()
                if code > 0:
                    return bytes(out), code
            # stray; continue scanning


class BurstWriter:
    def __init__(self, stream):
        self.stream = stream

    def write_marker(self, code: int) -> None:
        self.stream.write(marker(code))

    def write_string_stream(self, payload: bytes | str) -> None:
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        self.stream.write(marker(STRING_START))
        self.stream.write(data)
        self.stream.write(marker(STRING_END))

    def write_byte_stream(self, raw: bytes) -> None:
        """Hex-doubled byte stream: each nibble + 0x41 ('A')."""
        dbl = bytearray(len(raw) * 2)
        for i, b in enumerate(raw):
            dbl[i * 2] = ((b >> 4) & 0xF) + 0x41
            dbl[i * 2 + 1] = (b & 0xF) + 0x41
        self.stream.write(marker(BYTES_START))
        self.stream.write(bytes(dbl))
        self.stream.write(marker(BYTES_END))

    def flush(self) -> None:
        self.stream.flush()


def decode_byte_stream(payload: bytes) -> bytes:
    """Inverse of write_byte_stream's hex-doubling."""
    if len(payload) % 2:
        raise ProtocolError("Odd-length byte stream")
    out = bytearray(len(payload) // 2)
    for i in range(len(out)):
        out[i] = ((payload[i * 2] - 0x41) << 4) | (payload[i * 2 + 1] - 0x41)
    return bytes(out)
