# angr-ghidra-core

[![CI](https://github.com/angr/angr-ghidra-core/actions/workflows/ci.yml/badge.svg)](https://github.com/angr/angr-ghidra-core/actions/workflows/ci.yml)

Replaces Ghidra's C++ decompiler with the **angr decompiler**, without modifying
Ghidra itself.

## How it works

Ghidra doesn't decompile in Java: it spawns a native executable named `decompile`
and talks to it over a framed, packed-binary protocol on stdin/stdout. That core
has **no SLEIGH engine of its own** — Ghidra feeds it p-code one instruction at a
time and answers all its questions about bytes, symbols, types and comments
through callbacks. This project reimplements the protocol and answers with
`angr.analyses.Decompiler` instead:

- **`launcher/`** — a small, zero-dependency Rust binary installed in place of
  `decompile`. It finds a Python interpreter and the core, then hands over the
  process's stdio. Being native rather than a shell script is what makes the same
  drop-in work on Windows.
- **`angr_ghidra_core/ghidra_wire/`** — the wire protocol: packed encoding, burst
  framing, both endpoints, and element/attribute id tables generated from
  Ghidra's Java sources.
- **`angr_ghidra_core/core/`** — the angr-backed core. It parses Ghidra's spec
  documents, pulls the function's bytes through `getBytes`, runs angr, and emits
  the HighFunction model and C markup that Ghidra's decoders expect.
- **`angr_ghidra_core/harness/`** — a pypcode/CLE oracle that stands in for
  Ghidra, so the core can be driven and tested with no Ghidra installed.

Ghidra's own Java decoders accept the result: variable tokens resolve through
`varref → varnode → HighVariable → HighSymbol`, renames and retypes round-trip,
p-code slicing works, and listing ↔ decompiler navigation works in both
directions. Validated against real headless Ghidra on x86-64, i386, ARM
(including Thumb), AArch64, MIPS (big- and little-endian) and PPC32 — see
`ghidra_validation/` and [ROADMAP.md](ROADMAP.md).

## Installation

Needs a Python with `angr`, `pypcode` and `cle` (the installer can create one).
Rust is needed only when no prebuilt launcher is available.

### With the install script

```bash
./install.sh --ghidra /path/to/ghidra           # Linux / macOS
install.bat  --ghidra C:\path\to\ghidra         # Windows
```

This obtains the launcher, backs up Ghidra's original decompiler, installs the
launcher in its place, and writes the config next to it. **Restart Ghidra**
afterwards.

| Option | Meaning |
|---|---|
| `--ghidra DIR` | Ghidra installation; defaults to `$GHIDRA_INSTALL_DIR`, then a search of common locations |
| `--python PATH` | an interpreter that already has angr/pypcode/cle |
| `--venv DIR` | create a virtualenv there and `pip install` the dependencies |
| `--server` | enable the faster shared-server mode |
| `--launcher PATH` | use this prebuilt launcher binary |
| `--build` | force a `cargo build` even when a prebuilt binary is present |

The launcher comes from `--launcher`, else `prebuilt/<platform>/decompile` or
`prebuilt/decompile` as shipped in a release, else a `cargo build` — so a release
that bundles the binary installs with no compiler at all.

### By hand

Ghidra spawns `decompile` (`decompile.exe` on Windows) from
`<ghidra>/Ghidra/Features/Decompiler/os/<platform>/`. Build the launcher and put
it there, keeping the original alongside:

```bash
cargo build --release --manifest-path launcher/Cargo.toml
# Windows cross-build: --target x86_64-pc-windows-gnu (or -msvc) -> decompile.exe
OS=<ghidra>/Ghidra/Features/Decompiler/os/linux_x86_64
mv "$OS/decompile" "$OS/decompile.orig"
cp launcher/target/release/decompile "$OS/decompile"
```

Then write an `angr-decompile.conf` beside it — see Configuration.

## Removal

```bash
./install.sh --ghidra /path/to/ghidra --uninstall
install.bat  --ghidra C:\path\to\ghidra --uninstall
```

This restores the backed-up original decompiler and removes the config. By hand:
move `decompile.orig` back over `decompile` and delete `angr-decompile.conf`.

## Configuration

Ghidra spawns the decompiler itself, so setting environment variables for it is
awkward (especially on Windows). The launcher instead reads
`angr-decompile.conf` (or `decompile.conf`) from **its own directory**:

```ini
# angr-decompile.conf  (next to decompile / decompile.exe)
python     = C:\path\to\angr-venv\Scripts\python.exe
core       = C:\path\to\angr-ghidra-core\bin\angr-decompile
pythonpath = C:\path\to\angr-ghidra-core      # makes angr_ghidra_core importable
# server   = 1                                # shared long-lived angr process
# log      = C:\temp\angr-logs                # debug log (dir -> per-pid files)
```

| Key | Env override | Meaning |
|---|---|---|
| `python` | `ANGR_GHIDRA_PYTHON` | interpreter with angr/pypcode/cle (default: search `PATH`) |
| `core` | `ANGR_GHIDRA_CORE` | angr core entry (default: `angr-decompile` beside the binary, else `python -m angr_ghidra_core.core.angr_core`) |
| `pythonpath` | `PYTHONPATH` (prepended) | import path for the core, so the package need not be installed |
| `server` | `ANGR_GHIDRA_SERVER` | use a shared long-lived angr server (much faster after the first decompile) |
| `server_socket` | `ANGR_GHIDRA_SERVER_SOCKET` | where that server listens (default: a per-user path) |
| `server_idle` | `ANGR_GHIDRA_SERVER_IDLE` | seconds of no connections before the server exits (default 600) |
| `cfg_max_size` | `ANGR_GHIDRA_CFG_MAX_SIZE` | only build a whole-image CFG for images up to this size (default 512000) |
| `log` | `ANGR_GHIDRA_LOG` | debug log; a **directory** yields per-pid files, a file is appended |
| `log_io` | `ANGR_GHIDRA_LOG_IO` | also dump raw protocol bytes to `<log>.stdin.bin` / `.stdout.bin` |
| `fallback` | `ANGR_GHIDRA_FALLBACK` | run this stock `decompile` binary **instead of** angr (an escape hatch; leave unset for normal use) |
| `env.NAME` | — | set arbitrary environment variables on the child |

An environment variable, if set, overrides the file. Relative paths are resolved
against the config file's directory. Values may be quoted.

**Debugging a startup failure** (e.g. *"Unable to initialize decompiler
interface; the pipe has ended"* — the core died during registration): set `log`
to a directory (Ghidra runs several decompiler processes at once, each getting
its own file), reproduce, then read the log. It records the resolved
interpreter/core/env and captures the child's stderr — the Python traceback that
Ghidra otherwise swallows. Add `log_io` to see the raw protocol bytes and
pinpoint how far registration got.
