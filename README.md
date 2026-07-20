# angr-ghidra-core

Replace Ghidra's C++ (SLEIGH) decompiler core with the **angr decompiler**, without
modifying any Ghidra Java code.

Ghidra's UI, analyzers, and scripts talk to a native executable named `decompile`
over a framed, packed-binary protocol on stdin/stdout. The C++ core has **no SLEIGH
engine of its own** — Ghidra feeds it p-code one instruction at a time via a
`getPcode` callback and answers all its questions about bytes, symbols, types, and
comments through other callbacks. This project reimplements that protocol in Python
and backs the `decompile` command with `angr.analyses.Decompiler`.

## What works today

- **`ghidra_wire`** — a bit-exact implementation of Ghidra 12.2's wire protocol:
  - `packed.py` — `PackedEncode`/`PackedDecode` (element/attribute ids, integers,
    strings, spaces), verified against the format spec.
  - `framing.py` — the burst framer (command / query / response / exception /
    byte-stream / string-stream markers, codes 2–19).
  - `client.py` — plays Ghidra's Java role (`DecompileProcess`): register a
    program, set actions, `decompileAt`, service callback queries, handle
    exception frames.
  - `server.py` — plays the C++ core's role (`ghidra_process.cc`): read commands,
    issue callback queries, return responses in the correct 6-…-7 framing.
  - `ids.py` — element/attribute id tables generated from Ghidra's Java sources
    (`scripts/gen_id_tables.py`).
- **`harness`** — a `PypcodeOracle` that answers the core's callbacks from CLE
  (bytes, symbols) and pypcode/SLEIGH (per-instruction p-code, registers), and
  authors the `registerProgram` spec documents. Lets us drive **either** core
  with no Ghidra installation.
- **`core`** — the angr-backed core: parses the spec documents, loads the target
  function's bytes through `getBytes`, runs a scoped `CFGFast` + `Decompiler`, and
  emits a `decompileAt` `<doc>` (a minimal HighFunction model + a Clang C-markup
  token tree) that Ghidra's `DecompileResults` can parse.

Both the genuine C++ core (`ghidra_opt`) and the angr core decompile the same
binary through the identical harness — see `tests/`.

**Validated against real Ghidra.** The angr core has been driven by an actual
headless Ghidra 12.2 (`analyzeHeadless` → `DecompInterface` → our shim). Ghidra's
own Java decoders accept the response: a non-null `HighFunction` with a 7-symbol
`LocalSymbolMap` (2 params + 5 locals), a `FunctionPrototype`, rendered C, and
every variable token resolving through `varref → varnode → HighVariable →
HighSymbol` (per-occurrence identity; rename targets resolve). See
`ghidra_validation/ValidateAngrCore.java` and `scripts/run_ghidra_validation.sh`.

### Ghidra testing

Needs a JDK 25 and a built Ghidra dist:

```bash
# 1. JDK 25 (Temurin) into /workspace/jdk, then build Ghidra's staged dist
cd /workspace/ghidra
JAVA_HOME=/workspace/jdk ./gradlew -I gradle/support/fetchDependencies.gradle
JAVA_HOME=/workspace/jdk ./gradlew buildGhidra   # staged dir usable even if the
                                                 # final SBOM/zip step fails
# 2. build + install the launcher as the dist's decompile binary
#    (keep the real ghidra_opt around as an ANGR_GHIDRA_FALLBACK escape hatch)
(cd /workspace/angr-ghidra-core/launcher && cargo build --release)
OS=build/dist/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64
cp <ghidra_opt> $OS/ghidra_opt_real
cp /workspace/angr-ghidra-core/launcher/target/release/decompile $OS/decompile
# 3. run the headless validation
/workspace/angr-ghidra-core/scripts/run_ghidra_validation.sh
```

## Quick start

```bash
# decompile a function with the real C++ core (validation oracle)
PYTHONPATH=. python scripts/decompile.py /path/to/binary main

# ...or with the angr-backed core
PYTHONPATH=. python scripts/decompile.py /path/to/binary main --angr

# drive the real core with full protocol tracing
PYTHONPATH=. python scripts/drive_real_core.py /path/to/binary main --trace
```

Example (fauxware `main`, angr core):

```c
unsigned int main(unsigned int a0, unsigned long long a1)
{
    ...
    v2 = 4195940();
    return (!v2 ? (unsigned int)4196093() : (unsigned int)4196077());
}
```

## Installing into a Ghidra tree

Ghidra spawns an executable literally named `decompile` (`decompile.exe` on
Windows) from `<ghidra>/Ghidra/Features/Decompiler/os/<platform>/`. The
**`launcher/`** crate builds a small, zero-dependency native binary that stands in
for it: it locates a Python interpreter and the angr core, then hands over the
process's stdio transparently (a real `exec` on Unix; spawn-and-wait on Windows),
so the Python core speaks the protocol to Ghidra directly. A native launcher —
rather than a shell script — is what makes the same drop-in work on Windows.

```bash
cd launcher
cargo build --release                       # -> target/release/decompile
# Windows (from a Windows box, or Linux with a mingw/MSVC cross toolchain):
#   cargo build --release --target x86_64-pc-windows-gnu    # -> decompile.exe
#   cargo build --release --target x86_64-pc-windows-msvc
cp target/release/decompile \
   <ghidra>/Ghidra/Features/Decompiler/os/linux_x86_64/decompile
```

### Configuration

Because Ghidra spawns the decompiler itself, setting environment variables for it
is awkward (especially on Windows). The launcher instead reads a config file that
sits **next to the binary** — `angr-decompile.conf` (or `decompile.conf`) in the
same `os/<platform>/` directory. See `launcher/angr-decompile.conf.example`:

```ini
# angr-decompile.conf  (next to decompile / decompile.exe)
python     = C:\path\to\angr-venv\Scripts\python.exe
core       = C:\path\to\angr-ghidra-core\bin\angr-decompile
pythonpath = C:\path\to\angr-ghidra-core      # makes angr_ghidra_core importable
log        = C:\temp\angr-logs                # debug log (dir -> per-pid files)
# log_io   = 1                                # also dump raw protocol bytes
# fallback = ...\decompile.orig.exe           # restore the original C++ core
# env.NAME = value                            # extra child env vars
```

| Config key | Env override | Meaning |
|---|---|---|
| `python` | `ANGR_GHIDRA_PYTHON` | interpreter with angr/pypcode/cle (default: search `PATH`) |
| `core` | `ANGR_GHIDRA_CORE` | angr core entry (default: `angr-decompile` next to the binary, else `python -m angr_ghidra_core.core.angr_core`) |
| `pythonpath` | `PYTHONPATH` (prepended) | import path for the core, so the package need not be installed |
| `fallback` | `ANGR_GHIDRA_FALLBACK` | run this stock `decompile` binary instead (restore the C++ core) |
| `log` | `ANGR_GHIDRA_LOG` | debug log; a **directory** yields per-pid files, a file is appended |
| `log_io` | `ANGR_GHIDRA_LOG_IO` | also dump raw protocol bytes to `<log>.stdin.bin` / `.stdout.bin` |
| `env.NAME` | — | set arbitrary environment variables on the child |

An environment variable, if set, overrides the file. Relative paths in the config
are resolved against the config file's directory. Values may be quoted.

**Debugging a startup failure** (e.g. *"Unable to initialize decompiler
interface; the pipe has ended"* — the core died during registration). Set `log`
in the config (a directory is cleanest — Ghidra runs several decompiler processes
at once, each getting its own file), reproduce, then read the log: it records the
resolved interpreter/core/env and captures the child's stderr — the Python
traceback (a `ModuleNotFoundError`, an `angr`/`pypcode` import error, a wrong core
path, …) that Ghidra otherwise swallows. Add `log_io` to also see the raw
protocol bytes and pinpoint how far registration got. Enabling the log switches
the launcher to a spawn-and-wait model on all platforms (it still forwards stderr
to Ghidra); normal operation uses a direct `exec` on Unix.

## Status and roadmap

Beyond stage 3 (text-level decompilation through the real protocol):

- **[done] Symbol names for calls.** Call targets are resolved to names via a
  `getCodeLabel` callback and registered as named, returning stubs in angr's KB,
  so calls render as `puts()` / `authenticate()` etc. instead of raw addresses.
- **[done] Local-variable symbols + token links.** The model function now carries
  a real `<localdb>` `LocalSymbolMap`: one HighSymbol per angr variable with a
  stable id, name, core datatype, and storage (stack special-space offset or a
  register-space address resolved via `getRegister`). Variable tokens carry
  `symref` links to those symbols. (The `<symbol>`/`<mapsym>`/`<addr>` encoding is
  cross-validated: the real C++ core consumes the same shape from the oracle's
  `getMappedSymbols` replies.)

- **[done] HighVariables + per-occurrence identity.** The model function now
  emits an `<ast>` with a representative varnode per variable and a `<highlist>`
  of HighVariables (`HighLocal`/`HighParam`) linking each varnode (`repref`) to
  its symbol (`symref`). Variable tokens carry `varref`, so every occurrence of a
  variable resolves through the same varnode to the same HighVariable to the same
  symbol — enabling highlight-all-occurrences and per-occurrence rename/retype.
  The whole chain is now confirmed end-to-end against a running headless Ghidra
  (see "Validated against real Ghidra" above).

- **[done] Edit round-trip + types.** Variable renames/retypes committed in the
  GUI round-trip: locked localdb symbols are matched by storage and applied to
  angr's variables (rename → unified name; retype → manual type + re-decompile).
  Stack varnodes are marked addr-tied so Ghidra stores edits as fixed `<addr>`
  rather than DynamicHash. Ghidra datatypes ↔ `SimType` mapping.
- **[done] P-code op graph.** The `<ast>` now carries a real p-code def-use graph
  (`<block>`/`<op>`/`<blockedge>`) lowered from angr's AIL. Verified against real
  Ghidra: the HighFunction has p-code ops and basic blocks, and forward/backward
  slicing (`DecompilerUtils.getForwardSlice`) returns non-trivial slices. It's a
  best-effort data-flow lowering (see `core/pcode.py`).
- **[done] Listing ↔ decompiler navigation.** Each C token carries an `opref` to
  the p-code op at its instruction, so both directions work through Ghidra's
  standard machinery: `ClangToken.getMinAddress()` moves the listing cursor from
  a clicked token, and `DecompilerUtils.getTokensFromView` highlights the tokens
  for a selected instruction. Op seqnums are stamped with each expression's own
  `ins_addr` so per-expression tokens find a matching op. Verified against real
  headless Ghidra (`ghidra_validation/NavTest.java`, RESULT PASS); coverage is
  bounded by angr's AIL being coarser than the machine listing.

- **[done] Per-token varref.** Variable tokens now reference the varnode of the
  exact SSA value they render (via `CVariable.vvar_id` → the op-graph varnode),
  not one shared representative per variable — so def/use highlighting and
  slices are per-occurrence-accurate. Each HighVariable lists all of its SSA
  values as instances (disjoint across variables, even when storage is shared),
  so every token still resolves token → varnode → HighVariable → HighSymbol.
  This is the prerequisite for consuming DynamicHash-stored edits (SSA-local
  renames), which Ghidra can now store against the right varnode.

- **[done] DynamicHash edit consumption.** Edits on variables with no stable
  storage address (SSA temporaries, non-addr-tied stack) are stored by Ghidra as
  a 64-bit hash of the varnode's local def-use neighborhood and come back as
  `<hash>` symbols. `core/dynahash.py` is a faithful port of Ghidra's
  `DynamicHash` (CRC neighborhood hash, edge ordering, candidate gathering,
  method cycling) over our op graph: the stored (address, hash) pair resolves to
  the varnode, whose storage feeds the normal rename/retype path. Validated
  end-to-end against real Ghidra: a hash computed by Ghidra's own `DynamicHash`
  over our emitted graph, stored as a hash-storage DB local, round-trips into
  the C output (`ghidra_validation/HashEditRoundTrip.java`).

- **[done] Performance: warm server + whole-image CFG cache.** Instead of a
  fresh Python+angr process per decompile, the native launcher starts a
  long-lived **server** (`core/server_daemon.py`) once and proxies each Ghidra
  `decompile` invocation to it over a local socket; the server shares one
  whole-image CFG cache across all sessions and exits ~10 min after Ghidra
  closes. For programs whose mapped code image is ≤ 500 KB, the core recovers
  one `CFGFast` over the whole image (probed via `getBytes`, since Ghidra never
  sends the file), content-addresses it, and persists it with **angrdb** keyed
  by that hash — so a function is decompiled straight out of the cached CFG
  instead of a per-call scoped load. A function is only served this way when its
  angr-recovered extent matches Ghidra's function size (the "block range matches
  Ghidra's" guard); otherwise it falls back to the scoped path, so a differing
  CFG split never yields a wrong body. On `bomb` (14 functions) this is ~2×
  faster per function after the first; with the warm server the first-decompile
  CFG cost is paid once per binary across the whole Ghidra session. Enable it
  with `server = 1` in `angr-decompile.conf`. Validated against real headless
  Ghidra in server mode (failures=0; Nav/Slice/Edit/HashEdit all PASS).

- **[done] Multi-architecture.** The core is no longer x86-only. It infers the
  architecture by probing Ghidra's `getRegister` callback for landmark registers
  (the normalized specs Ghidra sends carry no ABI register names, so a spec-text
  fingerprint is unreliable); resolves the return register from either a named or
  an offset-based compiler-spec pentry; detects call targets via VEX
  (`Ijk_Call`) rather than an x86 `call` mnemonic; and retries without the
  data-reading peephole optimizations when a code-only image can't satisfy a
  MIPS `gp` / PC-relative / constant load. Validated against real headless
  Ghidra (`failures=0`) on **x86-64, i386, ARM (armel), AArch64, MIPS32 (BE and
  LE), and PPC32** — covering both endiannesses, 32/64-bit, and four ISA
  families. See `tests/test_multiarch.py`. Not yet supported: ARM Thumb (odd
  entry needs consistent T-bit handling) and PPC64 ELFv1 (the symbol points at a
  function descriptor, not code).

Remaining, in planned order:

1. **True LOAD/STORE lowering.** Memory def-use is currently approximated by
   COPY (no space-id inputs); real LOAD/STORE ops would deepen slices further.
2. **Coverage + hybrid routing.** `normalize`/`paramid` styles, `generateSignatures`
   and `structureGraph` routed to the C++ core; option plumbing; performance.
3. **Scale validation** against the C++ core across a large corpus.
4. **Multi-architecture** beyond x86-64.

## Layout

```
angr_ghidra_core/
  ghidra_wire/   protocol: packed encoding, framing, client, server, ids, dump, clang
  harness/       PypcodeOracle, DecompSession (drive either core from a binary)
  core/          angr-backed core: spec parsing, response emission, main loop
bin/
  angr-decompile   the angr core entry point (python)
launcher/          zero-dep Rust crate -> native `decompile`/`decompile.exe`
ghidra_validation/ headless GhidraScript validating the decode contract
scripts/           gen_id_tables.py, decompile.py, drive_real_core.py,
                   run_ghidra_validation.sh
tests/             packed unit tests + real-core and angr-core integration tests
```

## Requirements

The `/workspace/angr-venv` virtualenv with editable `angr` (and its `rustylib`
native extension built), `pypcode`, and `cle`. The real-core tests additionally
need `ghidra_opt` built under
`Ghidra/Features/Decompiler/src/decompile/cpp/` (`make ghidra_opt`).
