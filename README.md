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

`bin/decompile` is a shim you can drop in place of Ghidra's native binary
(`<ghidra>/Ghidra/Features/Decompiler/os/<platform>/decompile`). See the header of
that script. Set `ANGR_GHIDRA_FALLBACK` to the stock binary path to restore the
original core at any time.

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

Remaining, in planned order:

1. **P-code AST for slicing.** Emit the `<ast>` (AIL-SSA → p-code
   varnodes/ops/blocks/edges), `<highlist>`, and per-token `varref`/`opref` links
   so GUI slicing, per-occurrence variable resolution, and the switch analyzer
   work. (The decoder treats these as optional today, so the model is valid
   without them; they're needed for the p-code-graph consumers.)
2. **Edit round-trip + types.** Consume DB renames/retypes/prototype overrides
   from callbacks into angr KB overrides; map `getDataType` to `SimType`.
   Nail the exact stack-offset convention (angr bp-relative → Ghidra stack space)
   so rename/retype write-back targets the right variable.
3. **Coverage + hybrid routing.** `normalize`/`paramid` styles, `generateSignatures`
   and `structureGraph` routed to the C++ core; option plumbing; performance.
4. **Scale validation** against the C++ core across a large corpus.

## Layout

```
angr_ghidra_core/
  ghidra_wire/   protocol: packed encoding, framing, client, server, ids, dump, clang
  harness/       PypcodeOracle, DecompSession (drive either core from a binary)
  core/          angr-backed core: spec parsing, response emission, main loop
bin/
  angr-decompile the angr core entry point
  decompile      shim for dropping into a Ghidra install
scripts/         gen_id_tables.py, decompile.py, drive_real_core.py
tests/           packed unit tests + real-core and angr-core integration tests
```

## Requirements

The `/workspace/angr-venv` virtualenv with editable `angr` (and its `rustylib`
native extension built), `pypcode`, and `cle`. The real-core tests additionally
need `ghidra_opt` built under
`Ghidra/Features/Decompiler/src/decompile/cpp/` (`make ghidra_opt`).
