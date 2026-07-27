# Roadmap

Status of the angr-backed core, beyond stage 3 (text-level decompilation through
the real protocol).

## Done

- **Symbol names for calls.** Call targets are resolved to names via a
  `getCodeLabel` callback and registered as named, returning stubs in angr's KB,
  so calls render as `puts()` / `authenticate()` etc. instead of raw addresses.

- **Local-variable symbols + token links.** The model function carries a real
  `<localdb>` `LocalSymbolMap`: one HighSymbol per angr variable with a stable
  id, name, core datatype, and storage (stack special-space offset or a
  register-space address resolved via `getRegister`). Variable tokens carry
  `symref` links to those symbols. (The `<symbol>`/`<mapsym>`/`<addr>` encoding is
  cross-validated: the real C++ core consumes the same shape from the oracle's
  `getMappedSymbols` replies.)

- **HighVariables + per-occurrence identity.** The model function emits an
  `<ast>` with a representative varnode per variable and a `<highlist>` of
  HighVariables (`HighLocal`/`HighParam`) linking each varnode (`repref`) to its
  symbol (`symref`). Variable tokens carry `varref`, so every occurrence of a
  variable resolves to the same HighVariable and symbol — enabling
  highlight-all-occurrences and per-occurrence rename/retype.

- **Edit round-trip + types.** Variable renames/retypes committed in the GUI
  round-trip: locked localdb symbols are matched by storage and applied to angr's
  variables (rename → unified name; retype → manual type + re-decompile). Stack
  varnodes are marked addr-tied so Ghidra stores edits as fixed `<addr>` rather
  than DynamicHash. Ghidra datatypes ↔ `SimType` mapping.

- **P-code op graph.** The `<ast>` carries a real p-code def-use graph
  (`<block>`/`<op>`/`<blockedge>`) lowered from angr's AIL. Verified against real
  Ghidra: the HighFunction has p-code ops and basic blocks, and forward/backward
  slicing (`DecompilerUtils.getForwardSlice`) returns non-trivial slices. It's a
  best-effort data-flow lowering (see `core/pcode.py`).

- **Listing ↔ decompiler navigation.** Each C token carries an `opref` to the
  p-code op at its instruction, so both directions work through Ghidra's standard
  machinery: `ClangToken.getMinAddress()` moves the listing cursor from a clicked
  token, and `DecompilerUtils.getTokensFromView` highlights the tokens for a
  selected instruction. Op seqnums are stamped with each expression's own
  `ins_addr` so per-expression tokens find a matching op. Coverage is bounded by
  angr's AIL being coarser than the machine listing
  (`ghidra_validation/NavTest.java`).

- **Per-token varref.** Variable tokens reference the varnode of the exact SSA
  value they render (via `CVariable.vvar_id` → the op-graph varnode), not one
  shared representative per variable — so def/use highlighting and slices are
  per-occurrence-accurate. Each HighVariable lists all of its SSA values as
  instances (disjoint across variables, even when storage is shared), so every
  token still resolves token → varnode → HighVariable → HighSymbol.

- **DynamicHash edit consumption.** Edits on variables with no stable storage
  address (SSA temporaries, non-addr-tied stack) are stored by Ghidra as a 64-bit
  hash of the varnode's local def-use neighborhood and come back as `<hash>`
  symbols. `core/dynahash.py` is a faithful port of Ghidra's `DynamicHash` (CRC
  neighborhood hash, edge ordering, candidate gathering, method cycling) over our
  op graph: the stored (address, hash) pair resolves to the varnode, whose
  storage feeds the normal rename/retype path
  (`ghidra_validation/HashEditRoundTrip.java`).

- **Performance: warm server + whole-image CFG cache.** Instead of a fresh
  Python+angr process per decompile, the launcher starts a long-lived **server**
  (`core/server_daemon.py`) once and proxies each Ghidra `decompile` invocation to
  it over a local socket; the server shares one whole-image CFG cache across all
  sessions and exits ~10 min after Ghidra closes. For programs whose mapped code
  image is ≤ 500 KB, the core recovers one `CFGFast` over the whole image (probed
  via `getBytes`, since Ghidra never sends the file), content-addresses it, and
  persists it with **angrdb** keyed by that hash — so a function is decompiled
  straight out of the cached CFG instead of a per-call scoped load. A function is
  only served this way when its angr-recovered extent matches Ghidra's function
  size (the "block range matches Ghidra's" guard); otherwise it falls back to the
  scoped path, so a differing CFG split never yields a wrong body. On `bomb`
  (14 functions) this is ~2× faster per function after the first. Enable with
  `server = 1`.

- **Multi-architecture.** The core infers the architecture by probing Ghidra's
  `getRegister` callback for landmark registers (the normalized specs Ghidra
  sends carry no ABI register names, so a spec-text fingerprint is unreliable);
  resolves the return register from either a named or an offset-based
  compiler-spec pentry; detects call targets via VEX (`Ijk_Call`) rather than an
  x86 `call` mnemonic; and retries without the data-reading peephole
  optimizations when a code-only image can't satisfy a MIPS `gp` / PC-relative /
  constant load. Validated against real headless Ghidra (`failures=0`) on
  **x86-64, i386, ARM (armel), AArch64, MIPS32 (BE and LE), and PPC32** — both
  endiannesses, 32/64-bit, four ISA families. See `tests/test_multiarch.py`.

- **ARM Thumb.** Ghidra addresses a Thumb function at its even base and doesn't
  expose the T-mode context register to the decompiler, so the mode is detected
  by probing `getPcode` at the entry: any 2-byte instruction means Thumb. angr
  then recovers and decompiles the function at `base | 1` (its set-low-bit Thumb
  convention). ARM-32 resolves to `ArchARMHF`, which lifts both soft- and
  hard-float integer code without the spurious flag `ccall`s that `ArchARMEL`
  emits on Thumb. `ValidateAngrCore` also asserts the output contains no
  undecoded instructions, so a clean run means something.

## Remaining

1. **True LOAD/STORE lowering.** Memory def-use is currently approximated by
   COPY (no space-id inputs); real LOAD/STORE ops would deepen slices further.
2. **Coverage + hybrid routing.** `normalize`/`paramid` styles,
   `generateSignatures` and `structureGraph` routed to the C++ core; option
   plumbing; performance.
3. **Scale validation** against the C++ core across a large corpus.
4. **PPC64 ELFv1**, where the `main` symbol points at a function descriptor
   rather than code — currently the one unsupported target.
