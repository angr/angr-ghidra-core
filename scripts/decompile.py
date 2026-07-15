"""Decompile a function with either core. Usage:
  python scripts/decompile.py [binary] [func] [--angr|--real] [--dump]
"""
import sys
from angr_ghidra_core.harness.session import DecompSession, REAL_CORE, ANGR_CORE

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    binary = args[0] if args else "/workspace/binaries/tests/x86_64/fauxware"
    func = args[1] if len(args) > 1 else "main"
    core = ANGR_CORE if "--angr" in sys.argv else REAL_CORE
    trace = (lambda w,k,x: print(f"[{w}] {k}: {x}", file=sys.stderr)) if "--trace" in sys.argv else None
    sess = DecompSession(binary, core=core, trace=trace)
    try:
        res = sess.decompile(func)
        if "--dump" in sys.argv:
            for r in res.roots: print(r.pretty(max_depth=4), file=sys.stderr)
        print(res.c)
    finally:
        sess.close()

if __name__ == "__main__":
    main()
