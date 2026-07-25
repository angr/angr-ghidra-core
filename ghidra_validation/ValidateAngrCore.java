// Validate the angr-backed decompiler core against Ghidra's real Java decoders.
//
// Run headless, e.g.:
//   analyzeHeadless <proj_dir> tmpproj -import <binary> \
//       -scriptPath <this dir> -postScript ValidateAngrCore.java <funcName>
//
// It decompiles the named function through DecompInterface (which spawns the
// installed `decompile` binary -- our shim), then checks that the response
// decodes into a real HighFunction with a populated LocalSymbolMap and a
// ClangTokenGroup whose variable tokens resolve to HighVariables. Prints
// ANGR_CORE_VALIDATION: PASS/FAIL lines that the runner greps for.
//@category Test

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ValidateAngrCore extends GhidraScript {

	private int failures = 0;

	private void check(boolean cond, String msg) {
		if (cond) {
			println("ANGR_CORE_VALIDATION: PASS " + msg);
		}
		else {
			println("ANGR_CORE_VALIDATION: FAIL " + msg);
			failures++;
		}
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String funcName = (args.length > 0) ? args[0] : "main";

		Function func = null;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(funcName)) {
				func = f;
				break;
			}
		}
		if (func == null) {
			println("ANGR_CORE_VALIDATION: FAIL function '" + funcName + "' not found");
			println("ANGR_CORE_VALIDATION: DONE failures=1");
			return;
		}
		println("ANGR_CORE_VALIDATION: target " + funcName + " @ " + func.getEntryPoint());

		DecompInterface ifc = new DecompInterface();
		try {
			boolean opened = ifc.openProgram(currentProgram);
			check(opened, "openProgram");

			DecompileResults res = ifc.decompileFunction(func, 60, monitor);

			check(res != null && res.decompileCompleted(),
				"decompileCompleted (err: " + (res == null ? "null" : res.getErrorMessage()) + ")");
			if (res == null || !res.decompileCompleted()) {
				println("ANGR_CORE_VALIDATION: DONE failures=" + (failures + 1));
				return;
			}

			// --- HighFunction / LocalSymbolMap ---
			HighFunction hf = res.getHighFunction();
			check(hf != null, "getHighFunction non-null");
			if (hf != null) {
				LocalSymbolMap lsm = hf.getLocalSymbolMap();
				int nsym = (lsm == null) ? -1 : countSymbols(lsm);
				println("ANGR_CORE_VALIDATION: lsm.getSymbols=" + nsym
					+ " numParams=" + (lsm == null ? -1 : lsm.getNumParams()));
				try {
					Iterator<HighSymbol> it = lsm.getSymbols();
					int shown = 0;
					while (it.hasNext() && shown < 12) {
						HighSymbol hs = it.next();
						println("ANGR_CORE_VALIDATION:   sym '" + hs.getName() + "' id=" + hs.getId()
							+ " isParam=" + hs.isParameter());
						shown++;
					}
				}
				catch (Exception e) {
					println("ANGR_CORE_VALIDATION:   symbol iteration threw " + e);
				}
				check(lsm != null && nsym >= 5,
					"LocalSymbolMap has >=5 symbols (got " + nsym + ")");
				check(hf.getFunctionPrototype() != null, "FunctionPrototype non-null");
				// p-code op graph
				int nops = 0;
				java.util.Iterator<ghidra.program.model.pcode.PcodeOpAST> ops = hf.getPcodeOps();
				while (ops.hasNext()) { ops.next(); nops++; }
				int nblocks = hf.getBasicBlocks().size();
				println("ANGR_CORE_VALIDATION: pcodeOps=" + nops + " basicBlocks=" + nblocks);
				check(nops > 0, "HighFunction has p-code ops");
				check(nblocks > 0, "HighFunction has basic blocks");
			}

			// --- C markup tokens ---
			ClangTokenGroup markup = res.getCCodeMarkup();
			check(markup != null, "getCCodeMarkup non-null");

			String c = (res.getDecompiledFunction() != null)
				? res.getDecompiledFunction().getC() : null;
			check(c != null && c.contains(funcName), "getC() renders and names the function");
			// Semantic sanity: a structurally-valid response can still be wrong
			// (e.g. Thumb bytes decoded as ARM), which angr marks with this
			// string. Guard against it so a clean failures=0 means something.
			check(c != null && !c.contains("unsupported instruction"),
				"no undecoded instructions in output");
			if (c != null) {
				println("---- decompiled C (real Ghidra) ----");
				println(c);
				println("---- end C ----");
			}

			// --- variable tokens resolve to HighVariables (varref chain) ---
			if (markup != null) {
				List<ClangToken> varToks = new ArrayList<>();
				collectTokens(markup, varToks);
				int resolved = 0, varTokens = 0;
				for (ClangToken t : varToks) {
					HighVariable hv = t.getHighVariable();
					if (hv != null) {
						varTokens++;
						HighSymbol hs = hv.getSymbol();
						if (hs != null) {
							resolved++;
						}
					}
				}
				check(varTokens > 0, "found tokens with a HighVariable (varref resolves)");
				check(resolved > 0, "HighVariables resolve to a HighSymbol (rename target)");
				// Our emission lists every rendered SSA value as a HighVariable
				// instance, so *all* variable tokens must resolve. This is also a
				// tripwire for accidentally decompiling with the stock C++ core
				// (e.g. a launcher 'fallback' left enabled), whose varnodes only
				// partially resolve this way.
				check(resolved == varTokens,
					"every variable token resolves (" + resolved + "/" + varTokens + ")");
				println("ANGR_CORE_VALIDATION: varTokens=" + varTokens + " resolved=" + resolved);
			}
		}
		finally {
			ifc.dispose();
		}

		println("ANGR_CORE_VALIDATION: DONE failures=" + failures);
	}

	private int countSymbols(LocalSymbolMap lsm) {
		int n = 0;
		Iterator<HighSymbol> it = lsm.getSymbols();
		while (it.hasNext()) {
			it.next();
			n++;
		}
		return n;
	}

	private void collectTokens(ClangNode node, List<ClangToken> out) {
		if (node instanceof ClangToken) {
			out.add((ClangToken) node);
		}
		for (int i = 0; i < node.numChildren(); i++) {
			collectTokens(node.Child(i), out);
		}
	}
}
