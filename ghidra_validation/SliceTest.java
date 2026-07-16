// Test that forward/backward slicing works on the angr core's p-code graph:
// pick a variable token, get its varnode, and walk the def-use slice.
//@category Test

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class SliceTest extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String funcName = (args.length > 0) ? args[0] : "main";
        Function func = null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(funcName)) { func = f; break; }
        }
        if (func == null) { println("SLICE: no function"); return; }

        DecompInterface ifc = new DecompInterface();
        try {
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            ClangTokenGroup markup = res.getCCodeMarkup();
            if (markup == null) { println("SLICE: no markup"); return; }

            List<ClangToken> toks = new ArrayList<>();
            collect(markup, toks);

            int tried = 0, fwdHits = 0, bwdHits = 0;
            for (ClangToken t : toks) {
                Varnode vn = t.getVarnode();
                HighVariable hv = t.getHighVariable();
                if (vn == null || hv == null) continue;
                tried++;
                Set<Varnode> fwd = DecompilerUtils.getForwardSlice(vn);
                Set<Varnode> bwd = DecompilerUtils.getBackwardSlice(vn);
                if (fwd.size() > 1) fwdHits++;
                if (bwd.size() > 1) bwdHits++;
                if (tried <= 3) {
                    println("SLICE: token '" + t.getText() + "' vn=" + vn
                        + " fwd=" + fwd.size() + " bwd=" + bwd.size());
                }
            }
            println("SLICE: tokensWithVarnode=" + tried
                + " forwardSlices>1=" + fwdHits + " backwardSlices>1=" + bwdHits);
            println("SLICE: RESULT " + ((fwdHits > 0 || bwdHits > 0) ? "PASS" : "FAIL"));
        } finally {
            ifc.dispose();
        }
    }

    private void collect(ClangNode n, List<ClangToken> out) {
        if (n instanceof ClangToken) out.add((ClangToken) n);
        for (int i = 0; i < n.numChildren(); i++) collect(n.Child(i), out);
    }
}
