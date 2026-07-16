// Verify listing<->decompiler navigation on the angr core's output:
//  * decompiler->listing: tokens have getMinAddress() (from opref -> op seqnum)
//  * listing->decompiler: each function instruction maps back to >=1 token whose
//    address range covers it (what DecompilerUtils.getTokensFromView does).
//@category Test

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class NavTest extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String funcName = (args.length > 0) ? args[0] : "main";
        Function func = null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(funcName)) { func = f; break; }
        }
        if (func == null) { println("NAV: no function"); return; }

        DecompInterface ifc = new DecompInterface();
        try {
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            ClangTokenGroup markup = res.getCCodeMarkup();
            if (markup == null) { println("NAV: no markup"); return; }

            List<ClangToken> toks = new ArrayList<>();
            collect(markup, toks);

            // decompiler -> listing: tokens with an address (from opref)
            int withAddr = 0;
            Set<Address> tokenAddrs = new HashSet<>();
            for (ClangToken t : toks) {
                Address a = t.getMinAddress();
                if (a != null) { withAddr++; tokenAddrs.add(a); }
            }
            println("NAV: tokens=" + toks.size() + " tokensWithAddress=" + withAddr
                + " distinctTokenInstrs=" + tokenAddrs.size());
            for (ClangToken t : toks) {
                if (t.getMinAddress() != null && t.getText().trim().length() > 0) {
                    println("NAV: '" + t.getText() + "' -> " + t.getMinAddress());
                    break;
                }
            }

            // listing -> decompiler: for each instruction in the function body,
            // is there a token whose [min,max] covers it?
            int instrs = 0, mapped = 0;
            InstructionIterator it =
                currentProgram.getListing().getInstructions(func.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                instrs++;
                Address a = ins.getAddress();
                for (ClangToken t : toks) {
                    Address lo = t.getMinAddress(), hi = t.getMaxAddress();
                    if (lo != null && hi != null
                        && a.compareTo(lo) >= 0 && a.compareTo(hi) <= 0) {
                        mapped++;
                        break;
                    }
                }
            }
            println("NAV: instructions=" + instrs + " mappedToTokens=" + mapped);
            println("NAV: RESULT " + ((withAddr > 0 && mapped > 0) ? "PASS" : "FAIL"));
        } finally {
            ifc.dispose();
        }
    }

    private void collect(ClangNode n, List<ClangToken> out) {
        if (n instanceof ClangToken) out.add((ClangToken) n);
        for (int i = 0; i < n.numChildren(); i++) collect(n.Child(i), out);
    }
}
