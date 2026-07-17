// Validate DynamicHash edit consumption end-to-end against the angr core:
// compute Ghidra's own DynamicHash for a variable token's varnode (exactly what
// the GUI stores when a variable has no stable storage address), write it into
// the DB as a hash-storage local named 'hash_renamed', re-decompile, and check
// the angr core resolved the hash back to the variable (rename shows in the C).
//@category Test

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;

public class HashEditRoundTrip extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String funcName = (args.length > 0) ? args[0] : "main";
        Function func = null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(funcName)) { func = f; break; }
        }
        if (func == null) { println("HASHEDIT: no function"); return; }

        DecompInterface ifc = new DecompInterface();
        try {
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            HighFunction hf = res.getHighFunction();
            ClangTokenGroup markup = res.getCCodeMarkup();
            if (hf == null || markup == null) { println("HASHEDIT: no HighFunction"); return; }

            // pick the first local (non-param) variable token's varnode
            List<ClangToken> toks = new ArrayList<>();
            collect(markup, toks);
            Varnode target = null;
            for (ClangToken t : toks) {
                Varnode vn = t.getVarnode();
                HighVariable hv = t.getHighVariable();
                if (vn == null || hv == null || hv.getSymbol() == null) continue;
                if (hv.getSymbol().isParameter()) continue;
                target = vn;
                println("HASHEDIT: target token '" + t.getText() + "' vn=" + vn);
                break;
            }
            if (target == null) { println("HASHEDIT: no local variable token"); return; }

            // Ghidra's own hash over the graph the angr core emitted -- the
            // exact value the GUI would store for a dynamic-storage variable
            DynamicHash dh = new DynamicHash(target, hf);
            long hash = dh.getHash();
            Address pcaddr = dh.getAddress();
            println("HASHEDIT: hash=0x" + Long.toHexString(hash) + " pcaddr=" + pcaddr);
            if (hash == 0 || pcaddr == null) { println("HASHEDIT: RESULT FAIL (no hash)"); return; }

            int firstUse = (int) pcaddr.subtract(func.getEntryPoint());
            DataType dt = Undefined.getUndefinedDataType(target.getSize());
            VariableStorage storage = new VariableStorage(currentProgram,
                AddressSpace.HASH_SPACE.getAddress(hash), target.getSize());
            Variable var = new LocalVariableImpl("hash_renamed", firstUse, dt, storage,
                currentProgram);
            func.addLocalVariable(var, SourceType.USER_DEFINED);
            println("HASHEDIT: stored hash-storage local 'hash_renamed' firstUse=" + firstUse);

            DecompileResults res2 = ifc.decompileFunction(func, 60, monitor);
            String c = (res2.getDecompiledFunction() != null)
                ? res2.getDecompiledFunction().getC() : "";
            boolean ok = c.contains("hash_renamed");
            println("HASHEDIT: second decompile completed=" + res2.decompileCompleted()
                + " err=" + res2.getErrorMessage().trim());
            println("HASHEDIT: contains 'hash_renamed'? " + ok);
            println("HASHEDIT: RESULT " + (ok ? "PASS" : "FAIL"));
        } finally {
            ifc.dispose();
        }
    }

    private void collect(ClangNode n, List<ClangToken> out) {
        if (n instanceof ClangToken) out.add((ClangToken) n);
        for (int i = 0; i < n.numChildren(); i++) collect(n.Child(i), out);
    }
}
