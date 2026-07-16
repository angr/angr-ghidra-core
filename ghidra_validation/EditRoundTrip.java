// Rename + retype a local variable through HighFunctionDBUtil (the path GUI
// actions use), then re-decompile. With the angr core in ANGR_GHIDRA_DEBUG mode
// the core logs the getMappedSymbols localdb it receives, so we can see how the
// edit arrives on the wire.
//@category Test

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;

import java.util.Iterator;

public class EditRoundTrip extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String funcName = (args.length > 0) ? args[0] : "main";

        Function func = null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(funcName)) { func = f; break; }
        }
        if (func == null) { println("EDIT: function not found"); return; }

        DecompInterface ifc = new DecompInterface();
        try {
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            HighFunction hf = res.getHighFunction();
            if (hf == null) { println("EDIT: no high function (err " + res.getErrorMessage() + ")"); return; }

            // pick the first non-parameter local symbol
            LocalSymbolMap lsm = hf.getLocalSymbolMap();
            HighSymbol target = null;
            Iterator<HighSymbol> it = lsm.getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (!s.isParameter()) { target = s; break; }
            }
            if (target == null) { println("EDIT: no local to rename"); return; }
            println("EDIT: renaming '" + target.getName() + "' (storage " + target.getStorage() + ") -> renamed_by_user : int");

            int tx = currentProgram.startTransaction("edit");
            boolean ok = false;
            try {
                // rename + retype to char* (8 bytes -> matches the 8-byte slot)
                DataType charPtr = new PointerDataType(CharDataType.dataType);
                HighFunctionDBUtil.updateDBVariable(target, "renamed_by_user", charPtr,
                    SourceType.USER_DEFINED);
                ok = true;
            } finally {
                currentProgram.endTransaction(tx, ok);
            }
            println("EDIT: update ok=" + ok);

            // re-decompile: the core will get the edited symbol via getMappedSymbols
            DecompileResults res2 = ifc.decompileFunction(func, 60, monitor);
            println("EDIT: res2 completed=" + res2.decompileCompleted()
                + " hf=" + (res2.getHighFunction() != null)
                + " markup=" + (res2.getCCodeMarkup() != null)
                + " err=" + res2.getErrorMessage());
            String c = (res2.getDecompiledFunction() != null) ? res2.getDecompiledFunction().getC() : null;
            println("EDIT: ---- C after edit ----");
            println(c);
            println("EDIT: ---- end ----");
            println("EDIT: contains 'renamed_by_user'? " + (c != null && c.contains("renamed_by_user")));
        } finally {
            ifc.dispose();
        }
    }
}
