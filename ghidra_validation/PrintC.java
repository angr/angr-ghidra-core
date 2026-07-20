//@category Test
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
public class PrintC extends GhidraScript {
    @Override public void run() throws Exception {
        String fn = getScriptArgs().length>0 ? getScriptArgs()[0] : "main";
        Function f=null;
        for (Function x: currentProgram.getFunctionManager().getFunctions(true))
            if (x.getName().equals(fn)) { f=x; break; }
        if (f==null){ println("PRINTC: no func"); return; }
        DecompInterface ifc=new DecompInterface(); ifc.openProgram(currentProgram);
        DecompileResults r=ifc.decompileFunction(f,60,monitor);
        println("PRINTC-BEGIN");
        println(r.getDecompiledFunction()!=null ? r.getDecompiledFunction().getC() : "(null)");
        println("PRINTC-END");
        ifc.dispose();
    }
}
