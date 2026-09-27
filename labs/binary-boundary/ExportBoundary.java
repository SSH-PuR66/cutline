// Export recovered code and the actual basic-block graph of the controlled fixture.
// @category Research.Boundary
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.Application;
import ghidra.program.model.block.BasicBlockModel;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public class ExportBoundary extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Pass one JSON output path");
        var allowed = Set.of("legacy_boolean", "canonical_boolean", "legacy_range", "bounded_range");
        var report = new JsonObject();
        report.addProperty("schema_version", 1);
        report.addProperty("ghidra_version", Application.getApplicationVersion());
        report.addProperty("program", currentProgram.getName());
        report.addProperty("language", currentProgram.getLanguageID().toString());
        report.addProperty("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        report.addProperty("binary_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("method", "Headless import and auto-analysis; default inferred types; no prototype or symbol corrections supplied.");
        var functions = new JsonArray();
        var decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Cannot open decompiler");
        try {
            var iterator = currentProgram.getFunctionManager().getFunctions(true);
            var model = new BasicBlockModel(currentProgram);
            while (iterator.hasNext()) {
                var function = iterator.next();
                if (!allowed.contains(function.getName())) continue;
                monitor.checkCancelled();
                var result = decompiler.decompileFunction(function, 30, monitor);
                if (!result.decompileCompleted()) throw new IllegalStateException("Decompile failed: " + function.getName());
                var row = new JsonObject();
                row.addProperty("name", function.getName());
                row.addProperty("entry", function.getEntryPoint().toString());
                row.addProperty("decompiled_c", result.getDecompiledFunction().getC());
                var blocks = new JsonArray();
                var blockIterator = model.getCodeBlocksContaining(function.getBody(), monitor);
                int instructionCount = 0;
                while (blockIterator.hasNext()) {
                    var block = blockIterator.next();
                    var b = new JsonObject();
                    b.addProperty("start", block.getFirstStartAddress().toString());
                    var instructions = new JsonArray();
                    var ii = currentProgram.getListing().getInstructions(block, true);
                    while (ii.hasNext()) {
                        var ins = ii.next();
                        var ir = new JsonObject();
                        ir.addProperty("address", ins.getAddress().toString());
                        ir.addProperty("text", ins.toString());
                        ir.addProperty("bytes", java.util.HexFormat.ofDelimiter(" ").formatHex(ins.getBytes()));
                        instructions.add(ir); instructionCount++;
                    }
                    b.add("instructions", instructions);
                    var edges = new JsonArray();
                    var references = block.getDestinations(monitor);
                    while (references.hasNext()) {
                        var ref = references.next();
                        if (!function.getBody().contains(ref.getDestinationAddress())) continue;
                        var edge = new JsonObject();
                        edge.addProperty("to", ref.getDestinationAddress().toString());
                        edge.addProperty("kind", ref.getFlowType().toString());
                        edges.add(edge);
                    }
                    b.add("edges", edges); blocks.add(b);
                }
                row.addProperty("instruction_count", instructionCount);
                row.add("blocks", blocks); functions.add(row);
            }
        } finally { decompiler.dispose(); }
        if (functions.size() != 4) throw new IllegalStateException("Expected exactly four exported fixture functions");
        report.add("functions", functions);
        Files.writeString(Path.of(args[0]), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n", StandardCharsets.UTF_8);
        println("BOUNDARY_EXPORT_OK functions=" + functions.size());
    }
}
