package ghidump.model;

import java.util.List;
import java.util.Map;

/**
 * Normalized, immutable data model representing the complete analysis result.
 * All strings are stored once in the stringTable and referenced by index.
 */
public record AnalysisResult(
    String binaryName,
    String binaryMd5,
    List<String> stringTable,
    Map<Integer, FunctionObject> functions,
    Map<Integer, BasicBlockObject> basicBlocks
) {}