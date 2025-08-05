package ghidump.model;

import java.util.List;

/**
 * Immutable representation of a function.
 * Function name is referenced by index into the stringTable to avoid duplication.
 */
public record FunctionObject(
    int functionId,
    int functionNameId,  // Index into stringTable
    long entryPointAddress,
    List<Integer> basicBlockIds  // List of BasicBlockObject IDs
) {}