package ghidump.model;

/**
 * Immutable representation of a basic block.
 * Contains the disassembled code that will be used for embedding generation.
 */
public record BasicBlockObject(
    int blockId,
    long startAddress,
    long endAddress,
    String disassembledCode  // The raw text for embedding
) {}