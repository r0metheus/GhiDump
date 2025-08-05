package ghidump;

import ghidump.model.AnalysisResult;
import ghidump.model.BasicBlockObject;
import ghidump.model.FunctionObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * DataModeler is responsible for building a normalized data model from a Ghidra program.
 * It ensures no string duplication by using a string table with integer references.
 */
public class DataModeler {
    
    private final Program program;
    private final TaskMonitor monitor;
    private final List<String> stringTable;
    private final Map<String, Integer> stringToId;
    private final Map<Integer, FunctionObject> functions;
    private final Map<Integer, BasicBlockObject> basicBlocks;
    private int nextStringId;
    private int nextFunctionId;
    private int nextBlockId;
    
    public DataModeler(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
        this.stringTable = new ArrayList<>();
        this.stringToId = new HashMap<>();
        this.functions = new HashMap<>();
        this.basicBlocks = new HashMap<>();
        this.nextStringId = 0;
        this.nextFunctionId = 0;
        this.nextBlockId = 0;
    }
    
    /**
     * Build the complete normalized analysis result from the program.
     */
    public AnalysisResult buildModel() throws CancelledException {
        String binaryName = program.getName();
        String binaryMd5 = computeMd5();
        
        // Process all functions
        processFunctions();
        
        return new AnalysisResult(
            binaryName,
            binaryMd5,
            Collections.unmodifiableList(stringTable),
            Collections.unmodifiableMap(functions),
            Collections.unmodifiableMap(basicBlocks)
        );
    }
    
    private void processFunctions() throws CancelledException {
        Listing listing = program.getListing();
        FunctionIterator functionIterator = listing.getFunctions(true);
        
        while (functionIterator.hasNext()) {
            monitor.checkCancelled();
            Function function = functionIterator.next();
            processFunction(function);
        }
    }
    
    private void processFunction(Function function) throws CancelledException {
        int functionId = nextFunctionId++;
        String functionName = function.getName();
        int functionNameId = getOrCreateStringId(functionName);
        long entryPoint = function.getEntryPoint().getOffset();
        
        List<Integer> blockIds = new ArrayList<>();
        
        try {
            // Use SimpleBlockModel to get basic blocks
            SimpleBlockModel blockModel = new SimpleBlockModel(program);
            CodeBlockIterator blockIterator = blockModel.getCodeBlocksContaining(
                function.getBody(), monitor);
            
            while (blockIterator.hasNext()) {
                monitor.checkCancelled();
                CodeBlock block = blockIterator.next();
                int blockId = processBasicBlock(block);
                blockIds.add(blockId);
            }
        } catch (Exception e) {
            // If we can't get blocks, create a single block for the entire function
            int blockId = processFunctionAsOneBlock(function);
            blockIds.add(blockId);
        }
        
        FunctionObject functionObj = new FunctionObject(
            functionId,
            functionNameId,
            entryPoint,
            Collections.unmodifiableList(blockIds)
        );
        
        functions.put(functionId, functionObj);
    }
    
    private int processBasicBlock(CodeBlock block) throws CancelledException {
        int blockId = nextBlockId++;
        long startAddress = block.getMinAddress().getOffset();
        long endAddress = block.getMaxAddress().getOffset();
        
        StringBuilder disassembledCode = new StringBuilder();
        
        // Get disassembled instructions for the block
        InstructionIterator instructions = program.getListing().getInstructions(
            block.getMinAddress(), true);
        
        CodeUnitFormat formatter = new CodeUnitFormat(
            new CodeUnitFormatOptions());
        
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            
            // Stop if we've gone past the block's end
            if (instruction.getAddress().compareTo(block.getMaxAddress()) > 0) {
                break;
            }
            
            // Add the disassembled instruction
            disassembledCode.append(formatter.getRepresentationString(instruction))
                           .append("\n");
        }
        
        BasicBlockObject blockObj = new BasicBlockObject(
            blockId,
            startAddress,
            endAddress,
            disassembledCode.toString()
        );
        
        basicBlocks.put(blockId, blockObj);
        return blockId;
    }
    
    private int processFunctionAsOneBlock(Function function) {
        int blockId = nextBlockId++;
        long startAddress = function.getEntryPoint().getOffset();
        long endAddress = function.getBody().getMaxAddress().getOffset();
        
        StringBuilder disassembledCode = new StringBuilder();
        InstructionIterator instructions = program.getListing().getInstructions(
            function.getBody(), true);
        
        CodeUnitFormat formatter = new CodeUnitFormat(
            new CodeUnitFormatOptions());
        
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            disassembledCode.append(formatter.getRepresentationString(instruction))
                           .append("\n");
        }
        
        BasicBlockObject blockObj = new BasicBlockObject(
            blockId,
            startAddress,
            endAddress,
            disassembledCode.toString()
        );
        
        basicBlocks.put(blockId, blockObj);
        return blockId;
    }
    
    private int getOrCreateStringId(String str) {
        return stringToId.computeIfAbsent(str, s -> {
            int id = nextStringId++;
            stringTable.add(s);
            return id;
        });
    }
    
    private String computeMd5() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] executableBytes = program.getMemory().getAllInitializedAddressSet()
                .toString().getBytes();
            byte[] digest = md.digest(executableBytes);
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "unknown";
        }
    }
}