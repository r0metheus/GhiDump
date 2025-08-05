package ghidump.serialization;

import ghidump.model.AnalysisResult;
import ghidump.model.BasicBlockObject;
import ghidump.model.FunctionObject;

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

/**
 * Serializes the normalized analysis result to MessagePack format.
 * MessagePack provides efficient binary serialization with smaller payload sizes
 * compared to Protocol Buffers.
 */
public class MessagePackSerializer {
    
    /**
     * Serialize an AnalysisResult to MessagePack byte array.
     * 
     * @param result The analysis result to serialize
     * @return Serialized byte array
     * @throws IOException if serialization fails
     */
    public byte[] serialize(AnalysisResult result) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        try (MessagePacker packer = MessagePack.newDefaultPacker(outputStream)) {
            // Write root object as a map with 5 fields
            packer.packMapHeader(5);
            
            // 1. Binary name
            packer.packString("binaryName");
            packer.packString(result.binaryName());
            
            // 2. Binary MD5
            packer.packString("binaryMd5");
            packer.packString(result.binaryMd5());
            
            // 3. String table
            packer.packString("stringTable");
            packer.packArrayHeader(result.stringTable().size());
            for (String str : result.stringTable()) {
                packer.packString(str);
            }
            
            // 4. Functions
            packer.packString("functions");
            packFunctions(packer, result.functions());
            
            // 5. Basic blocks
            packer.packString("basicBlocks");
            packBasicBlocks(packer, result.basicBlocks());
            
            packer.flush();
        }
        
        return outputStream.toByteArray();
    }
    
    private void packFunctions(MessagePacker packer, Map<Integer, FunctionObject> functions) 
            throws IOException {
        // Pack as map: functionId -> function object
        packer.packMapHeader(functions.size());
        
        for (Map.Entry<Integer, FunctionObject> entry : functions.entrySet()) {
            packer.packInt(entry.getKey());
            
            FunctionObject function = entry.getValue();
            // Pack function as map with 4 fields
            packer.packMapHeader(4);
            
            packer.packString("functionId");
            packer.packInt(function.functionId());
            
            packer.packString("functionNameId");
            packer.packInt(function.functionNameId());
            
            packer.packString("entryPointAddress");
            packer.packLong(function.entryPointAddress());
            
            packer.packString("basicBlockIds");
            packer.packArrayHeader(function.basicBlockIds().size());
            for (Integer blockId : function.basicBlockIds()) {
                packer.packInt(blockId);
            }
        }
    }
    
    private void packBasicBlocks(MessagePacker packer, Map<Integer, BasicBlockObject> blocks) 
            throws IOException {
        // Pack as map: blockId -> block object
        packer.packMapHeader(blocks.size());
        
        for (Map.Entry<Integer, BasicBlockObject> entry : blocks.entrySet()) {
            packer.packInt(entry.getKey());
            
            BasicBlockObject block = entry.getValue();
            // Pack block as map with 4 fields
            packer.packMapHeader(4);
            
            packer.packString("blockId");
            packer.packInt(block.blockId());
            
            packer.packString("startAddress");
            packer.packLong(block.startAddress());
            
            packer.packString("endAddress");
            packer.packLong(block.endAddress());
            
            packer.packString("disassembledCode");
            packer.packString(block.disassembledCode());
        }
    }
}