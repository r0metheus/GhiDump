// Export Ghidra analysis results into Protocol Buffers
// @author r0metheus
// @category CodeAnalysis
// @keybinding
// @menupath Tools.GhiDump
// @toolbar

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.ParserWalker;

import ghidra.app.plugin.processors.sleigh.SleighParserContext;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.ValueMapSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.VarnodeListSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.VarnodeSymbol;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import protoclasses.DataProto.DataList;
import protoclasses.DataProto.DataMessage;
import protoclasses.FunctionProto.ASTNodeMessage;
import protoclasses.FunctionProto.ASTNodeMessage.Builder;
import protoclasses.FunctionProto.FunctionMessage;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage.InstructionMessage;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage.InstructionMessage.OperandMessage;
import protoclasses.FunctionProto.FunctionMessage.ParameterMessage;
import protoclasses.FunctionProto.FunctionMessage.VariableMessage;
import protoclasses.FunctionProto.FunctionsList;
import protoclasses.KindOfData.DataKind;
import protoclasses.LabelsProto.LabelMessage;
import protoclasses.LabelsProto.LabelsList;
import protoclasses.MetadataProto.MetaList;
import protoclasses.MetadataProto.MetadataMessage;

import protoclasses.ReferenceProto.ReferenceList;
import protoclasses.ReferenceProto.ReferenceMessage;
import protoclasses.ReferenceProto.ReferenceMessage.ReferenceType;
import protoclasses.ReferenceProto.ReferenceMessage.SourceType;

import protoclasses.SegmentsProto.SegmentList;
import protoclasses.SegmentsProto.SegmentMessage;
import protoclasses.SymbolsProto.SymbolMessage;
import protoclasses.SymbolsProto.SymbolMessage.SymbolMessageType;
import protoclasses.SymbolsProto.SymbolsList;

public class GhiDump extends GhidraScript {

  static ReferenceList.Builder references = ReferenceList.newBuilder();
  static Map<ReferenceKey, Integer> referenceMap = new LinkedHashMap<ReferenceKey, Integer>();
  static Map<String, Integer> labels = new LinkedHashMap<String, Integer>();

  private FunctionsList dumpFunctions(FlatDecompilerAPI decompilerAPI, Listing listing) {
    FunctionIterator fooIter = listing.getFunctions(true);
    FunctionsList.Builder fooList = FunctionsList.newBuilder();
    int counter = 0;

    while (fooIter.hasNext()) {
      Function foo = fooIter.next();
      String entrypoint = foo.getEntryPoint().toString();

      FunctionMessage.Builder function = FunctionMessage.newBuilder();

      function.setName(foo.getName());

      if (!entrypoint.matches("-?[0-9a-f]+"))
        function.setSymbolicEntryPoint(entrypoint);
      else
        function.setEntryPoint(Long.parseLong(entrypoint, 16));

      // PARAMETERS
      for (Parameter p : foo.getParameters()) {
        ParameterMessage.Builder parameter = ParameterMessage.newBuilder();

        parameter.setName(p.getName());
        parameter.setDataType(p.getDataType().getName());
        parameter.setLength(p.getLength());

        if (p.getRegisters() != null)
          for (Register reg : p.getRegisters()) {
            parameter.addRegisterId(labelgsetter(reg.getName()));
          }

        function.addParameters(parameter.build());
      }

      // VARIABLES
      for (Variable v : foo.getAllVariables()) {
        VariableMessage.Builder variable = VariableMessage.newBuilder();

        variable.setName(v.getName());
        variable.setDataType(v.getDataType().getName());
        variable.setLength(v.getLength());

        if (v.isStackVariable())
          variable.setStackOffset(v.getStackOffset());

        if (v.getRegisters() != null)
          for (Register reg : v.getRegisters()) {
            variable.addRegisterId(labelgsetter(reg.getName()));
          }

        function.addVariables(variable.build());
      }

      try {
        decompilerAPI.decompile(foo);
      } catch (Exception e) {
        Logger.getGlobal().log(Level.WARNING, "Oops! Error while decompiling " + foo.getName() + '.', e);
      }

      DecompileResults results = decompilerAPI.getDecompiler().decompileFunction(foo, 30, getMonitor());

      if (results.decompileCompleted() && results.getDecompiledFunction() != null)
        function.setDecompiled(results.getDecompiledFunction().getC());

      HighFunction hf = results.getHighFunction();

      if (hf != null) {

        for (PcodeBlockBasic bb : hf.getBasicBlocks()) {
          BasicBlockMessage.Builder basicblock = BasicBlockMessage.newBuilder();

          Address start = bb.getStart();
          Address end = bb.getStop();

          if (!start.toString().matches("-?[0-9a-f]+"))
            basicblock.setSymbolicStartingAddress(start.toString());
          else
            basicblock.setStartingAddress(Long.parseLong(start.toString(), 16));

          if (!end.toString().matches("-?[0-9a-f]+"))
            basicblock.setSymbolicEndingAddress(end.toString());
          else
            basicblock.setEndingAddress(Long.parseLong(end.toString(), 16));

          InstructionIterator instrIter = listing.getInstructions(new AddressSet(currentProgram, start, end), true);

          while (instrIter.hasNext()) {

            Instruction instr = instrIter.next();
            
            if (instr == null || instr.getInstructionContext() == null)
              continue;

            InstructionMessage.Builder instruction = InstructionMessage.newBuilder();
            
            instruction.setIsThumb(ObjectiveC1_Utilities.isThumb(currentProgram, instr.getAddress()));
            
            ASTNode ASTRoot = instructionAST(instr);

            ASTNodeMessage.Builder root = ASTNodeMessage.newBuilder();
            
            root = serializeAST(ASTRoot);
                                                
            instruction.setRoot(root.build());         
            
            // OPERANDS XREFS
            int opsNum = instr.getNumOperands();
            for (int i = 0; i < opsNum; i++) {
              OperandMessage.Builder operand = OperandMessage.newBuilder();
              Reference[] refs = instr.getOperandReferences(i);
              
              if(refs.length == 0)
                continue;
              
              operand.setOperandNumber(i+1);

              for (Reference ref : refs) {
                ReferenceKey refKey = new ReferenceKey(ref.getFromAddress().toString(), ref.getToAddress().toString());

                if (referenceMap.containsKey(refKey))
                  operand.addReferenceId(referenceMap.get(refKey));
              }

              instruction.addOperands(operand.build());
            }

            basicblock.addInstructions(instruction.build());
          }

          function.addBasicBlocks(basicblock.build());
        }

      }

      try {
        protoWriter(function.build(), currentProgram.getName() + "_function_" + Integer.toString(counter));
      } catch (IOException e) {
        Logger.getGlobal().log(Level.WARNING, "Oops! Unable to print out a function", e);

      }

      counter++;
    }

    return fooList.build();
  }

  private SymbolsList dumpSymbols(Listing listing) {
    SymbolIterator symIter = currentProgram.getSymbolTable().getAllSymbols(false);

    SymbolsList.Builder symbols = SymbolsList.newBuilder();
    int reference_id = 0;

    while (symIter.hasNext()) {
      Symbol current = symIter.next();
      String source = current.getSource().toString().toUpperCase();
      String symbolType = current.getSymbolType().toString().toUpperCase();
      String address = current.getAddress().toString();
      SymbolMessage.Builder symbol = SymbolMessage.newBuilder();

      symbol.setName(current.getName());

      if (!address.matches("-?[0-9a-f]+"))
        symbol.setSymbolicAddress(address);
      else
        symbol.setLongAddress(Long.parseLong(address, 16));

      if (symbolType.equals("NULL"))
        symbol.setType(SymbolMessageType.NULL);
      if (symbolType.equals("LABEL"))
        symbol.setType(SymbolMessageType.LABEL);
      if (symbolType.equals("LIBRARY"))
        symbol.setType(SymbolMessageType.LIBRARY);
      if (symbolType.equals("NAMESPACE"))
        symbol.setType(SymbolMessageType.NAMESPACE);
      if (symbolType.equals("CLASS"))
        symbol.setType(SymbolMessageType.CLASS);
      if (symbolType.equals("FUNCTION"))
        symbol.setType(SymbolMessageType.FUNCTION);
      if (symbolType.equals("PARAMETER"))
        symbol.setType(SymbolMessageType.PARAMETER);
      if (symbolType.equals("LOCAL_VAR"))
        symbol.setType(SymbolMessageType.LOCAL_VAR);
      if (symbolType.equals("GLOBAL_VAR"))
        symbol.setType(SymbolMessageType.GLOBAL_VAR);

      symbol.setNamespace(current.getParentNamespace().getName());

      if (source.equals("DEFAULT"))
        symbol.setSource(protoclasses.SymbolsProto.SymbolMessage.SourceType.DEFAULT);
      if (source.equals("ANALYSIS"))
        symbol.setSource(protoclasses.SymbolsProto.SymbolMessage.SourceType.ANALYSIS);
      if (source.equals("IMPORTED"))
        symbol.setSource(protoclasses.SymbolsProto.SymbolMessage.SourceType.IMPORTED);
      if (source.equals("USER_DEFINED"))
        symbol.setSource(protoclasses.SymbolsProto.SymbolMessage.SourceType.USER_DEFINED);

      for (Reference ref : current.getReferences()) {
        ReferenceMessage.Builder reference = ReferenceMessage.newBuilder();

        Address refFrom = ref.getFromAddress();
        Address refTo = ref.getToAddress();

        String refType = ref.getReferenceType().toString();
        String refSource = ref.getSource().toString().toUpperCase();

        if (!refFrom.toString().matches("-?[0-9a-f]+"))
          reference.setSymbolicFromAddress(refFrom.toString());
        else
          reference.setLongFromAddress(Long.parseLong(refFrom.toString(), 16));

        if (!refTo.toString().matches("-?[0-9a-f]+"))
          reference.setSymbolicToAddress(refTo.toString());
        else
          reference.setLongToAddress(Long.parseLong(refTo.toString(), 16));

        referenceMap.put(new ReferenceKey(refFrom.toString(), refTo.toString()), reference_id);

        // REF TYPE
        if (refType.equals("THUNK"))
          reference.setRefType(ReferenceType.THUNK);
        if (refType.equals("CALL_OVERRIDE_UNCONDITIONAL"))
          reference.setRefType(ReferenceType.CALL_OVERRIDE_UNCONDITIONAL);
        if (refType.equals("CALL_TERMINATOR"))
          reference.setRefType(ReferenceType.CALL_TERMINATOR);
        if (refType.equals("CALLOTHER_OVERRIDE_CALL"))
          reference.setRefType(ReferenceType.CALLOTHER_OVERRIDE_CALL);
        if (refType.equals("CALLOTHER_OVERRIDE_JUMP"))
          reference.setRefType(ReferenceType.CALLOTHER_OVERRIDE_JUMP);
        if (refType.equals("COMPUTED_CALL"))
          reference.setRefType(ReferenceType.COMPUTED_CALL);
        if (refType.equals("COMPUTED_CALL_TERMINATOR"))
          reference.setRefType(ReferenceType.COMPUTED_CALL_TERMINATOR);
        if (refType.equals("COMPUTED_JUMP"))
          reference.setRefType(ReferenceType.COMPUTED_JUMP);
        if (refType.equals("CONDITIONAL_CALL"))
          reference.setRefType(ReferenceType.CONDITIONAL_CALL);
        if (refType.equals("CONDITIONAL_CALL_TERMINATOR"))
          reference.setRefType(ReferenceType.CONDITIONAL_CALL_TERMINATOR);
        if (refType.equals("CONDITIONAL_COMPUTED_CALL"))
          reference.setRefType(ReferenceType.CONDITIONAL_COMPUTED_CALL);
        if (refType.equals("CONDITIONAL_COMPUTED_JUMP"))
          reference.setRefType(ReferenceType.CONDITIONAL_COMPUTED_JUMP);
        if (refType.equals("CONDITIONAL_JUMP"))
          reference.setRefType(ReferenceType.CONDITIONAL_JUMP);
        if (refType.equals("CONDITIONAL_TERMINATOR"))
          reference.setRefType(ReferenceType.CONDITIONAL_TERMINATOR);
        if (refType.equals("DATA"))
          reference.setRefType(ReferenceType.DATA);
        if (refType.equals("DATA_IND"))
          reference.setRefType(ReferenceType.DATA_IND);
        if (refType.equals("EXTERNAL_REF"))
          reference.setRefType(ReferenceType.EXTERNAL_REF);
        if (refType.equals("FALL_THROUGH"))
          reference.setRefType(ReferenceType.FALL_THROUGH);
        if (refType.equals("FLOW"))
          reference.setRefType(ReferenceType.FLOW);
        if (refType.equals("INDIRECTION"))
          reference.setRefType(ReferenceType.INDIRECTION);
        if (refType.equals("INVALID"))
          reference.setRefType(ReferenceType.INVALID);
        if (refType.equals("JUMP_OVERRIDE_UNCONDITIONAL"))
          reference.setRefType(ReferenceType.JUMP_OVERRIDE_UNCONDITIONAL);
        if (refType.equals("JUMP_TERMINATOR"))
          reference.setRefType(ReferenceType.JUMP_TERMINATOR);
        if (refType.equals("PARAM"))
          reference.setRefType(ReferenceType.PARAM);
        if (refType.equals("READ"))
          reference.setRefType(ReferenceType.READ);
        if (refType.equals("READ_IND"))
          reference.setRefType(ReferenceType.READ_IND);
        if (refType.equals("READ_WRITE"))
          reference.setRefType(ReferenceType.READ_WRITE);
        if (refType.equals("READ_WRITE_IND"))
          reference.setRefType(ReferenceType.READ_WRITE_IND);
        if (refType.equals("TERMINATOR"))
          reference.setRefType(ReferenceType.TERMINATOR);
        if (refType.equals("UNCONDITIONAL_CALL"))
          reference.setRefType(ReferenceType.UNCONDITIONAL_CALL);
        if (refType.equals("UNCONDITIONAL_JUMP"))
          reference.setRefType(ReferenceType.UNCONDITIONAL_JUMP);
        if (refType.equals("WRITE"))
          reference.setRefType(ReferenceType.WRITE);
        if (refType.equals("WRITE_IND"))
          reference.setRefType(ReferenceType.WRITE_IND);

        // REF SOURCE
        if (refSource.equals("DEFAULT"))
          reference.setSource(SourceType.DEFAULT);
        if (refSource.equals("ANALYSIS"))
          reference.setSource(SourceType.ANALYSIS);
        if (refSource.equals("IMPORTED"))
          reference.setSource(SourceType.IMPORTED);
        if (refSource.equals("USER_DEFINED"))
          reference.setSource(SourceType.USER_DEFINED);
        
        
        // REF DATA
        if (refType.equals("DATA") && getDataAt(refFrom) != null) {
          DataMessage.Builder data = DataMessage.newBuilder();
          Data refData = getDataAt(refFrom);

          data.setDataType(refData.getDataType().getName());

          if (!refFrom.toString().matches("-?[0-9a-f]+"))
            data.setSymbolicAddress(refFrom.toString());
          else
            data.setLongAddress(Long.parseLong(refFrom.toString(), 16));

          if (refData.isDefined())
            data.addKind(DataKind.DEFINED);
          if (refData.hasStringValue())
            data.addKind(DataKind.STRING);
          if (refData.isArray())
            data.addKind(DataKind.ARRAY);
          if (refData.isConstant())
            data.addKind(DataKind.CONSTANT);
          if (refData.isDynamic())
            data.addKind(DataKind.DYNAMIC);
          if (refData.isPointer())
            data.addKind(DataKind.POINTER);
          if (refData.isStructure())
            data.addKind(DataKind.STRUCTURE);
          if (refData.isUnion())
            data.addKind(DataKind.UNION);
          if (refData.isVolatile())
            data.addKind(DataKind.VOLATILE);

          if (refData.getValue() != null) {
            try {
              data.setValue(ByteString.copyFrom(refData.getBytes()));
            } catch (MemoryAccessException e) {
              Logger.getGlobal().log(Level.INFO,
                  "Oops! Error while writing out some data values in dumpSymbols.", e);
            } finally {
              reference.setRefData(data);
            }
          }
        }

        references.addReferences(reference.build());

        symbol.addReferenceId(reference_id);
        reference_id++;
      }

      symbols.addSymbols(symbol.build());
    }

    try {
      protoWriter(references.build(), currentProgram.getName() + "_references");
    } catch (IOException e) {
      Logger.getGlobal().log(Level.WARNING, "Oops! Error while writing out references in dumpSymbols.", e);
    }

    return symbols.build();
  }

  public DataList dumpData(FlatProgramAPI programAPI, Listing listing) {
    DataList.Builder database = DataList.newBuilder();

    for (MemoryBlock mb : programAPI.getMemoryBlocks()) {
      String blockName = mb.getName();

      if (!blockName.equals(".bss") && !blockName.equals(".data"))
        continue;

      Address start = mb.getStart();
      Address end = mb.getEnd();

      DataIterator dataIter = listing.getData(new AddressSet(currentProgram, start, end), true);

      while (dataIter.hasNext()) {
        Data data = dataIter.next();
        Address dataAddress = data.getAddress();

        if (blockName.equals(".bss") && getReferencesTo(dataAddress).length == 0)
          continue;

        DataMessage.Builder dataProto = DataMessage.newBuilder();

        if (!dataAddress.toString().matches("-?[0-9a-f]+"))
          dataProto.setSymbolicAddress(dataAddress.toString());
        else
          dataProto.setLongAddress(Long.parseLong(dataAddress.toString(), 16));

        dataProto.setDataType(data.getDataType().getName());

        if (blockName.equals(".data")) {
          try {
            dataProto.setValue(ByteString.copyFrom(data.getBytes()));
            dataProto.setLength(dataProto.getValue().size());
          } catch (MemoryAccessException e) {
            Logger.getGlobal().log(Level.INFO, "Oops! Error while writing out some data values in dumpData.", e);
          }
        }

        if (data.isDefined())
          dataProto.addKind(DataKind.DEFINED);
        if (data.hasStringValue())
          dataProto.addKind(DataKind.STRING);
        if (data.isArray())
          dataProto.addKind(DataKind.ARRAY);
        if (data.isConstant())
          dataProto.addKind(DataKind.CONSTANT);
        if (data.isDynamic())
          dataProto.addKind(DataKind.DYNAMIC);
        if (data.isPointer())
          dataProto.addKind(DataKind.POINTER);
        if (data.isStructure())
          dataProto.addKind(DataKind.STRUCTURE);
        if (data.isUnion())
          dataProto.addKind(DataKind.UNION);
        if (data.isVolatile())
          dataProto.addKind(DataKind.VOLATILE);

        database.addData(dataProto.build());
      }

    }
    return database.build();
  }

  private SegmentList dumpSegments(FlatProgramAPI programAPI) {
    SegmentList.Builder segments = SegmentList.newBuilder();

    for (MemoryBlock mb : programAPI.getMemoryBlocks()) {
      SegmentMessage.Builder segment = SegmentMessage.newBuilder();

      String start = mb.getStart().toString();
      String end = mb.getEnd().toString();

      segment.setName(mb.getName());

      if (!start.matches("-?[0-9a-f]+"))
        segment.setSymbolicStartingAddress(start);
      else
        segment.setLongStartingAddress(Long.parseLong(start, 16));

      if (!end.matches("-?[0-9a-f]+"))
        segment.setSymbolicEndingAddress(end);
      else
        segment.setLongEndingAddress(Long.parseLong(end, 16));

      segment.setLength((int) mb.getSize());

      segments.addSegments(segment.build());
    }

    return segments.build();
  }

  private MetaList dumpMetadata() {
    MetaList.Builder metadata = MetaList.newBuilder();

    for (Map.Entry<String, String> entry : currentProgram.getMetadata().entrySet()) {
      MetadataMessage.Builder meta = MetadataMessage.newBuilder();

      meta.setKey(entry.getKey());

      if (entry.getValue() != null)
        meta.setValue(entry.getValue());
      else
        meta.setValue("null");

      metadata.addMetadata(meta.build());
    }

    return metadata.build();
  }

  private void protoWriter(Message message, String filename) throws IOException {
    File results = new File("GhiDumps" + File.separator + currentProgram.getName() + File.separator + filename + ".pb");
    FileOutputStream output = new FileOutputStream(results);
    message.writeTo(output);
    output.close();
  }

  private void printTriple(int indent, ParserWalker walker, TripleSymbol triple, ASTNode current)
      throws MemoryAccessException {
    ASTNode newnode = new ASTNode("");

    if (triple instanceof VarnodeSymbol) {
      VarnodeSymbol node = (VarnodeSymbol) triple;

      newnode.setValue(node.getName());
    }

    else if (triple instanceof VarnodeListSymbol) {
      VarnodeListSymbol node = (VarnodeListSymbol) triple;

      int ind = (int) node.getPatternValue().getValue(walker);
      ArrayList<VarnodeSymbol> syms = new ArrayList<>(node.getVarnodeTable());

      newnode.setValue(syms.get(ind).getName());
    }

    else if (triple instanceof ValueMapSymbol) {
      ValueMapSymbol node = (ValueMapSymbol) triple;

      int ind = (int) node.getPatternValue().getValue(walker);
      ArrayList<Long> vals = new ArrayList<>(node.getMap());
      long val = vals.get(ind);

      if (val >= 0) {

        newnode.setValue("0x" + Long.toHexString(val));
      } else {

        newnode.setValue("-0x" + Long.toHexString(-val));
      }


    }
    
    current.addChild(newnode);
  }

  private void printOperand(int indent, ParserWalker walker, OperandSymbol operandSymbol, ASTNode current) throws MemoryAccessException {
    TripleSymbol triple = operandSymbol.getDefiningSymbol();
    PatternExpression defexp = operandSymbol.getDefiningExpression();
    ASTNode child = new ASTNode("");

    if (triple != null) {
      if (triple instanceof SubtableSymbol) {
        Constructor constructor = walker.getConstructor();
        printConstructor(indent + 1, walker, constructor, child);
      } else {
        printTriple(indent + 1, walker, triple, child);
      }
    } else {
        long val = defexp.getValue(walker);
        
        if (val >= 0) {
          child.setValue("0x" + Long.toHexString(val));
        } else {
          child.setValue("-0x" + Long.toHexString(-val));
        }
    }
    
    current.addChild(child);
  }

  private void printConstructor(int indent, ParserWalker walker, Constructor constructor, ASTNode current) throws MemoryAccessException {
    List<String> printpiece = constructor.getPrintPieces();

    for (String piece : printpiece) {
      if (piece.length() == 0) {
        continue;
      }

      if (piece.charAt(0) == '\n') {
        int index = piece.charAt(1) - 'A';

        walker.pushOperand(index);
        ASTNode child = new ASTNode("");

        printOperand(indent + 1, walker, constructor.getOperand(index), child);
        current.addChild(child);

        walker.popOperand();

      } else {
        ASTNode newnode = new ASTNode(piece);
        current.addChild(newnode);
      }
    }

  }

  private ASTNode instructionAST(Instruction instr) {
    InstructionContext context = instr.getInstructionContext();

    ASTNode ASTRoot = new ASTNode("root");

    SleighParserContext protoContext;

    try {
      protoContext = (SleighParserContext) context.getParserContext();

      ParserWalker walker = new ParserWalker(protoContext);

      walker.baseState();

      printConstructor(0, walker, walker.getConstructor(), ASTRoot);

      ArrayList<ASTNode> ASTList = new ArrayList<ASTNode>();
      ASTtoList(ASTRoot, ASTList);
      Collections.reverse(ASTList);

      cleanAST(ASTList);

      ASTNode firstuseless = ASTRoot.getChildren().get(0);
      if (ASTRoot.getChildren().size() == 1 && !firstuseless.hasValue())
        firstuseless.deleteASTNode();

      // OPERANDS REPLACEMENT
      int numops = instr.getNumOperands();
      int addroffset = 2;
      for(int i = 0; i<numops; ++i) {
        Map<String, String> opobjectstype = new LinkedHashMap<String, String>();
        
        for(Object obj: instr.getOpObjects(i)) {
          String type = obj.getClass().getSimpleName();
          String value = obj.toString();
    
          opobjectstype.put(value, type);
        }
        
        for(ASTNode node: ASTList) {
          if(!node.hasValue())
            continue;
          
          if(opobjectstype.containsKey(node.getValue())) {
            node.setType(opobjectstype.get(node.getValue()));
            
            continue;
          }
          
          if(node.getValue().contains("0x"))
            if(opobjectstype.containsKey("00"+node.getValue().substring(addroffset)))
              node.setType("Address");
        }

        String pure = instr.getDefaultOperandRepresentation(i).replaceAll("\\[|\\]", "");
        String label = CodeUnitFormat.DEFAULT.getOperandRepresentationString(instr, i);
        String replacement = StringUtils.difference(pure, label).replaceAll("\\[|\\]", "");
        
        if(replacement.isEmpty() || replacement.isBlank())
          continue;

        for(ASTNode node: ASTList) {
          if(!node.hasValue())
            continue;
          
          if(node.getValue().equals(pure)) {
            
            node.setValue(replacement);
          }

          else if(node.getValue().contains("0x") && node.getValue().substring(addroffset).equals(pure.substring(addroffset+2))) {
   
            node.setValue(replacement);
          }
 
        }
        
        opobjectstype.clear();
      }

      // LABELS REPLACEMENT
      for(ASTNode node: ASTList) {
        if(node.hasValue()) {
          String value = node.getValue();
          
          if(!value.equals("root"))          
            node.setValue(Integer.toString(labelgsetter(value)));
        }
      }

      return ASTRoot;

    } catch (Exception e) {
      e.printStackTrace();
    }
    
    return null;

  }
  
  public int labelgsetter(String value) {
    if(labels.containsKey(value))
      return labels.get(value);
    
    int size = labels.size();
    
    labels.put(value, size);
    
    return size;    
  }

  private boolean isUseless(ASTNode node) {
    boolean flag = false;

    if (node.hasValue()) {
      flag = false;
    }
    
    if (node.hasValue() && node.hasChildren() && !node.getValue().equals("root"))
      throw new IllegalArgumentException("hasValue but hasChildren too");

    if (!node.hasValue()) {
      if (node.hasChildren() && node.getChildren().size() == 1
          && !node.getChildren().get(0).hasValue())
        flag = true;

      if (node.getChildren().isEmpty())
        flag = true;

      for (ASTNode child : node.getChildren())
        if (child.hasValue())
          return false;
    }

    return flag;

  }

  private void ASTtoList(ASTNode node, ArrayList<ASTNode> list) {
    list.add(node);
    node.getChildren().forEach(each -> ASTtoList(each, list));
  }

  private void cleanAST(ArrayList<ASTNode> list) {
    for (ASTNode node : list) {
      if (isUseless(node)) {
        node.deleteASTNode();
      }
    }
  }

  private ASTNodeMessage.Builder serializeAST(ASTNode node) {
    ASTNodeMessage.Builder rootProto = ASTNodeMessage.newBuilder();
    
    node.getChildren().forEach(each -> autumnLeaves(each, rootProto));
    
    return rootProto;
  }
  
  private void autumnLeaves(ASTNode node, ASTNodeMessage.Builder nodeProto) {

    if(node.hasValue()) {
      ASTNodeMessage.Builder leaf = ASTNodeMessage.newBuilder();
      
      leaf.setLabelId(Integer.parseInt(node.getValue()));
      
      if(node.getType().equals("Address"))
        leaf.setType(protoclasses.FunctionProto.ASTNodeMessage.Type.ADDR);
      
      if(node.getType().equals("Scalar"))
        leaf.setType(protoclasses.FunctionProto.ASTNodeMessage.Type.CONST);
      
      if(node.getType().equals("Register"))
        leaf.setType(protoclasses.FunctionProto.ASTNodeMessage.Type.REG);

      nodeProto.addChildren(leaf.build());
      
      return;      
    }
    
    ASTNodeMessage.Builder child = serializeAST(node);
    
    nodeProto.addChildren(child.build());
    
  }
  
  private void dumpLabels() throws IOException {
    LabelsList.Builder labelslist = LabelsList.newBuilder();
    
    for(Map.Entry<String, Integer> entry: labels.entrySet()) {
      LabelMessage.Builder label = LabelMessage.newBuilder();
      String input = entry.getKey();
     
      label.setLabel(input);
      
      labelslist.addLabels(label.build());
    }
    
    protoWriter(labelslist.build(), currentProgram.getName()+"_labels");
  }

  @Override
  public void run() throws Exception {
    Listing listing = currentProgram.getListing();
    FlatProgramAPI programAPI = new FlatProgramAPI(currentProgram);
    FlatDecompilerAPI decompilerAPI = new FlatDecompilerAPI(programAPI);
    String programName = currentProgram.getName();

    File results = new File("GhiDumps" + File.separator + programName);
    
    if (!results.exists())
      results.mkdirs();

    println("   ________    _ ____                      ");
    println("  / ____/ /_  (_) __ \\__  ______ ___  ____ ");
    println(" / / __/ __ \\/ / / / / / / / __ `__ \\/ __ \\");
    println("/ /_/ / / / / / /_/ / /_/ / / / / / / /_/ /");
    println("\\____/_/ /_/_/_____/\\__,_/_/ /_/ /_/ .___/ ");
    println("                                  /_/      ");
    println("Dumping " + programName + "...");

    protoWriter(dumpMetadata(), programName+"_metadata"); 
    protoWriter(dumpSegments(programAPI), programName+"_segments"); 
    protoWriter(dumpSymbols(listing), programName+"_symbols");
    protoWriter(dumpData(programAPI, listing), programName+"_data");

    dumpFunctions(decompilerAPI, listing);
    dumpLabels();
    
    println("Dump completed.");
  }

}
