// Export Ghidra analysis results into Protocol Buffers
// @author r0metheus
// @category CodeAnalysis
// @keybinding
// @menupath Tools.GhiDump
// @toolbar

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
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
import protoclasses.FunctionProto.FunctionMessage;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage.InstructionMessage;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage.InstructionMessage.OperandMessage;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage.InstructionMessage.OperandMessage.OperandObject;
import protoclasses.FunctionProto.FunctionMessage.BasicBlockMessage.InstructionMessage.OperandMessage.OperandObject.Type;
import protoclasses.FunctionProto.FunctionMessage.ParameterMessage;
import protoclasses.FunctionProto.FunctionMessage.VariableMessage;
import protoclasses.FunctionProto.FunctionsList;
import protoclasses.GhiDumpProto.GhiDumpMessage;
import protoclasses.KindOfData.DataKind;
import protoclasses.MetadataProto.MetaList;
import protoclasses.MetadataProto.MetadataMessage;
import protoclasses.ReferenceProto.ReferenceMessage;
import protoclasses.ReferenceProto.ReferenceMessage.ReferenceType;
import protoclasses.ReferenceProto.ReferenceMessage.SourceType;
import protoclasses.ReferenceProto.ReferencesMap;
import protoclasses.SegmentsProto.SegmentList;
import protoclasses.SegmentsProto.SegmentMessage;
import protoclasses.SymbolsProto.SymbolMessage;
import protoclasses.SymbolsProto.SymbolMessage.SymbolMessageType;
import protoclasses.SymbolsProto.SymbolsList;

public class GhiDump extends GhidraScript {
	
	static ReferencesMap.Builder references = ReferencesMap.newBuilder();

	private FunctionsList dumpFunctions(FlatDecompilerAPI decompilerAPI, Listing listing) {
		FunctionIterator fooIter = listing.getFunctions(true);
		FunctionsList.Builder fooList = FunctionsList.newBuilder();
		int counter = 0;

		while (fooIter.hasNext()) {
			Function foo = fooIter.next();

			FunctionMessage.Builder function = FunctionMessage.newBuilder();

			function.setName(foo.getName());
			function.setEntryPoint(foo.getEntryPoint().toString());

			// PARAMETERS
			for (Parameter p : foo.getParameters()) {
				ParameterMessage.Builder parameter = ParameterMessage.newBuilder();

				parameter.setName(p.getName());
				parameter.setDataType(p.getDataType().getName());
				parameter.setLength(p.getLength());

				if (p.getRegisters() != null)
					for (Register r : p.getRegisters())
						parameter.addRegisters(r.getName());

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
					for (Register r : v.getRegisters())
						variable.addRegisters(r.getName());

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

					if(!start.toString().matches("-?[0-9a-fA-F]+"))
						basicblock.setSymbolicStartingAddress(start.toString());
					else
						basicblock.setLongStartingAddress(Long.parseLong(start.toString(), 16));
					
					if(!end.toString().matches("-?[0-9a-fA-F]+"))
						basicblock.setSymbolicEndingAddress(end.toString());
					else
						basicblock.setLongEndingAddress(Long.parseLong(end.toString(), 16));

					InstructionIterator instrIter = listing.getInstructions(new AddressSet(currentProgram, start, end), true);

					while (instrIter.hasNext()) {
						Instruction instr = instrIter.next();

						if (instr == null)
							continue;

						InstructionMessage.Builder instruction = InstructionMessage.newBuilder();
						int opsNum = instr.getNumOperands();

						instruction.setMnemonic(instr.getMnemonicString());
						instruction.setIsThumb(ObjectiveC1_Utilities.isThumb(currentProgram, instr.getAddress()));

						// OPERAND
						for (int i = 0; i < opsNum; i++) {
							OperandMessage.Builder operand = OperandMessage.newBuilder();

							operand.setName(instr.getDefaultOperandRepresentation(i));

							for (Object o : instr.getOpObjects(i)) {
								OperandObject.Builder opobject = OperandObject.newBuilder();

								String opClass = o.getClass().toString();
								String type = opClass.substring(opClass.lastIndexOf('.') + 1);

								opobject.setName(o.toString());
								
								if(type.equals("Register"))
									opobject.setType(Type.REGISTER);
								if(type.equals("Scalar"))
									opobject.setType(Type.SCALAR);
								if(type.equals("GenericAddress"))
									opobject.setType(Type.ADDRESS);

								operand.addOpObjects(opobject.build());
							}
							
							for (Reference ref: instr.getOperandReferences(i)) {
								String fromAddress = ref.getFromAddress().toString();
								String toAddress = ref.getToAddress().toString();
								
								Map<Integer, ReferenceMessage> refs = references.getReferencesMap();

								for(Map.Entry<Integer, ReferenceMessage> entry: refs.entrySet()) {
									ReferenceMessage rm = entry.getValue();
																		
									if(rm.getToAddress().equals(toAddress) && rm.getFromAddress().equals(fromAddress))
										operand.addReferenceId(entry.getKey());

								}
							}

							instruction.addOperands(operand.build());
						}

						basicblock.addInstructions(instruction.build());
					}

					function.addBasicBlocks(basicblock.build());
				}

			}
			
			try {
				protoWriter(function.build(), String.valueOf(counter));
			} catch (IOException e) {
				Logger.getGlobal().log(Level.WARNING, "Oops! Unable to print out a function", e);
				
			}
			
			counter++;

			//fooList.addFunctions(function.build());
			
		}

		return fooList.build();
	}

	private SymbolsList dumpSymbols(Listing listing) {
		SymbolIterator symbolIterator = currentProgram.getSymbolTable().getAllSymbols(true);

		SymbolsList.Builder symbols = SymbolsList.newBuilder();
		int reference_id = 0;

		while (symbolIterator.hasNext()) {
			
			Symbol current = symbolIterator.next();
			String source = current.getSource().toString().toUpperCase();
			String symbolType = current.getSymbolType().toString().toUpperCase();
			String address = current.getAddress().toString();
			SymbolMessage.Builder symbol = SymbolMessage.newBuilder();

			symbol.setName(current.getName());
			
			if(!address.matches("-?[0-9a-fA-F]+"))
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


			for (Reference ref: current.getReferences()) {
				ReferenceMessage.Builder reference = ReferenceMessage.newBuilder();

				Address refFrom = ref.getFromAddress();
				Address refTo = ref.getToAddress();

				String refType = ref.getReferenceType().toString();
				String refSource = ref.getSource().toString().toUpperCase();

				// REF ID
				reference.setReferenceId(reference_id);
				
				reference.setFromAddress(refFrom.toString());
				reference.setToAddress(refTo.toString());
				
				// REF TYPE
				if(refType.equals("THUNK"))
					reference.setRefType(ReferenceType.THUNK);
				if(refType.equals("CALL_OVERRIDE_UNCONDITIONAL"))
						reference.setRefType(ReferenceType.CALL_OVERRIDE_UNCONDITIONAL);
				if(refType.equals("CALL_TERMINATOR"))
						reference.setRefType(ReferenceType.CALL_TERMINATOR);
				if(refType.equals("CALLOTHER_OVERRIDE_CALL"))
						reference.setRefType(ReferenceType.CALLOTHER_OVERRIDE_CALL);
				if(refType.equals("CALLOTHER_OVERRIDE_JUMP"))
						reference.setRefType(ReferenceType.CALLOTHER_OVERRIDE_JUMP);
				if(refType.equals("COMPUTED_CALL"))
						reference.setRefType(ReferenceType.COMPUTED_CALL);
				if(refType.equals("COMPUTED_CALL_TERMINATOR"))
						reference.setRefType(ReferenceType.COMPUTED_CALL_TERMINATOR);
				if(refType.equals("COMPUTED_JUMP"))
						reference.setRefType(ReferenceType.COMPUTED_JUMP);
				if(refType.equals("CONDITIONAL_CALL"))
						reference.setRefType(ReferenceType.CONDITIONAL_CALL);
				if(refType.equals("CONDITIONAL_CALL_TERMINATOR"))
						reference.setRefType(ReferenceType.CONDITIONAL_CALL_TERMINATOR);
				if(refType.equals("CONDITIONAL_COMPUTED_CALL"))
						reference.setRefType(ReferenceType.CONDITIONAL_COMPUTED_CALL);
				if(refType.equals("CONDITIONAL_COMPUTED_JUMP"))
						reference.setRefType(ReferenceType.CONDITIONAL_COMPUTED_JUMP);
				if(refType.equals("CONDITIONAL_JUMP"))
						reference.setRefType(ReferenceType.CONDITIONAL_JUMP);
				if(refType.equals("CONDITIONAL_TERMINATOR"))
						reference.setRefType(ReferenceType.CONDITIONAL_TERMINATOR);
				if(refType.equals("DATA"))
						reference.setRefType(ReferenceType.DATA);
				if(refType.equals("DATA_IND"))
						reference.setRefType(ReferenceType.DATA_IND);
				if(refType.equals("EXTERNAL_REF"))
						reference.setRefType(ReferenceType.EXTERNAL_REF);
				if(refType.equals("FALL_THROUGH"))
						reference.setRefType(ReferenceType.FALL_THROUGH);
				if(refType.equals("FLOW"))
						reference.setRefType(ReferenceType.FLOW);
				if(refType.equals("INDIRECTION"))
						reference.setRefType(ReferenceType.INDIRECTION);
				if(refType.equals("INVALID"))
						reference.setRefType(ReferenceType.INVALID);
				if(refType.equals("JUMP_OVERRIDE_UNCONDITIONAL"))
						reference.setRefType(ReferenceType.JUMP_OVERRIDE_UNCONDITIONAL);
				if(refType.equals("JUMP_TERMINATOR"))
						reference.setRefType(ReferenceType.JUMP_TERMINATOR);
				if(refType.equals("PARAM"))
						reference.setRefType(ReferenceType.PARAM);
				if(refType.equals("READ"))
						reference.setRefType(ReferenceType.READ);
				if(refType.equals("READ_IND"))
						reference.setRefType(ReferenceType.READ_IND);
				if(refType.equals("READ_WRITE"))
						reference.setRefType(ReferenceType.READ_WRITE);
				if(refType.equals("READ_WRITE_IND"))
						reference.setRefType(ReferenceType.READ_WRITE_IND);
				if(refType.equals("TERMINATOR"))
						reference.setRefType(ReferenceType.TERMINATOR);
				if(refType.equals("UNCONDITIONAL_CALL"))
						reference.setRefType(ReferenceType.UNCONDITIONAL_CALL);
				if(refType.equals("UNCONDITIONAL_JUMP"))
						reference.setRefType(ReferenceType.UNCONDITIONAL_JUMP);
				if(refType.equals("WRITE"))
					reference.setRefType(ReferenceType.WRITE);
				if(refType.equals("WRITE_IND"))
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


				if (refType.equals("DATA") && getDataAt(refFrom) != null) {
					DataMessage.Builder data = DataMessage.newBuilder();
					Data refData = getDataAt(refFrom);

					data.setDataType(refData.getDataType().getName());
					
					if(!refFrom.toString().matches("-?[0-9a-fA-F]+"))
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
							Logger.getGlobal().log(Level.INFO, "Oops! Error while writing out some data values in dumpSymbols.", e);
						}

						reference.setRefData(data);
					}
				}

				references.putReferences(reference_id, reference.build());

				symbol.addReferenceId(reference_id);
				reference_id++;
			}

			symbols.addSymbols(symbol.build());
		}
		
		try {
			protoWriter(references.build(), "references");
		} catch (IOException e) {
			Logger.getGlobal().log(Level.WARNING, "Oops! Error while writing out references in dumpSymbols.", e);
		}

		return symbols.build();
	}

	public DataList dumpData(FlatProgramAPI programAPI, Listing listing) {
		DataList.Builder database = DataList.newBuilder();

		for (MemoryBlock mb: programAPI.getMemoryBlocks()) {
			String blockName = mb.getName();

			if (!blockName.equals(".bss") && !blockName.equals(".data"))
				continue;
			
			Address start = mb.getStart();
			Address end = mb.getEnd();
			
			DataIterator dataIter = listing.getData(new AddressSet(currentProgram, start, end), true);
			
			while (dataIter.hasNext()) {
				Data data = dataIter.next();
				Address dataAddress = data.getAddress();
					
				if(blockName.equals(".bss") && getReferencesTo(dataAddress).length == 0)
					continue;

				DataMessage.Builder dataProto = DataMessage.newBuilder();

				if(!dataAddress.toString().matches("-?[0-9a-fA-F]+"))
					dataProto.setSymbolicAddress(dataAddress.toString());
				else
					dataProto.setLongAddress(Long.parseLong(dataAddress.toString(), 16));
				
				dataProto.setDataType(data.getDataType().getName());

				if(blockName.equals(".data")) {
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

		for (MemoryBlock mb: programAPI.getMemoryBlocks()) {
			SegmentMessage.Builder segment = SegmentMessage.newBuilder();
			
			String start = mb.getStart().toString();
			String end = mb.getEnd().toString();

			segment.setName(mb.getName());
			
			if(!start.matches("-?[0-9a-fA-F]+"))
				segment.setSymbolicStartingAddress(start);
			else
				segment.setLongStartingAddress(Long.parseLong(start, 16));
			
			if(!end.matches("-?[0-9a-fA-F]+"))
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
		File results = new File("GhiDumps" + File.separator + filename + ".pb");
		FileOutputStream output = new FileOutputStream(results);
		message.writeTo(output);
		output.close();
	}

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		FlatProgramAPI programAPI = new FlatProgramAPI(currentProgram);
		FlatDecompilerAPI decompilerAPI = new FlatDecompilerAPI(programAPI);
		String programName = currentProgram.getName();

		//GhiDumpMessage.Builder ghimsg = GhiDumpMessage.newBuilder();

		File results = new File("GhiDumps");

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
		
		
		
		
		//protoWriter(ghimsg.build(), programName);


		//protoWriter(ghimsg.build(), programName);
		println("Dump completed.");
	}

}
