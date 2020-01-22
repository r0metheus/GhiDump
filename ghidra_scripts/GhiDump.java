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
import protoclasses.FunctionProto.FunctionMessage.ParameterMessage;
import protoclasses.FunctionProto.FunctionMessage.VariableMessage;
import protoclasses.FunctionProto.FunctionsList;
import protoclasses.GhiDumpProto.GhiDumpMessage;
import protoclasses.KindOfData.Kind;
import protoclasses.MetadataProto.MetaList;
import protoclasses.MetadataProto.MetadataMessage;
import protoclasses.SegmentsProto.SegmentList;
import protoclasses.SegmentsProto.SegmentMessage;
import protoclasses.SymbolsProto.SymbolMessage;
import protoclasses.SymbolsProto.SymbolMessage.ReferenceMessage;
import protoclasses.SymbolsProto.SymbolMessage.SourceType;
import protoclasses.SymbolsProto.SymbolMessage.SymbolMessageType;
import protoclasses.SymbolsProto.SymbolsList;

public class GhiDump extends GhidraScript {

	private FunctionsList dumpFunctions(FlatDecompilerAPI decompilerAPI, Listing listing) {
		FunctionIterator fooIter = listing.getFunctions(true);
		FunctionsList.Builder fooList = FunctionsList.newBuilder();

		while (fooIter.hasNext()) {
			Function foo = fooIter.next();

			FunctionMessage.Builder function = FunctionMessage.newBuilder();
			ArrayList<PcodeBlockBasic> bbx;

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
				bbx = hf.getBasicBlocks();

				for (PcodeBlockBasic bb : bbx) {
					BasicBlockMessage.Builder basicblock = BasicBlockMessage.newBuilder();

					Address start = bb.getStart();
					Address end = bb.getStop();
					basicblock.setStartingAddress(start.toString());
					basicblock.setEndingAddress(end.toString());

					InstructionIterator instrIter = listing.getInstructions(new AddressSet(currentProgram, start, end),
							true);

					while (instrIter.hasNext()) {
						Instruction instr = instrIter.next();

						if (instr == null)
							continue;

						InstructionMessage.Builder instruction = InstructionMessage.newBuilder();
						int opsNum = instr.getNumOperands();

						instruction.setInstruction(instr.toString());
						instruction.setMnemonic(instr.getMnemonicString());
						instruction.setOpsNumber(opsNum);
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
								opobject.setType(type);

								operand.addOpObjects(opobject.build());
							}

							for (Reference ref : instr.getOperandReferences(i)) {
								OperandMessage.Reference.Builder reference = OperandMessage.Reference.newBuilder();

								reference.setFromAddress(ref.getFromAddress().toString());
								reference.setToAddress(ref.getToAddress().toString());
								reference.setReferenceType(ref.getReferenceType().getName());

								if (getDataAt(ref.getToAddress()) != null) {
									try {
										reference.setReferenceValue(
												ByteString.copyFrom(getDataAt(ref.getToAddress()).getBytes()));
									} catch (MemoryAccessException e) {
										Logger.getGlobal().log(Level.INFO,
												"Oops! Error while writing out some references data values in dumpFunctions.",
												e);
									}
								}

								operand.addReferences(reference.build());
							}

							instruction.addOperands(operand.build());
						}

						basicblock.addInstructions(instruction.build());
					}

					function.addBasicBlocks(basicblock.build());
				}

			}

			fooList.addFunctions(function.build());
		}

		return fooList.build();
	}

	private SymbolsList dumpSymbols(Listing listing) {
		SymbolIterator symbolIterator = currentProgram.getSymbolTable().getAllSymbols(true);

		SymbolsList.Builder symbols = SymbolsList.newBuilder();

		while (symbolIterator.hasNext()) {
			Symbol current = symbolIterator.next();
			String source = current.getSource().toString().toUpperCase();
			String symbolType = current.getSymbolType().toString().toUpperCase();
			SymbolMessage.Builder symbol = SymbolMessage.newBuilder();

			symbol.setName(current.getName());
			symbol.setAddress(current.getAddress().toString());

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
				symbol.setSource(SourceType.DEFAULT);
			if (source.equals("ANALYSIS"))
				symbol.setSource(SourceType.ANALYSIS);
			if (source.equals("IMPORTED"))
				symbol.setSource(SourceType.IMPORTED);
			if (source.equals("USER_DEFINED"))
				symbol.setSource(SourceType.USER_DEFINED);

			symbol.setRefCount(current.getReferenceCount());

			ReferenceMessage.Builder reference = ReferenceMessage.newBuilder();

			for (Reference ref : current.getReferences()) {
				Address refFrom = ref.getFromAddress();
				String refType = ref.getReferenceType().toString();
				String refSource = ref.getSource().toString().toUpperCase();

				reference.setFromAddress(refFrom.toString());
				reference.setReferenceType(refType);

				if (refSource.equals("DEFAULT"))
					reference.setSource(SourceType.DEFAULT);
				if (refSource.equals("ANALYSIS"))
					reference.setSource(SourceType.ANALYSIS);
				if (refSource.equals("IMPORTED"))
					reference.setSource(SourceType.IMPORTED);
				if (refSource.equals("USER_DEFINED"))
					reference.setSource(SourceType.USER_DEFINED);

				if (listing.getInstructionAt(refFrom) != null)
					reference.setInstruction(listing.getInstructionAt(refFrom).toString());

				Data refData = getDataAt(refFrom);

				ReferenceMessage.DataMessage.Builder data = ReferenceMessage.DataMessage.newBuilder();

				if (refType.equals("DATA") && refData != null) {
					String refDataType = refData.getDataType().getName();

					data.setDataType(refDataType);

					if (refData.isDefined())
						data.addKind(Kind.DEFINED);
					if (refData.hasStringValue())
						data.addKind(Kind.STRING);
					if (refData.isArray())
						data.addKind(Kind.ARRAY);
					if (refData.isConstant())
						data.addKind(Kind.CONSTANT);
					if (refData.isDynamic())
						data.addKind(Kind.DYNAMIC);
					if (refData.isPointer())
						data.addKind(Kind.POINTER);
					if (refData.isStructure())
						data.addKind(Kind.STRUCTURE);
					if (refData.isUnion())
						data.addKind(Kind.UNION);
					if (refData.isVolatile())
						data.addKind(Kind.VOLATILE);

					if (refData.getValue() != null) {

						try {
							data.setValue(ByteString.copyFrom(refData.getBytes()));
						} catch (MemoryAccessException e) {
							Logger.getGlobal().log(Level.INFO,
									"Oops! Error while writing out some data values in dumpSymbols.", e);
						}

						reference.setReferred(data);
					}
				}

				symbol.addReferences(reference.build());
			}

			symbols.addSymbols(symbol.build());
		}

		return symbols.build();
	}

	public DataList dumpData(FlatProgramAPI programAPI, Listing listing) {
		DataList.Builder database = DataList.newBuilder();

		for (MemoryBlock mb : programAPI.getMemoryBlocks()) {

			if (mb.getName().equals(".bss") || mb.getName().equals(".data")) {
				Address start = mb.getStart();
				Address end = mb.getEnd();

				DataIterator dataIter = listing.getData(new AddressSet(currentProgram, start, end), true);

				while (dataIter.hasNext()) {
					Data data = dataIter.next();

					DataMessage.Builder dataProto = DataMessage.newBuilder();

					dataProto.setAddress(data.getAddress().toString());
					dataProto.setDataType(data.getDataType().getName());

					try {
						dataProto.setValue(ByteString.copyFrom(data.getBytes()));
						dataProto.setLength(dataProto.getValue().size());
					} catch (MemoryAccessException e) {
						Logger.getGlobal().log(Level.INFO,
								"Oops! Error while writing out some data values in dumpData.", e);
					}

					if (data.isDefined())
						dataProto.addKind(Kind.DEFINED);
					if (data.hasStringValue())
						dataProto.addKind(Kind.STRING);
					if (data.isArray())
						dataProto.addKind(Kind.ARRAY);
					if (data.isConstant())
						dataProto.addKind(Kind.CONSTANT);
					if (data.isDynamic())
						dataProto.addKind(Kind.DYNAMIC);
					if (data.isPointer())
						dataProto.addKind(Kind.POINTER);
					if (data.isStructure())
						dataProto.addKind(Kind.STRUCTURE);
					if (data.isUnion())
						dataProto.addKind(Kind.UNION);
					if (data.isVolatile())
						dataProto.addKind(Kind.VOLATILE);

					database.addData(dataProto.build());
				}
			}
		}

		return database.build();
	}

	private SegmentList dumpSegments(FlatProgramAPI programAPI) {
		SegmentList.Builder segments = SegmentList.newBuilder();

		for (MemoryBlock mb : programAPI.getMemoryBlocks()) {
			SegmentMessage.Builder segment = SegmentMessage.newBuilder();

			segment.setName(mb.getName());
			segment.setStartingAddress(mb.getStart().toString());
			segment.setEndingAddress(mb.getEnd().toString());
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

	private void protoWriter(Message message, String programName) throws IOException {
		File results = new File("GhiDumps" + File.separator + programName + ".pb");
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

		GhiDumpMessage.Builder ghimsg = GhiDumpMessage.newBuilder();

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

		ghimsg.setMetadata(dumpMetadata());
		ghimsg.setSegments(dumpSegments(programAPI));
		ghimsg.setSymbols(dumpSymbols(listing));
		ghimsg.setData(dumpData(programAPI, listing));
		ghimsg.setFunctions(dumpFunctions(decompilerAPI, listing));

		protoWriter(ghimsg.build(), programName);
		println("Dump completed.");
	}

}
