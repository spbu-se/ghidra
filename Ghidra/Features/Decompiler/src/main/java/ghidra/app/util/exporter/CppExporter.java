/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.exporter;

import java.io.*;
import java.util.*;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

//import aQute.bnd.header.Attrs.DataType;
import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.QCallback;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileOptions.CommentStyleEnum;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.ChunkingParallelDecompiler;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.util.*;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Equate;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import util.CollectionUtils;

public class CppExporter extends Exporter {

	public static final String CREATE_C_FILE = "Create C File (.c)";
	public static final String CREATE_HEADER_FILE = "Create Header File (.h)";
	public static final String USE_CPP_STYLE_COMMENTS = "Use C++ Style Comments (//)";
	public static final String EMIT_TYPE_DEFINITONS = "Emit Data-type Definitions";
	public static final String EXPORT_GLOBAL_VARIABLES = "Export Global Variables";
	public static final String FUNCTION_TAG_FILTERS = "Function Tags to Filter";
	public static final String FUNCTION_TAG_EXCLUDE = "Function Tags Excluded";
	public static final String C_RUNTIME_EXCLUDE = "Exclude C Runtime functions";
	public static final String PLT_TRAMPOLINES_EXCLUDE = "Exclude PLT Trampolines";
	public static final String INCLUDE_HEADER_FILES = "Include header files";
	private static String EOL = System.getProperty("line.separator");

	private boolean isCreateHeaderFile = false;
	private boolean isCreateCFile = true;
	private boolean isUseCppStyleComments = true;
	private boolean emitDataTypeDefinitions = true;
	private boolean exportGlobalVariables = true;
	private boolean excludeCRuntime = true;
	private boolean excludePLTTrampolines = true;
	private boolean includeHeaderFiles = true;
	private String tagOptions = "";
	private Set<String> exclude_sections = new HashSet<>(Arrays.asList(
	        ".dynamic", ".got", ".got.plt", ".plt", ".eh_frame", ".init_array", ".fini_array", ".interp", ".eh_frame_hdr", ".eh_frame"
	    ));

	private Set<String> exclude_variables = new HashSet<>(Arrays.asList(
	        "_IO_stdin_used", "data_start", "__dso_handle"
	    ));

	private Set<FunctionTag> functionTagSet = new HashSet<>();
	private boolean excludeMatchingTags = true;

	private DecompileOptions options;
	private boolean userSuppliedOptions = false;

	public CppExporter() {
		super("C/C++", "c", new HelpLocation("ExporterPlugin", "c_cpp"));
	}

	public CppExporter(DecompileOptions options, boolean createHeader, boolean createFile,
			boolean emitTypes, boolean excludeTags, String tags) {
		this();
		this.options = options;
		if (options != null) {
			userSuppliedOptions = true;
		}
		isCreateHeaderFile = createHeader;
		isCreateCFile = createFile;
		emitDataTypeDefinitions = emitTypes;
		excludeMatchingTags = excludeTags;
		if (tags != null) {
			tagOptions = tags;
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {
		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}

		Program program = (Program) domainObj;

		configureOptions(program);
		configureFunctionTags(program);

		if (addrSet == null) {
			addrSet = program.getMemory();
		}

		File header = getHeaderFile(file);
		PrintWriter headerWriter = null;
		if (isCreateHeaderFile) {
			headerWriter = new PrintWriter(header);
		}

		PrintWriter cFileWriter = null;
		if (isCreateCFile) {
			cFileWriter = new PrintWriter(file);
		}

		CachingPool<DecompInterface> decompilerPool =
			new CachingPool<>(new DecompilerFactory(program));
		ParallelDecompilerCallback callback = new ParallelDecompilerCallback(decompilerPool);
		ChunkingTaskMonitor chunkingMonitor = new ChunkingTaskMonitor(monitor);
		ChunkingParallelDecompiler<CPPResult> parallelDecompiler =
			ParallelDecompiler.createChunkingParallelDecompiler(callback, chunkingMonitor);

		try {
			if (includeHeaderFiles) {
				writeIncludeHeaders(program, header, headerWriter, cFileWriter);
			}
      
			if (cFileWriter != null && headerWriter != null) {
				cFileWriter.println("#include \"" + header.getName() + "\"");
			}

			if (emitDataTypeDefinitions) {
				writeEquates(program, header, headerWriter, cFileWriter, chunkingMonitor);
				writeProgramDataTypes(program, header, headerWriter, cFileWriter, chunkingMonitor);
			}

			if (exportGlobalVariables) {
				writeProgramData(program, cFileWriter, chunkingMonitor);
			}

			chunkingMonitor.checkCancelled();

			decompileAndExport(addrSet, program, headerWriter, cFileWriter, parallelDecompiler,
				chunkingMonitor);

			return true;
		}
		catch (CancelledException e) {
			return false;
		}
		catch (Exception e) {
			Msg.error(this, "Error exporting C/C++", e);
			return false;
		}
		finally {
			decompilerPool.dispose();
			parallelDecompiler.dispose();

			if (headerWriter != null) {
				headerWriter.close();
			}
			if (cFileWriter != null) {
				cFileWriter.close();
			}
		}

	}

	private String convertCodeUnitToCObject(Data data) {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append(getDeclaration(data));
		String cObject = data.getValueAsCObject();
		if (cObject != "" && cObject != null) {
			stringBuilder.append(" = ");
			stringBuilder.append(cObject);
		}

		stringBuilder.append(";");
		return stringBuilder.toString();
	}

	private String getDeclaration(Data codeUnit)
	{
		if (codeUnit.isArray())
		{
			return getArrayDeclaration(codeUnit);
		}

		StringBuilder stringBuilder = new StringBuilder();
		if (codeUnit.hasStringValue())
		{
			stringBuilder.append("char *");
			stringBuilder.append(codeUnit.getLabel());
			return stringBuilder.toString();
		}

		stringBuilder.append(codeUnit.getDataType().getName() + " ");
		stringBuilder.append(codeUnit.getLabel());
		return stringBuilder.toString();
	}

	private String getArrayDeclaration(Data codeUnit) {
		StringBuilder stringBuilder = new StringBuilder();
	    StringBuilder arraySize = new StringBuilder();
	    while (codeUnit.getDataType() instanceof Array) {
	        arraySize.append("[" + codeUnit.getNumComponents() + "]");
	        codeUnit = codeUnit.getComponent(0);
	    }

	    stringBuilder.append(codeUnit.getDataType().getName());
	    stringBuilder.append(" ");
	    stringBuilder.append(codeUnit.getLabel());
	    stringBuilder.append(arraySize.toString());
	    return stringBuilder.toString();
	}

	private void writeProgramData(Program program, PrintWriter cFileWriter,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (cFileWriter != null)  {
			String regex = "^[a-zA-Z_][a-zA-Z0-9_]*$";
			Pattern pattern = Pattern.compile(regex);
			Listing listing = program.getListing();
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if ((program.getExecutableFormat().equals(ElfLoader.ELF_NAME) &&(exclude_sections.contains(block.getName()) ||
						!(block.getComment().startsWith("SHT_NOBITS") || block.getComment().startsWith("SHT_PROGBITS")))) ||
						!block.isLoaded() || block.isExecute() || block.isArtificial() || block.isExternalBlock()) {
					continue;
				}

				CodeUnitIterator codeUnits = listing.getCodeUnits(block.getStart(), true);
				while (codeUnits.hasNext() && !monitor.isCancelled()) {
					CodeUnit codeUnit = codeUnits.next();
					if (codeUnit.getAddress().compareTo(block.getEnd()) > 0) {
						break;
					}

					if (codeUnit instanceof Data && codeUnit.getLabel() != null &&
							pattern.matcher(codeUnit.getLabel()).matches() &&
							!exclude_variables.contains(codeUnit.getLabel())) {
						try {
							cFileWriter.println(convertCodeUnitToCObject((Data) codeUnit));
						}
						catch (Exception e) {
							cFileWriter.print("// CodeUnit ");
							cFileWriter.print(((Data) codeUnit).getDataType().getName());
							cFileWriter.print(" ");
							cFileWriter.print(codeUnit.getLabel());
							cFileWriter.println(" cannot be converted to a C object.");
						}
					}
				}
			}

			cFileWriter.println("");
			cFileWriter.println("");
		}
	}

	private void decompileAndExport(AddressSetView addrSet, Program program,
			PrintWriter headerWriter, PrintWriter cFileWriter,
			ChunkingParallelDecompiler<CPPResult> parallelDecompiler,
			ChunkingTaskMonitor chunkingMonitor)
			throws InterruptedException, Exception, CancelledException {

		int functionCount = program.getFunctionManager().getFunctionCount();
		chunkingMonitor.doInitialize(functionCount);

		Listing listing = program.getListing();
		FunctionIterator iterator = listing.getFunctions(addrSet, true);
		List<Function> functions = new ArrayList<>();
		for (int i = 0; iterator.hasNext(); i++) {
			//
			// Write results every so many items so that we don't blow out memory
			//
			if (i % 10000 == 0) {
				List<CPPResult> results = parallelDecompiler.decompileFunctions(functions);
				writeResults(results, headerWriter, cFileWriter, chunkingMonitor);
				functions.clear();
			}

			Function currentFunction = iterator.next();
			if (excludeFunction(currentFunction)) {
				continue;
			}

			functions.add(currentFunction);
		}

		// handle any remaining functions
		List<CPPResult> results = parallelDecompiler.decompileFunctions(functions);
		writeResults(results, headerWriter, cFileWriter, chunkingMonitor);
	}

	private static final String CRT_PREFIX = "_";

	private boolean isCRTFunction(Function function) {
		String functionName = function.getName();
		return functionName.startsWith(CRT_PREFIX);
	}
		
	private static final String PLT_TRAMPOLINE_INSTRUCTION_QWORD = "JMP qword ptr";
	private static final String PLT_TRAMPOLINE_INSTRUCTION_DWORD = "JMP dword ptr";

	private boolean isPLTTrampoline(Function function) {
		Program program = function.getProgram();
		Listing listing = program.getListing();
		AddressSetView body = function.getBody();
		for (Address address : body.getAddresses(true)) {
			CodeUnit codeUnit = listing.getCodeUnitAt(address);
			if (!(codeUnit instanceof Instruction))
				continue;
			Instruction instruction = (Instruction) codeUnit;
			String instructionString = instruction.toString();
			if (instructionString.startsWith(PLT_TRAMPOLINE_INSTRUCTION_QWORD)
					|| instructionString.startsWith(PLT_TRAMPOLINE_INSTRUCTION_DWORD)) {
				Object inputObject = instruction.getInputObjects()[0];
				if (!(inputObject instanceof Address))
					continue;
				Address jmpAddress = (Address) inputObject;
				if (!(body.contains(jmpAddress))) {
					return true;
				}
			}
		}
		return false;
	}
	
	private boolean excludeFunction(Function currentFunction) {

		if (excludeCRuntime && isCRTFunction(currentFunction)) {
			return true;
		}

		if (excludePLTTrampolines && isPLTTrampoline(currentFunction)) {
			return true;
		}
		
		if (functionTagSet.isEmpty()) {
			return false;
		}

		Set<FunctionTag> tags = currentFunction.getTags();
		boolean hasTag = false;
		for (FunctionTag tag : functionTagSet) {
			if (tags.contains(tag)) {
				hasTag = true;
				break;
			}
		}

		return excludeMatchingTags == hasTag;
	}

	private void writeResults(List<CPPResult> results, PrintWriter headerWriter,
			PrintWriter cFileWriter, TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();

		Collections.sort(results);

		StringBuilder headers = new StringBuilder();
		StringBuilder bodies = new StringBuilder();
		for (CPPResult result : results) {
			monitor.checkCancelled();
			if (result == null) {
				continue;
			}
			String headerCode = result.getHeaderCode();
			if (headerCode != null) {
				headers.append(headerCode);
				headers.append(EOL);
			}

			String bodyCode = result.getBodyCode();
			if (bodyCode != null) {
				bodies.append(bodyCode);
				bodies.append(EOL);
			}
		}

		monitor.checkCancelled();

		if (headerWriter != null) {
			headerWriter.println(headers.toString());
		}
		if (cFileWriter != null) {
			cFileWriter.print(bodies.toString());
		}
	}

	private void configureOptions(Program program) {
		if (!userSuppliedOptions) {

			options = DecompilerUtils.getDecompileOptions(provider, program);

			if (isUseCppStyleComments) {
				options.setCommentStyle(CommentStyleEnum.CPPStyle);
			}
			else {
				options.setCommentStyle(CommentStyleEnum.CStyle);
			}
		}
	}

	private void configureFunctionTags(Program program) {
		if (StringUtils.isBlank(tagOptions)) {
			return;
		}

		FunctionManager functionManager = program.getFunctionManager();

		FunctionTagManager tagManager = functionManager.getFunctionTagManager();
		String[] split = tagOptions.split(",");
		for (String tag : split) {
			FunctionTag functionTag = tagManager.getFunctionTag(tag.trim());
			if (functionTag != null) {
				functionTagSet.add(functionTag);
			}
		}
	}

	private void writeIncludeHeaders(Program program, File header, PrintWriter headerWriter,
			PrintWriter cFileWriter) throws IOException, CancelledException {
		if (headerWriter != null) {
			headerWriter.print(getAllHeaderFiles(program));
		}
		else if (cFileWriter != null) {
			cFileWriter.print(getAllHeaderFiles(program));
		}

		if (cFileWriter != null) {
			cFileWriter.println("");
			cFileWriter.println("");
		}

	}

	private String getAllHeaderFiles(Program program) throws IOException  {
		HashSet<String> headerList = new HashSet<String>();
		String resultString = new String();
		for (SourceArchive sourceArchive : program.getDataTypeManager().getSourceArchives())
		{
			for (DataType dataType :  program.getDataTypeManager().getDataTypes(sourceArchive)) {
				String headerName = dataType.getPathName().substring(1, dataType.getPathName().indexOf(".h") + 2);
				if (dataType.getPathName().contains(".h") &&
						!headerList.contains(headerName)) {
					headerList.add(headerName);
					resultString = resultString.concat("#include <" + headerName + ">\n");
				}
			}
		}

		return resultString;
	}

	private void writeProgramDataTypes(Program program, File header, PrintWriter headerWriter,
			PrintWriter cFileWriter, TaskMonitor monitor) throws IOException, CancelledException {
		if (headerWriter != null) {
			DataTypeManager dtm = program.getDataTypeManager();
			DataTypeWriter dataTypeWriter;
			if (includeHeaderFiles) {
				dataTypeWriter =
					new DataTypeWriter(dtm, cFileWriter, isUseCppStyleComments, dtm.getSourceArchives());
			}
			else {
				dataTypeWriter =
						new DataTypeWriter(dtm, cFileWriter, isUseCppStyleComments);
			}

			headerWriter.write(getFakeCTypeDefinitions(dtm.getDataOrganization()));
			dataTypeWriter.write(dtm, monitor);

			headerWriter.println("");
			headerWriter.println("");
		}
		else if (cFileWriter != null) {
			DataTypeManager dtm = program.getDataTypeManager();
			DataTypeWriter dataTypeWriter;
			if (includeHeaderFiles) {
				dataTypeWriter =
					new DataTypeWriter(dtm, cFileWriter, isUseCppStyleComments, dtm.getSourceArchives());
			}
			else {
				dataTypeWriter =
						new DataTypeWriter(dtm, cFileWriter, isUseCppStyleComments);
			}

			dataTypeWriter.write(dtm, monitor);
		}

		if (cFileWriter != null) {
			cFileWriter.println("");
			cFileWriter.println("");
		}

	}

	private void writeEquates(Program program, File header, PrintWriter headerWriter,
			PrintWriter cFileWriter, TaskMonitor monitor) throws CancelledException {
		boolean equatesPresent = false;
		for (Equate equate : CollectionUtils.asIterable(program.getEquateTable().getEquates())) {
			monitor.checkCancelled();
			equatesPresent = true;
			String define =
				"#define %s %s".formatted(equate.getDisplayName(), equate.getDisplayValue());
			if (headerWriter != null) {
				headerWriter.println(define);
			}
			else if (cFileWriter != null) {
				cFileWriter.println(define);
			}
		}
		if (equatesPresent) {
			if (headerWriter != null) {
				headerWriter.println();
			}
			else if (cFileWriter != null) {
				cFileWriter.println();
			}
		}
	}

	private File getHeaderFile(File file) {
		String name = file.getName();
		int pos = name.lastIndexOf('.');
		if (pos > 0) {
			name = name.substring(0, pos);
		}
		return new File(file.getParent(), name + ".h");
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		ArrayList<Option> list = new ArrayList<>();
		list.add(new Option(CREATE_HEADER_FILE, Boolean.valueOf(isCreateHeaderFile)));
		list.add(new Option(CREATE_C_FILE, Boolean.valueOf(isCreateCFile)));
		list.add(new Option(USE_CPP_STYLE_COMMENTS, Boolean.valueOf(isUseCppStyleComments)));
		list.add(new Option(EMIT_TYPE_DEFINITONS, Boolean.valueOf(emitDataTypeDefinitions)));
		list.add(new Option(EXPORT_GLOBAL_VARIABLES, Boolean.valueOf(exportGlobalVariables)));
		list.add(new Option(FUNCTION_TAG_FILTERS, tagOptions));
		list.add(new Option(FUNCTION_TAG_EXCLUDE, Boolean.valueOf(excludeMatchingTags)));
		list.add(new Option(C_RUNTIME_EXCLUDE, Boolean.valueOf(excludeCRuntime)));
		list.add(new Option(PLT_TRAMPOLINES_EXCLUDE, Boolean.valueOf(excludePLTTrampolines)));
		return list;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(CREATE_HEADER_FILE)) {
					isCreateHeaderFile = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(CREATE_C_FILE)) {
					isCreateCFile = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(USE_CPP_STYLE_COMMENTS)) {
					isUseCppStyleComments = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(EMIT_TYPE_DEFINITONS)) {
					emitDataTypeDefinitions = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(INCLUDE_HEADER_FILES)) {
					includeHeaderFiles = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(EXPORT_GLOBAL_VARIABLES)) {
					exportGlobalVariables = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(FUNCTION_TAG_FILTERS)) {
					tagOptions = (String) option.getValue();
				}
				else if (optName.equals(FUNCTION_TAG_EXCLUDE)) {
					excludeMatchingTags = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(C_RUNTIME_EXCLUDE)) {
					excludeCRuntime = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(PLT_TRAMPOLINES_EXCLUDE)) {
					excludePLTTrampolines = ((Boolean) option.getValue()).booleanValue();
				}
				else {
					throw new OptionException("Unknown option: " + optName);
				}
			}
			catch (ClassCastException e) {
				throw new OptionException(
					"Invalid type for option: " + optName + " - " + e.getMessage());
			}
		}
	}

	private static String getBuiltInDeclaration(String typeName, String ctypeName) {
		return "#define " + typeName + "   " + ctypeName + EOL;
	}

	private static String getBuiltInDeclaration(String typeName, int typeLen, boolean signed,
			DataOrganization dataOrganization) {
		return getBuiltInDeclaration(typeName,
			dataOrganization.getIntegerCTypeApproximation(typeLen, signed));
	}

	/**
	 * Generate suitable C-style definition statements (#define) for any fake data-type names
	 * which may be produced by the decompiler (e.g., unkint, unkuint, etc.).
	 * @param dataOrganization is the data organization to result the size of core types.
	 * @return multi-line string containing C-style declarations of fake decompiler types.
	 */
	private static String getFakeCTypeDefinitions(DataOrganization dataOrganization) {

		StringWriter writer = new StringWriter();

		// unkbyte - decompiler fabricated unknown types - need only cover sizes larger than the max Undefined size
		for (int n = 9; n <= 16; n++) {
			writer.write(getBuiltInDeclaration("unkbyte" + n, n, false, dataOrganization));
		}
		writer.write(EOL);

		// unkuint - decompiler fabricated unsigned integer types
		// need only cover sizes larger than the max integer size (i.e., AbstractIntegerDataType)
		for (int n = 9; n <= 16; n++) {
			writer.write(getBuiltInDeclaration("unkuint" + n, n, false, dataOrganization));
		}
		writer.write(EOL);

		// unkint - decompiler fabricated signed integer types
		// need only cover sizes larger than the max integer size (i.e., AbstractIntegerDataType)
		for (int n = 9; n <= 16; n++) {
			writer.write(getBuiltInDeclaration("unkint" + n, n, true, dataOrganization));
		}
		writer.write(EOL);

		// unkfloat - decompiler fabricated floating point types
		writer.write(getBuiltInDeclaration("unkfloat1", "float"));
		writer.write(getBuiltInDeclaration("unkfloat2", "float"));
		writer.write(getBuiltInDeclaration("unkfloat3", "float"));
		//writer.write(getBuiltInDeclaration("unkfloat4", "float")); // covered by fixed-size built-in float
		writer.write(getBuiltInDeclaration("unkfloat5", "double"));
		writer.write(getBuiltInDeclaration("unkfloat6", "double"));
		writer.write(getBuiltInDeclaration("unkfloat7", "double"));
		//writer.write(getBuiltInDeclaration("unkfloat8", "double")); // covered by fixed-size built-in double
		writer.write(getBuiltInDeclaration("unkfloat9", "long double"));
		//writer.write(getBuiltInDeclaration("unkfloat10", "long double")); // covered by fixed-size built-in longdouble
		writer.write(getBuiltInDeclaration("unkfloat11", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat12", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat13", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat14", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat15", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat16", "long double"));
		writer.write(EOL);

		writer.write(getBuiltInDeclaration("BADSPACEBASE", "void"));
		writer.write(getBuiltInDeclaration("code", "void"));
		writer.write(EOL);

		return writer.toString();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CPPResult implements Comparable<CPPResult> {

		private Address address;
		private String bodyCode;
		private String headerCode;

		CPPResult(Address address, String headerCode, String bodyCode) {
			this.address = address;
			this.headerCode = headerCode;
			this.bodyCode = bodyCode;
		}

		String getHeaderCode() {
			return headerCode;
		}

		String getBodyCode() {
			return bodyCode;
		}

		@Override
		public int compareTo(CPPResult other) {
			return address.compareTo(other.address);
		}

	}

	private class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

		private Program program;

		DecompilerFactory(Program program) {
			this.program = program;
		}

		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {
			DecompInterface decompiler = new DecompInterface();
			decompiler.setOptions(options);
			decompiler.openProgram(program);
			decompiler.toggleSyntaxTree(false);		// Don't need syntax tree
			return decompiler;
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}

	private class ParallelDecompilerCallback implements QCallback<Function, CPPResult> {

		private CachingPool<DecompInterface> pool;

		ParallelDecompilerCallback(CachingPool<DecompInterface> decompilerPool) {
			this.pool = decompilerPool;
		}

		@Override
		public CPPResult process(Function function, TaskMonitor monitor) throws Exception {
			if (monitor.isCancelled()) {
				return null;
			}

			DecompInterface decompiler = pool.get();
			try {
				CPPResult result = doWork(function, decompiler, monitor);
				return result;
			}
			finally {
				pool.release(decompiler);
			}
		}

		private CPPResult doWork(Function function, DecompInterface decompiler,
				TaskMonitor monitor) {
			Address entryPoint = function.getEntryPoint();
			CodeUnit codeUnitAt = function.getProgram().getListing().getCodeUnitAt(entryPoint);
			if (codeUnitAt == null || !(codeUnitAt instanceof Instruction)) {
				return new CPPResult(entryPoint, function.getPrototypeString(false, false) + ';',
					null);
			}

			monitor.setMessage("Decompiling " + function.getName());

			DecompileResults dr =
				decompiler.decompileFunction(function, options.getDefaultTimeout(), monitor);
			String errorMessage = dr.getErrorMessage();
			if (!"".equals(errorMessage)) {
				Msg.warn(CppExporter.this, "Error decompiling: " + errorMessage);
				if (options.isWARNCommentIncluded()) {
					monitor.incrementProgress(1);
					return new CPPResult(entryPoint, null,
						"/*" + EOL + "Unable to decompile '" + function.getName() + "'" + EOL +
							"Cause: " + errorMessage + EOL + "*/" + EOL);
				}
				return null;
			}

			DecompiledFunction decompiledFunction = dr.getDecompiledFunction();
			return new CPPResult(entryPoint, decompiledFunction.getSignature(),
				decompiledFunction.getC());
		}
	}

	/**
	 * A class that exists because we are doing something that the ConcurrentQ was not
	 * designed for--chunking.  We do not want out monitor being reset every time we start a new
	 * chunk. So, we wrap a real monitor, overriding the behavior such that initialize() has
	 * no effect when it is called by the queue.
	 */
	private class ChunkingTaskMonitor extends TaskMonitorAdapter {
		private TaskMonitor monitor;

		ChunkingTaskMonitor(TaskMonitor monitor) {
			this.monitor = monitor;
		}

		void doInitialize(long value) {
			// this lets us initialize when we want to
			monitor.initialize(value);
		}

		@Override
		public void setProgress(long value) {
			monitor.setProgress(value);
		}

		@Override
		public void checkCancelled() throws CancelledException {
			monitor.checkCancelled();
		}

		@Override
		public void setMessage(String message) {
			monitor.setMessage(message);
		}

		@Override
		public synchronized void addCancelledListener(CancelledListener listener) {
			monitor.addCancelledListener(listener);
		}

		@Override
		public synchronized void removeCancelledListener(CancelledListener listener) {
			monitor.removeCancelledListener(listener);
		}
	}
}
