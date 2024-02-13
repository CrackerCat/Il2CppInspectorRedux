# Ghidra-specific implementation
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.script import GhidraScriptUtil
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.symbol import SourceType

def set_name(addr, name):
	createLabel(toAddr(addr), name, True)

def make_function(start, end = None):
	addr = toAddr(start)
	# Don't override existing functions
	fn = getFunctionAt(addr)
	if fn is None:
		# Create new function if none exists
		createFunction(addr, None)

def make_array(addr, numItems, cppType):
	if cppType.startswith('struct '):
		cppType = cppType[7:]
	
	t = getDataTypes(cppType)[0]
	a = ArrayDataType(t, numItems, t.getLength())
	addr = toAddr(addr)
	removeDataAt(addr)
	createData(addr, a)

def define_code(code):
	# Code declarations are not supported in Ghidra
	# This only affects string literals for metadata version < 19
	# TODO: Replace with creating a DataType for enums
	pass

def set_function_type(addr, sig):
	make_function(addr)
	typeSig = CParserUtils.parseSignature(None, currentProgram, sig)
	ApplyFunctionSignatureCmd(toAddr(addr), typeSig, SourceType.USER_DEFINED, False, True).applyTo(currentProgram)

def set_type(addr, cppType):
	if cppType.startswith('struct '):
		cppType = cppType[7:]
	
	t = getDataTypes(cppType)[0]
	addr = toAddr(addr)
	removeDataAt(addr)
	createData(addr, t)

def set_comment(addr, text):
	setEOLComment(toAddr(addr), text)

def set_header_comment(addr, text):
	setPlateComment(toAddr(addr), text)

def script_prologue(status):
	# Check that the user has parsed the C headers first
	if len(getDataTypes('Il2CppObject')) == 0:
		print('STOP! You must import the generated C header file (%TYPE_HEADER_RELATIVE_PATH%) before running this script.')
		print('See https://github.com/djkaty/Il2CppInspector/blob/master/README.md#adding-metadata-to-your-ghidra-workflow for instructions.')
		sys.exit()

	# Ghidra sets the image base for ELF to 0x100000 for some reason
	# https://github.com/NationalSecurityAgency/ghidra/issues/1020
	if currentProgram.getExecutableFormat().endswith('(ELF)'):
		currentProgram.setImageBase(toAddr(%IMAGE_BASE%), True)

def script_epilogue(status): pass

def get_script_directory():
	return getSourceFile().getParentFile().toString()

def add_function_to_group(addr, group): pass

class StatusWrapper(BaseStatusHandler): pass