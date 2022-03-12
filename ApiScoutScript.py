#Defines Windows system API functions from ApiScout's output into Ghidra as external functions
#@author Firpo7 - zxgio 
#@category Shellcoding
#@keybinding 
#@menupath 
#@toolbar 


import re, sys
from ghidra.program.model.data import PointerDataType

path = askFile("FILE", "Choose file:").toString()

f = open(path, "r")

REGEX = ".*:\s+(0x[a-zA-Z0-9]+);\s+(?:0x[a-zA-Z0-9]+);\s+[a-zA-Z0-9]+;\s+[0-9]+;\s+([a-zA-Z0-9\._\-+]+)_0x[0-9a-fA-F]+(?:\s+\([0-9]+bit\))\s+;\s+([a-zA-Z0-9]+)"

addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()

for matches in re.findall(REGEX, f.read()):
	offset = int(matches[0],16)
	dll = matches[1]
	label = matches[2]
	a = addr_space.getAddress(offset)
	cu = listing.getCodeUnitAt(a)
	if type(cu) == ghidra.program.database.code.InstructionDB or getFunctionContaining(a) is not None:
		print 'Skipping address', hex(offset), 'since it contains code'
		continue
	dt = getDataAt(a)
	if dt != None:
		removeDataAt(a)
	try:
		dt = createData(a, PointerDataType())
	except:
		print 'Skipping address', hex(offset), ':', sys.exc_info()[0]
		continue
	
	ref = createExternalReference(dt, dll, label, None)
	f = ref.externalLocation.createFunction()