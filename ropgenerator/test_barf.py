from Database import *

setArch( "X86_64" )

generated_gadgets_to_DB()
fillGadgetLookUp()
# Print gadgetLookUp
for reg in gadgetLookUp[GadgetType.REGtoREG].keys():
	print str(reg) + ":"
	for reg2 in gadgetLookUp[GadgetType.REGtoREG][reg].keys():
		if( gadgetLookUp[GadgetType.REGtoREG][reg][reg2] != [] ):
			print "\n\t<-- " + revertRegNamesTable[reg2] 
			print "\n\tFrom gadget:\n " + gadgetDB[gadgetLookUp[GadgetType.REGtoREG][reg][reg2][0]].asmStr + "\n\t" +  gadgetDB[gadgetLookUp[GadgetType.REGtoREG][reg][reg2][0]].hexStr + '\n'
	for cst in gadgetLookUp[GadgetType.CSTtoREG][reg].keys():
		if( gadgetLookUp[GadgetType.CSTtoREG][reg][cst] != [] ):
			print "\n\t<-- " + str(cst)
			print "\n\tFrom gadget:\n " + gadgetDB[gadgetLookUp[GadgetType.CSTtoREG][reg][cst][0]].asmStr + "\n\t" + gadgetDB[gadgetLookUp[GadgetType.CSTtoREG][reg][cst][0]].hexStr + '\n'

	#for mem in gadgetLookUp[GadgetType.MEMtoREG][reg].keys():
	#	if( gadgetLookUp[GadgetType.MEMtoREG][reg][mem] != []):
	#		print("\n\t<-- MEM[" + str(mem) + "]")
	#		print( "\n\tFrom gadget:\n " + gadgetDB[gadgetLookUp[GadgetType.MEMtoREG][reg][mem][0]].asmStr + "\n\t" + gadgetDB[gadgetLookUp[GadgetType.MEMtoREG][reg][mem][0]].hexStr + '\n' )

exit() 

