# RPGEnerator - Load.py module 
# Read a binary and load the gadgets contained in the file 

import Database
import Analysis
import generate_opcodes

# Help for the load command
CMD_LOAD_HELP = "\n\t---------------------------------"
CMD_LOAD_HELP += "\n\tROPGenerator 'load' command\n\t(Load gadgets from a binary file)"
CMD_LOAD_HELP += "\n\t---------------------------------" 
CMD_LOAD_HELP += "\n\n\tUsage:\tload [OPTIONS] <filename>"
CMD_LOAD_HELP += "\n\n\tOptions: No options available for the moment"
CMD_LOAD_HELP += "\n\n\tExamples:\n\t\tload /bin/ls\t\t(load gadgets from /bin/ls program)"

def print_help():
	print(CMD_LOAD_HELP)
	
def load(args):
	
	if( len(args) > 0 ):
		filename = args[0]
		msg = "Extracting gadgets from file '" + filename + "'"
		if( len(args) > 1 ):
			msg += " (Ignoring extra arguments '"
			msg += ', '.join(args[1:])
			msg += "')"
		print(msg)
	else:
		print("Missing argument. Type 'load help' for help")

	if( generate_opcodes.generate(filename)):
		Database.generated_gadgets_to_DB()
		Database.simplifyGadgets()
		Database.fillGadgetLookUp()
	else:
		print("\n Could not load gadgets")
	
	
	
