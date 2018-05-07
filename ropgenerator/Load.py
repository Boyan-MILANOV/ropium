# RPGEnerator - Load.py module 
# Read a binary and load the gadgets contained in the file 

import ropgenerator.Database as Database
import ropgenerator.Analysis as Analysis
import ropgenerator.generate_opcodes as generate_opcodes
import ropgenerator.SearchHelper as SearchHelper
import ropgenerator.Gadget as Gadget
import ropgenerator.BinaryScanner as BinaryScanner
from ropgenerator.Colors import string_bold, info_colored, BOLD_COLOR_ANSI, END_COLOR_ANSI, string_special


# Help for the load command
CMD_LOAD_HELP = string_bold("\n\t---------------------------------")
CMD_LOAD_HELP += string_bold("\n\tROPGenerator 'load' command\n\t")
CMD_LOAD_HELP += string_special("(Load gadgets from a binary file)")
CMD_LOAD_HELP += string_bold("\n\t---------------------------------")
CMD_LOAD_HELP += "\n\n\t"+string_bold("Usage")+":\tload [OPTIONS] <filename>"
CMD_LOAD_HELP += "\n\n\t"+string_bold("Options")+": No options available for the moment"
CMD_LOAD_HELP += "\n\n\t"+string_bold("Examples")+":\n\t\tload /bin/ls\t\t(load gadgets from /bin/ls program)\n\t\tload ../test/vuln_prog\t(load gadgets from own binary)"


def print_help():
    print(CMD_LOAD_HELP)
    
def load(args):
    
    if( len(args) > 0 ):
        filename = args[0]
        msg = string_bold("Extracting gadgets from file")+ " '" + filename + "'"
        if( len(args) > 1 ):
            msg += " (Ignoring extra arguments '"
            msg += ', '.join(args[1:])
            msg += "')"
        info_colored(msg+'\n')
    else:
        print(string_bold("\n\tMissing argument.\n\tType 'load help' for help"))

    # Cleaning the data structures
    Gadget.reinit()
    Database.reinit()
    Analysis.reinit()
    SearchHelper.reinit()

    if( generate_opcodes.generate(filename)):
        BinaryScanner.set_binary(filename)
        Database.generated_gadgets_to_DB()
        Database.simplifyGadgets()
        Database.gadgetLookUp.fill()
        #DEBUG SearchHelper.build_all()
    
    
    
    
