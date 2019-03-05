# -*- coding:utf-8 -*- 
# Find module: implement de find command - find gadgets and build ropchains :) 

from ropgenerator.core.IO import error, banner, str_bold, str_special, alert
from ropgenerator.main.Utils import *
from ropgenerator.core.ChainingEngine import SearchParametersBinding
from ropgenerator.core.Gadget import set_gadgets_offset
import sys

# Definition of options names
OPTION_HELP = '--help'
OPTION_HELP_SHORT = '-h'

OPTION_BAD_BYTES = '--bad-bytes'
OPTION_KEEP_REGS = '--keep-regs'
OPTION_LMAX = '--max-length'
OPTION_SHORTEST = '--shortest'
OPTION_OFFSET = '--offset'

OPTION_BAD_BYTES_SHORT = '-b'
OPTION_KEEP_REGS_SHORT = '-k' 
OPTION_LMAX_SHORT = '-m' 
OPTION_SHORTEST_SHORT = '-s'
OPTION_OFFSET_SHORT = '-off'

OPTION_OUTPUT = '--output-format'
OPTION_OUTPUT_SHORT = '-f'
# Options for output
OUTPUT_CONSOLE = 'console'
OUTPUT_PYTHON = 'python'
OUTPUT_RAW = 'raw'
OUTPUT = None # The one choosen 


# Help for the search command
CMD_FIND_HELP = banner([str_bold("'query' command"),
                str_special("(Find gadgets/ropchains that execute specific operations)")])
CMD_FIND_HELP += "\n\n\t"+str_bold("Usage")+":\tfind [OPTIONS] <reg>=<expr>"+\
                "\n\t\tfind [OPTIONS] <reg>=mem(<expr>)"+\
                "\n\t\tfind [OPTIONS] mem(<expr>)=<expr>"+\
                "\n\t\tfind [OPTIONS] int80"+\
                "\n\t\tfind [OPTIONS] syscall"
CMD_FIND_HELP += "\n\n\t"+str_bold("Options")+":"
CMD_FIND_HELP += "\n\t\t"+str_special(OPTION_BAD_BYTES_SHORT)+","+str_special(OPTION_BAD_BYTES)+" <bytes>\t Bad bytes for payload.\n\t\t\t\t\t Expected format is a list of bytes \n\t\t\t\t\t separated by comas (e.g '-b 0A,0B,2F')"
CMD_FIND_HELP += "\n\n\t\t"+str_special(OPTION_KEEP_REGS_SHORT)+","+str_special(OPTION_KEEP_REGS)+" <regs>\t Registers that shouldn't be modified.\n\t\t\t\t\t Expected format is a list of registers \n\t\t\t\t\t separated by comas (e.g '-k edi,eax')"
CMD_FIND_HELP += "\n\n\t\t"+str_special(OPTION_OFFSET_SHORT)+","+str_special(OPTION_OFFSET)+" <int>\t Offset to add to gadget addresses"
CMD_FIND_HELP += "\n\n\t\t"+str_special(OPTION_SHORTEST_SHORT)+","+str_special(OPTION_SHORTEST)+"\t\t Find the shortest matching ROP-Chains"
CMD_FIND_HELP += "\n\n\t\t"+str_special(OPTION_LMAX_SHORT)+","+str_special(OPTION_LMAX)+" <int>\t Max length of the ROPChain in bytes."
CMD_FIND_HELP += "\n\n\t\t"+str_special(OPTION_OUTPUT_SHORT)+","+str_special(OPTION_OUTPUT)+" <fmt> Output format for ropchains.\n\t\t\t\t\t Expected format is one of the following\n\t\t\t\t\t "+str_special(OUTPUT_CONSOLE)+','+str_special(OUTPUT_PYTHON)
CMD_FIND_HELP += "\n\n\t"+str_bold("Examples")+":\n\t\tfind rax=rbp\n\t\tfind rbx=0xff\n\t\tfind rax=mem(rsp)\n\t\tfind mem(rsp-8)=rcx\n\t\tfind "+OPTION_KEEP_REGS+ " rdx,rsp mem(rbp-0x10)=0b101\n\t\tfind "+ OPTION_BAD_BYTES+" 0A,0D "+ OPTION_OUTPUT + ' ' + OUTPUT_PYTHON + "  rax=rcx+4" 

def print_help():
    print(CMD_FIND_HELP)


def find(args):
    """
    args - List of user arguments as strings
    (the command should not be included in the list as args[0])
    """
    
    if( (not args) or args[0] == OPTION_HELP or args[0] == OPTION_HELP_SHORT ):
        print_help()
        return 
    
    parsed_args = parse_args(args)
    if( not parsed_args[0] ):
        error(parsed_args[1])
        return 
    
    dest_arg =  parsed_args[1]
    assign_arg = parsed_args[2]
    params = parsed_args[3]
    offset = parsed_args[4]
    bad_bytes = parsed_args[5] # Used only for printing, they are already in params
    
    # Set the offset
    set_gadgets_offset(offset)
    set_search_verbose(True)
    
    # Do the search 
    keyboard_interrupt = False
    try:
        res = search(dest_arg, assign_arg, params)
    except KeyboardInterrupt:
        alert("Search aborted by Keyboard Interrupt.\n")
        keyboard_interrupt = True
    
    if( not keyboard_interrupt ):
        # Print result 
        if( res.found ):
            if( OUTPUT == OUTPUT_CONSOLE ):
                print(res.chain.to_str_console(curr_arch_bits()//8, bad_bytes ))
            elif( OUTPUT == OUTPUT_PYTHON ):
                print(res.chain.to_str_python(curr_arch_bits()//8, bad_bytes, True, False ))
        else:
            error("No matching ROPChain found")
        
    # Reset normal state
    set_gadgets_offset(0)
    set_search_verbose(False)
    
    return 


def parse_args(args):
    """
    Parse the user supplied arguments to the 'find' function
    Returns ????
    Or if not supported or invalid arguments, returns a tuple (False, msg)
    """
    global OUTPUT
    
    seenQuery = False
    seenBadBytes = False
    seenKeepRegs = False
    seenOutput = False
    seenLmax = False
    seenShortest = False
    seenOffset = False
    
    i = 0 # Argument counter 
    bad_bytes = []
    keep_regs = []
    lmax = get_default_lmax()
    OUTPUT = OUTPUT_CONSOLE
    offset = 0
    
    while( i < len(args)):
        arg = args[i]
        # Look for options
        if( arg[0] == '-'):
            if( seenQuery ):
                return (False, "Error. Options must come before the search request")       
            # bad bytes option 
            if( arg == OPTION_BAD_BYTES or arg == OPTION_BAD_BYTES_SHORT):
                if( seenBadBytes ):
                    return (False, "Error. '" + arg + "' option should be used only once")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing bad bytes after option '"+arg+"'")
                seenBadBytes = True
                (success, bad_bytes) = parse_bad_bytes(args[i+1])
                if( not success ):
                    return (False, bad_bytes)
                i = i+1
            # Keep regs option
            elif( arg == OPTION_KEEP_REGS or arg == OPTION_KEEP_REGS_SHORT):
                if( seenKeepRegs ):
                    return (False, "Error. '" + arg + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing registers after option '"+arg+"'")
                seenKeepRegs = True
                (success, keep_regs) = parse_keep_regs(args[i+1])
                if( not success ):
                    return (False, keep_regs)
                i = i+1
            # Output option 
            elif( arg == OPTION_OUTPUT or arg == OPTION_OUTPUT_SHORT ):
                if( seenOutput ):
                    return (False, "Error. '" + arg + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing output format after option '"+arg+"'")
                if( args[i+1] in [OUTPUT_CONSOLE, OUTPUT_PYTHON]):
                    OUTPUT = args[i+1]
                    seenOutput = True
                    i = i +1
                else:
                    return (False, "Error. '" + args[i+1] + "' output format is not supported")
            # Offset option
            elif( arg == OPTION_OFFSET or arg == OPTION_OFFSET_SHORT):
                if( seenOffset ):
                    return (False, "Error. '" + arg + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing output format after option '"+arg+"'")
                (success, offset) = parse_offset(args[i+1])
                if( not success ):
                    return (False, offset)
                i = i+1
                seenOffset = True
            # Lmax option 
            elif( arg == OPTION_LMAX or arg == OPTION_LMAX_SHORT ):
                if( seenLmax ):
                    return (False, "Error. '" + arg + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing length after option '"+arg+"'")
                (success, lmax) = parse_lmax(args[i+1])
                if( not success ):
                    return (False, lmax)
                i = i +1 
                seenLmax = True
            # Shortest option
            elif( arg == OPTION_SHORTEST  or arg == OPTION_SHORTEST_SHORT ):
                if( seenShortest ):
                    return (False,"Error. '" + arg + "' option should be used only once.")
                seenShortest = True
            # Otherwise Ignore
            else:
                return (False, "Error. Unknown option: '{}' ".format(arg))
        
        # If not option it should be a request expr=expr
        else:    
            if( seenQuery ):
                return (False, "Error. Unexpected extra expression: '" + ' '.join(args[i:]) + "'")
            else:
                seenQuery = True
                parsed_query = parse_query(''.join(args[i:]))
                if( not parsed_query[0] ):
                    return (False, parsed_query[1])
                else:
                    i = len(args)
                    dest_arg = parsed_query[1]
                    assign_arg = parsed_query[2]
        i = i + 1

    # After parsing arguments 
    if( not seenQuery ):
        return (False, "Error. Missing semantic query")
    else:
        parameters = SearchParametersBinding(keep_regs, bad_bytes, lmax, seenShortest)
        return (True, dest_arg, assign_arg, parameters, offset, bad_bytes)
        
