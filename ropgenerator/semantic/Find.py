# -*- coding:utf-8 -*- 
# Find module: implement de find command - find gadgets and build ropchains :) 

from ropgenerator.Constraints import Constraint, BadBytes, RegsNotModified, Assertion,\
    RegsValidPtrRead, RegsValidPtrWrite
from ropgenerator.IO import error, banner, string_bold, string_special 
from ropgenerator.Database import QueryType
from ropgenerator.Expressions import parseStrToExpr, ConstExpr, MEMExpr
from ropgenerator.semantic.Engine import search, search_not_chainable
import ropgenerator.Architecture as Arch

# Definition of options names
OPTION_HELP = '--help'
OPTION_HELP_SHORT = '-h'

OPTION_BAD_BYTES = '--bad-bytes'
OPTION_KEEP_REGS = '--keep-regs'

OPTION_BAD_BYTES_SHORT = '-b'
OPTION_KEEP_REGS_SHORT = '-k' 

OPTION_OUTPUT = '--output-format'
OPTION_OUTPUT_SHORT = '-f'
# Options for output
OUTPUT_CONSOLE = 'console'
OUTPUT_PYTHON = 'python'
OUTPUT_RAW = 'raw'
OUTPUT = None # The one choosen 


# Help for the search command
CMD_FIND_HELP = banner([string_bold("'find' command"),
                string_special("(Find gadgets/ropchains that execute specific operations)")])
CMD_FIND_HELP += "\n\n\t"+string_bold("Usage")+":\tfind [OPTIONS] <reg>=<expr>"+\
                "\n\t\tfind [OPTIONS] <reg>=mem(<expr>)"+\
                "\n\t\tfind [OPTIONS] mem(<expr>)=<expr>"+\
                "\n\t\tfind [OPTIONS] int80"+\
                "\n\t\tfind [OPTIONS] syscall"
CMD_FIND_HELP += "\n\n\t"+string_bold("Options")+":"
CMD_FIND_HELP += "\n\t\t"+string_special(OPTION_BAD_BYTES_SHORT)+","+string_special(OPTION_BAD_BYTES)+":\tbad bytes for payload.\n\t\t\t\tExpected format is a list of bytes \n\t\t\t\tseparated by comas (e.g '-b 0A,0B,2F')"
CMD_FIND_HELP += "\n\n\t\t"+string_special(OPTION_KEEP_REGS_SHORT)+","+string_special(OPTION_KEEP_REGS)+":\tregisters that shouldn't be modified.\n\t\t\t\tExpected format is a list of registers \n\t\t\t\tseparated by comas (e.g '-k edi,eax')"
CMD_FIND_HELP += "\n\n\t\t"+string_special(OPTION_OUTPUT_SHORT)+","+string_special(OPTION_OUTPUT)+": output format for ropchains.\n\t\t\t\tExpected format is one of the following\n\t\t\t\t"+string_special(OUTPUT_CONSOLE)+','+string_special(OUTPUT_PYTHON)
CMD_FIND_HELP += "\n\n\t"+string_bold("Examples")+":\n\t\tfind rax=rbp\n\t\tfind rbx=0xff\n\t\tfind rax=mem(rsp)\n\t\tfind mem(rsp-8)=rcx\n\t\tfind "+OPTION_KEEP_REGS+ " rdx,rsp mem(rbp-0x10)=0b101\n\t\tfind "+ OPTION_BAD_BYTES+" 0A,0D "+ OPTION_OUTPUT + ' ' + OUTPUT_PYTHON + "  rax=rcx+4" 

def print_help():
    print(CMD_FIND_HELP)

def find(args):
    """
    args - List of user arguments as strings
    (the command should not be included in the list as args[0])
    """
    if( not args ):
        print_help()
        return 
    
    if( args[0] == OPTION_HELP or args[0] == OPTION_HELP_SHORT ):
        print_help()
        return 
    
    parsed_args = parse_args(args)
    if( not parsed_args[0]):
        error(parsed_args[1])
    else:
        qtype = parsed_args[1]
        arg1 = parsed_args[2]
        arg2 = parsed_args[3]
        constraint = parsed_args[4]
        assertion = Assertion().add(\
            RegsValidPtrRead([(Arch.spNum(),-5000, 10000)])).add(\
            RegsValidPtrWrite([(Arch.spNum(), -5000, 0)]))
        # Search 
        res = search(qtype, arg1, arg2, constraint, assertion, n=4)
        if( res ):
            print_chains(res, "Built matching ROPChain(s)", constraint.getBadBytes())
        else:
            res = search_not_chainable(qtype, arg1, arg2, constraint, assertion, n=4)
            print_chains(res, "Possibly matching gadget(s)", constraint.getBadBytes())
            
        
        
def parse_args(args):
    """
    Parse the user supplied arguments to the 'find' function
    Returns either a tuple (True, GadgetType, x, y )
    Or if not supported or invalid arguments, returns a tuple (False, msg)
    
    ---> See parse_user_request() specification for the list of possible tuples
         and values/types of x and y     
    """
    global OUTPUT
    
    seenExpr = False
    seenBadBytes = False
    seenKeepRegs = False
    seenOutput = False
    i = 0 # Argument counter 
    constraint = Constraint()
    OUTPUT = OUTPUT_CONSOLE
    while( i < len(args)):
        arg = args[i]
        # Look for options
        if( arg[0] == '-' and arg[1] != '>' ):
            if( seenExpr ):
                return (False, "Error. Options must come before the search request")       
            # bad bytes option 
            if( arg == OPTION_BAD_BYTES or arg == OPTION_BAD_BYTES_SHORT):
                if( seenBadBytes ):
                    return (False, "Error. '" + OPTION_BAD_BYTES + "' option should be used only once")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing bad bytes after option '"+arg+"'")
                seenBadBytes = True
                (success, res) = parse_bad_bytes(args[i+1])
                if( not success ):
                    return (False, res)
                i = i+1
                constraint = constraint.add(BadBytes(res))
            elif( arg == OPTION_KEEP_REGS or arg == OPTION_KEEP_REGS_SHORT):
                if( seenKeepRegs ):
                    return (False, "Error. '" + OPTION_KEEP_REGS + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing registers after option '"+arg+"'")
                seenKeepRegs = True
                (success, res) = parse_keep_regs(args[i+1])
                if( not success ):
                    return (False, res)
                i = i+1
                constraint = constraint.add( RegsNotModified(res))
            elif( arg == OPTION_OUTPUT or arg == OPTION_OUTPUT_SHORT ):
                if( seenOutput ):
                    return (False, "Error. '" + OPTION_OUTPUT + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing output format after option '"+arg+"'")
                if( args[i+1] in [OUTPUT_CONSOLE, OUTPUT_PYTHON]):
                    OUTPUT = args[i+1]
                    seenOutput = True
                    i = i +1
                else:
                    return (False, "Error. '" + args[i+1] + "' output format is not supported")
            # Otherwise Ignore
            else:
                return (False, "Error. Unknown option: '{}' ".format(arg))
        # If not option it should be a request expr=expr
        else:    
            if( seenExpr ):
                return (False, "Error. Unexpected extra expression: '" + ' '.join(args[i:]) + "'")
            else:
                seenExpr = True
                parsed_query = parse_query(''.join(args[i:]))
                if( not parsed_query[0] ):
                    return (False, parsed_query[1])
                else:
                    i = len(args)
        i = i + 1
    if( not seenExpr ):
        return (False, "Error. Missing specification of gadget to find")
    else:
        return parsed_query+(constraint,)
    
def parse_query(req):
    """
    Parses a user request for a gadget
    Request is of the form  expression=expression
    Returns either a tuple (True, GadgetType, x, y )where x and y are:
        if REGtoREG, x is register uid, y is (reg,cst)
        if CSTtoREG, x is register uid,  y is an (int)
        if MEMtoREG, x is reg UID, y is (addr_reg, addr_cst)
        if CSTtoMEM, x is (addr_reg, addr_cst) and y is (int) 
        if REGtoMEM, x is (addr_reg, addr_cst) and y is (reg, cst)
        if MEMtoMEM, x is (addr_reg, addr_cst) and y is (addr_reg2, addr_cst2)
        if INT80 or SYSCALL, x and y are None
    Or if not supported or invalid arguments, returns a tuple (False, msg)
    """
    # Check for int80 and syscall
    if( req == 'int80' ):
        return (True, QueryType.INT80, None, None)
    elif( req == 'syscall' ):
        return (True, QueryType.SYSCALL, None, None)
    
    # Check for Regular query 
    args = [x for x in req.split('=',1) if x]
    if( len(args) != 2):
        # Test if request with '->'  
        return (False, "\n\tInvalid semantic query: " + str(req))
        args = [x for x in user_input.split('->',1) if x]
        if( len(args) != 2 ):    
            return (False, "\n\tInvalid semantic query: " + user_input )
        else:
            left = args[0].strip()
            right = ''
            if( left not in Analysis.regNamesTable ):
                return (False, "Left operand '{}' should be a register".format(left))
            # Parsing right side
            i = 0
            args[1] = args[1].encode('ascii', 'replace').decode('ascii', 'ignore')
            while( i < len(args[1]) and args[1][i] in [' ', '\t'] ):
                i = i + 1
            if( i == len(args[1]) or args[1][i] != '"'):
                 return (False, '\n\tInvalid right operand: {} \n\tIt should be an ASCII string between quotes\n\tE.g: find rax -> "Example operand string"'.format(args[1]))   
            saved_args1 = args[1]
            args[1] = args[1][i+1:]
            index = args[1].find('"')
            if( index == -1 or len(args[1].split('"')[1].strip()) > 0 ):
                return (False,'\n\tInvalid right operand: {} \n\tIt should be an ASCII string between quotes\n\tE.g: find rbx -> "Example operand string"'.format(saved_args1))
            args[1] =  args[1][:-1]
            right = args[1]
            return (False, "'->' not supported yet ;)")
            #return (True, GadgetType.STRPTRtoREG, Analysis.regNamesTable[left], right) 
                
    # Normal request with '=' 
    left = args[0]
    right = args[1]
    # Test if it is XXXtoREG
    if( left in Arch.regNameToNum):
        (success, right_expr) = parseStrToExpr(right, Arch.regNameToNum)
        if( not success ):
            return (False, "\n\tError. Operand '"+right+"' is incorrect: " + right_expr)
        right_expr = right_expr.simplify()
        if( not is_supported_expr(right_expr)):
            return (False, "Error. Right expression '"+right+"' is not supported :(")
        # Test if CSTtoREG
        if( isinstance(right_expr, ConstExpr)):
            return (True, QueryType.CSTtoREG, Arch.regNameToNum[left], right_expr.value)
        # if MEMtoREG
        elif( isinstance(right_expr, MEMExpr)):
            (isInc, num, inc) = right_expr.addr.isRegIncrement(-1)
            return (True, QueryType.MEMtoREG, Arch.regNameToNum[left], [num,inc])
        # otherwise REGtoREG
        else:
            (isInc, num, inc) = right_expr.isRegIncrement(-1)
            return (True, QueryType.REGtoREG, Arch.regNameToNum[left], [num,inc])
    
    elif( left[:4] == 'mem(' ):
        (success,addr) = parseStrToExpr(left[4:-1], Arch.regNameToNum)
        if( not success ):
            return (False, "\n\tError. {}".format(addr))
        addr = addr.simplify()
        if( not is_supported_expr(addr)):
            return (False, "\n\tError. Address '"+addr+"' is not supported :(")
            
        (success, right_expr) = parseStrToExpr(right, Arch.regNameToNum)
        if( not success ):
            return (False, "\n\tError. {}".format(right_expr))
        right_expr = right_expr.simplify()
        if( not is_supported_expr(right_expr)):
            return (False, "\n\tError. Right expression '"+right+"' is not supported :(")
            
        (isInc, addr_reg, addr_cst) = addr.isRegIncrement(-1)
        
        # Test if CSTtoMEM
        if( isinstance(right_expr, ConstExpr)):
            return (True, QueryType.CSTtoMEM, [addr_reg, addr_cst], right_expr.value)        
        # Test if it is MEMEXPRtoMEM
        elif( isinstance( right_expr, MEMExpr)):
            (isInc, num, inc) = right_expr.addr.isRegIncrement(-1)
            return (True, QueryType.MEMtoMEM, [addr_reg, addr_cst], [num,inc])
        # Otherwise REGEXPRtoMEM
        else:
            (isInc, num, inc) = right_expr.isRegIncrement(-1)
            return (True, QueryType.REGtoMEM, [addr_reg, addr_cst], [num,inc])
    else:
        return ( False, "\n\tOperand '" +left+"' is invalid or not yet supported :(")

def is_supported_expr(expr):
    """
    Checks if an expression is supported for semantic queries 
    So far we support 
        CST
        REG +- CST
        mem(CST)
        mem(REG +- CST)
    """
    if( isinstance(expr, ConstExpr) ):
        return True
    elif( isinstance(expr, MEMExpr)):
        return (not isinstance( expr.addr, MEMExpr)) and \
            (not isinstance(expr.addr, ConstExpr)) and \
            is_supported_expr(expr.addr)
    else:
        (isInc, reg, inc) = expr.isRegIncrement(-1)
        return isInc

def parse_bad_bytes(string):
    """
    Parses a bad bytes string into a list of bad bytes
    Input: a string of format like "00,0A,FF,32,C7"
    Ouput if valid string : (True, list) where list = 
        ['00', '0a', 'ff', '32', 'c7'] (separate them in individual strings
        and force lower case)
    Output if invalid string (False, error_message)
    """
    hex_chars = '0123456789abcdefABCDEF'
    i = 0
    bad_bytes = []
    user_bad_bytes = [b.lower() for b in string.split(',')]
    for user_bad_byte in user_bad_bytes:
        if( not user_bad_byte ):
            return (False, "Error. Missing bad byte after ','")
        elif( len(user_bad_byte) != 2 ):
            return (False, "Error. '{}' is not a valid byte".format(user_bad_byte))
        elif( not ((user_bad_byte[i] in hex_chars) and (user_bad_byte[i+1] in hex_chars))):
            return (False, "Error. '{}' is not a valid byte".format(user_bad_byte))
        else:
            bad_bytes.append(user_bad_byte)
    return (True, bad_bytes)
    
def parse_keep_regs(string):
    """
    Parses a 'keep registers' string into a list of register uids
    Input: a string of format like "rax,rcx,rdi"
    Output if valid string (True, list) where list = 
        [1, 3, 4] (R1 is rax, R3 is RCX, ... )
    Output if invalid string (False, error_message)
    """
    user_keep_regs = string.split(',')
    keep_regs = set()
    for reg in user_keep_regs:
        if( reg in Arch.regNameToNum ):
            keep_regs.add(Arch.n2r(reg))
        else:
            return (False, "Error. '{}' is not a valid register".format(reg))
    return (True, list(keep_regs))

##########################
# Pretty print functions #
##########################

def print_chains(chainList, msg, badBytes=[]):
    global OUTPUT
    sep = "------------------"
    if( chainList):
        print(string_bold('\n\t'+msg))
        if( OUTPUT == OUTPUT_CONSOLE ):
            print("\n"+chainList[0].strConsole(Arch.currentArch.bits, badBytes))
        elif( OUTPUT == OUTPUT_PYTHON ):
            print('\n' + chainList[0].strPython(Arch.currentArch.bits, badBytes))
        for chain in chainList[1:]:
            if( OUTPUT == OUTPUT_CONSOLE ):
                print('\t'+sep + "\n"+ chain.strConsole(Arch.currentArch.bits, badBytes))
            elif( OUTPUT == OUTPUT_PYTHON ):
                print('\t'+sep + '\n' + chain.strPython(Arch.currentArch.bits, badBytes))
    else:
        print(string_bold("\n\tNo matching Gadget or ROPChain found"))
    
