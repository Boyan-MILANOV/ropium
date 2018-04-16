# ROPGenerator - Gadget_finder module 
# Searching for gadgets and chaining them :) !! 

import ropgenerator.Expr as Expr
import ropgenerator.Database as Database
import ropgenerator.Analysis as Analysis
import re
from ropgenerator.Gadget import GadgetType
import ropgenerator.Config as Config
import ropgenerator.SearchHelper as SearchHelper
from ropgenerator.Constraints import Constraint, ConstraintType
from ropgenerator.Colors import string_special, BOLD_COLOR_ANSI, END_COLOR_ANSI, string_bold

# Definition of options names
OPTION_BAD_BYTES = '--bad-bytes'
OPTION_KEEP_REGS = '--keep-regs'

OPTION_BAD_BYTES_SHORT = '-b'
OPTION_KEEP_REGS_SHORT = '-k' 

# Help for the search command
CMD_FIND_HELP = BOLD_COLOR_ANSI
CMD_FIND_HELP +=    "\n\t-----------------------------------------------"
CMD_FIND_HELP += "\n\tROPGenerator 'find' command\n\t(Find gadgets that execute specific operations)"
CMD_FIND_HELP += "\n\t-----------------------------------------------"
CMD_FIND_HELP += END_COLOR_ANSI
CMD_FIND_HELP += "\n\n\t"+string_bold("Usage")+":\tfind [OPTIONS] <reg>=<expr>\n\t\tfind [OPTIONS] <reg>=mem(<expr>)\n\t\tfind [OPTIONS] mem(<expr>)=<expr>"
CMD_FIND_HELP += "\n\n\t"+string_bold("Options")+":"
CMD_FIND_HELP += "\n\t\t"+string_special(OPTION_BAD_BYTES_SHORT)+","+string_special(OPTION_BAD_BYTES)+"\t: bad bytes for payload.\n\t\t\t\tExpected format is a list of bytes \n\t\t\t\tseparated by comas (e.g '-b 0A,0B,2F')"
CMD_FIND_HELP += "\n\n\t\t"+string_special(OPTION_KEEP_REGS_SHORT)+","+string_special(OPTION_KEEP_REGS)+"\t: registers that shouldn't be modified.\n\t\t\t\tExpected format is a list of registers \n\t\t\t\tseparated by comas (e.g '-k edi,eax')"
CMD_FIND_HELP += "\n\n\t"+string_bold("Examples")+":\n\t\tfind rax=rbp\n\t\tfind rbx=0xff\n\t\tfind rax=mem(rsp)\n\t\tfind mem(rsp-8)=rcx\n\t\tfind "+OPTION_KEEP_REGS+ " rdx,rsp mem(rbp-0x10)=0b101\n\t\tfind "+ OPTION_BAD_BYTES+" 0A,0D rax=rcx+4"



def print_help():
    print(CMD_FIND_HELP)

# The different options
RAW_OUTPUT = True # Output the gadgets addresses raw
PYTHON_OUTPUT = False # Output the gadgets in python ( like p += <gadget hex>  # commentary )


##############################
# SEARCH ENGINE FOR GADGETS #
############################

DEFAULT_DEPTH = 3
class search_engine:
    global DEFAULT_DEPTH

    def __init__(self):
        self.truc = None
 
    def find(self, gtype, arg1, arg2, constraint, n=1, basic=True, chainable=True, unusable=[], init=False):
        """
        Searches for gadgets 
        basic = False means that we don't call _basic_strategy
        chainable = True means that we want only chainable gadgets 
        init = True means the search just started and we have to do some initialization in SearchHelper
        """
        if( init ):
            SearchHelper.init_impossible()
        res = []        
        if( not chainable ):
            return self._basic_strategy(gtype, arg1, arg2, constraint.remove_all(ConstraintType.CHAINABLE_RET), n=n)
        # Adjusting the constraint
        constraint_with_chainable = constraint.add(ConstraintType.CHAINABLE_RET, [])
        # Searching with basic strategies for chainable
        if( basic ):
            res = self._basic_strategy(gtype, arg1, arg2, constraint_with_chainable, n=n)
        # If not enough chains found, chaining with advanced strategy 
        if(len(res) < n):
            res += self._chaining_strategy(gtype, arg1, arg2, constraint_with_chainable, n=n-len(res), unusable=unusable)
        return sorted(res, key = lambda x:len(x)) 
 
    def _basic_strategy(self, gtype, arg1, arg2, constraint, n=1, no_padding=False):
        """
        Search for gadgets basic method ( without chaining ) 
        Returns a list of possible gadgets of maximum size n

        Parameters: 
        gtype - instance of GadgetType
        n - (int) number of gadgets to return 
        arg1, arg2 - depends on gtype : 
            see the parse_user_request function :) 
        """
        gadgets =  Database.gadgetLookUp.find(gtype, arg1, arg2, constraint, n)
        if( no_padding ):
            return [[g] for g in gadgets]
        else:
            return SearchHelper.pad_gadgets(gadgets, constraint)
            
    def _chaining_strategy(self, gtype, arg1, arg2, constraint, n=1, unusable=[]):
        """
        Search for gadgets with advanced chaining methods
        Returns a list of chains ( a chain is a list of gadgets )
        """
        res = []  
        if( (gtype == GadgetType.REGEXPRtoREG) and (arg2[1] == 0)):
            res += self._REGtoREG_transitivity(arg1, arg2[0], constraint, n=n, unusable=unusable)
            res += self._REGtoREG_adjust_jmp_reg(arg1, arg2[0], constraint, n=n)
            # reg <- reg2 is not possible 
            if( len(res) == 0 ):
                SearchHelper.add_impossible_REGtoREG(arg1, arg2[0])
        elif( gtype == GadgetType.CSTtoREG ):
            res += self._CSTtoREG_pop_from_stack(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.STRPTRtoREG ):
            res += self._STRPTRtoREG_on_stack(arg1, arg2, constraint=constraint, n=n)
        return res
        
        
    def _REGtoREG_transitivity(self, reg, reg2, constraint, unusable=[], n=1):
        """
        Searches for a chain that puts reg2 in reg
        reg, reg2 - (int)
        """
        if( len(unusable) > DEFAULT_DEPTH ):
            return []
            
        res = []
        for inter_reg in SearchHelper.possible_REGtoREG_transitivity(reg):
            if( (inter_reg != reg) and (inter_reg != reg2) and (not inter_reg in unusable)):
                base_chains = self.find(GadgetType.REGEXPRtoREG, reg, [inter_reg,0], \
                constraint=constraint, unusable=unusable+[reg2],n=n)
                for inter_chain in self.find( GadgetType.REGEXPRtoREG, inter_reg, \
                [reg2, 0], constraint, unusable=unusable+[reg], n=n):
                    for base_chain in base_chains:
                        res.append( inter_chain + base_chain )
                        if( len(res) >= n ):
                            return res
        return res
                    
   
    def _REGtoREG_adjust_jmp_reg(self, reg, reg2, constraint, n=1):
        """
        Searches for chains matching gadgets finishing by jmp or call 
        And adjusts them by handling the call/jmp
        """
        ACCEPTABLE_SPINC = -4 *Analysis.ArchInfo.bits/8 # We accept to correct gadgets with spinc down to this value  
        res = []
        # Find possible not chainable gadgets 
        constraint_not_chainable = constraint.remove_all(ConstraintType.CHAINABLE_RET)
        possible_gadgets = [g[0] for g in self._basic_strategy(GadgetType.REGEXPRtoREG, reg, [reg2,0], \
            constraint_not_chainable, n=n) if ((Database.gadgetDB[g[0]].hasJmpReg()[0] \
                                                or Database.gadgetDB[g[0]].hasCallReg()[0]) \
                                            and Database.gadgetDB[g[0]].isValidSpInc(ACCEPTABLE_SPINC))]

        for gadget in possible_gadgets:
            # Pad the gadget 
            padded_gadget = SearchHelper.pad_gadgets([gadget], constraint_not_chainable, force_padding=True)[0]
            # Get the register we are jumping to 
            jmp_to_reg = Database.gadgetDB[gadget].retValue
            # COMPUTE PRE CONSTRAINT (don't modify reg2)
            preConstraint = constraint.add(ConstraintType.REGS_NOT_MODIFIED, [reg2])
            # COMPUTE CONSTRAINT FOR THE RET GADGET (don't modify reg after we assigned it)
            retConstraint = constraint.add(ConstraintType.REGS_NOT_MODIFIED, [reg])
            # Get chains that adjust the register to be pointing to ret
            if( Database.gadgetDB[gadget].spInc < 0 ):
                    correction = -1 * Database.gadgetDB[gadget].spInc
            else: 
                    correction = 0
            if( Database.gadgetDB[gadget].hasJmpReg() ):
                offset = correction 
            else:
                offset = correction + Analysis.ArchInfo.bits/8 
            adjusting_jmp_reg_chains = self._put_RET_in_reg(jmp_to_reg, offset, preConstraint, RET_gadget_constraint = retConstraint)
            # Combine the two to get the chain adjusted chain :) 
            for adjust_chain in adjusting_jmp_reg_chains:
                res.append( adjust_chain + padded_gadget )
                if( len(res) >= n ):
                    return res
        
        return res 
        
    
    def _put_RET_in_reg(self, reg, offset, constraint, n=1, RET_gadget_constraint=None):
        """
        Finds chains that puts in 'reg' the address of a ip <- mem(sp+CST) gadget
        """
        if( RET_gadget_constraint != None ):
            adjust_gadget_constraint = RET_gadget_constraint
        else:
            adjust_gadget_constraint = constraint
        ret_adjust_gadgets = [c[0] for c in self._RET_offset(offset, adjust_gadget_constraint, n=n) if len(c) == 1]
        if( not ret_adjust_gadgets ):
            return []
        res = []
        for g in ret_adjust_gadgets:
            addr = Database.gadgetDB[g].addr
            res += self.find(GadgetType.CSTtoREG, reg, addr, constraint, n=n-len(res))
            # Update the addr_to_gadgetStr dict in SearchHelper
            # This is used to have a better printing of the chains
            # Instead of indicating the constant as (Custom Padding)
            # we will write 'address of gadget ....'
            SearchHelper.addr_to_gadgetStr[addr]=Database.gadgetDB[g].asmStr
            if( len(res) >= n ):
                return res
        return res
    
    def _RET_offset(self, offset, constraint, n=1):
        """
        Searches for gadgets that do ip <- mem(sp + offset) 
        """
        ip_num = Analysis.regNamesTable[Analysis.ArchInfo.ip]
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp]
        res = self._basic_strategy(GadgetType.MEMEXPRtoREG, ip_num, [sp_num,offset], constraint=constraint, n=n, no_padding=True)
        return res
    
    def _CSTtoREG_pop_from_stack(self, reg, cst, constraint, n=1):
        """
        Returns a payload that puts cst into register reg by poping it from the stack
        """ 
        res = []
        # Direct pop from the stack
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp] 
        for offset in sorted([off for off in Database.gadgetLookUp.types[GadgetType.MEMEXPRtoREG][reg].expr[sp_num].keys()\
        if off >= 0 ]):
            possible_gadgets = [g for g in Database.gadgetLookUp.types[GadgetType.MEMEXPRtoREG][reg].expr[sp_num][offset]\
            if Database.gadgetDB[g].isValidSpInc() and Database.gadgetDB[g].hasNormalRet()]
            for chain in SearchHelper.pad_CSTtoREG_pop_from_stack(possible_gadgets, offset, cst, constraint=constraint):
                # At this point 'gadget' does reg <- mem(sp+offset)
                res.append(chain)
                if( len(res) >= n ):
                    return res
        return res
        
    def _CSTtoREG_transitivity(self):
        """
        Returns a payload that puts cst into register reg by poping it from the stack
        unusable: list of reg UID that can not be used in the chaining strategy 
        """ 
        return []
        
    def _STRPTRtoREG_on_stack(self, reg, string, constraint, n=1):
        """
        Searches for gadgets that put the address of a string "string"
        into register reg
        reg - int
        string - str
        """
        # We need a gadget that does:
        # reg <- sp+XX 
        # ip <- sp+YY 
        # where the string can fit between XX and YY ...
        
        # First find all s.t reg <- sp+XX
        string_len = len(string)+1 # We need to add a \x00 in the end
        if( string_len % 4 == 0 ):
            string_bytes_needed = string_len
        else:
            string_bytes_needed = string_len + (4 - (string_len%4))
        
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp]
        # Get the posible offsets 
        possible_offsets = [off for off in Database.gadgetLookUp.types[GadgetType.REGEXPRtoREG][reg].expr[sp_num].keys() if off>=0]
        print("DEBUG, possible offsets:")
        print(possible_offsets)
        res = []
        for offset in possible_offsets:
            res += self.find(GadgetType.REGEXPRtoREG, reg, (sp_num, offset), constraint=constraint, n=1000)
        return res
    
    
        

# The module-wide search engine 
search = search_engine()




###########################
# COMMAND TO FIND GADGETS #
###########################
user_input = '' # The command that has been typed by the user
                # Used when parsing the '->' operator 
    
def set_user_input(string):
    global user_input 
    user_input = string
    
def find_gadgets(args):
    """
    Main function to find gadgets !! 
    args - List of user arguments as strings ( command 'find' should not be included in the list as args[0] )
    """
    
    if( len(Database.gadgetDB) == 0 ):
        print("You have to load gadgets before running the 'find' command (type 'load help' for more details)")
        return     
    parsed_args = parse_args(args)
    # If parsing returned an error, print it and return 
    if( not parsed_args[0] ):
        print(parsed_args[1])
        return
    # Else execute the search ;) 
    else:
        gtype = parsed_args[1]
        left = parsed_args[2]
        right = parsed_args[3]
        constraint = parsed_args[4]
        chains = []
        # Search with basic strategy
        chains = search.find(gtype, left, right, constraint, n=Config.LIMIT, init=True)
        # Display results 
        if( chains ):
            print(string_bold("\n\tBuilt matching ROP Chain(s):\n"))
            show_chains(chains)
        else:
            possible_gadgets = search.find(gtype, left, right, constraint, n=Config.LIMIT, chainable=False, init=True)
            if( possible_gadgets ):
                print(string_bold("\n\tFound possibly matching Gadget(s):\n"))
                show_chains(possible_gadgets)
            else:
                print(string_bold("\n\tNo matching Gadgets or ROP Chains found"))
                
               
def show_gadgets(gadget_list, check_length=False):
    """
    Pretty prints a list of gadgets 
    Parameters:
        gadget_list - list of gadget UID 
        check_length = True <=> Factorizes the print if a lot of padding for a single gadget 
    """
    if( RAW_OUTPUT ):
        for gadget_num in gadget_list:
            print("\t"+Database.gadgetDB[gadget_num].addrStr + " (" + Database.gadgetDB[gadget_num].asmStr + ")  ") 
    elif( PYTHON_OUTPUT ):
        print("\t\tPython output not supported yet :'(")
        
def show_chains( chain_list ):
    """
    Pretty prints a list of ROP chains 
    Parameters:
        chain_list - list of chains (a chain is a list of gadget UID and/or padding units)
    """
    
    if( RAW_OUTPUT ):
        for chain in chain_list:
            print(string_bold("\t-------------------"))
            for gadget_num in chain:
                if( SearchHelper.is_padding(gadget_num)):
                    padding_str = string_special('0x'+format(SearchHelper.get_padding_unit(gadget_num), '0'+str(Analysis.ArchInfo.bits/4)+'x'))
                    if( gadget_num == SearchHelper.DEFAULT_PADDING_UNIT_INDEX ):
                        padding_str += " (Padding)"
                    elif( SearchHelper.get_padding_unit(gadget_num) in SearchHelper.addr_to_gadgetStr ):
                        padding_str += " (@ddress of: "+SearchHelper.addr_to_gadgetStr[SearchHelper.get_padding_unit(gadget_num)]+")"
                    else:
                        padding_str += " (Custom Padding)"
                    print("\t"+padding_str)
                else:
                    print("\t"+string_special(Database.gadgetDB[gadget_num].addrStr) + " (" + Database.gadgetDB[gadget_num].asmStr + ")")
    elif( PYTHON_OUTPUT ):
        print("\t\tPython output not supported yet :'(")
    

def parse_args(args):
    """
    Parse the user supplied arguments to the 'find' function
    Returns either a tuple (True, GadgetType, x, y )
    Or if not supported or invalid arguments, returns a tuple (False, msg)
    
    ---> See parse_user_request() specification for the list of possible tuples
         and values/types of x and y     
    """
    global OPTION_BAD_BYTES
    
    seenExpr = False
    seenBadBytes = False
    seenKeepRegs = False
    i = 0 # Argument counter 
    constraint = Constraint()
    while( i < len(args)):
        arg = args[i]
        # Look for options
        if( arg[0] == '-' and arg[1] != '>' ):
            if( seenExpr ):
                return (False, "Error. Options must come before the search request")       
            # bad bytes option 
            if( arg == OPTION_BAD_BYTES or arg == OPTION_BAD_BYTES_SHORT):
                if( seenBadBytes ):
                    return (False, "Error. '" + OPTION_BAD_BYTES + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing bad bytes after option '"+arg+"'")
                seenBadBytes = True
                (success, bad_bytes_list) = parse_bad_bytes(args[i+1])
                if( not success ):
                    return (False, bad_bytes_list)
                i = i+1
                constraint = constraint.add( ConstraintType.BAD_BYTES, bad_bytes_list)
            elif( arg == OPTION_KEEP_REGS or arg == OPTION_KEEP_REGS_SHORT):
                if( seenKeepRegs ):
                    return (False, "Error. '" + OPTION_KEEP_REGS + "' option should be used only once.")
                if( i+1 >= len(args)):
                    return (False, "Error. Missing registers after option '"+arg+"'")
                seenKeepRegs = True
                (success, keep_regs_list) = parse_keep_regs(args[i+1])
                if( not success ):
                    return (False, keep_regs_list)
                i = i+1
                constraint = constraint.add( ConstraintType.REGS_NOT_MODIFIED, keep_regs_list)
            # Otherwise Ignore
            else:
                return (False, "Error. Unknown option: '{}' ".format(arg))
        # If not option it should be a request expr=expr
        else:    
            if( seenExpr ):
                return (False, "Error. Unexpected extra expression: '" + ' '.join(args[i:]) + "'. Only one at a time please")
            else:
                seenExpr = True
                set_user_input(' '.join(args[i:]))
                parsed_expr = parse_user_request(''.join(args[i:]))
                if( not parsed_expr[0] ):
                    return (False, parsed_expr[1])
                else:
                    i = len(args)
        i = i + 1
    if( not seenExpr ):
        return (False, "Error. Missing specification of gadget to find")
    else:
        return parsed_expr+(constraint,)
        
                 
def parse_user_request(req):
    """
    Parses a user request for a gadget
    Request is of the form  expression=expression
    Returns either a tuple (True, GadgetType, x, y )where x and y are:
        if REGEXPRtoREG, x is register uid, y is (reg,cst)
        if CSTtoREG, x is register uid for ROPG IR and y is an (int)
        if MEMEXPRtoREG, x is reg UID, y is (addr_reg, addr_cst)
        if CSTtoMEM, x is (addr_reg, addr_cst) and y is (int) 
        if REGEXPRtoMEM, x is (addr_reg, addr_cst) and y is (reg, cst)
        if MEMEXPRtoMEM, x is (addr_reg, addr_cst) and y is (addr_reg2, addr_cst2)
        if STRPTRtoREG, x is register uid, y is a string
    Or if not supported or invalid arguments, returns a tuple (False, msg)
    """
    global user_input
    args = [x for x in req.split('=',1) if x]
    if( len(args) != 2):
        # Test if request with '->'  
        args = [x for x in user_input.split('->',1) if x]
        if( len(args) != 2 ):    
            return (False, "Invalid request: " + user_input )
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
                 return (False, '\nInvalid right operand: {} \nIt should be an ASCII string between quotes\nE.g: find rax -> "Example operand string"'.format(args[1]))   
            saved_args1 = args[1]
            args[1] = args[1][i+1:]
            index = args[1].find('"')
            if( index == -1 or len(args[1].split('"')[1].strip()) > 0 ):
                return (False, '\nInvalid right operand: {} \nIt should be an ASCII string between quotes\nE.g: find rbx -> "Example operand string"'.format(saved_args1))
            args[1] =  args[1][:-1]
            
            right = args[1]
            return (True, GadgetType.STRPTRtoREG, Analysis.regNamesTable[left], right) 
                
    # Normal request with '=' 
    left = args[0]
    right = args[1]
    # Test if it is XXXtoREG
    if( left in Analysis.regNamesTable):
        (success, right_expr) = Expr.parseStrToExpr(right, Analysis.regNamesTable)
        if( not success ):
            return (False, "Error. Operand '"+right+"' is incorrect: " + right_expr)
        right_expr = right_expr.simplify()
        if( not is_supported_expr(right_expr)):
            return (False, "Error. Right expression '"+right+"' is not supported :(")
        # Test if CSTtoREG
        if( isinstance(right_expr, Expr.ConstExpr)):
            return (True, GadgetType.CSTtoREG, Analysis.regNamesTable[left], right_expr.value)
        # if MEMEXPRtoREG
        elif( isinstance(right_expr, Expr.MEMExpr)):
            (isInc, num, inc) = right_expr.addr.isRegIncrement(-1)
            return (True, GadgetType.MEMEXPRtoREG, Analysis.regNamesTable[left], [num,inc])
        # otherwise REGEXPRtoREG
        else:
            (isInc, num, inc) = right_expr.isRegIncrement(-1)
            return (True, GadgetType.REGEXPRtoREG, Analysis.regNamesTable[left], [num,inc])
    
    elif( left[:4] == 'mem(' ):
        (success,addr) = Expr.parseStrToExpr(left[4:-1], Analysis.regNamesTable)
        if( not success ):
            return (False, "Error. {}".format(addr))
        addr = addr.simplify()
        if( not is_supported_expr(addr)):
            return (False, "Error. Address '"+addr+"' is not supported :(")
            
        (success, right_expr) = Expr.parseStrToExpr(right, Analysis.regNamesTable)
        if( not success ):
            return (False, "Error. {}".format(right_expr))
        right_expr = right_expr.simplify()
        if( not is_supported_expr(right_expr)):
            return (False, "Error. Right expression '"+right+"' is not supported :(")
            
        (isInc, addr_reg, addr_cst) = addr.isRegIncrement(-1)
        
        # Test if CSTtoMEM
        if( isinstance(right_expr, Expr.ConstExpr)):
            return (True, GadgetType.CSTtoMEM, [addr_reg, addr_cst], right_expr.value)        
        # Test if it is MEMEXPRtoMEM
        elif( isinstance( right_expr, Expr.MEMExpr)):
            (isInc, num, inc) = right_expr.addr.isRegIncrement(-1)
            return (True, GadgetType.MEMEXPRtoMEM, [addr_reg, addr_cst], [num,inc])
        # Otherwise REGEXPRtoMEM
        else:
            (isInc, num, inc) = right_expr.isRegIncrement(-1)
            return (True, GadgetType.REGEXPRtoMEM, [addr_reg, addr_cst], [num,inc])
    else:
        return ( False, "Operand '" +left+"' is invalid or not yet supported by ROPGenerator :(")
    
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
        if( reg in Analysis.regNamesTable ):
            keep_regs.add(Analysis.regNamesTable[reg])
        else:
            return (False, "Error. '{}' is not a valid register".format(reg))
    return (True, list(keep_regs))


def is_supported_expr(expr):
    """
    Checks if an expression is supported for semantic queries 
    So far we support 
        CST
        REG +- CST
        mem(CST)
        mem(REG +- CST)
    """
    if( isinstance(expr, Expr.ConstExpr) ):
        return True
    elif( isinstance(expr, Expr.MEMExpr)):
        return (not isinstance( expr.addr, Expr.MEMExpr)) and \
            (not isinstance(expr.addr, Expr.ConstExpr)) and \
            is_supported_expr(expr.addr)
    else:
        (isInc, reg, inc) = expr.isRegIncrement(-1)
        return isInc
