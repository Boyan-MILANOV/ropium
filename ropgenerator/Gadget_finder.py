# ROPGenerator - Gadget_finder module 
# Searching for gadgets and chaining them :) !! 

import ropgenerator.Expr as Expr
import ropgenerator.Database as Database
import ropgenerator.Analysis as Analysis
import re
from ropgenerator.Gadget import GadgetType
from ropgenerator.Config import LIMIT 
import ropgenerator.SearchHelper as SearchHelper
from ropgenerator.Constraints import Constraint, ConstraintType 

# Definition of options names
OPTION_BAD_BYTES = '-bad' 

# Help for the search command
CMD_FIND_HELP =    "\n\t-----------------------------------------------"
CMD_FIND_HELP += "\n\tROPGenerator 'find' command\n\t(Find gadgets that execute specific operations)"
CMD_FIND_HELP += "\n\t-----------------------------------------------"
CMD_FIND_HELP += "\n\n\tUsage:\tfind [OPTIONS] <reg>=<expr>\n\t\tfind [OPTIONS] <reg>=mem(<expr>)\n\t\tfind [OPTIONS] mem(<expr>)=<expr>"
CMD_FIND_HELP += "\n\n\tOptions:"
CMD_FIND_HELP += "\n\t\t"+OPTION_BAD_BYTES+"\tspecify bad bytes for payload. Expected format is a \n\t\t\tlist of bytes separated by comas (e.g '-bad 0A,0B,2F')"
#CMD_FIND_HELP += "\n\n\tExamples:\n\t\tfind rax=rbp\t\t\t(put the value of rbp in rax)\n\t\tfind rbx=0xff\t\t\t(put the value 255 in rbx)\n\t\tfind rax=mem(rsp)\t\t(pop the top of the stack into rax)\n\t\tfind mem(rsp-8)=rcx\t\t(push rcx onto the stack)\n\t\tfind mem(rbp-0x10)=0b101\t(write 5 at address rbp-16)\n\t\tfind -bad 0A,0D rax=rcx\t\t(exclude bad bytes '\\x0a','\\x0d')"
CMD_FIND_HELP += "\n\n\tExamples:\n\t\tfind rax=rbp\n\t\tfind rbx=0xff)\n\t\tfind rax=mem(rsp)\n\t\tfind mem(rsp-8)=rcx\n\t\tfind mem(rbp-0x10)=0b101\n\t\tfind -bad 0A,0D rax=rcx+rax+4"



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
 
    def find(self, gtype, arg1, arg2, constraint, n=1, basic=True, chainable=True):
        """
        Searches for gadgets 
        basic = False means that we don't call _basic_strategy
        chainable = True means that we want only chainable gadgets 
        """
        res = []        
        if( not chainable ):
            return self._basic_strategy(gtype, arg1, arg2, constraint, n=n)
        # Adjusting the constraint
        constraint_with_chainable = constraint.add(ConstraintType.CHAINABLE_RET, [])
        # Searching with basic strategies for chainable
        if( basic ):
            res = self._basic_strategy(gtype, arg1, arg2, constraint_with_chainable, n=n)
        # If not enough chains found, chaining with advanced strategy 
        if(len(res) <= n):
            res += self._chaining_strategy(gtype, arg1, arg2, constraint_with_chainable, n=n-len(res))
        return res
 
    def _validate_gadget_(self, gadget_num):
        return ( Database.gadgetDB[gadget_num].hasNormalRet() and Database.gadgetDB[gadget_num].isValidSpInc() )
    
    def _basic_strategy(self, gtype, arg1, arg2, constraint, n=1):
        """
        Search for gadgets basic method ( without chaining ) 
        Returns a list of possible gadgets of maximum size n

        Parameters: 
        gtype - instance of GadgetType
        n - (int) number of gadgets to return 
        arg1, arg2 - depends on gtype : 
            gtype = GadgetType.REGtoREG, arg1 and arg2 are two ints (register UID)
            gtype = GadgetType.CSTtoREG, arg1 is reg UID, arg2 is an (int)
            gtype = GadgetType.MEMtoREG, arg1 and arg2 are reg UID
            gtype = GadgetType.REGtoMEM, arg1 is Expr, arg2 is reg UID
            gtype = GadgetType.CSTtoMEM, arg1 is Expr, arg2 is (int)
            gtype = GadgetType.EXPRtoREG, arg1 is reg UID, arg2 is Expr
            gtype = GadgetType.MEMEXPRtoREG, arg1 is reg UID, arg2 is an Expr (addr of MEMEXPR)
            gtype = GadgetType.MEMEXPRtoMEM, arg1 is Expr, arg2 is Expr
        """
        if( gtype == GadgetType.REGtoREG ):
            return self._REGtoREG_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.CSTtoREG ):
            return self._CSTtoREG_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.MEMtoREG ):
            return self._MEMtoREG_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.REGtoMEM ):
            return self._REGtoMEM_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.CSTtoMEM ):
            return self._CSTtoMEM_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.EXPRtoREG ):
            return self._EXPRtoREG_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.MEMEXPRtoREG ):
            return self._MEMEXPRtoREG_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.MEMEXPRtoMEM ):
            return self._MEMEXPRtoMEM_basic_strategy(arg1, arg2, constraint, n=n)
        elif( gtype == GadgetType.EXPRtoMEM ):
            return self._EXPRtoMEM_basic_strategy(arg1, arg2, constraint, n=n)
        else:
            return []
            
    def _chaining_strategy(self, gtype, arg1, arg2, constraint, n=1, unusable=[], depth=DEFAULT_DEPTH):
        """
        Search for gadgets with advanced chaining methods
        Returns a list of chains ( a chain is a list of gadgets )
        """
        if( depth <= 0 ):
            return []
        res = []  
        if( gtype == GadgetType.REGtoREG ): 
            res += self._REGtoREG_transitivity(arg1, arg2, constraint, n=n)
            res += self._REGtoREG_adjust_jmp_reg(arg1, arg2, constraint, n=n, unusable=unusable, depth=depth)
            return res
        elif( gtype == GadgetType.CSTtoREG ):
            res += self._CSTtoREG_pop_from_stack(arg1, arg2, constraint, n=n,unusable=unusable)
            return res
        else:
            return []
        
        
    def _REGtoREG_transitivity(self, reg, reg2, constraint, n=1):
        """
        Searches for a chain that puts reg2 in reg
        """
        # Direct search with the SearchHelper
        return SearchHelper.found_REGtoREG_reg_transitivity(reg, reg2, constraint, n=n)
   
    def _REGtoREG_adjust_jmp_reg(self, reg, reg2, constraint, n=1, unusable=[], depth=DEFAULT_DEPTH):
        """
        Searches for chains matching gadgets finishing by jmp or call 
        And adjusts them by handling the call/jmp
        """
        if( depth <= 0 ):
            return []
            
        res = []
        # Find not chainable gadgets 
        constraint_not_chainable = constraint.remove_all(ConstraintType.CHAINABLE_RET)
        # For all possible intermediate registers that come
        #     from jmpReg gadgets 
        for inter_reg in range(0,Analysis.ssaRegCount):
            if( inter_reg in unusable or inter_reg == reg or inter_reg == reg2 ):
                continue
            # Get gadgets that terminate by jmp reg
            # Here since _basc_strategy returns single gadgets
            # as padded ROP chains we take only g[0] which is
            # the number of the gadget, first in the ROP chain           
            possible_gadgets = [g[0] for g in  self._REGtoREG_basic_strategy( reg, inter_reg, constraint_not_chainable, n=n-len(res)) if Database.gadgetDB[g[0]].hasJmpReg()[0] ]
            # Then try to adjust them 
            for g in possible_gadgets:
                padded_g = SearchHelper.pad_gadgets([g], constraint_not_chainable)[0]
                jmp_to_reg = Database.gadgetDB[g].hasJmpReg()[1]
                # COMPUTE PRE CONSTRAINT 
                # Get a corresponding ret gadget 
                adjusting_jmp_reg = self._adjust_jmp_reg(jmp_to_reg, constraint)
                if( not adjusting_jmp_reg ):
                    continue
                else:
                    # Get the rest of the chain
                    previous_chains = self._chaining_strategy( GadgetType.REGtoREG, inter_reg, reg2, constraint, n=n, unusable=unusable+[reg], depth=depth-1)
                    for c in previous_chains:
                        res.append(c+adjusting_jmp_reg[0]+padded_g)
                        if( len(res) >= n ):
                            return res
        
        # For all normal ret gadgets, try jmReg gadgets
        for inter_reg in SearchHelper.possible_REGtoREG_reg_transitivity(reg):
            if( inter_reg in unusable or inter_reg == reg or inter_reg == reg2 ):
                continue
            # Get inter_reg <- reg2
            last_chains = SearchHelper.found_REGtoREG_reg_transitivity(reg, inter_reg, constraint, n=n-len(res))
            possible_gadgets = [g[0] for g in  self._REGtoREG_basic_strategy( inter_reg, reg2, constraint_not_chainable, n=n-len(res))if Database.gadgetDB[g[0]].hasJmpReg()[0]]
            # Then try to adjust them 
            for g in possible_gadgets:
                padded_g = SearchHelper.pad_gadgets([g], constraint_not_chainable)[0]
                jmp_to_reg = Database.gadgetDB[g].hasJmpReg()[1]
                # COMPUTE PRE CONSTRAINT 
                # Get a corresponding ret gadget 
                adjusting_jmp_reg = self._adjust_jmp_reg(jmp_to_reg, constraint)
                if( not adjusting_jmp_reg ):
                    continue
                else:                   
                    for c in last_chains:
                        res.append( adjusting_jmp_reg[0] + padded_g + c )
                        if( len(res) >= n ):
                            return res
        
        # TODO for all 'normal ret' gadgets, recursive call
        # with unusable options and constraints about what can be modified or not ;-) 
        return res
        
    
    def _adjust_jmp_reg(self, reg, constraint, n=1):
        """
        Finds chains that puts in 'reg' the address of a ret gadget
        """
        ret_adjust_gadgets = [c[0] for c in self._RET_offset(0, constraint, n=100) if len(c) == 1]
        if( not ret_adjust_gadgets ):
            return []
        res = []
        for g in ret_adjust_gadgets:
            addr = Database.gadgetDB[g].addr
            res += self.find(GadgetType.CSTtoREG, reg, addr, constraint, n=n-len(res))
            # Update the addr_to_gadgetStr dict in SearchHelper
            # This is used to have a better printing of the chains
            # Instead of indicating the constant as (Custom Padding)
            # we will write 'address of gadget ....'
            SearchHelper.addr_to_gadgetStr[addr]=Database.gadgetDB[g].asmStr
            if( len(res) >= n ):
                return res
        return res
             
        
    def _CSTtoREG_basic_strategy(self, reg, cst, constraint, n=1):
        """
        Searches for a gadget that puts directly the constant cst into register reg 
        """
        db = Database.gadgetLookUp[GadgetType.CSTtoREG]
        if( not cst in db[reg] ):
            return []
        res = []
        for gadget_num in db[reg][cst]:
            if( len(res) >= n ):
                break
            elif( constraint.validate(Database.gadgetDB[gadget_num])):
                res.append(gadget_num)
        return SearchHelper.pad_gadgets(res[:n], constraint)
        
    
    def _CSTtoREG_pop_from_stack(self, reg, cst, constraint, n=1, unusable=[]):
        """
        Returns a payload that puts cst into register reg by poping it from the stack
        unusable: list of reg UID that can not be used in the chaining strategy 
        """ 
        # Direct pop from the stack 
        res = SearchHelper.found_CSTtoREG_pop_from_stack(reg, cst, constraint, n=n)        
        # Pop in another register and use register transitivity
        if( len(res) <= n ):
            for other_reg in SearchHelper.possible_REGtoREG_reg_transitivity(reg):
                if( other_reg != reg and not other_reg in unusable):
                    # Get other s.t reg <- other_reg 
                    reg_to_reg_chains = SearchHelper.found_REGtoREG_reg_transitivity(reg, other_reg, constraint, n=n)
                    # If we have reg <- other_reg 
                    # We try to pop the constant in other_reg
                    if( reg_to_reg_chains ):
                        other_reg_CSTtoREG = self._CSTtoREG_basic_strategy(other_reg, cst, constraint, n=n)
                        if( len(other_reg_CSTtoREG) < n ):
                            # TODO,  HERE SHOULD ADD SOME CONSTRAINT 
                            other_reg_CSTtoREG += self._CSTtoREG_pop_from_stack(other_reg, cst, constraint, n=n, unusable=unusable+[reg])
                        # Merge: 
                        # First cst to other_reg 
                        # then other_reg in reg
                        for other_pop in other_reg_CSTtoREG:
                            for reg_to_reg in reg_to_reg_chains:
                                res.append( other_pop + reg_to_reg )
                                if( len(res) >= n ):
                                    return res
        return res
        
    
    
    def _REGtoREG_basic_strategy(self, reg1, reg2, constraint, n=1):
        """
        Searches for a gadget that puts reg2 into reg1
        reg1, reg2 - int 
        """
        db = Database.gadgetLookUp[GadgetType.REGtoREG]
        if( not reg2 in db[reg1]):
            return []
        res = []
        for gadget_num in db[reg1][reg2]:
            if( len(res) >= n ):
                break
            elif( constraint.validate(Database.gadgetDB[gadget_num])):
                res.append(gadget_num)
        return SearchHelper.pad_gadgets(res[:n], constraint)
            
        
    def _MEMtoREG_basic_strategy(self, reg, addr, constraint, n=1):
        """
        Searches for a gadget that puts mem(addr) into reg
        reg - int, number of the register to affect
        addr - int, number of the register used as an address 
        """
        db = Database.gadgetLookUp[GadgetType.MEMtoREG]
        if( not addr in db[reg] ):
            return []
        res = []
        for gadget_num in db[reg][addr]:
            if( len(res) >= n ):
                break
            elif( constraint.validate(Database.gadgetDB[gadget_num])):
                res.append( gadget_num )
        return SearchHelper.pad_gadgets(res[:n], constraint)
    
    def _EXPRtoREG_basic_strategy(self, reg, expr, constraint, n=1):
        """
        Searches for gadgets that put the expression 'expr' into register reg 
        expr - Expr
        reg - int
        """
        db = Database.gadgetLookUp[GadgetType.EXPRtoREG]
        if( not reg in db ):
            return []
        return SearchHelper.pad_gadgets(db[reg].lookUpEXPRtoREG(expr, constraint, n), constraint)
        
    def _MEMEXPRtoREG_basic_strategy(self, reg, addr, constraint, n=1):
        """
        Searches for gadgets that put the expression mem(addr) into register reg
        addr - Expr
        reg - int
        
        """
        db = Database.gadgetLookUp[GadgetType.MEMEXPRtoREG]
        if( not reg in db ):
            return []
        # Search for addr directly, because we store only reg<-addr instead of reg<-mem(addr)
        return SearchHelper.pad_gadgets(db[reg].lookUpEXPRtoREG(addr, constraint, n), constraint)
        
        
    def _CSTtoMEM_basic_strategy(self, addr_expr, cst, constraint, n=1):
        """
        Searches for gadgets that write the constant cst att mem(addr_expr)
        addr_expr - Expr
        cst - int 
        """
        return SearchHelper.pad_gadgets( Database.gadgetLookUp[GadgetType.CSTtoMEM].lookUpCSTtoMEM(addr_expr, cst, constraint, n), constraint)

    def _REGtoMEM_basic_strategy(self, addr_expr, reg, constraint, n=1):
        """
        Searches for gadgets that write reg in the memory at address addr_expr
        addr_expr - Expr
        reg - int, number of the register 
        """
        return SearchHelper.pad_gadgets( Database.gadgetLookUp[GadgetType.REGtoMEM].lookUpREGtoMEM(addr_expr, reg, constraint, n), constraint)

    def _MEMEXPRtoMEM_basic_strategy(self, addr, expr, constraint, n=1):
        """
        Searches for gadgets that write mem(expr) at mem(addr)
        addr - Expr
        expr - Expr 
        """
        return SearchHelper.pad_gadgets(Database.gadgetLookUp[GadgetType.MEMEXPRtoMEM].lookUpEXPRtoMEM(addr, expr, constraint, n), constraint)
        
    def _EXPRtoMEM_basic_strategy(self, addr, expr, constraint, n=1):
        """
        Searches for gadgets that write expr at mem(addr)
        addr - Expr
        expr - Expr 
        """
        return SearchHelper.pad_gadgets(Database.gadgetLookUp[GadgetType.EXPRtoMEM].lookUpEXPRtoMEM(addr, expr, constraint, n), constraint)


    def _RET_offset(self, offset, constraint, n=1):
        """
        Searches for gadgets that do ip <- mem(sp + offset) 
        """
        ip_num = Analysis.regNamesTable[Analysis.ArchInfo.ip]
        return SearchHelper.found_REG_pop_from_stack(ip_num, offset, constraint, n=n)
        

# The module-wide search engine 
search = search_engine()




###########################
# COMMAND TO FIND GADGETS #
###########################
    
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
        chains = search.find(gtype, left, right, constraint, n=LIMIT)
        # Display results 
        if( chains ):
            print("\n\tBuilt matching ROP Chain(s):\n")
            show_chains(chains)
        else:
            possible_gadgets = search.find(gtype, left, right, constraint, n=LIMIT, chainable=False)
            if( possible_gadgets ):
                print("\n\tFound possibly matching Gadget(s):\n")
                show_chains(possible_gadgets)
            else:
                print("\n\tNo matching Gadgets or ROP Chains found")
                
               
def show_gadgets(gadget_list):
    """
    Pretty prints a list of gadgets 
    Parameters:
        gadget_list - list of gadget UID 
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
            print("\t-------------------")
            for gadget_num in chain:
                if( SearchHelper.is_padding(gadget_num)):
                    padding_str = '0x'+format(SearchHelper.get_padding_unit(gadget_num), '0'+str(Analysis.ArchInfo.bits/4)+'x')
                    if( gadget_num == SearchHelper.DEFAULT_PADDING_UNIT_INDEX ):
                        padding_str += " (Padding)"
                    elif( SearchHelper.get_padding_unit(gadget_num) in SearchHelper.addr_to_gadgetStr ):
                        padding_str += " (@ddress of: "+SearchHelper.addr_to_gadgetStr[SearchHelper.get_padding_unit(gadget_num)]+")"
                    else:
                        padding_str += " (Custom Padding)"
                    print("\t"+padding_str)
                else:
                    print("\t"+Database.gadgetDB[gadget_num].addrStr + " (" + Database.gadgetDB[gadget_num].asmStr + ")")
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
    i = 0 # Argument counter 
    constraint = Constraint()
    while( i < len(args)):
        arg = args[i]
        # Look for options
        if( arg[0] == '-' ):
            if( seenExpr ):
                return (False, "Error. Options must come before the search request")       
            # bad bytes option 
            if( arg == OPTION_BAD_BYTES):
                if( seenBadBytes ):
                    return (False, "Error. '" + OPTION_BAD_BYTES + "' option should be used only once.")
                seenBadBytes = True
                (success, bad_bytes_list) = parse_bad_bytes(args[i+1])
                if( not success ):
                    return (False, bad_bytes_list)
                i = i+1
                constraint = constraint.add( ConstraintType.BAD_BYTES, bad_bytes_list)
            # Otherwise Ignore
            else:
                return (False, "Error. Option '{}' not supported".format(arg))
        # If not option it should be a request expr=expr
        else:    
            if( seenExpr ):
                return (False, "Error. Extra expressions not supported (" + arg + "). Only one at a time please")
            else:
                seenExpr = True
                parsed_expr = parse_user_request(arg)
                if( not parsed_expr[0]):    
                    # Maybe the user added millions of spaces, BAD but we try to correct his request syntaxe :/ 
                    parsed_expr = parse_user_request(''.join(args[i:]))
                    i = len(args)
                if( parsed_expr[0] == False ):
                    return (False, parsed_expr[1])
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
        if REGtoREG, x and y are register uid for ROPG IR
        if CSTtoREG, x is register uid for ROPG IR and y is an (int)
        if MEMtoREG, x and y are register UID
        if EXPRtoREG, x is register UID and y is (Expr)
        if CSTtoMEM, x is (Expr)(the memory address) and y is (int)
        if REGtoMEM, x is (Expr) and y is register UID
        if MEMEXPRtoMEM, x is (Expr) and y is (Expr) the address of the memory that has
                        been stored. (e.g mem(a) <- mem(b), then x = a and y = b )
    Or if not supported or invalid arguments, returns a tuple (False, msg)
    """

    args = req.split('=')
    if( len(args) != 2):
        return (False, "Invalid request: " + req )
    left = args[0]
    right = args[1]
    # Test if it is XXXtoREG
    if( left in Analysis.regNamesTable):
        # Test if it is REGtoREG
        (success, right_expr) = Expr.parseStrToExpr(right, Analysis.regNamesTable)
        if( not success ):
            return (False, "Error. Operand '"+right+"' is incorrect")
        right_expr = right_expr.simplify()
        if( isinstance(right_expr, Expr.SSAExpr)):
            return (True, GadgetType.REGtoREG, Analysis.regNamesTable[left], right_expr.reg.num)
        # Test if it is MEMtoREG
        elif( isinstance(right_expr, Expr.MEMExpr)):
            splited = right[4:].split(')',1)
            if( len(splited) == 1 or  splited[1] != '' ):
                return ( False, "Error. Operand '"+right+"' is incorrect")
            addr = right_expr.addr
            if( isinstance(addr, Expr.SSAExpr)):
                return (True, GadgetType.MEMtoREG, Analysis.regNamesTable[left], addr.reg.num)
            else:
                return (True, GadgetType.MEMEXPRtoREG, Analysis.regNamesTable[left], right_expr.addr)
            
        # Test if CSTtoREG
        elif( isinstance(right_expr, Expr.ConstExpr)):
            return ( True, GadgetType.CSTtoREG, Analysis.regNamesTable[left], right_expr.value )
        # Else it is EXPRtoREG
        else:
            return (True, GadgetType.EXPRtoREG, right_expr, Analysis.regNamesTable[left])

    
    elif( left[:4] == 'mem(' ):
        (success,addr) = Expr.parseStrToExpr(left[4:-1], Analysis.regNamesTable)
        if( not success ):
            return (False, "Error. {}".format(addr))
        addr = addr.simplify()
        (success, right_expr) = Expr.parseStrToExpr(right, Analysis.regNamesTable)
        if( not success ):
            return (False, "Error. {}".format(right_expr))
        right_expr = right_expr.simplify()
        # Test if REGtoMEM
        if( isinstance(right_expr, Expr.SSAExpr)):
            return (True, GadgetType.REGtoMEM, addr, right_expr.reg.num)        
        # Test if it is CSTtoMEM
        elif( isinstance( right_expr, Expr.ConstExpr)):
            return (True, GadgetType.CSTtoMEM, addr, right_expr.value )
        # Test if it is MEMEXPRtoMEM
        elif( isinstance( right_expr, Expr.MEMExpr)):
            return (True, GadgetType.MEMEXPRtoMEM, addr, right_expr.addr )
        # Test if it is EXPRtoMEM
        elif( isinstance( right_expr, Expr.Expr )):
            return (True, GadgetType.EXPRtoMEM, addr, right_expr )
        # Otherwise, wrong argument 
        else:
            return (False, "Formula '" +req+"' is invalid or not yet supported by ROPGenerator :(")
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
