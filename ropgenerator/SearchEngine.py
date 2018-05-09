# ROPGenerator - Gadget_finder module 
# Searching for gadgets and chaining them :) !! 

import ropgenerator.Expr as Expr
import ropgenerator.Database as Database
import ropgenerator.Analysis as Analysis
import re
from ropgenerator.Gadget import GadgetType
import ropgenerator.Config as Config
import ropgenerator.SearchHelper as SearchHelper
import ropgenerator.BinaryScanner as BinaryScanner
from ropgenerator.Constraints import Constraint, ConstraintType, Assertion, AssertionType
from ropgenerator.Colors import info, string_special, BOLD_COLOR_ANSI, END_COLOR_ANSI, string_bold, string_payload
from struct import unpack
import itertools

# Definition of options names
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
CMD_FIND_HELP = string_bold("\n\t---------------------------------------------------------")
CMD_FIND_HELP += string_bold("\n\tROPGenerator 'find' command\n\t")
CMD_FIND_HELP += string_special("(Find gadgets/ropchains that execute specific operations)")
CMD_FIND_HELP += string_bold("\n\t---------------------------------------------------------")
CMD_FIND_HELP += "\n\n\t"+string_bold("Usage")+":\tfind [OPTIONS] <reg>=<expr>\n\t\tfind [OPTIONS] <reg>=mem(<expr>)\n\t\tfind [OPTIONS] mem(<expr>)=<expr>"+\
"\n\t\tfind [OPTIONS] int80"+\
"\n\t\tfind [OPTIONS] syscall"
CMD_FIND_HELP += "\n\n\t"+string_bold("Options")+":"
CMD_FIND_HELP += "\n\t\t"+string_special(OPTION_BAD_BYTES_SHORT)+","+string_special(OPTION_BAD_BYTES)+":\tbad bytes for payload.\n\t\t\t\tExpected format is a list of bytes \n\t\t\t\tseparated by comas (e.g '-b 0A,0B,2F')"
CMD_FIND_HELP += "\n\n\t\t"+string_special(OPTION_KEEP_REGS_SHORT)+","+string_special(OPTION_KEEP_REGS)+":\tregisters that shouldn't be modified.\n\t\t\t\tExpected format is a list of registers \n\t\t\t\tseparated by comas (e.g '-k edi,eax')"
CMD_FIND_HELP += "\n\n\t\t"+string_special(OPTION_OUTPUT_SHORT)+","+string_special(OPTION_OUTPUT)+": output format for ropchains.\n\t\t\t\tExpected format is one of the following\n\t\t\t\t"+string_special(OUTPUT_CONSOLE)+','+string_special(OUTPUT_PYTHON)
CMD_FIND_HELP += "\n\n\t"+string_bold("Examples")+":\n\t\tfind rax=rbp\n\t\tfind rbx=0xff\n\t\tfind rax=mem(rsp)\n\t\tfind mem(rsp-8)=rcx\n\t\tfind "+OPTION_KEEP_REGS+ " rdx,rsp mem(rbp-0x10)=0b101\n\t\tfind "+ OPTION_BAD_BYTES+" 0A,0D "+ OPTION_OUTPUT + ' ' + OUTPUT_PYTHON + "  rax=rcx+4" 

def print_help():
    print(CMD_FIND_HELP)

##############################
# SEARCH ENGINE FOR GADGETS #
############################

DEFAULT_DEPTH = 3
class search_engine:
    global DEFAULT_DEPTH

    def __init__(self):
        self.truc = None
 
    def find(self, gtype, arg1, arg2, constraint, n=1, basic=True, chainable=True, unusable=[], init=True, conditionnal=False):
        """
        Searches for gadgets 
        basic = False means that we don't call _basic_strategy
        chainable = True means that we want only chainable gadgets 
        init = True means the search just started and we have to do some initialization in SearchHelper
        """
        if( init ):
            SearchHelper.init_impossible()
        res = []        
        # (1) First check if conditionnal gadgets requested
        if( conditionnal ):
            return [[g] for (g,cond) in Database.gadgetLookUp.find(gtype, arg1, arg2, constraint, n, conditionnal=True)]
        
        # (2) Then not chainable simple gadgets 
        if( not chainable ):
            return self._basic_strategy(gtype, arg1, arg2, constraint.remove_all(ConstraintType.CHAINABLE_RET), n=n)
        
        # (3) Then normal rop chain search
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
        # Check for special gadgets
        if( gtype == GadgetType.INT80 ):
            return self.int80(constraint, n)
        elif( gtype == GadgetType.SYSCALL ):
            return self.syscall(constraint,n)
        
        # Regular gadgets 
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
            res += self._REGtoREG_adjust_jmp_reg(arg1, arg2[0], constraint, n=n-len(res))
            # reg <- reg2 is not possible 
            if( len(res) == 0 ):
                SearchHelper.add_impossible_REGtoREG(arg1, arg2[0])
        elif( gtype == GadgetType.CSTtoREG ):
            res += self._CSTtoREG_pop_from_stack(arg1, arg2, constraint, n=n)
            res += self._CSTtoREG_zero_inc(arg1, arg2, constraint, n=n-len(res))
            res += self._CSTtoREG_transitivity(arg1, arg2, constraint, n=n-len(res), unusable=unusable)
        elif( gtype == GadgetType.STRPTRtoREG ):
            res += self._STRPTRtoREG_on_stack(arg1, arg2, constraint=constraint, n=n)
            res += self._STRPTRtoREG_static_memory(arg1, arg2, constraint=constraint, n=n-len(res))
        return res
        
        
    def _REGtoREG_transitivity(self, reg, reg2, constraint, unusable=[], n=1):
        """
        Searches for a chain that puts reg2 in reg
        reg, reg2 - (int)
        """
        if( len(unusable) > DEFAULT_DEPTH or n < 1):
            return []
            
        res = []
        for inter_reg in SearchHelper.possible_REGtoREG_transitivity(reg):
            if( (inter_reg != reg) and (inter_reg != reg2) and (not inter_reg in unusable)):
                base_chains = self.find(GadgetType.REGEXPRtoREG, reg, [inter_reg,0], \
                constraint=constraint, unusable=unusable+[reg2],n=n, init=False)
                for inter_chain in self.find( GadgetType.REGEXPRtoREG, inter_reg, \
                [reg2, 0], constraint, unusable=unusable+[reg], n=n, init=False):
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
        if (n < 1 ):
            return []
        
        ACCEPTABLE_SPINC = -4 *Analysis.ArchInfo.bits/8 # We accept to correct gadgets with spinc down to this value  
        res = []
        # Find possible not chainable gadgets 
        constraint_not_chainable = constraint.remove_all(ConstraintType.CHAINABLE_RET)
        possible_gadgets = [g[0] for g in self._basic_strategy(GadgetType.REGEXPRtoREG, reg, [reg2,0], \
            constraint_not_chainable, n=1000) if ((Database.gadgetDB[g[0]].hasJmpReg()[0] \
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
        if (n < 1 ):
            return []
        
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
            SearchHelper.addr_to_gadgetStr[addr]='@ddress of: '+string_bold(Database.gadgetDB[g].asmStr)
            if( len(res) >= n ):
                return res
        return res
    
    def _RET_offset(self, offset, constraint, n=1):
        """
        Searches for gadgets that do ip <- mem(sp + offset) 
        """
        if (n < 1 ):
            return []
        
        ip_num = Analysis.regNamesTable[Analysis.ArchInfo.ip]
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp]
        res = self._basic_strategy(GadgetType.MEMEXPRtoREG, ip_num, [sp_num,offset], constraint=constraint, n=n, no_padding=True)
        return res
    
    def _CSTtoREG_pop_from_stack(self, reg, cst, constraint, n=1):
        """
        Returns a payload that puts cst into register reg by poping it from the stack
        """ 
        if (n < 1 ):
            return []
        
        res = []
        # Direct pop from the stack
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp] 
        for offset in sorted([off for off in Database.gadgetLookUp.types[GadgetType.MEMEXPRtoREG][reg].expr[sp_num].keys()\
        if off >= 0 ]):
            possible_gadgets = [g for g in Database.gadgetLookUp.types[GadgetType.MEMEXPRtoREG][reg].expr[sp_num][offset]\
            if Database.gadgetDB[g].isValidSpInc() \
                and Database.gadgetDB[g].spInc >= Analysis.ArchInfo.bits/8 \
                and Database.gadgetDB[g].hasNormalRet()\
                and Database.gadgetDB[g].spInc - Analysis.ArchInfo.bits/8 > offset ]
            for chain in SearchHelper.pad_CSTtoREG_pop_from_stack(possible_gadgets, offset, cst, constraint=constraint):
                # At this point 'gadget' does reg <- mem(sp+offset)
                res.append(chain)
                if( len(res) >= n ):
                    return res
        return res
        
    def _CSTtoREG_zero_inc(self, reg, cst, constraint, n=1):
        """
        Returns a ropchain that xor reg then increments it to cst
        """
        MIN_CST=1
        MAX_CST=300
        if( cst < MIN_CST or cst > MAX_CST ):
            return []
        # Put the register at zero
        reg_zero_chains = self.find(GadgetType.CSTtoREG, reg, 0, constraint)
        if( not reg_zero_chains ):
            return []
        else:
            reg_zero = reg_zero_chains[0]
        # Finding increment gadgets
        possible_inc = SearchHelper.possible_REGINCtoREG(reg, \
                                    reg,constraint, mini=MIN_CST, maxi=MAX_CST)
        # Checking for the constraint
        if( not possible_inc ):
            return []
        # Find the best combination
        inc_gadgets = combine_increments(possible_inc, cst)
        if( not inc_gadgets ):
            return []
        # Pad the gadgets 
        inc_chain = list(itertools.chain.from_iterable(SearchHelper.pad_gadgets(inc_gadgets, constraint)))
        # Concatenate the reg <- 0 then inc reg chain
        res = [reg_zero+inc_chain]
        return res
    
    def _CSTtoREG_transitivity(self, reg, cst, constraint, n=1, unusable=[]):
        """
        Returns a ropchain that puts cst into register reg by poping it into another register
            then using register transitivity  
        unusable: list of reg UID that can not be used in the chaining strategy 
        """ 
        if (n < 1 ):
            return []
        
        res = []
        for inter in SearchHelper.possible_REGtoREG_transitivity(reg):
            if( inter == reg or inter in unusable):
                continue
            pop_chains = self.find(GadgetType.CSTtoREG, inter, cst, constraint, n=n, unusable=unusable+[reg])
            #pop_chains = self._CSTtoREG_pop_from_stack(inter, cst, constraint, n)
            transitivity_chains = self.find(GadgetType.REGEXPRtoREG, reg, [inter,0], constraint, n)
            for pop in pop_chains:
                for trans in transitivity_chains:
                    res.append(pop+trans)
                    if( len(res) >= n ):
                        return res
        return res
        
    
        
        
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
        if (n < 1 ):
            return []
            
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp]
        # Can't adjust the stack pointer with the stack pointer... :/  
        if( reg == sp_num ):
            return []
        # Adjusting length 
        string_len = len(string)+1 # We need to add a \x00 in the end
        if( string_len % 4 == 0 ):
            string_bytes_needed = string_len
        else:
            string_bytes_needed = string_len + (4 - (string_len%4))
        
        # Get the posible offsets 
        possible_offsets = [off for off in Database.gadgetLookUp.types[GadgetType.REGEXPRtoREG][reg].expr[sp_num].keys() if off>=0]
        #print("DEBUG, possible offsets:")
        #print(possible_offsets)
        res = []
        for offset in possible_offsets:
            res += self.find(GadgetType.REGEXPRtoREG, reg, (sp_num, offset), constraint=constraint, n=1000)
        return res
    
    def str_to_mem(self, addr, addr_string, string, constraint, hex_info=False):
        """
        Write a string in memory 
        hex_info = True <=> We print the string in hex 
        """
        def _strcpy_strategy(string, constraint, custom_stack, stack_str):
            """
            STRCPY STRATEGY
            Returns a single ropchain 
            """
            (function_addr, function_name ) = BinaryScanner.find_function('strcpy')
            if( not function_addr ):
                info('Could not find strcpy function')
                return []
            function_padding = SearchHelper.set_padding_unit(value=function_addr, msg=string_payload(function_name))
            
            # We decompose the string in substrings to be copied
            substrings_addr = BinaryScanner.find_bytes(string, add_null=True)
            if( not substrings_addr ):
                return []
                
            # Get address of a pop-pop-ret gadget 
            ppr_addrs = self._RET_offset(2*Analysis.ArchInfo.bits/8, constraint, n=1)
            if( not ppr_addrs ):
                return []
            ppr_addr = Database.gadgetDB[ppr_addrs[0][0]].addr # Get the first gadget then its address
            ppr_asmStr =  Database.gadgetDB[ppr_addrs[0][0]].asmStr
            ppr_padding = SearchHelper.set_padding_unit(value=ppr_addr, msg=string_bold(ppr_asmStr))
            
            # Chain to build the string loader ! 
            res = []
            stack_offset = 0
            for (substring_addr,substring_str) in substrings_addr:
                # Get padding for the memory where to copy
                stack_padding = SearchHelper.set_padding_unit(value=custom_stack, msg='@ddress of: ' +string_bold(stack_str+' + ' + str(stack_offset)))
                # Get padding for the bytes we will copy
                substring_padding = SearchHelper.set_padding_unit(value=substring_addr)
                if( hex_info ):
                    substring_info = '\\x'+'\\x'.join(["%02x"%ord(c) for c in substring_str])
                else:
                    substring_info = substring_str
                SearchHelper.addr_to_gadgetStr[substring_addr] = "@ddress of: " +string_bold(string_payload("'"+substring_info+"'"))
                # Add it to chain 
                res += [function_padding, ppr_padding, stack_padding, substring_padding]
                
                # Adjust
                custom_stack = custom_stack + len(substring_str)
                stack_offset = stack_offset + len(substring_str)

            return res
        
        def _memcpy_strategy(string, constraint, custom_stack, stack_str):
            """
            MEMCPY STRATEGY
            Returns a single chain
            """
            (function_addr, function_name ) = BinaryScanner.find_function('memcpy')
            if( not function_addr ):
                info('Could not find memcpy function')
                return []
            function_padding = SearchHelper.set_padding_unit(value=function_addr, msg=string_payload(function_name))
            
            # We decompose the string in substrings to be copied
            substrings_addr = BinaryScanner.find_bytes(string, add_null=False)
            if( not substrings_addr ):
                return []
        
        
            # Get address of a pop-pop-pop-ret gadget 
            pppr_addrs = self._RET_offset(3*Analysis.ArchInfo.bits/8, constraint, n=1)
            if( not pppr_addrs ):
                return []
            pppr_addr = Database.gadgetDB[pppr_addrs[0][0]].addr # Get the first gadget then its address
            pppr_asmStr =  Database.gadgetDB[pppr_addrs[0][0]].asmStr
            pppr_padding = SearchHelper.set_padding_unit(value=pppr_addr, msg=string_bold(pppr_asmStr))
            
            # Chain to build the string loader ! 
            res = []
            stack_offset = 0
            for (substring_addr,substring_str) in substrings_addr:
                # Get padding for the memory where to copy
                stack_padding = SearchHelper.set_padding_unit(value=custom_stack, msg='@ddress of: ' +string_bold(stack_str+' + ' + str(stack_offset)))
                # Get padding for the bytes we will copy
                substring_padding = SearchHelper.set_padding_unit(value=substring_addr)
                SearchHelper.addr_to_gadgetStr[substring_addr] = "@ddress of: " +string_bold(string_payload("'"+substring_str+"'"))
                # Get padding for the number of bytes to copy 
                size_padding = SearchHelper.set_padding_unit(value=len(substring_str))
                # Add it to chain 
                res += [function_padding, pppr_padding, stack_padding, substring_padding, size_padding]
                
                # Adjust
                custom_stack = custom_stack + len(substring_str)
                stack_offset = stack_offset + len(substring_str)
                
            return res
            
        def _store_reg_strategy(string, constraint, custom_stack, stack_str):
            """
            mov [REG],REG strategy 
            """
            
            # First find 3 chains such that:
            # 1) REG1 <- constant
            # 2) REG2 <- address
            # 3) mov [REG2], REG1
            nb_bytes = Analysis.ArchInfo.bits/8
            db = Database.gadgetLookUp
            sp_num = Analysis.n2r(Analysis.ArchInfo.sp)
            ip_num = Analysis.n2r(Analysis.ArchInfo.ip)
            # Trick to avoid error of formatting
            if( type(string) == type(u'')):
                substring = "%r"%string
                substring = substring[2:-1]
            else:
                substring = string
            # Get endianness and size 
            if( Analysis.ArchInfo.bits == 32 ):
                endianness_fmt = '<I'
            elif( Analysis.ArchInfo.bits == 64 ):
                endianness_fmt = '<Q'
            padding_char = chr(SearchHelper.get_valid_padding_byte(constraint))
            # Try to find mem[REG2+CST2] <- REG1+CST1
            for reg2 in db.types[GadgetType.REGEXPRtoMEM].addr.keys():
                if( reg2 == sp_num or reg2 == ip_num ):
                    # Can not use sp or ip for that 
                    continue
                assertion = Assertion().add(AssertionType.REGS_NO_OVERLAP, [[sp_num, reg2]])
                for cst2 in db.types[GadgetType.REGEXPRtoMEM].addr[reg2].keys():
                    for reg1 in db.types[GadgetType.REGEXPRtoMEM].addr[reg2][cst2].expr.keys():
                        if( reg1 == sp_num or reg1 == ip_num ):
                            # Can not use sp_num or ip for that ! 
                            continue
                        for cst1 in db.types[GadgetType.REGEXPRtoMEM].addr[reg2][cst2].expr[reg1].keys():
                            #print(db.types[GadgetType.REGEXPRtoMEM].addr[reg2][cst2].expr[reg1][cst1])
                            for store_gadget in [ g for g in db.types[GadgetType.REGEXPRtoMEM].addr[reg2][cst2].expr[reg1][cst1]\
                                                    if constraint.validate(Database.gadgetDB[g],ret_assert=assertion)]:
                                # Then try to copy the string part by part
                                #print("DEBUG, gadget:" + Database.gadgetDB[store_gadget].asmStr)
                                info("Trying to write with gadget: " + Database.gadgetDB[store_gadget].asmStr)
                                res = []
                                failed = False
                                current_stack_pos = custom_stack
                                while(substring and not failed):
                                    # Get first bytes of the substring
                                    first_bytes = substring[:nb_bytes]
                                    if ( len(first_bytes) < nb_bytes ):
                                        # If end of the string too soon, we pad a bit ;)
                                        first_bytes += padding_char*(nb_bytes-len(first_bytes))
                                    #print("DEBUG, first bytes " + first_bytes )
                                    #print("DEBUG, len " + str(len(first_bytes))) 
                                    first_bytes_int = unpack(endianness_fmt, first_bytes)[0]
                                    substring = substring[nb_bytes:]
                                    # Set the values we want for our registers
                                    reg2_value = current_stack_pos - cst2
                                    reg1_value = first_bytes_int - cst1
                                    # Pop them 
                                    pop_regs = pop_multiple([[reg1,reg1_value],[reg2, reg2_value]], constraint)
                                    if( not pop_regs ):
                                        info('Could not pop correct values in registers for the store')
                                        failed = True
                                    else:
                                        res += pop_regs + SearchHelper.pad_gadgets([store_gadget],constraint,force_padding=True)[0]
                                        current_stack_pos = current_stack_pos + nb_bytes
                                if( not failed ):
                                    info("Success")
                                    return res
            return []
        
        
        # Function body 
        # Try the different strategies
        chain = _store_reg_strategy(string, constraint, addr, addr_string)
        if( not chain ):
            chain = _strcpy_strategy(string, constraint, addr, addr_string)
        if( not chain ):
            chain = _memcpy_strategy(string, constraint, addr, addr_string)
        return chain
        
        
    def _STRPTRtoREG_static_memory(self, reg, string, constraint, n=1, custom_stack=None, stack_str='Custom stack'):    
        """
        Searches for gadgets that put the address of a string "string"
        into register reg
        reg - int
        string - RAW STRING ! (NOT UNICODE!!)
        """
        ########################
        # STRPTRtoREG function #
        ########################
        
        if (n < 1 ):
            return []
        
        # Get the custom stack address (.bss by default)
        if( not custom_stack ):
            custom_stack = BinaryScanner.bss_address()
            stack_str = '.bss'
        if( not custom_stack ):
            print("[*] DEBUG, couldn't find a custom stack address :'( ")
            return []
        
        # First check if this custom stack address can be poped in the register
        stack_to_reg_chains = self.find(GadgetType.CSTtoREG, reg, custom_stack, constraint, n=1)
        if( not stack_to_reg_chains ):
            return []
        else:
            stack_to_reg_chain = stack_to_reg_chains[0]
        
        # Then put the string in memory 
        str_to_mem_chain = self.str_to_mem(custom_stack, stack_str, string, constraint)
        
        # Wrap the chain in a list because search.find() returns a list of chains ;)
        return [str_to_mem_chain+stack_to_reg_chain]
        
    def int80(self, constraint, n=1):
        return Database.gadgetLookUp.int80(constraint, n)
        
    def syscall(self, constraint, n=1):
        return Database.gadgetLookUp.syscall(constraint, n)
    
    def jmp_addr(self, addr, constraint):
        """
        returns one chain s.t ip = addr
        """
        res = []
        ip = Analysis.regNamesTable[Analysis.ArchInfo.ip]
        for inter in SearchHelper.possible_REGtoREG_transitivity(ip):
            if( inter == ip ):
                continue
            pop_chains = self._CSTtoREG_pop_from_stack(inter, addr, constraint, n=1)
            transitivity_chains = self.find(GadgetType.REGEXPRtoREG, ip, [inter,0], constraint, n=1, chainable=False)
            for pop in pop_chains:
                for trans in transitivity_chains:
                    return pop+trans
        return []

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
        print(string_bold("\n\tYou have to load gadgets before running the 'find' command"+\
            "\n\tType 'load help' for more details"))
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
            possible_gadgets = search.find(gtype, left, right, constraint, n=Config.LIMIT, chainable=False, init=True, conditionnal=True)
            possible_gadgets += search.find(gtype, left, right, constraint, n=Config.LIMIT-len(possible_gadgets), chainable=False, init=True)
            if( possible_gadgets ):
                print(string_bold("\n\tFound possibly matching Gadget(s):\n"))
                show_chains(possible_gadgets)
            else:
                print(string_bold("\n\tNo matching Gadgets or ROP Chains found"))
                
        
def show_chains( chain_list, output='raw' ):
    """
    Pretty prints a list of ROP chains 
    Parameters:
        chain_list - list of chains (a chain is a list of gadget UID and/or padding units)
        output - one of 'raw' 'python'
    """
    global OUTPUT
    if( OUTPUT == OUTPUT_CONSOLE ):
        for chain in chain_list:
            print(string_bold("\t-------------------"))
            for gadget_num in chain:
                if( SearchHelper.is_padding(gadget_num)):
                    padding_str = string_special('0x'+format(SearchHelper.get_padding_unit(gadget_num), '0'+str(Analysis.ArchInfo.bits/4)+'x'))
                    if( gadget_num == SearchHelper.DEFAULT_PADDING_UNIT_INDEX ):
                        padding_str += " (Padding)"
                    elif( SearchHelper.get_padding_unit(gadget_num) in SearchHelper.addr_to_gadgetStr ):
                        padding_str += " ("+SearchHelper.addr_to_gadgetStr[SearchHelper.get_padding_unit(gadget_num)]+")"
                    else:
                        padding_str += " (Custom Padding)"
                    print("\t"+padding_str)
                else:
                    print("\t"+string_special(Database.gadgetDB[gadget_num].addrStr) + " (" + string_bold(Database.gadgetDB[gadget_num].asmStr) + ")")
    elif( OUTPUT == OUTPUT_PYTHON ):
        # Getting endianness to pack values 
        if( Analysis.ArchInfo.bits == 32 ):
            endianness_str = '<I'
        else:
            endianness_str = '<Q'
        pack_str = "P += pack("+endianness_str+","
        for chain in chain_list:
            print(string_bold("\t-------------------"))
            print("\tfrom struct import pack")
            print("\tp = ''")
            for gadget_num in chain:
                if( SearchHelper.is_padding(gadget_num)):
                    padding_str = pack_str
                    padding_str += string_special('0x'+format(SearchHelper.get_padding_unit(gadget_num), '0'+str(Analysis.ArchInfo.bits/4)+'x'))+")"
                    if( gadget_num == SearchHelper.DEFAULT_PADDING_UNIT_INDEX ):
                        padding_str += " # Padding"
                    elif( SearchHelper.get_padding_unit(gadget_num) in SearchHelper.addr_to_gadgetStr ):
                        padding_str += " # "+SearchHelper.addr_to_gadgetStr[SearchHelper.get_padding_unit(gadget_num)]
                    else:
                        padding_str += " # Custom Padding"
                    print("\t"+padding_str)
                else:
                    print("\t"+pack_str+string_special(Database.gadgetDB[gadget_num].addrStr) + ") # " + string_bold(Database.gadgetDB[gadget_num].asmStr))
    
    elif( OUTPUT == OUTPUT_RAW ):
        print("\tRaw output not supported yet :'( ")
         
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
                return (False, string_bold("\n\tError. Options must come before the search request"))       
            # bad bytes option 
            if( arg == OPTION_BAD_BYTES or arg == OPTION_BAD_BYTES_SHORT):
                if( seenBadBytes ):
                    return (False, string_bold("\n\tError. '" + OPTION_BAD_BYTES + "' option should be used only once."))
                if( i+1 >= len(args)):
                    return (False, string_bold("\n\tError. Missing bad bytes after option '"+arg+"'"))
                seenBadBytes = True
                (success, bad_bytes_list) = parse_bad_bytes(args[i+1])
                if( not success ):
                    return (False, bad_bytes_list)
                i = i+1
                constraint = constraint.add( ConstraintType.BAD_BYTES, bad_bytes_list)
            elif( arg == OPTION_KEEP_REGS or arg == OPTION_KEEP_REGS_SHORT):
                if( seenKeepRegs ):
                    return (False, string_bold("\n\tError. '" + OPTION_KEEP_REGS + "' option should be used only once."))
                if( i+1 >= len(args)):
                    return (False, string_bold("\n\tError. Missing registers after option '"+arg+"'"))
                seenKeepRegs = True
                (success, keep_regs_list) = parse_keep_regs(args[i+1])
                if( not success ):
                    return (False, keep_regs_list)
                i = i+1
                constraint = constraint.add( ConstraintType.REGS_NOT_MODIFIED, keep_regs_list)
            elif( arg == OPTION_OUTPUT or arg == OPTION_OUTPUT_SHORT ):
                if( seenOutput ):
                    return (False, string_bold("\n\tError. '" + OPTION_OUTPUT + "' option should be used only once."))
                if( i+1 >= len(args)):
                    return (False, string_bold("\n\tError. Missing output format after option '"+arg+"'"))
                if( args[i+1] in [OUTPUT_CONSOLE, OUTPUT_PYTHON]):
                    OUTPUT = args[i+1]
                    seenOutput = True
                    i = i +1
                else:
                    return (False, string_bold("\n\tError. '" + args[i+1] + "' output format is not supported"))
                    
            # Otherwise Ignore
            else:
                return (False, string_bold("\n\tError. Unknown option: '{}' ".format(arg)))
        # If not option it should be a request expr=expr
        else:    
            if( seenExpr ):
                return (False, string_bold("\n\tError. Unexpected extra expression: '") + ' '.join(args[i:]) + "'. Only one at a time please")
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
        return (False, string_bold("\n\tError. Missing specification of gadget to find"))
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
    # Check for int80 and syscall
    if( req == 'int80' ):
        return (True, GadgetType.INT80, None, None)
    elif( req == 'syscall' ):
        return (True, GadgetType.SYSCALL, None, None)
    
    # Check for Regular query 
    args = [x for x in req.split('=',1) if x]
    if( len(args) != 2):
        # Test if request with '->'  
        args = [x for x in user_input.split('->',1) if x]
        if( len(args) != 2 ):    
            return (False, string_bold("\n\tInvalid semantic request: ") + user_input )
        else:
            left = args[0].strip()
            right = ''
            if( left not in Analysis.regNamesTable ):
                return (False, string_bold("\n\tLeft operand '{}' should be a register".format(left)))
            # Parsing right side
            i = 0
            args[1] = args[1].encode('ascii', 'replace').decode('ascii', 'ignore')
            while( i < len(args[1]) and args[1][i] in [' ', '\t'] ):
                i = i + 1
            if( i == len(args[1]) or args[1][i] != '"'):
                 return (False, string_bold('\n\tInvalid right operand: {} \n\tIt should be an ASCII string between quotes\n\tE.g: find rax -> "Example operand string"'.format(args[1])))   
            saved_args1 = args[1]
            args[1] = args[1][i+1:]
            index = args[1].find('"')
            if( index == -1 or len(args[1].split('"')[1].strip()) > 0 ):
                return (False, string_bold('\n\tInvalid right operand: {} \n\tIt should be an ASCII string between quotes\n\tE.g: find rbx -> "Example operand string"'.format(saved_args1)))
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
            return (False, string_bold("\n\tError. Operand '"+right+"' is incorrect: " + right_expr))
        right_expr = right_expr.simplify()
        if( not is_supported_expr(right_expr)):
            return (False, string_bold("\n\tError. Right expression '"+right+"' is not supported :("))
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
            return (False, string_bold("\n\tError. {}".format(addr)))
        addr = addr.simplify()
        if( not is_supported_expr(addr)):
            return (False, string_bold("\n\tError. Address '"+addr+"' is not supported :("))
            
        (success, right_expr) = Expr.parseStrToExpr(right, Analysis.regNamesTable)
        if( not success ):
            return (False, string_bold("\n\tError. {}".format(right_expr)))
        right_expr = right_expr.simplify()
        if( not is_supported_expr(right_expr)):
            return (False, string_bold("\n\tError. Right expression '"+right+"' is not supported :("))
            
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
        return ( False, string_bold("\n\tOperand '" +left+"' is invalid or not yet supported by ROPGenerator :("))
    
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
            return (False, string_bold("\n\tError. Missing bad byte after ','"))
        elif( len(user_bad_byte) != 2 ):
            return (False, string_bold("\n\tError. '{}' is not a valid byte".format(user_bad_byte)))
        elif( not ((user_bad_byte[i] in hex_chars) and (user_bad_byte[i+1] in hex_chars))):
            return (False, string_bold("\n\tError. '{}' is not a valid byte".format(user_bad_byte)))
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
            return (False, string_bold("\n\tError. '{}' is not a valid register".format(reg)))
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


#######################################
# ADDITIONAL COMPLEX SEARCH FUNCTIONS #
#######################################

def pop_multiple(args, constraint=None):
    """
    args is a list of pairs (reg, value)
    reg is a reg UID
    value is an int
    Creates a chain that pops values into regs
    """
    if( constraint is None ):
        constr = Constraint()
    else:
        constr = constraint
    perms = itertools.permutations(args)
    for perm in perms:
        res = []
        for arg in perm:
            pop = search.find(GadgetType.CSTtoREG, arg[0], arg[1], constr)
            if( not pop ):
                break
            else:
                res += pop[0]
                constr = constr.add(ConstraintType.REGS_NOT_MODIFIED, \
                        [arg[0]])
        if( pop ):
            break
    return res
    
def combine_increments(increments_list, goal):
    """
    increments_list : list of (inc,gadget)
    goal : int
    Returns the shortest list of gadgets such that the sum of their
        increments equals the goal
    """
    MIN_GOAL = 1
    MAX_GOAL = 300
    INFINITY = 999999999
    if( goal < MIN_GOAL or goal > MAX_GOAL ):
        return []
    inc_list = filter(lambda x:x[0]<=goal, increments_list)
    inc_list.sort(key=lambda x:x[0])
    n = len(inc_list)
    if( n == 0 ):
        return []
    # Initialize dyn algorithm 
    shortest = [[INFINITY]*(goal+1)]*n
    for subgoal in range(goal+1):
        if subgoal % inc_list[0][0] == 0:
            shortest[0][subgoal] = subgoal // inc_list[0][0]
    for i in range(1,n):
        for j in range(goal+1):
            shortest[i][j] = shortest[i-1][j]
            if( inc_list[i][0] <= j ):
                if( shortest[i][j-inc_list[i][0]] + 1 < shortest[i][j]):
                    shortest[i][j] = shortest[i][j-inc_list[i][0]] + 1
                    
    # Select increments and gadgets
    chosen = [0]*n
    res = []
    j = goal
    i = n -1
    while j > 0 and i >= 0:
        if( j >= inc_list[i][0] ):
            if( shortest[i][j-inc_list[i][0]] + 1 == shortest[i][j] ):
                chosen[i] = chosen[i] + 1
                res.append(inc_list[i][1])
                j = j - inc_list[i][0]
                continue
        i = i - 1
    return res
