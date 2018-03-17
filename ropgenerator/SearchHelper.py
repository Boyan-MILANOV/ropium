# ROPGenerator - SearchHelper module 
# Keeping track of gadgets to fasten the search 
# This module supports the Gadget_finder module 
# It merely stores chains of gadgets obtained by different search strategies 

import ropgenerator.Database as Database
import ropgenerator.Analysis as Analysis
import sys
from ropgenerator.Colors import info_colored
from ropgenerator.Gadget import GadgetType, RetType
from ropgenerator.Constraints import ConstraintType

#####################################
#    ROP Chains format
#
# A ROP Chain is a list of gadget UID
# A negative UID ( so that does not correspond to a gadget) indicates padding units 
# UID -x is the padding unit stored at PADDING_UNITS[x] 
#
#######################################



# Some overall variables 
DEFAULT_PADDING_BYTE = 0xFF # The default byte used for padding 
PADDING_UNITS = []  # List of the different padding units ( as integers )
MAX_PADDING = 40 # The maximum padding accepted for a gadget in an ROP chain 
MAX_CHAINS = 1000 # The maximum number of chains we store for one operation 
DEFAULT_PADDING_UNIT_INDEX = -1

addr_to_gadgetStr = dict()


def is_padding(gadget_num):
    return (int(gadget_num) < 0)
        
def get_padding_unit(uid=-1):
    global PADDING_UNITS
    return PADDING_UNITS[-1-uid]
    
def set_padding_unit(value=None):
    global DEFAULT_PADDING_BYTE
    global PADDING_UNITS
    global DEFAULT_PADDING_UNIT_INDEX

    if( PADDING_UNITS == []):
        # Set the default padding unit  
        # This should be the first element of the list since DEFAULT_PADDING_UNIT_INDEX is -1 ( element at index 0 ;) ) 
        bytes_in_unit = Analysis.ArchInfo.bits/8
        res = 0
        for i in range(0, bytes_in_unit):
            res = res*0x100 + DEFAULT_PADDING_BYTE
        PADDING_UNITS = [res]
        
    if( value == get_padding_unit(DEFAULT_PADDING_UNIT_INDEX)):
        return DEFAULT_PADDING_UNIT_INDEX       
    if( value != None ):
        PADDING_UNITS.append(value)
        return -1*len(PADDING_UNITS)
    else:
        return DEFAULT_PADDING_UNIT_INDEX

def get_valid_padding( constraint ):
    """
    Creates a padding value that satisfies the BAD_BYTES constraint(s)
    in 'constraint'
    Returns a negative int if success
    Returns None if no valid padding unit has been found 
    """
    bad_bytes_list = constraint.get(ConstraintType.BAD_BYTES)
    # Getting a valid padding byte 
    hex_chars = 'fedcba9876543210'
    found = False
    for c1 in hex_chars:
        for c2 in hex_chars:
            c = c1+c2
            if( not c in bad_bytes_list ):
                found = True
                break
        if( found ):
            break
    if( not found ):
        return None
    else:
        padding_byte = int(c, 16)
    # Calculate the new padding unit 
    bytes_in_unit = Analysis.ArchInfo.bits/8
    res = 0
    for i in range(0, bytes_in_unit):
        res = res*0x100 + padding_byte
    return res

def validate_chain(chain, constraint):
    """
    Returns true iff all gadgets in a chain verify a constraint  
    """
    for gadget_num in chain:
        if( (not is_padding(gadget_num)) and not constraint.validate(Database.gadgetDB[gadget_num]) ):
            return False
        elif( is_padding(gadget_num) and gadget_num != DEFAULT_PADDING_UNIT_INDEX ):
            # Verify that the custom padding doesn't contain bad bytes 
            # Get the corresponding string 
            padding_str = format(get_padding_unit(gadget_num), '0'+str(Analysis.ArchInfo.bits/4)+'x')
            # Check for bad bytes
            for i in range(0, len(padding_str), 2):
                if( padding_str[i:i+2] in constraint.get(ConstraintType.BAD_BYTES)):
                    return False
    return True
    
def adjust_chain(chain, new_padding):
    """
    Replaces the default padding with new_padding in a chain
    """
    global DEFAULT_PADDING_UNIT_INDEX
    return [g if g != DEFAULT_PADDING_UNIT_INDEX else new_padding for g in chain]
    
    
def filter_chains(chain_list, constraint, n):
    """
    Returns the n first chains in chain_list that satisfy the constraint
    """
    global DEFAULT_PADDING_BYTE
    # If the default padding works, keep it, only validate the gadgets
    if( not hex(DEFAULT_PADDING_BYTE)[-2:] in constraint.get(ConstraintType.BAD_BYTES)):
        return [chain for chain in chain_list if validate_chain(chain, constraint)][:n]     
    
    # Otherwise get a new padding
    new_padding_int = get_valid_padding(constraint)
    if( not new_padding_int):
        # If no possible padding, return empty list 
        return []
    else:
        new_padding = set_padding_unit(value=new_padding_int)
    # Filter the chains 
    res = []
    for chain in chain_list:
        if( validate_chain( chain, constraint )):
            res.append(adjust_chain(chain, new_padding))
        if( len(res) >= n):
            break 
    return res


def pad_gadgets(gadget_num_list, constraint):
    """
    Takes a list of gadgets and returns a list of chains
    Each chain of the result corresponds to the padded gadget
    Pre-condition: the gadgets have a valid return and a valid sp increment 
    """
    res = []
    padding_int = get_valid_padding(constraint)
    padding_unit = set_padding_unit(padding_int)
    for gadget_num in gadget_num_list:
        gadget = Database.gadgetDB[gadget_num]
        if( gadget.ret == RetType.RET ):
            nb_padding_units = (Database.gadgetDB[gadget_num].spInc - Analysis.ArchInfo.bits/8)/(Analysis.ArchInfo.bits/8)
            res.append( [gadget_num] + [padding_unit]*nb_padding_units)
        elif( gadget.ret == RetType.JMP_REG ):
            nb_padding_units = Database.gadgetDB[gadget_num].spInc/(Analysis.ArchInfo.bits/8)
            res.append( [gadget_num] + [padding_unit]*nb_padding_units)
        else:
            res.append([gadget_num])
    return sorted(res, key = lambda x:len(x)) 

#############################################
# Chains for REGtoREG transitivity strategy #
#############################################

record_REGtoREG_reg_transitivity = dict()
built_REGtoREG_reg_transitivity = False


def build_REGtoREG_reg_transitivity():
    """
    Builds chains for operation REG <- REG 
    Parameters:
        iterations - (int) Number of iterations for the transitive closure algorithm  
    """
    # Transitive closure 
    #Initialisation 
    global built_REGtoREG_reg_transitivity
    global record_REGtoREG_reg_transitivity
    global PADDING_BYTE
    global PADDING_UNIT
    global PADDING_GADGET  
    global MAX_PADDING 
    
    if( built_REGtoREG_reg_transitivity ):
        return 
    
    iterations=4
    
    # Choose a padding unit 
    padding_uid = set_padding_unit()
    
    # Initialize printing info
    info_colored("Performing additionnal analysis (chain gadgets by transitivity)\n") 
    # Transitive closure 
    # During algorithm the chains are stored as triples:
    #     ( chain, used_regs, nb_instr )
    #     where used_regs is the list of registers we already considered for the chain rY <- rX <- .... <- rZ
    #    nb_instr is the total number of instructions (in REIL) composing the gadgets of the chain 
    db = Database.gadgetLookUp[GadgetType.REGtoREG]
    for reg1 in range(0,Analysis.ssaRegCount):
        record_REGtoREG_reg_transitivity[reg1] = dict()
        for reg2 in range(0,Analysis.ssaRegCount):
            record_REGtoREG_reg_transitivity[reg1][reg2] = []
            for gadget_num in db[reg1][reg2]:
                if( Database.gadgetDB[gadget_num].isValidSpInc() and Database.gadgetDB[gadget_num].hasNormalRet()  ):
                    padding_units = (Database.gadgetDB[gadget_num].spInc - Analysis.ArchInfo.bits/8)/(Analysis.ArchInfo.bits/8)
                    if( padding_units <= MAX_PADDING ):
                        padding_chain = [padding_uid for i in range(0,padding_units)] 
                        nbInstr = Database.gadgetDB[gadget_num].nbInstr
                        add_REGtoREG_reg_transitivity(reg1, reg2, [gadget_num]+padding_chain, [reg2], nbInstr)
                        
                else:
                    pass
                
    modified = True
    while( modified and (iterations > 0)):
        modified = False
        iterations = iterations - 1
        for reg1 in range(0,Analysis.ssaRegCount):
            for reg2 in range(0,Analysis.ssaRegCount):
                for reg3 in range(0,Analysis.ssaRegCount):
                    if( reg3 != reg1 and reg1 != reg2 and reg2 != reg3 ):
                        for chain2_3 in record_REGtoREG_reg_transitivity[reg2][reg3]:
                            for chain1_2 in record_REGtoREG_reg_transitivity[reg1][reg2]:
                                # Check for path redundency and looping 
                                if( not reg1 in chain2_3[1] and not [reg for reg in chain2_3[1] if reg in chain1_2[1]]):     
                                    new_chain = chain2_3[0] + chain1_2[0]
                                    new_regs_chain = chain2_3[1] + [reg2] + chain1_2[1]
                                    new_nbInstr = chain2_3[2] + chain1_2[2]
                                    added = add_REGtoREG_reg_transitivity(reg1, reg3, new_chain, new_regs_chain, new_nbInstr)
                                    modified = modified or added
                                    
                                else:
                                    pass
                                    
                                    
                                    
    # Remove the reg paths 
    for reg1 in range(0,Analysis.ssaRegCount):
        for reg2 in range(0,Analysis.ssaRegCount):
            record_REGtoREG_reg_transitivity[reg1][reg2] = [c[0] for c in record_REGtoREG_reg_transitivity[reg1][reg2]]        
            
                                        
    built_REGtoREG_reg_transitivity = True
            


def add_REGtoREG_reg_transitivity(reg1, reg2, chain , regs_chain, nbInstr):
    """
    Adds gadgets that put reg2 into reg1 
    Addition is made in increasing order ( order is number of gadgets in the chain, and if equal then the number of instructions of the chain ) to get the best chains (shorter) first 
    
    Parameters:
        chain = ROP chain ( list of gadgets, e.g [4,365,3,4] )
        regs_chain = the list of the registers appearing in the path of chain
        nbInstr = nb of REIL instructions of chain 
        reg1, reg2 = int
    
    Returns true if added the chain, or False if the chain was already present 
    """
    # DURING SEARCH, chains or not only lists of gadgets but triples (gadget_list, list of used intermediate resigters, number of instructions) to avoid looping through the same gadgets over and over again  
    
    global record_REGtoREG_reg_transitivity
    global MAX_CHAINS
    
    if( not chain ):
        return False
    if( not reg1 in record_REGtoREG_reg_transitivity ):
        record_REGtoREG_reg_transitivity[reg1] = dict()
    if( not reg2 in record_REGtoREG_reg_transitivity[reg1] ):
        record_REGtoREG_reg_transitivity[reg1][reg2] = []
    
    # Adding the chain in sorted 
    for i in range(0, len(record_REGtoREG_reg_transitivity[reg1][reg2])):
        if( i >= MAX_CHAINS ):
            return False
        nbInstr_recorded_chain = record_REGtoREG_reg_transitivity[reg1][reg2][i][2]
        if( chain == record_REGtoREG_reg_transitivity[reg1][reg2][i][0] ):
            return False
        elif( len(chain) < len(record_REGtoREG_reg_transitivity[reg1][reg2][i][0])):
            record_REGtoREG_reg_transitivity[reg1][reg2].insert(i, (chain, regs_chain, nbInstr))
            if( len(record_REGtoREG_reg_transitivity[reg1][reg2]) >= MAX_CHAINS ):
                del record_REGtoREG_reg_transitivity[reg1][reg2][-1]
            return True
        elif( len(chain) <= len(record_REGtoREG_reg_transitivity[reg1][reg2][i][0]) and nbInstr < nbInstr_recorded_chain):
            record_REGtoREG_reg_transitivity[reg1][reg2].insert(i, (chain, regs_chain, nbInstr))
            if( len(record_REGtoREG_reg_transitivity[reg1][reg2]) >= MAX_CHAINS ):
                del record_REGtoREG_reg_transitivity[reg1][reg2][-1]
            return True
    # If longer than all, add in the end 
    if( len(record_REGtoREG_reg_transitivity[reg1][reg2]) < MAX_CHAINS ):
        record_REGtoREG_reg_transitivity[reg1][reg2].append((chain, regs_chain, nbInstr))
        return True
    else:
        return False
    
def found_REGtoREG_reg_transitivity(reg1, reg2, constraint, n=1):
    """
    Returns the n first chains found for reg1 <- reg2 
    """
    global record_REGtoREG_reg_transitivity
    global built_REGtoREG_reg_transitivity
    
    if( not built_REGtoREG_reg_transitivity ):
        build_REGtoREG_reg_transitivity()
    
    if( not reg1 in record_REGtoREG_reg_transitivity ):
        return []
    if( reg2 in record_REGtoREG_reg_transitivity[reg1] ):
        return filter_chains(record_REGtoREG_reg_transitivity[reg1][reg2], constraint, n)
    else:
        return []    
 
def possible_REGtoREG_reg_transitivity(reg):
    """
    Returns all the registers reg2 such that reg <- reg2 is possible
    I.e, record_REGtoREG_reg_transitivity[reg][reg2] exists 
    """       
    global record_REGtoREG_reg_transitivity
    if( not reg in record_REGtoREG_reg_transitivity):
        return []
    else:
        res = []
        for key in record_REGtoREG_reg_transitivity[reg].keys():
            if( len(record_REGtoREG_reg_transitivity[reg][key]) > 0 ):
                res.append(key)
        return res
        
##########################################
# Chains for REG pop from stack strategy #
##########################################

record_REG_pop_from_stack = dict()
built_REG_pop_from_stack = False

def build_REG_pop_from_stack():
    global built_REG_pop_from_stack
    global record_REG_pop_from_stack
    
    if( built_REG_pop_from_stack ):
        return 
 
    # Initialization for printing charging bar 
    chargingBarSize = Analysis.ssaRegCount
    chargingBarStr = " "*chargingBarSize
    info_colored("Performing additionnal analysis (poping registers from stack)\n")
    sys.stdout.write("\tProgression [")
    sys.stdout.write(chargingBarStr)
    sys.stdout.write("]\r\tProgression [")
    sys.stdout.flush() 
        
    # First reg <- mem(esp)
    db = Database.gadgetLookUp[GadgetType.MEMtoREG]
    sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp]
    for reg in range(0,Analysis.ssaRegCount):
        record_REG_pop_from_stack[reg] = dict()
        if( sp_num in db[reg] and db[reg][sp_num] != [] ):
            add_REG_pop_from_stack( reg, 0, [ gadget_num for gadget_num in db[reg][sp_num] if Database.gadgetDB[gadget_num].hasNormalRet() and Database.gadgetDB[gadget_num].isValidSpInc()] )
            
    # Then reg <- mem(esp+ X )
    db = Database.gadgetLookUp[GadgetType.MEMEXPRtoREG]
    for reg in range(0,Analysis.ssaRegCount):
        # Printing the charging bar 
        sys.stdout.write("|")
        sys.stdout.flush()
        for i  in range(0, len(db[reg].expr_list)):
            # For each expr so that reg <- mem(expr)
            expr = db[reg].expr_list[i]
            (isInc, inc) = expr.isRegIncrement(sp_num)
            if( isInc and inc > 0):
                # If expr is esp + X 
                add_REG_pop_from_stack(reg, inc, [ gadget_num for gadget_num in db[reg].gadget_list[i] if Database.gadgetDB[gadget_num].hasNormalRet() and Database.gadgetDB[gadget_num].isValidSpInc()])
    
    sys.stdout.write("\r"+" "*70+"\r")
    built_REG_pop_from_stack = True
                
    
def add_REG_pop_from_stack(reg, offset, gadgets_list, gadgets_sorted=False ):
    """
    Adds gadgets that put mem(esp+offset) into reg
    Addition to the record_REG_pop_from_stack[reg] list is made in 
    increasing order according to gadgets length (number of REIL instructions. 
    This is to get the best gadgets (shorter) first 
    
    Parameters:
        reg - int
        offset - int 
        gadgets_list - list of int 
        gadgets_sorted - Bool (True iff the gadgets_list parameter supplied has been sorted already )
        
    """
    global MAX_CHAINS
    global record_REG_pop_from_stack    
    
    if( not offset in record_REG_pop_from_stack[reg] ):
        if( not gadgets_sorted ):
            record_REG_pop_from_stack[reg][offset] = sorted(gadgets_list, key= lambda gadget:Database.gadgetDB[gadget].nbInstr)
        else:
            record_REG_pop_from_stack[reg][offset] = list(gadgets_list)
        return 
        
    # Preparing merge with fusion sort 
    if( not gadgets_sorted ):
        gadgets_list = sorted(gadgets_list, key=lambda gadget:Database.gadgetDB[gadget].nbInstr)
        
    # Merging  
    for i in range(0, len(record_REG_pop_from_stack[reg][offset])):
        if( i >= MAX_CHAINS or not gadgets_list ):
            return 
        if( record_REG_pop_from_stack[reg][offset][i] == gadgets_list[0] ):
            gadgets_list = gadgets_list[1:]
        elif( Database.gadgetDB[record_REG_pop_from_stack[reg][offset][i]].nbInstr > Database.gadgetDB[gadgets_list[0]].nbInstr ):
            record_REG_pop_from_stack[reg][offset].insert(i, gadgets_list[0])
            gadgets_list = gadgets_list[1:]
        else:
            i = i + 1
            
    # If some are left in gadgets_list at the end 
    remaining_len = MAX_CHAINS - len(record_REG_pop_from_stack[reg][offset])
    if( remaining_len > 0 ):
        record_REG_pop_from_stack[reg][offset] += gadgets_list[:remaining_len]
        
def found_CSTtoREG_pop_from_stack(reg, cst, constraint, n=1):
    """
    Returns the n first gadgets that do reg <- cst by poping cst from the stack 
    """
    global record_REG_pop_from_stack
    global built_REG_pop_from_stack
    
    if( not built_REG_pop_from_stack ):
        build_REG_pop_from_stack()
        
    if( not reg in record_REG_pop_from_stack ):
        return []
    
    cst_padding = set_padding_unit(value=cst)
    default_padding = set_padding_unit()
    res = []
    for offset in sorted(record_REG_pop_from_stack[reg].keys()):
        for g in record_REG_pop_from_stack[reg][offset]:
            chain = [g] + [default_padding for i in range(0, offset*8/Analysis.ArchInfo.bits)] + [cst_padding] + [default_padding for i in range(offset+1, (Database.gadgetDB[g].spInc - Analysis.ArchInfo.bits/8)/(Analysis.ArchInfo.bits/8))]
            res.append(chain)
    return filter_chains(res, constraint, n)
    
  
def found_REG_pop_from_stack(reg, offset, constraint, n=1):  
    """
    Returns the n first gadgets that do reg <- mem(sp+offset)  
    """
    global record_REG_pop_from_stack
    global built_REG_pop_from_stack
    
    if( not built_REG_pop_from_stack ):
        build_REG_pop_from_stack()       
    if( not reg in record_REG_pop_from_stack ):
        return []
    if( not offset in record_REG_pop_from_stack ):
        return []
    res = [[g] for g in record_REG_pop_from_stack[reg][offset] if constraint.validate(Database.gadgetDB[g]) ]
    return res 
        
##################################
# Chains for reg write on stack  #
##################################


# record_REG_write_to_memory[reg] is a dict() --> D 
# D[reg2] where reg2 is a register is a dict() --> D2
# D2[offset] is the list of gadgets such that : 
#   mem(reg2 + offset) = reg 
record_REG_write_to_memory = dict()
built_REG_write_to_memory = False

def build_REG_write_to_memory():
    global record_REG_write_to_memory
    global built_REG_write_to_memory
    
    if( built_REG_write_to_memory ):
        return
    
    # Initialization for printing charging bar 
    chargingBarSize = Analysis.ssaRegCount
    chargingBarStr = " "*chargingBarSize
    info_colored("Performing additionnal analysis (writing registers on stack)\n")
    sys.stdout.write("\tProgression [")
    sys.stdout.write(chargingBarStr)
    sys.stdout.write("]\r\tProgression [")
    sys.stdout.flush() 
    
    # Initializing the dictionnaries
    for reg in range(0, Analysis.ssaRegCount):
        record_REG_write_to_memory[reg] = dict()
        for reg2 in range(0, Analysis.ssaRegCount):
            record_REG_write_to_memory[reg][reg2] = dict()
    
    # Filling the dictionnaries :
    
    db = Database.gadgetLookUp[GadgetType.REGtoMEM]
    for reg in range(0, Analysis.ssaRegCount):
        # Printing the charging bar 
        sys.stdout.write("|")
        sys.stdout.flush()
        
        for i in range(0, len(db.addr_list)):
            addr = db.addr_list[i]
            # We want to store only addresses of type REG +-/* CST
            (isInc, inc) = addr.isRegIncrement(addr)
            if( isInc ):
                add_REG_write_to_memory( reg, reg_list[0], offset, [g for g in db.written_values[i] if Database.gadgetDB[g].hasNormalRet() and Database.gadgetDB[g].isValidSpInc() ] )

    sys.stdout.write("\r"+" "*70+"\r")                               
    built_REG_write_to_memory = True
                 
    
    
    
    
def add_REG_write_to_memory(reg, reg2, offset, gadget_list, gadget_sorted=False):
    """
    Adds gadgets that write reg at mem(reg2+offset)
    Addition to the record_REG_write_to_memory list is made in increasing 
    order according to gadgets length (number of REIL instructions).   
    This is to get the best gadgets (shorter) first 
    
    Parameters:
        reg - int
        reg2 - int 
        offset - int
        gadgets_list - list of int 
        gadgets_sorted - Bool (True iff the gadgets_list parameter supplied has been sorted already ) 
    
    """
    global MAX_CHAINS
    global record_REG_write_to_memory
    
    if( not offset in record_REG_write_to_memory[reg][reg2] ):
        record_REG_write_to_memory[reg][reg2][offset] = []
        
    if( not gadget_sorted ):
        gadgets_list = sorted(gadgets_list, key=lambda gadget:Database.gadgetDB[gadget].nbInstr)
        
    for i in range(0, len(record_REG_write_to_memory[reg][reg2][offset])):
        if( i >= MAX_CHAINS or not gadgets_list ):
            return 
        if( record_REG_write_to_memory[reg][reg2][offset][i] == gadgets_list[0] ):
            gadgets_list = gadgets_list[1:]
        elif( Database.gadgetDB[record_REG_write_to_memory[reg][reg2][offset][i]].nbInstr > Database.gadgetDB[gadgets_list[0]].nbInstr ):
            record_REG_write_to_memory[reg][reg2][offset].insert(i, gadgets_list[0])
            gadgets_list = gadgets_list[1:]
        else:
            i = i + 1
            
    # If some are left in gadgets_list at the end 
    remaining_len = MAX_CHAINS - len(record_REG_write_to_memory[reg][reg2][offset])
    if( remaining_len > 0 ):
        record_REG_write_to_memory[reg][reg2][offset] += gadgets_list[:remaining_len]

    
def found_REG_write_to_memory(reg, reg2, offset, constraint, n=1):
    """
    Returns the n first gadgets that do mem(reg2+offset) <- reg by poping cst from the stack 
    Parameters:
        reg, reg2, offset - int
        n - int 
    """
    global record_REG_write_to_memory
    global built_REG_write_to_memory
    global MAX_PADDING
    
    if( not built_REG_write_to_memory ):
        build_REG_write_to_memory()
    
    if( not offset in record_REG_write_to_memory[reg][reg2] ):
        return []
    res = []
    for g in record_REG_write_to_memory[reg][reg2][offset]:
        default_padding = set_padding_unit()
        padding_units = (Database.gadgetDB[g].spInc - Analysis.ArchInfo.bits/8)/(Analysis.ArchInfo.bits/8)
        if( padding_units <= MAX_PADDING ):
            padding_chain = [default_padding for i in range(0,padding_units)]
            res.append( [g] + padding_chain )

    return filter_chains(res, constraint, n)
    
    
#####################
# GLOBAL FUNCTIONS  #
#####################

def build_all():
    build_REGtoREG_reg_transitivity()
    build_REG_pop_from_stack()
    build_REG_write_to_memory()

def reinit():
    global PADDING_UNITS
    global record_REGtoREG_reg_transitivity
    global built_REGtoREG_reg_transitivity
    global record_REG_pop_from_stack
    global built_REG_pop_from_stack
    global record_REG_write_to_memory
    global built_REG_write_to_memory

    PADDING_UNITS = []
    record_REGtoREG_reg_transitivity = dict()
    built_REGtoREG_reg_transitivity = False
    record_REG_pop_from_stack = dict()
    built_REG_pop_from_stack = False
    record_REG_write_to_memory = dict()
    built_REG_write_to_memory = False

