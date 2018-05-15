# ROPGenerator - SearchHelper module 
# Keeping track of gadgets to fasten the search 
# This module supports the Gadget_finder module 
# It merely stores chains of gadgets obtained by different search strategies 

import ropgenerator.Database as Database
import ropgenerator.Analysis as Analysis
import sys
from ropgenerator.Colors import string_bold, info_colored
from ropgenerator.Gadget import GadgetType, RetType
from ropgenerator.Constraints import ConstraintType, Constraint

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
num_to_str = dict()

def is_padding(gadget_num):
    return (int(gadget_num) < 0)
        
def get_padding_unit(uid=-1):
    global PADDING_UNITS
    return PADDING_UNITS[-1-uid]
    
def set_padding_unit(value=None, msg=None):
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
        padding_number = -1*len(PADDING_UNITS)
        if( msg ):
            addr_to_gadgetStr[value] = msg
            num_to_str[padding_number] = msg
        return padding_number
    else:
        return DEFAULT_PADDING_UNIT_INDEX

def get_valid_padding_byte ( constraint ):
    """
    Returns a byte that is not in constraint BAD_BYTES
    """
    bad_bytes_list = constraint.get(ConstraintType.BAD_BYTES)
    # Getting a valid padding byte 
    hex_chars = 'fedcba9876543210'
    found = False
    for c1 in hex_chars:
        for c2 in hex_chars:
            c = c1+c2
            if( not c in bad_bytes_list ):
                return int(c,16)
    return None
        
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
    
    
def filter_chains(chain_list, constraint, n=100):
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


def pad_gadgets(gadget_num_list, constraint, force_padding=False):
    """
    Takes a list of gadgets and returns a list of chains
    Each chain of the result corresponds to the padded gadget

    [!] force_padding = True means we will pad even if the gadget has not a
        valid ret or spinc 
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
        elif( force_padding and gadget.isValidSpInc() ):
            nb_padding_units = (Database.gadgetDB[gadget_num].spInc - Analysis.ArchInfo.bits/8)/(Analysis.ArchInfo.bits/8)
            res.append( [gadget_num] + [padding_unit]*nb_padding_units)
        elif( force_padding ):
            res.append([gadget_num])

    return sorted(res, key = lambda x:len(x)) 

#############################################
# Helper for REGtoREG transitivity strategy #
#############################################

record_REGtoREG_transitivity = dict()
record_REGtoREG_impossible = dict()
built_REGtoREG_transitivity = False

def add_impossible_REGtoREG(reg, reg2):
    global record_REGtoREG_impossible
    record_REGtoREG_impossible[reg][reg2]=True

def init_impossible():
    global record_REGtoREG_impossible
    for reg in range(0, Analysis.ssaRegCount):
        record_REGtoREG_impossible[reg] = dict() 

def is_impossible_REGtoREG(reg, reg2):
    return reg2 in record_REGtoREG_impossible[reg]
    
def build_REGtoREG_transitivity():
    global record_REGtoREG_transitivity
    global built_REGtoREG_transitivity
    
    db = Database.gadgetLookUp.types[GadgetType.REGEXPRtoREG]
    for reg in range(0, Analysis.ssaRegCount):
        record_REGtoREG_transitivity[reg] = dict()
        record_REGtoREG_impossible[reg] = dict()
        # Scanning the database
        for reg2 in db[reg].expr.keys():
            for cst in db[reg].expr[reg2].keys():
                if( cst == 0 ):
                    if( Database.gadgetDB[db[reg].expr[reg2][cst][0]].isValidSpInc()):
                        record_REGtoREG_transitivity[reg][reg2] = \
                                    Database.gadgetDB[db[reg].expr[reg2][cst][0]].spInc
                    break
    built_REGtoREG_transitivity = True

def possible_REGtoREG_transitivity(reg):
    """
    Returns all the registers reg2 such that reg <- reg2 is possible
    I.e, record_REGtoREG_reg_transitivity[reg][reg2] exists 
    """       
    global record_REGtoREG_transitivity
    global built_REGtoREG_transitivity
    
    if( not built_REGtoREG_transitivity ):
        build_REGtoREG_transitivity()

    possible = [[reg2,spInc] for reg2,spInc in record_REGtoREG_transitivity[reg].iteritems()\
            if reg2 not in record_REGtoREG_impossible[reg]]
    possible.sort(key=lambda x:x[1])
    return [x[0] for x in possible]

###########################################
# Helpers for REG pop from stack strategy #
###########################################

def pad_CSTtoREG_pop_from_stack(gadget_list, offset, cst, constraint):
    """
    Given a list of gadgets that does reg <- mem(sp+offset)
    pad it so that 'cst' is at the right position in the 
    stack to be put in reg 
    g - gadget num
    """
    cst_padding = set_padding_unit(value=cst)
    default_padding = set_padding_unit()
    res = []
    for g in gadget_list:
        chain= [g] + [default_padding for i in range(0, offset*8/Analysis.ArchInfo.bits)] + \
            [cst_padding] + \
            [default_padding for i in range(offset+1, (Database.gadgetDB[g].spInc - \
                                Analysis.ArchInfo.bits/8)/(Analysis.ArchInfo.bits/8))]
        res.append(chain)
    return filter_chains(res, constraint)

##################################
# Chains for reg write on stack  #
##################################

# !!!!!!!!!! NOT WORKING YET 

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
    
    # Initialization for printing charging bar 
    chargingBarSize = Analysis.ssaRegCount
    chargingBarStr = " "*chargingBarSize
    info_colored(string_bold("Performing additionnal analysis")+": writing registers on stack\n")
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
    
    
####################################
# Chains for reg <- reg +- offset  #
####################################

# record_REG_increment is a dict 
# D[reg1][reg2][offset] = list of gadgets that do reg1 <- reg2 + offset 
record_REGINCtoREG = dict()
built_REGINCtoREG = False    
    
def build_REGINCtoREG():
    global record_REGINCtoREG
    global built_REGINCtoREG
    
    if( built_REGINCtoREG ):
            return 
            
    # Initializing the dictionnaries
    for reg in range(0, Analysis.ssaRegCount):
        record_REGINCtoREG[reg] = dict()
        for reg2 in range(0, Analysis.ssaRegCount):
            record_REGINCtoREG[reg][reg2] = dict()
            
    # Filling the dictionnaries :
    db = Database.gadgetLookUp.types[GadgetType.REGEXPRtoREG]
    for reg in db.keys():
        for reg2 in db[reg].expr.keys():
            for cst in db[reg].expr[reg2].keys():
                add_REGINCtoREG( reg, reg2, cst, db[reg].expr[reg2][cst],gadgets_sorted=True )
                
                            
    built_REGINCtoREG = True
    
    
def add_REGINCtoREG(reg, reg2, inc, gadgets_list, gadgets_sorted=False):
    """
    Adds gadgets that put reg2+inc into reg
    Addition to the record_REGINC[reg][reg2][inc] list is made in 
    increasing order according to gadgets length (number of REIL instructions). 
    This is to get the best gadgets (shorter) first 
    
    Parameters:
        reg, reg2 - int
        inc - int 
        gadgets_list - list of int 
        gadgets_sorted - Bool (True iff the gadgets_list parameter supplied has been sorted already )
        
    """
    global MAX_CHAINS
    global record_REGINCtoREG   
    
    if( not inc in record_REGINCtoREG[reg][reg2] ):
        if( not gadgets_sorted ):
            record_REGINCtoREG[reg][reg2][inc] = sorted(gadgets_list, key= lambda gadget:Database.gadgetDB[gadget].nbInstr)
        else:
            record_REGINCtoREG[reg][reg2][inc] = list(gadgets_list)
        return 
        
    # Preparing merge with fusion sort 
    if( not gadgets_sorted ):
        gadgets_list = sorted(gadgets_list, key=lambda gadget:Database.gadgetDB[gadget].nbInstr)
        
    # Merging  
    for i in range(0, len(record_REGINCtoREG[reg][reg2][inc])):
        if( i >= MAX_CHAINS or not gadgets_list ):
            return 
        if( record_REGINCtoREG[reg][reg2][inc][i] == gadgets_list[0] ):
            gadgets_list = gadgets_list[1:]
        elif( Database.gadgetDB[record_REGINCtoREG[reg][reg2][inc][i]].nbInstr > Database.gadgetDB[gadgets_list[0]].nbInstr ):
            record_REGINCtoREG[reg][reg2][inc].insert(i, gadgets_list[0])
            gadgets_list = gadgets_list[1:]
        else:
            i = i + 1
            
    # If some are left in gadgets_list at the end 
    remaining_len = MAX_CHAINS - len(record_REGINCtoREG[reg][reg2][inc])
    if( remaining_len > 0 ):
        record_REGINCtoREG[reg][reg2][inc] += gadgets_list[:remaining_len]
        


def found_REGINCtoREG(reg, reg2, inc, constraint, n=1):  
    """
    Returns the n first gadgets that do reg <- mem(sp+offset)  
    """
    global record_REGINCtoREG
    global build_REGINCtoREG
    
    if( not built_REGINCtoREG ):
        build_REGINCtoREG()
    
    if( inc not in record_REGINCtoREG[reg][reg2] ):
        return []
    
    return filter_chains(pad_gadgets([ g for g in record_REGINCtoREG[reg][reg2][inc] if\
    Database.gadgetDB[g].hasNormalRet() and Database.gadgetDB[g].isValidSpInc()], constraint), constraint, n)
    
    
def found_REGINCtoREG_no_padding(reg, reg2, inc, constraint, n=1):
    global record_REGINCtoREG
    global build_REGINCtoREG
    
    if( not built_REGINCtoREG ):
        build_REGINCtoREG()
        
    if( inc in record_REGINCtoREG[reg][reg2] ):
        return [g for g in record_REGINCtoREG[reg][reg2][inc] if constraint.validate( Database.gadgetDB[g])][:n]
    else:  
        return []
    
def possible_REGINCtoREG( reg, reg2, constraint=Constraint(),mini=-1, maxi=300 ):
    """
    Returns a a list of pairs (inc, gadget)
    The increments are contained between mini and maxi
    """
    global record_REGINCtoREG
    global build_REGINCtoREG
    
    if( not built_REGINCtoREG ):
        build_REGINCtoREG()
    
    res= []
    for key in record_REGINCtoREG[reg][reg2].keys():
        if( key < mini or key > maxi ):
            continue
        if( len(record_REGINCtoREG[reg][reg2][key]) > 0 ):
            for g in record_REGINCtoREG[reg][reg2][key]:
                if( constraint.validate(Database.gadgetDB[g]) ):
                    res.append( [key,g] )
                    break
    return res
    

#####################
# GLOBAL FUNCTIONS  #
#####################
def reinit():
    global PADDING_UNITS
    global addr_to_gadgetStr
    global record_REGtoREG_transitivity
    global built_REGtoREG_transitivity
    global record_REG_pop_from_stack
    global built_REG_pop_from_stack
    global record_REG_write_to_memory
    global built_REG_write_to_memory
    global record_REGINCtoREG
    global built_REGINCtoREG

    PADDING_UNITS = []
    addr_to_gadgetStr = dict()
    record_REGtoREG__transitivity = dict()
    built_REGtoREG_transitivity = False
    record_REG_pop_from_stack = dict()
    built_REG_pop_from_stack = False
    record_REG_write_to_memory = dict()
    built_REG_write_to_memory = False
    record_REGINCtoREG = dict()
    built_REGINCtoREG = False
