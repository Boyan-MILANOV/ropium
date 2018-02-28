# ROPGenerator - Database.py module
# Storing the gadgets that are used during analysis

import sys
import ropgenerator.Analysis as Analysis
from ropgenerator.Gadget import Gadget, GadgetException, GadgetType, analyzed_raw_to_gadget
from datetime import datetime
from ropgenerator.Cond import Cond, CT
from ropgenerator.Expr import SSAExpr
from ropgenerator.Colors import write_colored, info_colored, error_colored
from ropgenerator.Config import ROPGENERATOR_DIRECTORY
from ropgenerator.generate_opcodes import opcodes_file

import ropgenerator.Expr as Expr
import signal

# List of the available gadgets
gadgetDB = []


old_stdout = sys.stdout
old_stderr = sys.stderr
# Used to limit max accepted computation time for a gadget 
def timeout_handler(signum, frame):
    global old_stdout
    global old_stderr
    
    signal.alarm(0)
    raise Exception("Too much to compute gadget dependencies")
signal.signal(signal.SIGALRM, timeout_handler)


#############################################
# GENERATING GADGETS AND STORING            #
# THEM IN THE DATABASE & SEARCH STRUCTURES  #
#############################################

sigint = False

def generated_gadgets_to_DB():
    """
    Generates the list of the available gadgets for ROP 
    Usage : must be called after the gadgets opcodes have been stored into the opcodes_gadget array in Generated_opcodes.py file.
    Result : 
        No value returned. But the gadgets are stored in the gadgets[] array in Database module.
    """
    global sigint 
    global current_gadget
    global old_stdout
    global old_stderr
    
    def sigint_handler(signal, frame):
        global sigint
        sigint = True

    # Read all gadgets that have been generated !
    f = open(opcodes_file, "r")
    asmGadgets = []
    for line in f:
        (addr,instr) = line[:-1].split('#')
        addr = int(addr,16)
        instr = instr.decode("hex")
        asmGadgets.append((addr, instr))
    f.close()
    # Analyze them
    junk_file = open("/dev/null", "w") 
    i = 0
    success = 0
    warnings = 0
    chargingBarSize = 30
    chargingBarStr = " "*chargingBarSize
    info_colored("Working under architecture: " + Analysis.ArchInfo.currentArch + '\n')
    info_colored("Creating gadget database\n")
    sys.stdout.write("\tProgression [")
    sys.stdout.write(chargingBarStr)
    sys.stdout.write("]\r\tProgression [")
    sys.stdout.flush()    
    warnings_file = ROPGENERATOR_DIRECTORY + "warnings-logs"
    f = open(warnings_file, "w") 
    original_sigint_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, sigint_handler)
    startTime = datetime.now()
    for g in asmGadgets:
        if( sigint ):
            break
        asm = g[1]
        addr = g[0]
        try:
            if( i % (len(asmGadgets)/30) == 0 and i > 0 or i == len(asmGadgets)):
                sys.stdout.write("|")
                sys.stdout.flush()
            #print("Gadget : " + '\\x'.join(["%02x" % ord(c) for c in asm]) + "\n")
            sys.stdout = sys.stderr = junk_file
            signal.alarm(1)
            gadget = Gadget(i, addr, asm)
            signal.alarm(0)
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            success += 1
            gadgetDB.append( gadget )
        
        except Exception as e:
            signal.alarm(0)
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            if( not isinstance(e, GadgetException)):
                warnings = warnings + 1
                f.write("Unexpected error in : " + '\\x'.join(["%02x" % ord(c) for c in asm]) + "\nException message: (" + str(type(e)) + ") " + str(e) + '\n\n')

        i = i + 1
    # Restoring the state
    f.close()
    junk_file.close()
    signal.signal(signal.SIGINT, original_sigint_handler)       
    # This variable should be written before calculating spInc or simplifying conditions !!!
    Expr.nb_regs = Analysis.ssaRegCount-1   
    # Second pass analysis once all gadgets are collected
    for gadget in gadgetDB:
        gadget.calculateSpInc()
        gadget.calculateRet()
        gadget.calculatePreConstraint()
        
     # Getting time   
    cTime = datetime.now() - startTime
    # Printing summary information 
    sys.stdout.write("\r"+" "*70+'\r')   
    if( sigint ):
        error_colored("SIGINT ended the analysis prematurely, gadget database might be incomplete\n")
        sigint = False
    print "\tGadgets analyzed : " + str(len(asmGadgets))
    print "\tSuccessfully translated : " + str(success)
    print "\tComputation time : " + str(cTime)
    if( warnings > 0 ):
        print("\tUnexpected exceptions : " + str(warnings) + " (logs in '{}')".format(warnings_file))
    
    
def simplifyGadgets():
    """
    Apply some simplifications on the gadget dependencies
    """
    chargingBarSize = 30
    chargingBarStr = " "*chargingBarSize
    i = 0
    info_colored("Simplifying gadgets\n")
    sys.stdout.write("\tProgression [")
    sys.stdout.write(chargingBarStr)
    sys.stdout.write("]\r\tProgression [")
    sys.stdout.flush()
    for gadget in gadgetDB:
        if( i % (len(gadgetDB)/30) == 0 and i > 0 or i == len(gadgetDB)):
                sys.stdout.write("|")
                sys.stdout.flush()
        gadget.getDependencies().simplifyConditions()
        i = i + 1
    sys.stdout.write("\r"+" "*70+"\r")
  
  
#################################################
# VARIOUS DATA STRUCTURES TO STORE DEPENDENCIES #
#################################################

# exprLookUp
class exprLookUp:
    """
    Class used to store dependencies of type EXPRtoREG
    Each register should have its own exprLookUp
    """
    def __init__(self):
        self.expr_list = []# LIst of EXPR that are stored in REG
        self.gadget_list = []# gadget_list[i] = list of gadgets that put expr_list[i] in the regiter

    def lookUpEXPRtoREG(self, expr, constraint, n=10):
        """
        Return at most n gadgets that correspond to expr
        """
        i = 0
        found = 0
        res = []
        while( i < len(self.expr_list ) and len(res) < n):
            cond = Cond(CT.EQUAL, self.expr_list[i], expr)
            if( cond.isTrue(hard=True)):
                res += [g for g in self.gadget_list[i] if constraint.validate(gadgetDB[g])]
            i = i + 1
        return res 


# memLookUp:
class memLookUp:
    """
    Class used to help storing the dependencies for the memory in gadgetLookUp
    
    - addr_list is a list of expressions corresponding to memory addresses 
    - written_values is a list of dictionnaries whose content depends on the type of dependency the structure is used to store. Values are always a list of gadgets. 
    Depending on the use: 
        REGtoMEM : keys are register uid (int)
        CSTtoMEM : keys are the constant value (int)
        MEMEXPRtoMEM : keys are Expr (addr of the MEMEXPR)
    """
    
    def __init__(self):
        self.addr_list=[] # To check if an access to an address is available
        self.written_values=[] # List of dictionnaries 
        
    def lookUpREGtoMEM( self, addr, reg, constraint, n=1 ):
        """
        Returns gadgets numbers that put reg at mem(addr) as a list of gadgets uids
        reg - (int)
        addr - Expr
        """
        i = 0
        res = []
        # Iterate for all write addresses 
        while( i < len(self.addr_list) and len(res) < n):
            # If we have a dependencie for the requested register 
            if( reg in self.written_values[i]):
                # Comparing the addresses with hard=True so we call z3 solver
                cond = Cond(CT.EQUAL, self.addr_list[i], addr)
                if( cond.isTrue(hard=True)):
                    res += [g for g in self.written_values[i][reg] if constraint.validate(gadgetDB[g])]
            i = i + 1
        return res[:n]
        
    def lookUpCSTtoMEM( self, addr, cst, constraint, n=1):
        """
        Returns gadgets numbers that put cst at mem(addr) as a list of gadgets uids
        cst - (int)
        addr - Expr
        """
        i = 0
        res = []
        # Iterate for all write addresses
        while( i < len(self.addr_list ) and len(res) < n):
            # If we have a dependencie for the requested constant
            if( cst in self.written_values[i]):
                # Comparing the addresses with hard=True so we call z3 solver
                cond = Cond(CT.EQUAL, self.addr_list[i], addr)
                if( cond.isTrue(hard=True)):
                    res += [g for g in self.written_values[i][cst] if constraint.validate(gadgetDB[g])]
            i = i + 1
        return res[:n]

    def lookUpEXPRtoMEM( self, addr, expr, constraint, n=1 ):
        """
        Returns gadgets numbers that put expr (or mem(expr) depending 
        of the use of the memLookUp ) into mem(addr)
        """
        i = 0
        res = []
        # Iterate for all write addresses
        while( i < len(self.addr_list ) and len(res) < n):
            # Check if addresses correspond
            addr_cond = Cond(CT.EQUAL, self.addr_list[i], addr)
            if( not addr_cond.isTrue(hard=True)):
                i = i + 1
                continue
            # If addresses correspond, then check if we
            # have a dependency for the given expr
            for stored_expr in self.written_values[i].keys():
                if( expr.size != stored_expr.size ):
                    # If different sizes, we don't compare 
                    continue
                cond = Cond(CT.EQUAL, expr, stored_expr)
                if( cond.isTrue(hard=True)):
                    res += [g for g in self.written_values[i][stored_expr] if constraint.validate(gadgetDB[g])]
            i = i + 1
        return res
        

# Hash tables to look up registers
# Different kinds :
# REGtoREG, REGtoMEM, MEMtoREG, MEMtoMEM, CSTtoREG, CSTtoMEM, EXPRtoREG, ... (see GadgetType class )

# gadgetLookUp: 
# keys are GadgetTypes
# values are dictionnaries (different organization for all of them 

# REGtoREG dictionnary : gadgetLookUp[REGtoREG][REG1][REG2] = uid (number) of gadget in the gadgetDB list that puts REG2 in REG1
# CSTtoREG dictionnary : gadgetLookUp[REGtoREG][REG][CST] = uid (number) of gadget in the gadgetDB list that puts CST in REG
# MEMtoREG dictionnary : gadgetLookUp[MEMtoREG][REG][ADDR] = uid (number) of gadget in the gadgetDB that puts MEM[addr] in REG
# REGtoMEM dictionnary : gadgetLookUp[REGtoMEM] = memLookUp() for gadgets  that writes registers in the memory 
# CSTtoMEM dictionnary : gadgetLookUp[CSTtoMEM] = memLookUp() for gadgets that writes constants in the memory 
# EXPRtoREG dictionnary : gadgetLookUp[EXPRtoREG][REG] = exprLookUp() 
# MEMEXPRtoREG dictionnary : gadgetLookUp[MEMEXPRtoREG][REG] = exprLookUp (stored expressions are not MEMEXPR but only the address)
# MEMEXPRtoMEM dictionnary : gadgetLookUp[MEMEXPRtoMEM] = memLookUp() for gadgets that write mem(expr) in the memory 
 
gadgetLookUp = {GadgetType.REGtoREG:dict(), GadgetType.REGtoMEM:memLookUp(), GadgetType.MEMtoREG:dict(),GadgetType.CSTtoREG:dict(),GadgetType.CSTtoMEM:memLookUp(), GadgetType.EXPRtoREG:dict(), GadgetType.MEMEXPRtoREG:dict(), GadgetType.MEMEXPRtoMEM:memLookUp(), GadgetType.EXPRtoMEM:memLookUp()} 
  
def fillGadgetLookUp():
    """
    Fill the gadgetLookUp dictionnary with gadgets from the gadgetDB list
    """
  
    def add_gadget( gadget_list, gadget_num ):
        """
        Adds a gadget in a list of gadgets in increasing order ( order is gadget.nbInstr value )
        """
        for i in range(0,len(gadget_list)):
            if( gadget_num == gadget_list[i] ):
                return 
            elif( gadgetDB[gadget_list[i]].nbInstr > gadgetDB[gadget_num].nbInstr ):
                gadget_list.insert(i, gadget_num)
                return
        gadget_list.append(gadget_num)
                
    
    # Initialize the gadgetLookUp dictionnaries
    # Only done for REGtoREG so far
    for reg_num in Analysis.revertRegNamesTable.keys():
        # For REGtoREG
        gadgetLookUp[GadgetType.REGtoREG][reg_num] = dict()
        for reg_num2 in Analysis.revertRegNamesTable.keys():
            gadgetLookUp[GadgetType.REGtoREG][reg_num][reg_num2] = []
        # For CSTtoREG
        gadgetLookUp[GadgetType.CSTtoREG][reg_num] = dict()
        # For MEMtoREG
        gadgetLookUp[GadgetType.MEMtoREG][reg_num] = dict()
        # For EXPRtoREG
        gadgetLookUp[GadgetType.EXPRtoREG][reg_num] = exprLookUp()
        # For MEMEXPRtoREG
        gadgetLookUp[GadgetType.MEMEXPRtoREG][reg_num] = exprLookUp()
        # For others types 
        # No initialisation needed

     
    # Initialize the printed charging bar
    chargingBarSize = 30 
    chargingBarStr = " "*chargingBarSize
    info_colored("Updating gadget tables\n")
    sys.stdout.write("\tProgression [")
    sys.stdout.write(chargingBarStr)
    sys.stdout.write("]\r\tProgression [")
    sys.stdout.flush()   
    # Update the gadgetLookUp table
    hard_simplify=False
    for i in range(0, len(gadgetDB)):
        if( i % (len(gadgetDB)/30) == 0 and i > 0 or i == len(gadgetDB)):
                sys.stdout.write("|")
                sys.stdout.flush()
        gadget = gadgetDB[i]
        for reg, deps in gadget.getDependencies().regDep.iteritems():
            for dep in deps:
                # For REGtoREG
                if( isinstance(dep[0], Expr.SSAExpr) and dep[1].isTrue(hard=hard_simplify)):
                    add_gadget(gadgetLookUp[GadgetType.REGtoREG][reg.num][dep[0].reg.num], i)
                # For CSTtoREG
                elif( isinstance(dep[0], Expr.ConstExpr) and dep[1].isTrue(hard=hard_simplify)):
                    if( not dep[0].value in gadgetLookUp[GadgetType.CSTtoREG][reg.num] ):
                        gadgetLookUp[GadgetType.CSTtoREG][reg.num][dep[0].value] = [i]
                    else:    
                        add_gadget(gadgetLookUp[GadgetType.CSTtoREG][reg.num][dep[0].value], i)
                # For XXXtoREG
                elif( isinstance(dep[0], Expr.MEMExpr) and dep[1].isTrue(hard=hard_simplify) ):
                    # For MEMtoREG
                    if( isinstance(dep[0].addr, Expr.SSAExpr)):
                        addrKey = dep[0].addr.reg.num
                        if( not addrKey in gadgetLookUp[GadgetType.MEMtoREG][reg.num]):
                            gadgetLookUp[GadgetType.MEMtoREG][reg.num][addrKey] = [i]
                        else:
                            add_gadget(gadgetLookUp[GadgetType.MEMtoREG][reg.num][addrKey], i)
                    # For MEMEXPRtoREG
                    else:
                        gadgetLookUp[GadgetType.MEMEXPRtoREG][reg.num].expr_list.append(dep[0].addr)
                        gadgetLookUp[GadgetType.MEMEXPRtoREG][reg.num].gadget_list.append([i])
                # FOR EXPRtoREG
                elif( dep[1].isTrue(hard=hard_simplify) ):
                    exprLookUpEXPRtoREG = gadgetLookUp[GadgetType.EXPRtoREG][reg.num]
                    exprLookUpEXPRtoREG.expr_list.append(dep[0])
                    exprLookUpEXPRtoREG.gadget_list.append([i])
                    
                    
        for addr, deps in gadget.getDependencies().memDep.iteritems():
            # Init 
            REGtoMEM_added = False           
            CSTtoMEM_added = False
            MEMEXPRtoMEM_added = False
            EXPRtoMEM_added = False
            
            # Going through dependencies 
            for dep in deps:
                # Check for integrity of the database
                if( not isinstance(dep[0], Expr.Expr)):
                    raise Exception("Invalid dependency in fillGadgetLookUp(): " + str(dep[0]))
            
                # For REGtoMEM
                if( isinstance( dep[0], Expr.SSAExpr ) and dep[1].isTrue(hard=hard_simplify)):
                    if( not REGtoMEM_added ):
                        REGtoMEM_added = True
                        gadgetLookUp[GadgetType.REGtoMEM].addr_list.append(addr)
                        gadgetLookUp[GadgetType.REGtoMEM].written_values.append(dict())
                    if( dep[0].reg.num in gadgetLookUp[GadgetType.REGtoMEM].written_values[-1]):
                        add_gadget(gadgetLookUp[GadgetType.REGtoMEM].written_values[-1][dep[0].reg.num], i)
                    else:
                        gadgetLookUp[GadgetType.REGtoMEM].written_values[-1][dep[0].reg.num] = [i]
                # For CSTtoMEM
                elif( isinstance(dep[0], Expr.ConstExpr) and dep[1].isTrue(hard=hard_simplify)):
                    if( not CSTtoMEM_added ):
                        CSTtoMEM_added = True
                        gadgetLookUp[GadgetType.CSTtoMEM].addr_list.append(addr)
                        gadgetLookUp[GadgetType.CSTtoMEM].written_values.append(dict())
                    if( dep[0].value in gadgetLookUp[GadgetType.CSTtoMEM].written_values[-1]):
                        add_gadget(gadgetLookUp[GadgetType.CSTtoMEM].written_values[-1][dep[0].value], i)
                    else:
                        gadgetLookUp[GadgetType.CSTtoMEM].written_values[-1][dep[0].value] = [i]
                # For MEMEXPRtoMEM
                elif( isinstance(dep[0], Expr.MEMExpr) and dep[1].isTrue(hard=hard_simplify)):
                    if( not MEMEXPRtoMEM_added ):
                        MEMEXPRtoMEM_added = True
                        gadgetLookUp[GadgetType.MEMEXPRtoMEM].addr_list.append(addr)
                        gadgetLookUp[GadgetType.MEMEXPRtoMEM].written_values.append(dict())
                    if( dep[0].addr in gadgetLookUp[GadgetType.MEMEXPRtoMEM].written_values[-1]):
                        add_gadget(gadgetLookUp[GadgetType.MEMEXPRtoMEM].written_values[-1][dep[0].addr], i)
                    else:
                        gadgetLookUp[GadgetType.MEMEXPRtoMEM].written_values[-1][dep[0].addr] = [i]      
                # For EXPRtoMEM
                elif( isinstance(dep[0], Expr.Expr) and dep[1].isTrue(hard=hard_simplify)):
                    if( not EXPRtoMEM_added ):
                        EXPRtoMEM_added = True
                        gadgetLookUp[GadgetType.EXPRtoMEM].addr_list.append(addr)
                        gadgetLookUp[GadgetType.EXPRtoMEM].written_values.append(dict())
                    if( dep[0] in gadgetLookUp[GadgetType.EXPRtoMEM].written_values[-1]):
                        add_gadget(gadgetLookUp[GadgetType.EXPRtoMEM].written_values[-1][dep[0]], i)
                    else:
                        gadgetLookUp[GadgetType.EXPRtoMEM].written_values[-1][dep[0]] = [i]

    # Clean the charging bar
    sys.stdout.write("\r"+" "*70+"\r") 

                
def pretty_print_registers():
    if( not gadgetDB ):
        print("You should generate gadgets before looking at the registers. Type 'load help' for help")
    else:
        print("\n\tRegisters present in the gadget database:")
        print("\t(Architeture is '" + Analysis.ArchInfo.currentArch +"')\n")
        for reg in Analysis.regNamesTable.keys():
            if( reg == Analysis.ArchInfo.ip ):
                print('\t'+reg+ " (instruction pointer)")
            elif( reg == Analysis.ArchInfo.sp ):
                print('\t'+reg+ " (stack pointer)")
            else:
                print('\t'+reg)
                
#############################
# REINITIALIZATION FUNCTION #
#############################
def reinit():
    global gadgetDB
    gadgetDB = []

