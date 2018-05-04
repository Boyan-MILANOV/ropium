# ROPGenerator - Database.py module
# Storing the gadgets that are used during analysis

import sys
import ropgenerator.Analysis as Analysis
from ropgenerator.Gadget import Gadget, GadgetException, GadgetType, GadgetSort, analyzed_raw_to_gadget
from datetime import datetime
from ropgenerator.Cond import Cond, CT
from ropgenerator.Expr import SSAExpr
from ropgenerator.Colors import notify, charging_bar, string_special, string_bold, write_colored, info_colored, error_colored
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
    # Sort the gadgets according to their instructions 
    asmGadgets.sort(key=lambda x:x[1])
    # Analyze them
    junk_file = open("/dev/null", "w") 
    i = 0
    success = 0
    warnings = 0
    info_colored(string_bold("Working under architecture: ") + Analysis.ArchInfo.currentArch + '\n')
    info_colored(string_bold("Creating gadget database\n"))  
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
            charging_bar(len(asmGadgets)-1, i, 30)
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
                f.write("Unexpected error in : " + '\\x'.join(["%02x" % ord(c) for c in asm]) + "\nException type: " + str(type(e)) + "\nException message: " + str(e) + '\n\n')

        i = i + 1
    # Restoring the state
    f.close()
    junk_file.close()
    signal.signal(signal.SIGINT, original_sigint_handler)       
    # This variable should be written before calculating spInc or simplifying conditions !!!
    Expr.nb_regs = Analysis.ssaRegCount-1   
        
    # Getting time   
    cTime = datetime.now() - startTime
    # Printing summary information    
    if( sigint ):
        print("\n")
        error_colored("SIGINT ended the analysis prematurely, gadget database might be incomplete\n")
        sigint = False
    notify("Gadgets analyzed : " + str(i))
    notify("Successfully translated : " + str(success))
    notify("Computation time : " + str(cTime))
    if( warnings > 0 ):
        pass
        #print("\tUnexpected exceptions : " + str(warnings) + " (logs in '{}')".format(warnings_file))
    
    
def simplifyGadgets():
    """
    Apply some simplifications on the gadget dependencies
    """
    chargingBarSize = 30
    chargingBarStr = " "*chargingBarSize
    i = 0
    info_colored(string_bold("Processing gadgets\n"))
    for gadget in gadgetDB:
        charging_bar(len(gadgetDB)-1, i, 30) 
        gadget.getDependencies().simplifyConditions()
        i = i + 1
        
    # Second pass analysis once all gadgets are collected
    for gadget in gadgetDB:
        gadget.calculateSpInc()
        gadget.calculateRet()
        gadget.calculatePreConstraint()
  

#################################################
# VARIOUS DATA STRUCTURES TO STORE GADGETS      # 
# ACCORDING TO THEIR DEPENDENCIES               #
#################################################

class cstLookUp:
    """
    Class used to store dependencies of type CSTto...
    """
    def __init__(self):
        self.values = dict()
        
    def add_gadget( self,cst, gadget_num ):
        """
        Adds a gadget in a list of gadgets in increasing order ( order is gadget.nbInstr value )
        """
        if not cst in self.values:
            self.values[cst] = [gadget_num]
        else:
            # Try dichotomy search 
            lmin = 0
            lmax = len(self.values[cst])-1
            while( True):
                lmoy = (lmax + lmin)/2
                if( lmax == lmin or gadgetDB[self.values[cst][lmoy]].nbInstr == gadgetDB[gadget_num].nbInstr ):
                    self.values[cst].insert(lmoy, gadget_num)
                    return 
                elif( lmin == lmax ):
                    if ( gadgetDB[self.values[cst][lmin]].nbInstr >= gadgetDB[gadget_num].nbInstr ):
                        self.values[cst].insert(lmin, gadget_num)
                    else:
                        self.values[cst].insert(lmin+1, gadget_num)
                    return 
                else:
                    if( gadgetDB[self.values[cst][lmoy]].nbInstr > gadgetDB[gadget_num].nbInstr ):
                        lmax = lmoy
                    else:
                        lmin = lmoy+1

    def find(self, cst, constraint, n=1):
        """
        Return at most n gadgets 
        cst - int 
        """
        res = []
        for gadget_num in self.values.get(cst, []):
            if( constraint.validate(gadgetDB[gadget_num])):
                res.append(gadget_num)
            if( len(res) >= n ):
                break
        return res

class exprLookUp:
    """
    Class used to store dependencies of type EXPRto...
    """
    def __init__(self):
		# Keys are registers uids, values are dictionnaries of constants
		# expr[reg][cst] = list of gadgets that put expressions reg + cst in .... 
		self.expr = dict()
		for reg in range(0,Analysis.ssaRegCount):
			self.expr[reg] = {}

    def add_gadget( self, reg, cst, gadget_num ):
        """
        Adds a gadget in a list of gadgets in increasing order ( order is gadget.nbInstr value )
        """
        if not cst in self.expr[reg]:
            self.expr[reg][cst] = [gadget_num]
        else:
            # Try dichotomy search 
            lmin = 0
            lmax = len(self.expr[reg][cst])-1
            while( True):
                lmoy = (lmax + lmin)/2
                if( gadgetDB[self.expr[reg][cst][lmoy]].nbInstr == gadgetDB[gadget_num].nbInstr ):
                    self.expr[reg][cst].insert(lmoy, gadget_num)
                    return 
                elif( lmin == lmax ):
                    if ( gadgetDB[self.expr[reg][cst][lmin]].nbInstr >= gadgetDB[gadget_num].nbInstr ):
                        self.expr[reg][cst].insert(lmin, gadget_num)
                    else:
                        self.expr[reg][cst].insert(lmin+1, gadget_num)
                    return 
                else:
                    if( gadgetDB[self.expr[reg][cst][lmoy]].nbInstr > gadgetDB[gadget_num].nbInstr ):
                        lmax = lmoy
                    else:
                        lmin = lmoy+1
    
    def find(self, reg, cst, constraint, n=1):
        """
        Return at most n gadgets 
        reg - int
        cst - int 
        """
        res = []
        for gadget_num in self.expr[reg].get(cst, []):
            if( constraint.validate(gadgetDB[gadget_num])):
                res.append(gadget_num)
            if( len(res) >= n ):
                break
        return res


class cstToMemLookUp:
    """
    Class used to store dependencies to the memory 
    """
    def __init__(self):
		# Keys are registers uids, values are dictionnaries of constants
		self.addr = dict()
		for reg in range(0,Analysis.ssaRegCount):
			self.addr[reg] = dict()
        
    def add_gadget( self, addr_reg, addr_cst, cst, gadget_num ):
        """
        Adds a gadget in a list of gadgets in increasing order ( order is gadget.nbInstr value )
        """
        if not addr_cst in self.addr[addr_reg]:
            self.addr[addr_reg][addr_cst] = cstLookUp()
        self.addr[addr_reg][addr_cst].add_gadget(cst, gadget_num)
            
    def find( self, addr_reg, addr_cst, cst, constraint, n = 1 ):
        """
        Return at most n gadgets 
        addr_reg - int
        addr_cst, cst - int 
        """
        if( not addr_cst in self.addr[addr_reg] ):
            return []
        return self.addr[addr_reg][addr_cst].find(cst, constraint=constraint, n=n)

class exprToMemLookUp:
    """
    Class used to store dependencies to the memory 
    """
    def __init__(self):
		# Keys are registers uids, values are dictionnaries of constants
		self.addr = dict()
		for reg in range(0,Analysis.ssaRegCount):
			self.addr[reg] = dict()
        
    def add_gadget( self, addr_reg, addr_cst, reg, cst, gadget_num ):
        """
        Adds a gadget in a list of gadgets in increasing order ( order is gadget.nbInstr value )
        """
        if not addr_cst in self.addr[addr_reg]:
            self.addr[addr_reg][addr_cst] = exprLookUp()
        self.addr[addr_reg][addr_cst].add_gadget(reg, cst, gadget_num)
            
    def find( self, addr_reg, addr_cst, reg, cst, constraint, n = 1 ):
        """
        Return at most n gadgets 
        addr_reg - int
        addr_cst, cst - int 
        """
        if( not addr_cst in self.addr[addr_reg] ):
            return []
        return self.addr[addr_reg][addr_cst].find(reg, cst, constraint=constraint, n=n)


class gadgetsLookUp:
    """
    Stores the gadgets according to their semantic 
    """
    def __init__(self):
        self.types = dict()
        self.types[GadgetType.CSTtoREG] = dict()
        self.types[GadgetType.CSTtoMEM] = None
        self.types[GadgetType.REGEXPRtoREG] = dict()
        self.types[GadgetType.MEMEXPRtoREG] = dict()
        self.types[GadgetType.MEMEXPRtoMEM] = None
        self.types[GadgetType.REGEXPRtoMEM] = None
        self.list_int80 = []
        self.list_syscall = []

    def fill(self):
        # Initialize the data structures ! 
        self.types[GadgetType.CSTtoMEM] = cstToMemLookUp()
        self.types[GadgetType.REGEXPRtoMEM] = exprToMemLookUp()
        self.types[GadgetType.MEMEXPRtoMEM] = exprToMemLookUp()
        for reg_num in Analysis.revertRegNamesTable.keys():
            self.types[GadgetType.CSTtoREG][reg_num] = cstLookUp()
            self.types[GadgetType.REGEXPRtoREG][reg_num] = exprLookUp()
            self.types[GadgetType.MEMEXPRtoREG][reg_num] = exprLookUp()

        # Initialize the printed charging bar
        chargingBarSize = 30 
        chargingBarStr = " "*chargingBarSize
        info_colored(string_bold("Sorting gadgets semantics\n")) 
        # Update the gadgetLookUp table
        for i in range(0, len(gadgetDB)):
            charging_bar(len(gadgetDB)-1, i, 30)
            gadget = gadgetDB[i]
            # Check for special gadgets (int 0x80 and syscall
            if( gadget.sort == GadgetSort.INT80 ):
                self.list_int80.append(i)
                continue
            elif( gadget.sort == GadgetSort.SYSCALL ):
                self.list_syscall.append(i)
                continue
            # For XXXtoREG
            for reg, deps in gadget.getDependencies().regDep.iteritems():
                for dep in deps:
                    # For REGEXPRtoREG
                    if( isinstance(dep[0], Expr.SSAExpr) and dep[1].isTrue()):
                        self.types[GadgetType.REGEXPRtoREG][reg.num].add_gadget(dep[0].reg.num, 0, i)
                    elif( isinstance(dep[0], Expr.Op) and dep[1].isTrue()):
                        (isInc, num, inc ) = dep[0].isRegIncrement(-1)
                        if( isInc ):
                            self.types[GadgetType.REGEXPRtoREG][reg.num].add_gadget(num, inc, i)
                    # For CSTtoREG
                    elif( isinstance(dep[0], Expr.ConstExpr) and dep[1].isTrue()):
                        self.types[GadgetType.CSTtoREG][reg.num].add_gadget(dep[0].value, i)
                    # For MEMEXPRtoREG
                    elif( isinstance(dep[0], Expr.MEMExpr) and dep[1].isTrue() ):
                        if( isinstance(dep[0].addr, Expr.SSAExpr)):
                            self.types[GadgetType.MEMEXPRtoREG][reg.num].add_gadget(dep[0].addr.reg.num, 0, i)
                        elif( isinstance( dep[0].addr, Expr.Op)):
                            (isInc, num, inc ) = dep[0].addr.isRegIncrement(-1)
                            if( isInc ):
                                self.types[GadgetType.MEMEXPRtoREG][reg.num].add_gadget(num, inc, i)
                    # If we found a true dependency, no need to check others 
                    if( dep[1].isTrue()):
                        break
                    
            # For XXXtoMEM 
            for addr, deps in gadget.getDependencies().memDep.iteritems():
                addr_reg = None
                addr_cst = None
                # Check if the address is of type REG + CST
                if( isinstance( addr, Expr.SSAExpr )):
                    addr_reg = addr.reg.num
                    addr_cst = 0
                elif( isinstance( addr, Expr.Op )):
                    (isInc, addr_reg, addr_cst) = addr.isRegIncrement(-1)
                    if( not isInc ):
                        continue
                else:
                    continue
                    
                # Going through dependencies 
                for dep in deps:
                    # Check for integrity of the database
                    if( not isinstance(dep[0], Expr.Expr)):
                        raise Exception("Invalid dependency in fillGadgetLookUp(): " + str(dep[0]))
                    
                    # For REGEXPRtoMEM
                    if( isinstance(dep[0], Expr.SSAExpr) and dep[1].isTrue()):
                        
                        self.types[GadgetType.REGEXPRtoMEM].add_gadget(addr_reg, addr_cst, dep[0].reg.num, 0, i)
                    elif( isinstance(dep[0], Expr.Op) and dep[1].isTrue()):
                        (isInc, num, inc ) = dep[0].isRegIncrement(-1)
                        if( isInc ):
                            self.types[GadgetType.REGEXPRtoMEM].add_gadget(addr_reg, addr_cst, num, inc, i)
                        
                    # For CSTtoMEM
                    elif( isinstance(dep[0], Expr.ConstExpr) and dep[1].isTrue()):
                        self.types[GadgetType.CSTtoMEM].add_gadget(addr_reg, addr_cst, dep[0].value, i)
                    # For MEMEXPRtoMEM
                    elif( isinstance(dep[0], Expr.MEMExpr) and dep[1].isTrue() ):
                        if( isinstance(dep[0].addr, Expr.SSAExpr)):
                            self.types[GadgetType.MEMEXPRtoMEM].add_gadget(addr_reg, addr_cst, dep[0].addr.reg.num, 0, i)
                        elif( isinstance( dep[0].addr, Expr.Op)):
                            (isInc, num, inc ) = dep[0].addr.isRegIncrement(-1)
                            if( isInc ):
                                self.types[GadgetType.MEMEXPRtoMEM].add_gadget(addr_reg, addr_cst, num, inc, i)
                    # If we found a true dependency, no need to check others 
                    if( dep[1].isTrue()):
                        break
                        
                        
        # Clean the charging bar
        sys.stdout.write("\r"+" "*70+"\r") 

    def find(self, gtype, arg1, arg2, constraint, n=1):
        if( gtype == GadgetType.CSTtoREG ):
            return self.types[gtype][arg1].find(arg2, constraint=constraint, n=n)
        elif( gtype == GadgetType.REGEXPRtoREG ):
            return self.types[gtype][arg1].find(arg2[0], arg2[1], constraint=constraint, n=n)
        elif( gtype == GadgetType.MEMEXPRtoREG ):
            return self.types[gtype][arg1].find(arg2[0], arg2[1], constraint=constraint, n=n)
        elif( gtype == GadgetType.CSTtoMEM ):
            return self.types[gtype].find(arg1[0], arg1[1], arg2, constraint=constraint, n=n)
        elif( gtype == GadgetType.REGEXPRtoMEM ):
            return self.types[gtype].find(arg1[0], arg1[1], arg2[0], arg2[1], constraint=constraint, n=n)
        elif( gtype == GadgetType.MEMEXPRtoMEM ):
            return self.types[gtype].find(arg1[0], arg1[1], arg2[0], arg2[1], constraint=constraint, n=n)
        else:
            return []
            
    def int80(self, constraint, n=1):
        res = []
        for gadget in self.list_int80:
            if( constraint.validate(gadgetDB[gadget], only_bad_bytes=True)):
                res.append([gadget])
                if( len(res) >= n ):
                    return res
        return res
        
    def syscall(self, constraint, n=1):
        res = []
        for gadget in self.list_syscall:
            if( constraint.validate(gadgetDB[gadget], only_bad_bytes=True)):
                res.append([gadget])
                if( len(res) >= n ):
                    return res
        return res
    
        
## Module wide gadgetsLookUp instance 
gadgetLookUp = gadgetsLookUp()
                
def pretty_print_registers():
    if( not gadgetDB ):
        print("You should generate gadgets before looking at the registers. Type 'load help' for help")
    else:
        print(string_bold("\n\tRegisters present in the gadget database:"))
        print(string_special("\t(Architeture is '" + Analysis.ArchInfo.currentArch +"')\n"))
        for reg in Analysis.regNamesTable.keys():
            if( reg == Analysis.ArchInfo.ip ):
                print('\t'+reg+ string_special(" (instruction pointer)"))
            elif( reg == Analysis.ArchInfo.sp ):
                print('\t'+reg+ string_special(" (stack pointer)"))
            else:
                print('\t'+reg)
                
#############################
# REINITIALIZATION FUNCTION #
#############################
def reinit():
    global gadgetDB
    gadgetDB = []
    gadgetLookUp = gadgetsLookUp()
