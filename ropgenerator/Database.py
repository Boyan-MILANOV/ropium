# -*- coding:utf-8 -*-
# Database module: save and classify gadgets 

from enum import Enum
from ropgenerator.Gadget import GadgetType, Gadget, GadgetException
from ropgenerator.Expressions import SSAExpr, ConstExpr, MEMExpr, OpExpr, Op, Expr
from ropgenerator.Conditions import CTrue
from ropgenerator.IO import info, error, fatal, string_bold, notify, charging_bar
from ropgenerator.Logs import log
from datetime import datetime

import ropgenerator.Architecture as Arch
import signal 

class DatabaseException(Exception):
    def __init__(self, msg):
        self.msg = msg
        
    def __str__(self):
        return self.msg
        
class TimeOutException(Exception):
    def __init__(self, msg):
        self.msg = msg
        
    def __str__(self):
        return self.msg
        

########################################
# Different types of supported queries #
########################################

class QueryType(Enum): 
    CSTtoREG = "Reg <- Cst"
    REGtoREG = "Reg <- Reg +/- Cst"
    MEMtoREG = "Reg <- MEM(Reg +/- Cst)"
    CSTtoMEM = "MEM(Reg +/- Cst) <- Cst"
    REGtoMEM = "MEM(Reg +/- Cst) <- Reg +/- Cst"
    MEMtoMEM = "MEM(Reg +/- Cst) <- MEM(Reg +/- Cst)"
    SYSCALL = "syscall"
    INT80 = "int 0x80"

#######################
# List of all gadgets #
#######################
gadgets = []
    
####################################
# Structures used to store gadget  #
# according to their semantics     #
####################################

def find_insert_index(gadgetList, gadget_num):
    """
    Dichotomy search to insert a gadget into a list of 
    gadgets sorted from shorter to longer 
    Returns the index where the gadget should be inserted
    """
    global gadgets
    if( not gadgetList ):
        return 0
    # Try dichotomy search 
    lmin = 0
    lmax = len(gadgetList)-1
    while( True):
        if( lmax == lmin ):
            if( gadgets[gadgetList[lmin]].nbInstr >= gadgets[gadget_num].nbInstr ):
                return lmin
            else:
                return lmin+1
        
        lmoy = (lmax + lmin)/2
        if( gadgets[gadgetList[lmoy]].nbInstr > gadgets[gadget_num].nbInstr ):
            lmax = lmoy
        elif( gadgets[gadgetList[lmoy]].nbInstr < gadgets[gadget_num].nbInstr ) :
            lmin = lmoy+1
        else:
            if( gadgets[gadgetList[lmoy]].nbInstrREIL >= gadgets[gadget_num].nbInstrREIL ):
                lmax = lmoy
            else:
                lmin = lmoy+1


class CSTList:
    """
    self.values and self.preConditions are dict()
    self.values[cst] = list of gadgets_num for ? <- cst
    self.preConditions[cst] = associated preConditions 
    """
    def __init__(self):
        self.values = dict()
        self.preConditions = dict()
        
    def add(self, cst, gadget_num, preCond = CTrue() ):
        if( not cst in self.values ):
            self.values[cst] = []
            self.preConditions[cst] = []
        index = find_insert_index(self.values[cst], gadget_num)
        self.values[cst].insert(index, gadget_num)
        self.preConditions[cst].insert(index, preCond)
        
    def find(self, cst, constraint, assertion, enablePreConds=False, n=1 , maxSpInc=None):
        res = []
        if( not cst in self.values ):
            return []
            
        for i in range(0,len(self.values[cst])):
            if( len(res) >= n ):
                break
            gadget = gadgets[self.values[cst][i]]
            # Check maxSpInc
            if( maxSpInc and gadget.spInc > maxSpInc ):
                continue
            
            # Check if the constraint can be verified 
            (status, conds) = constraint.verify(gadget)
            if( status ):
                # if yes, check if the assertion verifies the constraint
                remaining = assertion.filter(conds + [self.preConditions[cst][i]])
                if( enablePreConds ):
                    res.append((gadget, remaining))
                else:
                    if( not remaining ):
                        res.append(gadget)
        if( enablePreConds ):
            return sorted(res, key=lambda x:len(x[1]))
        else:
            return res
                        
class REGList:
    def __init__(self):
        self.registers = dict()
    
    def add(self, reg, cst, gadget_num, preCond = CTrue()):
        if( not reg in self.registers ):
            self.registers[reg] = CSTList()
        self.registers[reg].add(cst, gadget_num, preCond)
    
    def find(self, reg, cst, constraint, assertion, enablePreConds=False, n=1, maxSpInc=None):
        res = []
        if( not reg in self.registers ):
            return []
        return self.registers[reg].find(cst, constraint, assertion, enablePreConds, n, maxSpInc)
        
    def check(self, reg, cst):
        if( reg in self.registers):
            if( self.registers[reg].get(cst)):
                return True
        return False
        
class MEMList:
    def __init__(self):
        self.registers = dict()

    def add(self, reg, cst, gadget_num, preCond = None):
        if( not reg in self.registers ):
            self.registers[reg] = CSTList()
        self.registers[reg].add(cst, gadget_num, preCond)
        
    def find(self, reg, cst, constraint, assertion, enablePreConds=False, n=1, maxSpInc=None):
        res = []
        if( not reg in self.registers ):
            return []
        return self.registers[reg].find(cst, constraint, assertion, enablePreConds, n, maxSpInc)

class MEMDict:
    def __init__(self):
        self.registers = dict()
        for reg in range(0,Arch.ssaRegCount):
            self.registers[reg] = dict()
            
    def addCst(self, addr_reg, addr_cst, cst, gadget_num, preCond=CTrue()):
        if( not addr_cst in self.registers[addr_reg]):
            self.registers[addr_reg][addr_cst] = CSTList()
        self.registers[addr_reg][addr_cst].add(cst, gadget_num, preCond)
    
    def addExpr(self, addr_reg, addr_cst, reg, cst, gadget_num, preCond=CTrue()):
        if( not addr_cst in self.registers[addr_reg]):
            self.registers[addr_reg][addr_cst] = REGList()
        self.registers[addr_reg][addr_cst].add(reg, cst, gadget_num, preCond)
            
    def findCst(self, addr_reg, addr_cst, cst, constraint, assertion, \
                enablePreCond=False, n=1, maxSpInc=None):
        if( not addr_cst in self.registers[addr_reg] ):
            return []
        return self.registers[addr_reg][addr_cst].find(cst, constraint,\
            assertion, enablePreCond, n, maxSpInc)
            
    def findExpr(self, addr_reg, addr_cst, reg, cst, constraint, assertion,\
                enablePreCond=False, n=1, maxSpInc=None):
        if( not addr_cst in self.registers[addr_reg] ):
            return []
        return self.registers[addr_reg][addr_cst].find(reg, cst, constraint,\
            assertion, enablePreCond, n, maxSpInc)


def select_special_gadgets(gadgetList, constraint, n=1, maxSpInc=None):
    """
    Function used by Database.find()
    """
    res = []
    for i in range(0, len(gadgetList)):
        if( constraint.verify(gadgets[gadgetList[i]])[0] ):
            res.append( gadgets[gadgetList[i]] )
            if( len(res) >= n ):
                break
    return res

class Database:
    def __init__(self, gadgets=[]):    
        # List of gadgets 
        self.gadgets = gadgets
        
        # Different query types 
        self.types = dict()
        self.types[QueryType.CSTtoREG] = dict()
        self.types[QueryType.REGtoREG] = dict()
        self.types[QueryType.MEMtoREG] = dict()
        self.types[QueryType.CSTtoMEM] = MEMDict()
        self.types[QueryType.REGtoMEM] = MEMDict()
        self.types[QueryType.MEMtoMEM] = MEMDict()
        self.types[QueryType.SYSCALL] = []
        self.types[QueryType.INT80] = []

        # Initialize them 
        for r in range(0, Arch.ssaRegCount):
            self.types[QueryType.CSTtoREG][r] = CSTList()
            self.types[QueryType.REGtoREG][r] = REGList()
            self.types[QueryType.MEMtoREG][r] = MEMList()
            
        if( gadgets ):
            info(string_bold("Sorting gadgets semantics\n")) 
        
        # Fill them 
        for i in range(0, len(gadgets)):
            charging_bar(len(gadgets)-1, i, 30)
            gadget = gadgets[i]
            # Check for special gadgets (int 0x80 and syscall
            if( gadget.type == GadgetType.INT80 ):
                self.types[QueryType.INT80].append(i)
                continue
            elif( gadget.type == GadgetType.SYSCALL ):
                self.types[QueryType.SYSCALL].append(i)
                continue
            # For XXXtoREG
            for reg, pairs in gadget.semantics.registers.iteritems():
                # Check if it is the final semantic for the register
                if( reg.ind < gadget.graph.lastMod[reg.num]):
                    # If not, skip this SSA register 
                    continue
                for p in pairs:
                    # For REGtoREG
                    if( isinstance(p.expr, SSAExpr)):
                        self.types[QueryType.REGtoREG][reg.num].add(p.expr.reg.num, 0, i, p.cond)
                    elif( isinstance(p.expr, OpExpr)):
                        (isInc, num, inc ) = p.expr.isRegIncrement(-1)
                        if( isInc ):
                            self.types[QueryType.REGtoREG][reg.num].add(num, inc, i, p.cond)
                    # For CSTtoREG
                    elif( isinstance(p.expr, ConstExpr)):
                        self.types[QueryType.CSTtoREG][reg.num].add(p.expr.value, i, p.cond)
                    # For MEMtoREG
                    elif( isinstance(p.expr, MEMExpr)):
                        if( isinstance(p.expr.addr, SSAExpr)):
                            self.types[QueryType.MEMtoREG][reg.num].add(p.expr.addr.reg.num, 0, i, p.cond)
                        elif( isinstance( p.expr.addr, OpExpr)):
                            (isInc, num, inc ) = p.expr.addr.isRegIncrement(-1)
                            if( isInc ):
                                self.types[QueryType.MEMtoREG][reg.num].add(num, inc, i, p.cond)
            # For XXXtoMEM 
            for addr, pairs in gadget.semantics.memory.iteritems():
                addr_reg = None
                addr_cst = None
                
                # Check if the address is of type REG + CST
                if( isinstance( addr, SSAExpr )):
                    addr_reg = addr.reg.num
                    addr_cst = 0
                elif( isinstance( addr, OpExpr )):
                    (isInc, addr_reg, addr_cst) = addr.isRegIncrement(-1)
                    if( not isInc ):
                        continue
                else:
                    continue
                # Going through spairs  
                for p in pairs:
                    # Check for integrity of the database
                    if( not isinstance(p.expr, Expr)):
                        raise Exception("Invalid dependency in fillGadgetLookUp(): " + str(p.expr))
                    # For REGtoMEM
                    if( isinstance(p.expr, SSAExpr)):
                        self.types[QueryType.REGtoMEM].addExpr(addr_reg, \
                            addr_cst, p.expr.reg.num, 0, i, p.cond)
                    elif( isinstance(p.expr, OpExpr)):
                        (isInc, num, inc ) = p.expr.isRegIncrement(-1)
                        if( isInc ):
                            self.types[QueryType.REGtoMEM].addExpr(addr_reg,\
                             addr_cst, num, inc, i, p.cond)
                    # For CSTtoMEM
                    elif( isinstance(p.expr, ConstExpr)):
                        self.types[QueryType.CSTtoMEM].addCst(addr_reg, \
                        addr_cst, p.expr.value, i, p.cond)
                    # For MEMtoMEM
                    elif( isinstance(p.expr, MEMExpr)):
                        if( isinstance(p.expr.addr, SSAExpr)):
                            self.types[QueryType.MEMtoMEM].addExpr(addr_reg,\
                             addr_cst, p.expr.addr.reg.num, 0, i, p.cond)
                        elif( isinstance( p.expr.addr, OpExpr)):
                            (isInc, num, inc ) = p.expr.addr.isRegIncrement(-1)
                            if( isInc ):
                                self.types[QueryType.MEMtoMEM].addExpr(addr_reg,\
                                 addr_cst, num, inc, i, p.cond)
    
    def find(self, qtype, arg1, arg2, constraint, assertion, enablePreConds=False, n=1, maxSpInc=None):
        """
        qtype - QueryType instance
        arg1 - (cst) or (reg,cst)
        arg2 - (cst) or (reg,cst)  
        constraint - Constraint to apply
        assertion - Additionnal assertion
        n - int (number of gadgets to return)
        enablePreConds - bool (search for gadgets with precondition suppport)
        
        Returns
        -------
        If enablePreConds: list of pairs (gadget_num, precondition_list)
        Otherwise : list of gadget_num
        
        Warning
        -------
        enablePreConds is always disabled if the query type is 
        INT80 or SYSCALL 
        """
        
        if( qtype == QueryType.CSTtoREG ):
            return self.types[QueryType.CSTtoREG][arg1].find(\
                    arg2, constraint, assertion, enablePreConds, n, maxSpInc)
        elif( qtype == QueryType.REGtoREG ):
            return self.types[QueryType.REGtoREG][arg1].find(\
                    arg2[0], arg2[1], constraint, assertion, enablePreConds, n, maxSpInc)
        elif( qtype == QueryType.MEMtoREG ):
            return self.types[QueryType.MEMtoREG][arg1].find(\
                    arg2[0], arg2[1], constraint, assertion, enablePreConds, n, maxSpInc) 
        elif( qtype == QueryType.CSTtoMEM ):
            return self.types[QueryType.CSTtoMEM].findCst(\
                arg1[0], arg1[1], arg2, constraint, assertion, enablePreConds, n, maxSpInc)
        elif( qtype == QueryType.REGtoMEM ):
            return self.types[QueryType.REGtoMEM].findExpr(\
                arg1[0], arg1[1], arg2[0], arg2[1], constraint, assertion, enablePreConds, n, maxSpInc)
        elif( qtype == QueryType.MEMtoMEM ):
            return self.types[QueryType.MEMtoMEM].findExpr(\
                arg1[0], arg1[1], arg2[0], arg2[1], constraint, assertion, enablePreConds, n, maxSpInc)
        elif( qtype == QueryType.INT80 ):
            return select_special_gadgets(self.types[QueryType.INT80], constraint, n, maxSpInc)
        elif( qtype == QueryType.SYSCALL ):
            return select_special_gadgets(self.types[QueryType.SYSCALL], constraint, n, maxSpInc)    
        else:
            raise Exception("Unknown query type: {}".format(qtype))

    def possibleInc(self, reg, constraint, assertion):
        """
        Returns a dict {1: [gadget1, gadget2], 8:gadget3, ...}
        Skips the increment 0 
        """
        global gadgets
        res = dict()
        lookUp = self.types[QueryType.REGtoREG][reg].registers[reg]
        for cst in lookUp.values:
            if( cst == 0 ):
                continue
            tmp = []
            for i in range(0,len(lookUp.values[cst])):
                gadget = gadgets[lookUp.values[cst][i]]
                (status, conds) = constraint.verify(gadget)
                if( status ):
                    # if yes, check if the assertion verifies the constraint
                    remaining = assertion.filter(conds + [lookUp.preConditions[cst][i]])
                    if( not remaining ):
                        tmp.append(gadget)
            res[cst] = tmp
        return res

    def possiblePopOffsets(self, reg, constraint, assertion):
        global gadgets
        res = dict()
        lookUp = self.types[QueryType.MEMtoREG][reg]\
                 .registers.get(Arch.n2r(Arch.currentArch.sp), None)
        if( lookUp is None ):
            return dict()
        for cst in lookUp.values:
            tmp = []
            for i in range(0, len(lookUp.values[cst])):
                gadget = gadgets[lookUp.values[cst][i]]
                (status, conds) = constraint.verify(gadget)
                if( status ):
                    # if yes, check if the assertion verifies the constraint
                    remaining = assertion.filter(conds + [lookUp.preConditions[cst][i]])
                    if( not remaining ):
                        tmp.append(gadget)
            res[cst] = tmp
        return res
        
    def possibleMemWrites(self, reg, cst, constraint, assertion, n=1):
        """
        n : nb of gadgets for each case ! 
        """
        global gadgets 
        res = dict()
        try:
            write_regs = self.types[QueryType.REGtoMEM].registers[reg][cst].registers.keys()
        except:
            return dict()
        for write_reg in write_regs:
            if( write_reg not in res):
                res[write_reg] = dict()
            lookUp = self.types[QueryType.REGtoMEM].registers[reg][cst].registers[write_reg]
            for write_cst in lookUp.values:
                tmp = []
                for i in range(0, len(lookUp.values[write_cst])):
                    gadget = gadgets[lookUp.values[write_cst][i]]
                    (status,conds) = constraint.verify(gadget)
                    if( status ):
                        # if yes, check if the assertion verifies the constraint
                        remaining = assertion.filter(conds + [lookUp.preConditions[write_cst][i]])
                        if( not remaining ):
                            tmp.append(gadget)
                res[write_reg][write_cst] = tmp
        return res
        
    def possibleAddressWrites(self, reg, cst, constraint, assertion, n=1):
        """
        : : nb of gadgets for each case !! 
        """
        global gadgets
        res = dict()
        for addr_reg in self.types[QueryType.REGtoMEM].registers.keys():
            for addr_cst in self.types[QueryType.REGtoMEM].registers[addr_reg]:
                # Get the lookUp for list of deps for MEM(addr_reg, addr_cst)
                lookUp = self.types[QueryType.REGtoMEM].registers[addr_reg][addr_cst]
                if( addr_reg not in res ):
                    res[addr_reg] = dict()
                # The get matching gadgets for reg/cst 
                found = lookUp.find(reg, cst, constraint, assertion, n=n)
                if( found ):
                    # Found mem(addr_reg, addr_cst) <- reg+cst, add them !! 
                    if( addr_cst not in reg[addr_reg]):
                        res[addr_reg][addr_cst] = []
                    res[addr_reg][addr_cst] += found
                
                    
########################
# Module wise database #
########################
db = None
# Wrapper
def DBSearch(qtype, arg1, arg2, constraint, assertion, n=1, enablePreConds=False, maxSpInc=None):
    return db.find(qtype, arg1, arg2, constraint, assertion, enablePreConds, n, maxSpInc)

def DBPossibleInc(reg, constraint, assertion):
    """
    Return a list of constants C such that reg <- reg + C is possible 
    """
    return db.possibleInc(reg, constraint, assertion)
    
def DBPossiblePopOffsets(reg, constraint, assertion):
    """
    Return a list of offsets X such that reg <- mem(sp+X) possible 
    """
    return db.possiblePopOffsets(reg, constraint,assertion)
    
def DBPossibleMemWrites(addr_reg, addr_cst, constraint, assertion, n=1):
    """
    Return the list of [reg, cst] such that mem(addr_reg+addr_cst)<- reg+cst
    """
    return db.possibleMemWrites(addr_reg, addr_cst, constraint, assertion, n)
    
def DBPossibleAddressWrites(reg, cst, constraint, assertion, n=1):
    """
    Return the list of [addr_reg, addr_cst] such than mem(addr_reg, addr_cst) <- reg+cst
    """
    return db.possibleAddressWrites(reg, cst, constraint, assertion, n)

#############################
# Build the list of gadgets #
# And fill database         #
#############################
sigint = False
def build(pair_list):
    """
    Takes a list of pairs (addr, raw_asm) corresponding to 
    gagets (their address and their intructions as a byte string)
    Fills the 'gadgets' and 'db' global structures ;) 
    """
    def sigint_handler(signal, frame):
        global sigint
        sigint = True
    
    def timeout_handler(signum, frame):
        global sigalarm
        sigalarm = True
        signal.alarm(0)
        raise TimeOutException('Timeout')
    
    global gadgets, db, sigint
    gadgets = []
    raw_to_gadget = dict()
    sigint = False
    original_sigint_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGALRM, timeout_handler)
    
    info(string_bold("Creating gadget database\n"))  
    startTime = datetime.now()
    success = i = 0
    # Create the gadgets list
    for (addr, raw) in pair_list:
        charging_bar(len(pair_list)-1, i, 30)
        if( sigint ):
            break
        if( raw in raw_to_gadget):
            gadgets[raw_to_gadget[raw]].addrList.append(addr)
            success += 1
        else:
            try:
                signal.alarm(1)
                gadget = Gadget([addr], raw)
                signal.alarm(0)
                success += 1
                gadgets.append( gadget )
                raw_to_gadget[raw] = len(gadgets)-1
            except (GadgetException, TimeOutException) as e :
                signal.alarm(0)
                if( isinstance(e, GadgetException)):
                    log("Gadget ({}) :  ".format('\\x'+'\\x'\
                    .join("{:02x}".format(ord(c)) for c in raw)) + str(e))
        i += 1
    # Find syscalls
        # TODO 
    
    # Getting time   
    cTime = datetime.now() - startTime
    signal.signal(signal.SIGINT, original_sigint_handler) 
     
    if( sigint ):
        print("\n")
        fatal("SIGINT ended the analysis prematurely, gadget database might be incomplete\n")
        sigint = False
    notify("Gadgets analyzed : " + str(len(pair_list)))
    notify("Successfully translated : " + str(success))
    notify("Computation time : " + str(cTime))
    
    # Create the database
    db = Database(gadgets)

#############################
#   Initialisation function #
#############################
def initDB():
    global db, gadgets
    gadgets = []
    db = Database()
