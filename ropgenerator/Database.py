# -*- coding:utf-8 -*-
# Database module: save and classify gadgets 
from enum import Enum
from ropgenerator.Gadget import GadgetType
from ropgenerator.Expressions import SSAExpr, ConstExpr, MEMExpr, OpExpr, Op

import ropgenerator.Architecture as Arch

def DatabaseException(Exception):
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
    MEMtoREG = "Reg <- Mem +/- Cst"
    CSTtoMEM = "Mem <- Cst"
    REGtoMEM = "Mem <- Reg +/- Cst"
    MEMtoMEM = "Mem <- Mem +/- Cst"
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
     # Try dichotomy search 
    lmin = 0
    lmax = len(gadgetlist)-1
    while( True):
        lmoy = (lmax + lmin)/2
        if( lmax == lmin or gadgets[gadgetList[lmoy]].nbInstr == gadgets[gadget_num].nbInstr ):
            return lmoy
        elif( lmin == lmax ):
            if ( gadgetDB[self.values[cst][lmin]].nbInstr >= gadgetDB[gadget_num].nbInstr ):
                return lmin
            else:
                return lmin+1 
        else:
            if( gadgets[gadgetList[lmoy]].nbInstr > gadgets[gadget_num].nbInstr ):
                lmax = lmoy
            else:
                lmin = lmoy+1


class CSTList:
    """
    self.values and self.preConditions are dict()
    self.values[cst] = list of gadgets for ? <- cst
    self.preConditions[cst] = associated preConditions 
    """
    def __init__(self):
        self.values = []
        self.preConditions = []
        
    def add(self, cst, gadget_num, preCond = None ):
        if( not cst in self.values ):
            self.values[cst] = []
            self.preConditions[cst] = []
        index = find_insert_index(self.values[cst], gadget_num)
        self.values[cst].insert(index, gadget_num)
        self.preConditions[cst].insert(index, gadget_num)
            
class REGList:
    def __init__(self):
        self.registers = dict()
    
    def add(self, reg, cst, gadget_num, preCond = None):
        if( not reg in self.registers ):
            self.registers[reg] = CSTList()
        self.registers[reg].add(cst, gadget_num, preCond)
        
class MEMList:
    def __init__(self):
        self.registers = dict()

    def add(self, reg, cst, gadget_num, preCond = None):
        if( not reg in self.registers ):
            self.registers[reg] = CSTList()
        self.registers[reg].add(cst, gadget_num, preCond)

class MEMDict:
    def __init__(self):
        self.registers = dict()
        for reg in range(0,Arch.ssaRegCount):
            self.registers[reg] = dict()
            
    def addCst(self, addr_reg, addr_cst, cst, gadget_num, preCond=None):
        if( not addr_cst in self.registers[addr_reg]):
            self.registers[addr_reg][addr_cst] = CSTList()
        self.registers[addr_reg][addr_cst].add(cst, gadget_num, preCond)
    
    def addExpr(self, addr_reg, addr_cst, reg, cst, gadget_num, preCond=None):
        if( not addr_cst in self.registers[addr_reg]):
            self.registers[addr_reg][addr_cst] = REGList()
        self.registers[addr_reg][addr_cst].add(reg, cst, gadget_num, preCond)
            
            
class RegularDatabase:
    def __init__(self, gadgets):        
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
            
        # Fill them 
        for i in range(0, len(gadgets)):
            #charging_bar(len(gadgetDB)-1, i, 30)
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
                for p in pairs:
                    if not p.cond.isTrue():
                        break
                    # For REGtoREG
                    if( isinstance(p.expr, SSAExpr)):
                        self.types[QueryType.REGtoREG][reg.num].add(p.expr.reg.num, 0, i)
                    elif( isinstance(p.expr, OpExpr)):
                        (isInc, num, inc ) = p.expr.isRegIncrement(-1)
                        if( isInc ):
                            self.types[QueryType.REGtoREG][reg.num].add(num, inc, i)
                    # For CSTtoREG
                    elif( isinstance(p.expr, ConstExpr)):
                        self.types[QueryType.CSTtoREG][reg.num].add_gadget(p.expr.value, i)
                    # For MEMtoREG
                    elif( isinstance(p.expr, MEMExpr)):
                        if( isinstance(p.expr.addr, SSAExpr)):
                            self.types[QueryType.MEMtoREG][reg.num].add(p.expr.addr.reg.num, 0, i)
                        elif( isinstance( p.expr.addr, OpExpr)):
                            (isInc, num, inc ) = p.expr.addr.isRegIncrement(-1)
                            if( isInc ):
                                self.types[QueryType.MEMtoREG][reg.num].add(num, inc, i)
            # For XXXtoMEM 
            for addr, pairs in gadget.semantics.memory:
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
                            addr_cst, p.expr.reg.num, 0, i)
                    elif( isinstance(p.expr, OpExpr)):
                        (isInc, num, inc ) = p.expr.isRegIncrement(-1)
                        if( isInc ):
                            self.types[QueryType.REGtoMEM].addExpr(addr_reg,\
                             addr_cst, num, inc, i)
                    # For CSTtoMEM
                    elif( isinstance(p.expr, ConstExpr)):
                        self.types[QueryType.CSTtoMEM].addCst(addr_reg, \
                        addr_cst, p.expr.value, i)
                    # For MEMtoMEM
                    elif( isinstance(p.expr, MEMExpr)):
                        if( isinstance(p.expr.addr, SSAExpr)):
                            self.types[QueryType.MEMtoMEM].addExpr(addr_reg,\
                             addr_cst, p.expr.addr.reg.num, 0, i)
                        elif( isinstance( p.expr.addr, OpExpr)):
                            (isInc, num, inc ) = p.expr.addr.isRegIncrement(-1)
                            if( isInc ):
                                self.types[QueryType.MEMtoMEM].addExpr(addr_reg,\
                                 addr_cst, num, inc, i)
