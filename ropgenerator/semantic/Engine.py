# -*- coding:utf-8 -*- 
# Engine module: chaining gadgets and building ropchains

from ropgenerator.semantic.ROPChains import ROPChain
from ropgenerator.Database import QueryType, DBSearch, REGList
from ropgenerator.Constraints import Chainable, RegsNotModified, Constraint, Assertion
import ropgenerator.Architecture as Arch

def search(qtype, arg1, arg2, constraint, assertion, n=1, enablePreConds=False, \
            record=None):
    """
    Searches for gadgets 
    basic = False means that we don't call _basic_strategy
    chainable = True means that we want only chainable gadgets 
    init = True means the search just started and we have to do some initialization in SearchHelper
    """
    # Set the search record and increase its depth of 1 
    if ( record is None):
        record = SearchRecord()
    record.incDepth()
    # Search basic 
    res = _basic(qtype, arg1, arg2, constraint.add(Chainable(ret=True)), assertion, n)
    # Search chaining 
    if( len(res) < n ):
        res += _chain(qtype, arg1, arg2, constraint, assertion, record, n-len(res))
    # Reset the depth of the search record 
    record.decDepth()
    return sorted(res)
    
def _basic(qtype, arg1, arg2, constraint, assertion, n=1, noPadding=False):
    """
    Search for gadgets basic method ( without chaining ) 
    Direct Database check  
    """
    # Check for special gadgets
    if( qtype == QueryType.INT80 or qtype == QueryType.SYSCALL):
        gadgets = DBSearch(qtype, arg1, arg2, constraint, assertion, n=1)
        res = [ROPChain().addGadget(g) for g in gadgets]
        return res
    
    # Regular gadgets 
    gadgets =  DBSearch(qtype, arg1, arg2, constraint,assertion, n)
    if( noPadding ):
        return [ROPChain().addGadget(g) for g in gadgets]
    else:
        res = []
        padding = constraint.getValidPadding(Arch.currentArch.octets)
        for g in gadgets: 
            chain = ROPChain().addGadget(g)
            # Padding the chain if possible 
            if( g.spInc > 0 ):
                for i in range(0, g.spInc/Arch.currentArch.octets - 1):
                    chain.addPadding(padding)
            # Adding to the result 
            res.append(chain)
    return res

def _chain(qtype, arg1, arg2, constraint, assertion, record, n=1):
    """
    Search for ropchains by chaining gadgets 
    """
    global impossible_REGtoREG
    res = []  
    if( qtype == QueryType.REGtoREG):
        if( record.impossible_REGtoREG.check(arg1, arg2[0], arg2[1], constraint.getRegsNotModified())\
        or record.getDepth() >= 4):
            return [] 
        res += _REGtoREG_transitivity(arg1, arg2, constraint, assertion, record, n)
        if( not res ):
            record.impossible_REGtoREG.add(arg1, arg2[0], arg2[1], constraint.getRegsNotModified())
        return res

def _REGtoREG_transitivity(arg1, arg2, constraint, assertion, record, n=1):
    """
    Perform REG1 <- REG2 with REG1 <- REG3 <- REG2
    """
    res = []
    for inter_reg in range(0, Arch.ssaRegCount):
        if( inter_reg == arg1 or inter_reg == arg2[0] or (inter_reg in record.unusable_REGtoREG)):
            continue
        # Find reg1 <- inter_reg without using arg2    
        record.unusable_REGtoREG.append(arg2[0])
        inter_to_arg1_list = search(QueryType.REGtoREG, arg1, (inter_reg, 0), \
                constraint, assertion, n, record=record )
        record.unusable_REGtoREG.remove(arg2[0])
        if( not inter_to_arg1_list ):
            continue
        
        # Find inter_reg <- arg2 without using arg1
        record.unusable_REGtoREG.append(arg1)
        for arg2_to_inter in search(QueryType.REGtoREG, inter_reg, arg2, \
                constraint, assertion, n, record=record):
            for inter_to_arg1 in inter_to_arg1_list:
                res.append(arg2_to_inter.addChain(inter_to_arg1, new=True))
                if( len(res) >= n ):
                    return res
        record.unusable_REGtoREG.remove(arg1)
    return res 

###################################################################
# Data structures to store some info from the different searches
# and fasten the computation time for the next searches 
###################################################################
class RecordREGtoREG:
    def __init__(self):
        self.regs = dict()
        
    def add(self, reg1, reg2, cst, regsNotModified):
        if( not reg1 in self.regs ):
            self.regs[reg1] = dict()
        if( not reg2 in self.regs[reg1] ):
            self.regs[reg1][reg2] = dict()
        if( not cst in self.regs[reg1][reg2] ):
            self.regs[reg1][reg2][cst] = []
        # Adding 
        newNotModInt = sum([(1 << r) for r in regsNotModified])
        for i in range(0, len(self.regs[reg1][reg2][cst])):
            prevNotModInt = self.regs[reg1][reg2][cst][i]
            if( prevNotModInt & newNotModInt == prevNotModInt ):
                # new regsNotModified included in the previous ones
                return
            elif( prevNotModInt & newNotModInt == newNotModInt ):
                # previous regsNotModified included in the new one
                # We replace it 
                self.regs[reg1][reg2][cst][i] = newNotModInt
                return
        # If new really different from all others, add it 
        self.regs[reg1][reg2][cst].append(newNotModInt)
        
            
    def check(self, reg1, reg2, cst, regsNotModified):
            """
            Return True iff reg1 <- reg2 + cst in the Record 
            with the specified regsNotModified 
            """
            try:
                regsNotModified_list = self.regs[reg1][reg2][cst]
            except:
                return False
            regsInt = sum([(1<<r) for r in regsNotModified])
            for notModInt in regsNotModified_list:
                if( regsInt & notModInt == notModInt ):
                    # recorded regs included in specified regs 
                    return True
            return False

    def copy(self):
        new = RecordREGtoREG()
        for reg1 in self.regs:
            new.regs[reg1] = dict()
            for reg2 in self.regs[reg1]:
                new.regs[reg1][reg2] = dict()
                for cst in self.regs[reg1][reg2]:
                    new.regs[reg1][reg2][cst] = list(self.regs[reg1][reg2][cst])
        return new
    
class SearchRecord:
    def __init__(self):
        self.depth = 0
        self.impossible_REGtoREG = global_impossible_REGtoREG.copy()
        self.unusable_REGtoREG = []
        
    def getDepth(self):
        return self.depth
        
    def incDepth(self):
        self.depth += 1
        
    def decDepth(self):
        self.depth -= 1

################################################
# Global records for the ROPGenerator sessions
# Used for optimisations 
################################################

global_impossible_REGtoREG = RecordREGtoREG()

#############################
# Initialization function   #
#############################
def initEngine():
    #init_impossible_REGtoREG()
    pass

def init_impossible_REGtoREG():
    global global_impossible_REGtoREG
    record = SearchRecord()
    for reg1 in range(0, Arch.ssaRegCount):
        for reg2 in range(0, Arch.ssaRegCount):
            print("Doing {} <- {} ".format(reg1, reg2))
            if (reg2 == reg1):
                continue
            search(QueryType.REGtoREG, reg1, [reg2,0], Constraint(), Assertion(), n=1, record=record)
    global_impossible_REGtoREG = record.impossible_REGtoREG

