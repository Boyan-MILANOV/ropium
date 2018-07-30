# -*- coding:utf-8 -*- 
# Engine module: chaining gadgets and building ropchains

from ropgenerator.semantic.ROPChains import ROPChain, validAddrStr
from ropgenerator.Database import QueryType, DBSearch, DBPossibleInc, DBPossiblePopOffsets, REGList
from ropgenerator.Constraints import Chainable, RegsNotModified, Constraint, Assertion
from ropgenerator.Gadget import RetType
from ropgenerator.IO import string_bold
from itertools import product
import ropgenerator.Architecture as Arch

###################################
# Search functions and strategies #
###################################

def search(qtype, arg1, arg2, constraint, assertion, n=1, enablePreConds=False, \
            record=None, comment=None):
    """
    Searches for gadgets 
    """
    # Set the search record and increase its depth of 1 
    if ( record is None):
        record = SearchRecord()
    record.incDepth()
    # Search basic 
    res = _basic(qtype, arg1, arg2, constraint.add(Chainable(ret=True)), assertion, n)
    # Search chaining 
    if( len(res) < n and (qtype not in [QueryType.SYSCALL, QueryType.INT80])):
        res += _chain(qtype, arg1, arg2, constraint, assertion, record, n-len(res), comment)
    # Reset the depth of the search record 
    record.decDepth()
    return sorted(res)

def search_not_chainable(qtype, arg1, arg2, constraint, assertion, n=1):
    return _basic(qtype, arg1, arg2, constraint, assertion, n)
    
    
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

def _chain(qtype, arg1, arg2, constraint, assertion, record, n=1, comment=None):
    """
    Search for ropchains by chaining gadgets 
    """
    res = []  
    # For any types, adjust the returns 
    res += _adjust_ret(qtype, arg1, arg2, constraint, assertion, n, comment)
    
    if( qtype == QueryType.CSTtoREG ):
        res += _CSTtoREG_pop(arg1, arg2, constraint, assertion, n-len(res), comment)
        if( len(res) < n ):
            res += _CSTtoREG_transitivity(arg1, arg2, constraint, assertion, n-len(res), comment)
            
    elif( qtype == QueryType.REGtoREG):
        if( record.impossible_REGtoREG.check(arg1, arg2[0], arg2[1], constraint.getRegsNotModified())\
        or record.getDepth() >= 5):
            return [] 
        if( len(res) < n ):
            res += _REGtoREG_transitivity(arg1, arg2, constraint, assertion, record, n-len(res))
        #if( len(res) < n):
            #res += _REGtoREG_increment(arg1, arg2, constraint, assertion, record, n-len(res))
        if( not res ):
            record.impossible_REGtoREG.add(arg1, arg2[0], arg2[1], constraint.getRegsNotModified())
    
    return res

def _adjust_ret(qtype, arg1, arg2, constraint, assertion, n, comment):
    """
    Search with basic but adjust the bad returns they have 
    """
    res = []
    possible = _basic(qtype, arg1, arg2, \
            constraint.add(Chainable(jmp=True, call=True)), assertion, n)        
    for chain in possible:
        g = chain.chain[0]
        ret_reg = g.retValue.reg.num
        #Check if not modified within the gadget
        if( ret_reg in g.modifiedRegs()):
            continue
        # Check if stack is preserved 
        spInc = g.spInc
        if( not spInc ):
            continue
        # Find adjustment 
        if( g.spInc < 0 ):
            offset = -1 * g.spInc
        else: 
            if( g.retType == RetType.JMP ):
                offset = 0 
            else:
                offset = Arch.octets() 
        adjust_gadgets = search(QueryType.MEMtoREG, Arch.ipNum(), \
                (Arch.spNum(),offset), constraint, assertion, n=1)
        if( not adjust_gadgets ):
            continue
        else:
            adjust_addr = int(validAddrStr(adjust_gadgets[0].chain[0],\
                    constraint.getBadBytes(), Arch.octets()),  16)
        # Put the gadget address in the register 
        adjust = search(QueryType.CSTtoREG, ret_reg, adjust_addr, \
            constraint.add(RegsNotModified([arg2[0]])), assertion, n=1,\
            comment="Address of "+string_bold(str(adjust_gadgets[0].chain[0])))
        if( adjust ):
            res.append(adjust[0].addGadget(g))
            if( len(res) >= n ):
                return res
    return res
        

def _CSTtoREG_pop(reg, cst, constraint, assertion, n=1, comment=None):
    """
    Returns a payload that puts cst into register reg by poping it from the stack
    """ 
    if (n < 1 ):
        return []
    # Check if the cst is incompatible with the constraint
    if( not constraint.badBytes.verifyAddress(cst)):
        return []
    
    if( not comment ):
        comment = "Constant: " +string_bold("0x{:x}".format(cst))
        
    # Direct pop from the stack
    res = []
    possible = DBPossiblePopOffsets(reg, constraint.add(Chainable(ret=True)), assertion) 
    for offset in sorted(filter(lambda x:x>=0, possible.keys())):
        possible_gadgets = [g for g in possible[offset]\
            if g.spInc >= Arch.currentArch.octets \
            and g.spInc - Arch.currentArch.octets > offset ]
        # Pad the gadgets 
        padding = constraint.getValidPadding(Arch.currentArch.octets)
        for gadget in possible_gadgets:
            chain = ROPChain([gadget])
            for i in range(0, gadget.spInc-Arch.currentArch.octets, Arch.currentArch.octets):
                if( i == offset):
                    chain.addPadding(cst, comment)
                else:
                    chain.addPadding(padding)
            res.append(chain)
            if( len(res) >= n ):
                return res
    return res

def _CSTtoREG_transitivity(reg, cst, constraint, assertion, n=1, comment=None):
    """
    Perform REG1 <- CST with REG1 <- REG2 <- CST
    """
    res = []
    for inter in range(0, Arch.ssaRegCount):
        if( inter == reg or inter in constraint.getRegsNotModified() ):
            continue
        # Find reg <- inter 
        inter_to_reg = search(QueryType.REGtoREG, reg, (inter,0), constraint, assertion, n)
        if( inter_to_reg ):
            # We found ROPChains s.t reg <- inter
            # Now we want inter <- cst 
            cst_to_inter = _basic(QueryType.CSTtoREG, inter, cst, constraint, assertion, n/len(inter_to_reg)+1)
            for chain2 in inter_to_reg:
                for chain1 in cst_to_inter:
                    res.append(chain1.addChain(chain2, new=True))
            if( len(res) < n ):
                cst_to_inter = _CSTtoREG_pop(inter, cst, constraint, assertion, n/(len(inter_to_reg))+1, comment)
                for chain2 in inter_to_reg:
                    for chain1 in cst_to_inter:
                        res.append(chain1.addChain(chain2, new=True))
        # Did we get enough chains ?             
        if( len(res) >= n ):
            return res[:n]
    # Return what we got 
    return res


def _REGtoREG_transitivity(arg1, arg2, constraint, assertion, record, n=1):
    """
    Perform REG1 <- REG2+CST with REG1 <- REG3 <- REG2+CST
    """
    # If reg1 <- reg1 + 0, return 
    if( arg1 == arg2[0] and arg2[1] == 0 ):
        return []
    
    res = []
    for inter_reg in range(0, Arch.ssaRegCount):
        if( inter_reg == arg1 or (inter_reg == arg2[0] and arg2[1]==0)\
            or (inter_reg in record.unusable_REGtoREG) or inter_reg == Arch.ipNum()\
            or (inter_reg == Arch.spNum()) ):
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
                constraint, assertion, n/len(inter_to_arg1_list)+1, record=record):
            for inter_to_arg1 in inter_to_arg1_list:
                res.append(arg2_to_inter.addChain(inter_to_arg1, new=True))
                if( len(res) >= n ):
                    return res
        record.unusable_REGtoREG.remove(arg1)
    return res 

def _REGtoREG_increment(arg1, arg2, constraint, assertion, record, n=1):
    """
    Perform REG1 <- REG2+CST with REG1<-REG2; REG1 += CST
    """
    # Find possible increments gadgets for arg1
    possible_inc = DBPossibleInc(arg1, constraint, assertion)
    print("possible inc " + str(possible_inc))
    # Combine increments to get the constant 
    combination = combine_increments(possible_inc.keys(), arg2[1])
    print("combination : " + str(combination))
    if( not combination ):
        return []
    nb = reduce(lambda x,y:x*y, [len(possible_inc[inc]) for inc in combination])
    # Translate increments into gadgets 
    inc_gadgets = [possible_inc[inc] for inc in combination]
    print("inc_gadgets " + str(inc_gadgets))
    
    # And Create full ropchains
    res = inc_gadgets[0]
    for gadgets in inc_gadgets[1:]:
        res = product(res, gadgets)
    print("res : " + str(res))
    res = [ROPChain(c) for c in res]
    print("res : " + str(res))
    if( arg1 != arg2[0] ):
        # Get gadgets REG1 <- REG2
        arg2_to_arg1 = search(QueryType.REGtoREG, arg1, (arg2[0],0), \
                    constraint, assertion, record, n/nb + 1)
        res = [chain.addChain(c, new=True) for chain in arg2_to_arg1 for c in res]
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


#########
# Utils #
#########

def combine_increments(increments_list, goal):
    """
    increments_list : list of (inc)
    goal : int
    Returns the shortest list of gadgets such that the sum of their
        increments equals the goal
    """
    MIN_GOAL = 1
    MAX_GOAL = 300
    INFINITY = 999999999
    if( goal < MIN_GOAL or goal > MAX_GOAL ):
        return []
    inc_list = filter(lambda x:x<=goal, increments_list)
    inc_list.sort(key=lambda x:x)
    n = len(inc_list)
    if( n == 0 ):
        return []
    # Initialize dyn algorithm 
    shortest = [[INFINITY]*(goal+1)]*n
    for subgoal in range(goal+1):
        if subgoal % inc_list[0] == 0:
            shortest[0][subgoal] = subgoal // inc_list[0]
    for i in range(1,n):
        for j in range(goal+1):
            shortest[i][j] = shortest[i-1][j]
            if( inc_list[i] <= j ):
                if( shortest[i][j-inc_list[i]] + 1 < shortest[i][j]):
                    shortest[i][j] = shortest[i][j-inc_list[i]] + 1
                    
    # Select increments and gadgets
    chosen = [0]*n
    res = []
    j = goal
    i = n -1
    while j > 0 and i >= 0:
        if( j >= inc_list[i] ):
            if( shortest[i][j-inc_list[i]] + 1 == shortest[i][j] ):
                chosen[i] = chosen[i] + 1
                res.append(inc_list[i])
                j = j - inc_list[i]
                continue
        i = i - 1
    return res


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

