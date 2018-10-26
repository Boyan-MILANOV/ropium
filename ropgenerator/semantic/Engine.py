# -*- coding:utf-8 -*- 
# Engine module: chaining gadgets and building ropchains

from ropgenerator.semantic.ROPChains import ROPChain, validAddrStr
from ropgenerator.Database import QueryType, DBSearch, DBPossibleInc, DBPossiblePopOffsets, REGList, DBPossibleMemWrites
from ropgenerator.Constraints import Chainable, RegsNotModified, Constraint, Assertion, CstrTypeID, RegsNoOverlap
from ropgenerator.Gadget import RetType
from ropgenerator.IO import string_bold
from itertools import product
import ropgenerator.Architecture as Arch

###################################
# Search functions and strategies #
###################################     

LMAX = 80 # Default max number of elements (padding included) in ROPChains
MAXDEPTH = 6

def search(qtype, arg1, arg2, constraint, assertion, n=1, clmax=LMAX, enablePreConds=False, \
            noPadding=False, comment=None, maxdepth=4, optimizeLen=False):
                
    """
    Wrapper for search_first_hit and search_optimize_len
    """
    global MAXDEPTH
    
    env = SearchEnvironment(clmax, constraint, assertion, MAXDEPTH, enablePreConds, noPadding)
    return _search(qtype, arg1, arg2, env, n, optimizeLen)

def search_not_chainable(qtype, arg1, arg2, constraint, assertion, n=1, clmax=10000):
    global MAXDEPTH
    
    env = SearchEnvironment(clmax, constraint, assertion, MAXDEPTH, noPadding=True)
    return _basic(qtype, arg1, arg2, env, n)

def _search(qtype, arg1, arg2, env, n=1, optimizeLen=False):
                
    """
    Wrapper for search_first_hit and search_optimize_len
    """
    # Test the max length of the chain 
    if( env.getLmax() <= 0 ):
        return []
    # Test depth of the search 
    if( env.reachedMaxDepth()):
        return []
    else:
        env.incDepth()
    
    if( optimizeLen ):
        res = _search_optimize_len(qtype, arg1, arg2, env, n)
    else:
        res = _search_first_hit(qtype, arg1, arg2, env, n)
    
    env.decDepth()
    return res
        
def _search_first_hit(qtype, arg1, arg2, env, n=1):
    """
    Searches for gadgets 
    """
    
    # Search basic 
    # Add Chainable constraint in env.constraint
    
    constraint = env.getConstraint()
    env.setConstraint(constraint.add(Chainable(ret=True)))
    res = _basic(qtype, arg1, arg2, env, n)
    # Restore normal constraint
    env.setConstraint(constraint)
    # Search chaining 
    if( len(res) < n and (qtype not in [QueryType.SYSCALL, QueryType.INT80])):
        res += _chain(qtype, arg1, arg2, env, n-len(res))
    return sorted(res)

def _search_not_chainable(qtype, arg1, arg2, env, n=1):
    # Save and set env
    save_noPadding = env.noPadding
    env.setNoPadding(True)
    # Search
    res = _basic(qtype, arg1, arg2, env, n)
    # Restore env 
    env.setNoPadding(save_noPadding)
    return res
    
def _search_optimize_len(qtype, arg1, arg2, env, n=1):
    """
    Tries to find the shorter ROPChain possible 
    by using dichotomic calls to search() 
    """
    if( env.getLmax() <= 0 ):
        return []
    
    # Save env
    saved_lmax = env.getLmax()

    # Dichotomy search
    lmin = 1 
    lmax = env.getLmax()
    best_find = []
    while( lmin != lmax):
        lmoy = (lmin+lmax+1)/2
        # Set env
        env.setLmax(lmoy)
        # Search
        res = _search(qtype, arg1, arg2, env, n)
        if( res ):
            # If found we can try shorter 
            best_find = res
            lmax = lmoy-1
        else:
            # If not found we try longer 
            lmin = lmoy
    
    # Set env 
    env.setLmax(lmax)
    # Search
    res = search(qtype, arg1, arg2, env, n)
    # Restore env 
    env.setLmax(saved_lmax)
    
    if( res ):
        return res
    else:
        return best_find
            
def _basic(qtype, arg1, arg2, env, n=1):
    """
    Search for gadgets basic method ( without chaining ) 
    Direct Database check  
    """
    if( env.getLmax() <= 0 ):
        return []
    
    if( env.getNoPadding() ):
        maxSpInc = None
    else:
        maxSpInc = env.getLmax()*Arch.octets()
    
    # Check for special gadgets
    if( qtype == QueryType.INT80 or qtype == QueryType.SYSCALL):
        gadgets = DBSearch(qtype, arg1, arg2, env.getConstraint(), env.getAssertion(), n=n, maxSpInc=maxSpInc)
        res = [ROPChain().addGadget(g) for g in gadgets]
        return res
    
    # Check if the type is IP <- ... 
    # In this case we remove the CHAINABLE constraint which makes no sense 
    if( arg1 == Arch.ipNum() ):
        constraint2 = env.getConstraint().remove([CstrTypeID.CHAINABLE])
    else:
        constraint2 = env.getConstraint()
    
    # Check to add assertions when looking for Memory gadgets
    if( qtype == QueryType.CSTtoMEM or qtype == QueryType.REGtoMEM ):
        assertion2 = env.getAssertion().add(RegsNoOverlap([(arg1[0], Arch.spNum())]))
    else:
        assertion2 = env.getAssertion()
    
    # Regular gadgets 
    # maxSpInc -> +1 because we don't count the ret but -1 because the gadget takes one place 
    gadgets =  DBSearch(qtype, arg1, arg2, constraint2, assertion2, n, maxSpInc=maxSpInc)
    if( env.getNoPadding() ):
        return [ROPChain().addGadget(g) for g in gadgets]
    else:
        res = []
        padding = constraint2.getValidPadding(Arch.octets())
        for g in gadgets: 
            chain = ROPChain().addGadget(g)
            # Padding the chain if possible 
            if( g.spInc > 0 ):
                for i in range(0, g.spInc/Arch.octets() - 1):
                    chain.addPadding(padding)
            # Adding to the result 
            res.append(chain)
    return res

def _chain(qtype, arg1, arg2, env, n=1):
    """
    Search for ropchains by chaining gadgets 
    """
    return []
    
    # Test clmax
    if( clmax <= 0 ):
        return []
    # Test record 
    if( record.reachedMaxDepth() ):
        return []
    
    res = []  
    if( qtype == QueryType.CSTtoREG ):
        res += _CSTtoREG_pop(arg1, arg2, constraint, assertion, n-len(res), clmax, comment)
        if( len(res) < n ):
            res += _CSTtoREG_transitivity(arg1, arg2, constraint, assertion, n-len(res), clmax, comment, maxdepth)
    elif( qtype == QueryType.REGtoREG):
        if( record.impossible_REGtoREG.check(arg1, arg2[0], arg2[1], constraint.getRegsNotModified())):
            return [] 
        if( len(res) < n ):
            res += _REGtoREG_transitivity(arg1, arg2, constraint, assertion, record, n-len(res), clmax)
        #if( len(res) < n):
            #res += _REGtoREG_increment(arg1, arg2, constraint, assertion, record, n-len(res))
        if( not res ):
            record.impossible_REGtoREG.add(arg1, arg2[0], arg2[1], constraint.getRegsNotModified())
    elif( qtype == QueryType.MEMtoREG ):
        res += MEMtoREG_transitivity(arg1, arg2, constraint, assertion, n-len(res), clmax )
    elif( qtype == QueryType.CSTtoMEM ):
        res += CSTtoMEM_write(arg1, arg2, constraint, assertion, n-len(res), clmax)
    elif( qtype == QueryType.REGtoMEM ):
        res += REGtoMEM_transitivity(arg1,arg2, constraint, assertion, n-len(res), clmax)    
    # For any types, adjust the returns 
    if( len(res) < n ):
        res += _adjust_ret(qtype, arg1, arg2, constraint, assertion, n, clmax, record.copy(), comment)
    
    return res


def _REGtoREG_transitivity(arg1, arg2, env, n=1 ):
    """
    Perform REG1 <- REG2+CST with REG1 <- REG3 <- REG2+CST
    """
    ID = "REGtoREG_transitivity"
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # If reg1 <- reg1 + 0, return 
    if( arg1 == arg2[0] and arg2[1] == 0 ):
        return []
    
    # Set env 
    env.addCall(ID)
    
    # Search 
    res = []
    for inter_reg in range(0, Arch.ssaRegCount):
        if( inter_reg == arg1 or (inter_reg == arg2[0] and arg2[1]==0)\
            or (inter_reg in record.unusable_REGtoREG) or inter_reg == Arch.ipNum()\
            or (inter_reg == Arch.spNum()) ):
            continue
        # Find reg1 <- inter_reg without using arg2    
        record.unusable_REGtoREG.append(arg2[0])
        inter_to_arg1_list = search(QueryType.REGtoREG, arg1, (inter_reg, 0), \
                constraint, assertion, n, clmax=clmax-1, record=record )
        record.unusable_REGtoREG.remove(arg2[0])
        if( not inter_to_arg1_list ):
            continue
        
        # Find inter_reg <- arg2 without using arg1
        record.unusable_REGtoREG.append(arg1)
        n2 = n/len(inter_to_arg1_list)
        if( n2 == 0 ):
            n2 = 1 
        for arg2_to_inter in search(QueryType.REGtoREG, inter_reg, arg2, \
                constraint, assertion, n2, clmax=clmax-1, record=record):
            for inter_to_arg1 in inter_to_arg1_list:
                if( len(inter_to_arg1)+len(arg2_to_inter) <= clmax):
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
        newNotModInt = sum([(1 << r) for r in list(set(regsNotModified))])
        for i in range(0, len(self.regs[reg1][reg2][cst])):
            prevNotModInt = self.regs[reg1][reg2][cst][i]
            if( prevNotModInt & newNotModInt == newNotModInt ):
                # new regsNotModified included in the previous ones
                # We replace it (il engloble l'autre)
                self.regs[reg1][reg2][cst][i] = newNotModInt
                return
            elif( prevNotModInt & newNotModInt == prevNotModInt ):
                # previous regsNotModified included in the new one
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
            regsInt = sum([(1<<r) for r in list(set(regsNotModified))])
            for notModInt in regsNotModified_list:
                if( (regsInt & notModInt) == notModInt ):
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

class RecordAdjustRet:
    def __init__(self):
        self.regs = set()
        
    def add(self, reg_num):
        self.regs.add(reg_num)
        
    def check(self, reg_num):
        """
        Return True iff reg_num in self.regs
        """
        return (reg_num in self.regs)
        
    def copy(self):
        new = RecordAdjustRet()
        for reg in self.regs:
            new.add(reg)
        return new

class SearchRecord:
    def __init__(self, maxdepth=4):
        self.depth = 0
        self.maxdepth = maxdepth
        self.impossible_REGtoREG = global_impossible_REGtoREG.copy()
        self.unusable_REGtoREG = []
        self.impossible_AdjustRet = RecordAdjustRet()
        
    def getDepth(self):
        return self.depth
        
    def incDepth(self):
        self.depth += 1
        
    def decDepth(self):
        self.depth -= 1
        
    def reachedMaxDepth(self):
        return (self.depth > self.maxdepth)
        
    def copy(self):
        new = SearchRecord(maxdepth=self.maxdepth)
        new.impossible_REGtoREG = self.impossible_REGtoREG.copy()
        new. unusable_REGtoREG = self.unusable_REGtoREG
        new.impossible_AdjustRet = self.impossible_AdjustRet.copy()

#######################################
#                                     #
#          Search environment         #
#                                     #
#######################################

class SearchEnvironment:
    def __init__(self, lmax, constraint, assertion, maxdepth, enablePreConds=False, noPadding=False):
        self.constraint = constraint
        self.assertion = assertion
        self.depth = 0
        self.calls_record = dict()
        self.lmax = lmax
        self.maxdepth = maxdepth
        self.enablePreConds = enablePreConds
        self.noPadding = noPadding

    def getConstraint(self):
        return self.constraint
        
    def setConstraint(self, c):
        self.constraint = c
    
    def getAssertion(self):
        return self.assertion
        
    def getLmax(self):
        return self.lmax
        
    def addLmax(self, length):
        self.lmax += length
        
    def subLmax(self, length):
        self.lmax -= length
    
    def getDepth(self):
        return self.depth
        
    def incDepth(self):
        self.depth += 1
        
    def decDepth(self):
        self.depth -= 1
        
    def reachedMaxDepth(self):
        return self.depth >= self.maxdepth
        
    def getNoPadding(self):
        return self.noPadding
    
    def setNoPadding(self, b):
        self.noPadding = b
        
    def addCall(self, ID):
        if( not ID in self.calls_record ):
            self.calls_record[ID] = 0
        self.calls_record[ID] += 1
        
    def removeCall(self, ID):
        self.calls_record[ID] -= 1

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

