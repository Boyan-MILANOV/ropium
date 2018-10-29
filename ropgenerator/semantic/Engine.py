# -*- coding:utf-8 -*- 
# Engine module: chaining gadgets and building ropchains

from ropgenerator.semantic.ROPChains import ROPChain, validAddrStr
from ropgenerator.Database import QueryType, DBSearch, DBPossibleInc, DBPossiblePopOffsets, REGList, DBPossibleMemWrites
from ropgenerator.Constraints import Chainable, RegsNotModified, Constraint, Assertion, CstrTypeID, RegsNoOverlap, RegsValidPtrRead, RegsValidPtrWrite
from ropgenerator.Gadget import RetType
from ropgenerator.IO import string_bold, info, charging_bar, notify, fatal
from itertools import product
import ropgenerator.Architecture as Arch
from datetime import datetime

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
    global global_impossible_REGtoREG
    
    
    ## Preliminary tests 
    # Test clmax
    if( env.getLmax() <= 0 ):
        return []
    # Test record 
    elif( env.reachedMaxDepth() ):
        return []
    
    res = []  
    ## CSTtoREG
    if( qtype == QueryType.CSTtoREG ):
        res += _CSTtoREG_pop(arg1, arg2, env, n-len(res))
        if( len(res) < n ): 
            res += _CSTtoREG_transitivity(arg1, arg2, env, n-len(res))
    ## REGtoREG 
    elif( qtype == QueryType.REGtoREG):
        # Check if we already tried this query 
        if( env.checkImpossible_REGtoREG(arg1, arg2[0], arg2[1])):
            return [] 
        elif( (env.getAssertion() == baseAssertion) and global_impossible_REGtoREG.checkImpossible_REGtoREG(arg1, arg2[0], arg2[1])):
            return []
        # Use chaining strategies 
        if( len(res) < n ):
            res += _REGtoREG_transitivity(arg1, arg2, env,  n-len(res))
        # If unsucceful chaining attempt, record it in the environment 
        if( not res ):
            env.addImpossible_REGtoREG(arg1, arg2[0], arg2[1])
    elif( qtype == QueryType.MEMtoREG ):
        res += MEMtoREG_transitivity(arg1, arg2, env, n-len(res))
    elif( qtype == QueryType.CSTtoMEM ):
        return []
        res += CSTtoMEM_write(arg1, arg2, constraint, assertion, n-len(res), clmax)
    elif( qtype == QueryType.REGtoMEM ):
        return []
        res += REGtoMEM_transitivity(arg1,arg2, constraint, assertion, n-len(res), clmax)    
    # For any types, adjust the returns 
    if( len(res) < n ):
        return res
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
    # Limit number of calls to REGtoREG transitivity
    if( env.nbCalls(ID) >= 3 ):
        return []
    
    # Set env 
    env.addCall(ID)
    
    # Search 
    res = []
    for inter_reg in range(0, Arch.ssaRegCount):
        if( inter_reg == arg1 or (inter_reg == arg2[0] and arg2[1]==0)\
            or (inter_reg in env.getUnusableRegs()) or inter_reg == Arch.ipNum()\
            or (inter_reg == Arch.spNum()) ):
            continue
        # Find reg1 <- inter_reg without using arg2    
        env.addUnusableReg(arg2[0])
        env.subLmax(1)
        inter_to_arg1_list = _search(QueryType.REGtoREG, arg1, (inter_reg, 0), env, n)
        env.removeUnusableReg(arg2[0])
        env.addLmax(1)
        if( not inter_to_arg1_list ):
            continue
        else:
            min_len_chain = min([len(chain) for chain in inter_to_arg1_list])
        
        # Find inter_reg <- arg2 without using arg1
        env.addUnusableReg(arg1)
        env.subLmax(min_len_chain)
        n2 = n/len(inter_to_arg1_list)
        if( n2 == 0 ):
            n2 = 1 
        for arg2_to_inter in _search(QueryType.REGtoREG, inter_reg, arg2, env, n2):
            for inter_to_arg1 in inter_to_arg1_list:
                if( len(inter_to_arg1)+len(arg2_to_inter) <= env.getLmax()):
                    res.append(arg2_to_inter.addChain(inter_to_arg1, new=True))
                if( len(res) >= n ):
                    break
            if( len(res) >= n ):
                break
        env.addLmax(min_len_chain)
        env.removeUnusableReg(arg1)
        if( len(res) >= n ):
                break
    
    # Restore env
    env.removeCall(ID)
    return res 

def _CSTtoREG_pop(reg, cst, env, n=1, comment=None):
    """
    Returns a payload that puts cst into register reg by poping it from the stack
    """ 
    ID = "CSTtoREG_pop"
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # Limit number of calls to ... 
    elif( env.nbCalls(ID) >= 99 ):
        return []
    # Check if the cst is in badBytes 
    elif( not env.getConstraint().badBytes.verifyAddress(cst)):
        return []
    
    # Set env 
    env.addCall(ID)
    
    ########################
    if( not comment ):
        comment = "Constant: " +string_bold("0x{:x}".format(cst))
        
    # Direct pop from the stack
    res = []
    # Adapt constraint if ip <- cst
    if( reg != Arch.ipNum()):
        constraint2 =  env.getConstraint().add(Chainable(ret=True))
        
    possible = DBPossiblePopOffsets(reg,constraint2, env.getAssertion())
    for offset in sorted(filter(lambda x:x>=0, possible.keys())):
        # If offsets are too big to fit in the lmax just break
        if( offset > env.getLmax()*Arch.octets()):
            break 
        # Get possible gadgets
        possible_gadgets = [g for g in possible[offset]\
            if g.spInc >= Arch.octets() \
            and g.spInc - Arch.octets() > offset \
            and (g.spInc/Arch.octets()-1) <= env.getLmax()] # Test if padding is too much for clmax
        # Pad the gadgets 
        padding = env.getConstraint().getValidPadding(Arch.octets())
        for gadget in possible_gadgets:
            chain = ROPChain([gadget])
            for i in range(0, gadget.spInc-Arch.octets(), Arch.octets()):
                if( i == offset):
                    chain.addPadding(cst, comment)
                else:
                    chain.addPadding(padding)
            if( len(chain) <= env.getLmax() ):
                res.append(chain)
            if( len(res) >= n ):
                break
        if( len(res) >= n ):
            break
    #########################
    
    # Restore env 
    env.removeCall(ID)
    
    return res


def _CSTtoREG_transitivity(reg, cst, env, n=1):
    """
    Perform REG1 <- CST with REG1 <- REG2 <- CST
    """
    ID = "CSTtoREG_transitivity"
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # Limit number of calls to ... 
    elif( env.nbCalls(ID) >= 99 ):
        return []
    # Check if the cst is in badBytes 
    elif( not env.getConstraint().badBytes.verifyAddress(cst)):
        return []
    # Check if previous call was already CSTtoREG_transitivity
    # Reason: we handle the transitivity with REGtoREG transitivity
    # so no need to do it also recursively with this one ;) 
    elif( env.callsHistory()[-1] == ID ):
        return []
    
    # Set env 
    env.addCall(ID)
    
    #############################
    res = []
    for inter in Arch.registers():
        if( inter == reg or inter in env.getConstraint().getRegsNotModified() or inter == Arch.ipNum() or inter == Arch.spNum() ):
            continue
        # Find reg <- inter 
        inter_to_reg = _search(QueryType.REGtoREG, reg, (inter,0), env, n)
        if( inter_to_reg ):
            # We found ROPChains s.t reg <- inter
            # Now we want inter <- cst 
            min_len = min([len(chain) for chain in inter_to_reg])
            env.subLmax(min_len)
            env.addUnusableReg(reg)
            cst_to_inter = _search(QueryType.CSTtoREG, inter, cst, env, n/len(inter_to_reg)+1)
            env.removeUnusableReg(reg)
            env.addLmax(min_len)
            
            for chain2 in inter_to_reg:
                for chain1 in cst_to_inter:
                    if( len(chain1)+len(chain2) <= env.getLmax()):
                        res.append(chain1.addChain(chain2, new=True))
                            
        # Did we get enough chains ?             
        if( len(res) >= n ):
            break
    ###############################        
    # Restore env 
    env.removeCall(ID)
    
    return res[:n]


def MEMtoREG_transitivity(reg, arg2, env, n=1):
    """
    Perform reg <- inter <- mem(arg2)
    """
    ID = "MEMtoREG_transitivity"
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # Limit number of calls to ... 
    elif( env.nbCalls(ID) >= 99 ):
        return []
    # Check if previous call was already MEMtoREG_transitivity
    # Reason: we handle the transitivity with REGtoREG transitivity
    # so no need to do it also recursively with this one ;) 
    elif( env.callsHistory()[-1] == ID ):
        return []
        
    # Set env  
    env.addCall(ID)
        
    ###########################
    res = []
    for inter in Arch.registers():
        if( inter == reg or inter in env.getConstraint().getRegsNotModified() or inter == Arch.ipNum() or inter == Arch.spNum() ):
                continue    
        
        # Find arg1 <- inter
        inter_to_reg = _search(QueryType.REGtoREG, reg, (inter,0), env, n)
        if (inter_to_reg):
            min_len = min([len(chain) for chain in inter_to_reg])
            # Try to find inter <- arg2
            env.subLmax(min_len)
            env.addUnusableReg(reg)
            arg2_to_inter = _search(QueryType.MEMtoREG, inter, arg2, env, n)
            env.removeUnusableReg(reg)
            env.addLmax(min_len)
            res += [chain1.addChain(chain2, new=True) for chain1 in arg2_to_inter \
                for chain2 in inter_to_reg if len(chain1)+len(chain2) <= env.getLmax()  ]
        # Did we get enough chains ? 
        if( len(res) >= n ):
            break
    ########################
    
    # Restore env 
    env.removeCall(ID)
    
    return res[:n]

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
        self.calls_count = dict()
        self.calls_history = ["ROOT"]
        self.lmax = lmax
        self.maxdepth = maxdepth
        self.enablePreConds = enablePreConds
        self.noPadding = noPadding
        self.impossible_REGtoREG = RecordREGtoREG()
        self.unusable_regs_REGtoREG = []

    def __str__(self):
        s = "SearchEnvironment:\n-------------------\n\n"
        s += str(self.constraint) + '\n'
        s += str(self.assertion) + '\n'
        s += "Depth: " + str(self.depth) + '\n'
        s += "impossibleREGtoREG: " + str(self.impossible_REGtoREG.regs) + '\n'
        s += "Unusable regs REGtoREG " + str(self.unusable_regs_REGtoREG) + '\n'
        s += "Calls history: "
        tab = '\t'
        for call in self.calls_history:
            s += tab+call
            tab += '\t'
        return s 
    
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
        
    def setLmax(self, length):
        self.lmax = length
    
    def getDepth(self):
        return self.depth
        
    def incDepth(self):
        self.depth += 1
        
    def decDepth(self):
        self.depth -= 1
        
    def reachedMaxDepth(self):
        return self.depth > self.maxdepth
        
    def getNoPadding(self):
        return self.noPadding
    
    def setNoPadding(self, b):
        self.noPadding = b
        
    def addCall(self, ID):
        if( not ID in self.calls_count ):
            self.calls_count[ID] = 0
        self.calls_count[ID] += 1
        self.calls_history.append(ID)
        
    def removeCall(self, ID):
        self.calls_count[ID] -= 1
        self.calls_history.remove(ID)
        
    def nbCalls(self, ID):
        return self.calls_count.get(ID, 0)
        
    def callsHistory(self):
        return self.calls_history
        
    def getImpossible_REGtoREG(self):
        return self.impossible_REGtoREG
        
    def checkImpossible_REGtoREG(self, reg1, reg2, cst ):
        unusableRegsList = list(set(self.constraint.getRegsNotModified() + self.unusable_regs_REGtoREG))
        return self.impossible_REGtoREG.check(reg1, reg2, cst, unusableRegsList)
        
    def addImpossible_REGtoREG(self, reg1, reg2, cst):
        unusableRegsList = list(set(self.constraint.getRegsNotModified() + self.unusable_regs_REGtoREG))
        self.impossible_REGtoREG.add(reg1, reg2, cst, unusableRegsList)
        
    def getUnusableRegs(self):
        return self.unusable_regs_REGtoREG
        
    def addUnusableReg(self, reg):
        self.unusable_regs_REGtoREG.append(reg)
    
    def removeUnusableReg(self, reg):
        self.unusable_regs_REGtoREG.remove(reg)


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


####################################
# Module initialisation & Helpers  #
####################################
INIT_LMAX = 2000
INIT_MAXDEPTH = 6

# record to fasten REGtoREG search by cutting bad branches 
global_impossible_REGtoREG = None

# BaseAssertion, used as base for the basic search function 
baseAssertion = None

def initEngine():
    global INIT_LMAX, INIT_MAXDEPTH
    global global_impossible_REGtoREG
    global baseAssertion
    
    # Init global variables
    baseAssertion = Assertion().add(\
            RegsValidPtrRead([(Arch.spNum(),-5000, 10000)]), copy=False).add(\
            RegsValidPtrWrite([(Arch.spNum(), -5000, 0)]), copy=False)
    
    info(string_bold("Initializing Semantic Engine\n"))
    
    # Init helper for REGtoREG 
    global_impossible_REGtoREG = SearchEnvironment(INIT_LMAX, Constraint(), baseAssertion, INIT_MAXDEPTH )
    init_impossible_REGtoREG(global_impossible_REGtoREG)


def init_impossible_REGtoREG(env):
    global INIT_LMAX, INIT_MAXDEPTH
    global baseAssertion
    
    try: 
        startTime = datetime.now()
        i = 0
        impossible_count = 0 
        for reg1 in sorted(Arch.registers()):
            reg_name = Arch.r2n(reg1)
            if( len(reg_name) < 6 ):
                reg_name += " "*(6-len(reg_name))
            elif( len(reg_name) >= 6 ):
                reg_name = reg_name[:5] + "."
            for reg2 in Arch.registers():
                i += 1 
                charging_bar(len(Arch.registers()*len(Arch.registers())), i, 30)
                if (reg2 == reg1):
                    continue
                _search(QueryType.REGtoREG, reg1, [reg2,0], env, n=1)
                if( env.checkImpossible_REGtoREG(reg1, reg2, 0)):
                    impossible_count += 1
        cTime = datetime.now() - startTime
        # Get how many impossible path we found 
        impossible_rate = int(100*(float(impossible_count)/float((len(Arch.registers())-1)*len(Arch.registers()))))
        notify('Optimization rate : {}%'.format(impossible_rate))
        notify("Computation time : " + str(cTime))
    except: 
        print("\n")
        fatal("Exception caught, stopping Semantic Engine init process...")
        fatal("Search time might get very long !\n")
        env = SearchEnvironment(INIT_LMAX, Constraint(), baseAssertion, INIT_MAXDEPTH )
        

#########################
# Modle wide accessors ##
#########################

def getBaseAssertion():
    global baseAssertion
    return baseAssertion
