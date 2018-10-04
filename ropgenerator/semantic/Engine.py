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

def search(qtype, arg1, arg2, constraint, assertion, n=1, clmax=LMAX, enablePreConds=False, \
            record=None, noPadding=False, comment=None, maxdepth=4):
    """
    Searches for gadgets 
    enablePreConds : return couples (GAdget, preCond) 
    record : stores info about the current search 
    maxdepth : only for CSTtoREG_transitivity
    """
    # Test clmax
    if( clmax <= 0 ):
        return []
    
    # Set the search record and increase its depth of 1 
    if ( record is None):
        record = SearchRecord()
    record.incDepth()
    # Search basic 
    res = _basic(qtype, arg1, arg2, constraint.add(Chainable(ret=True)), assertion, n, clmax)
    # Search chaining 
    if( len(res) < n and (qtype not in [QueryType.SYSCALL, QueryType.INT80])):
        res += _chain(qtype, arg1, arg2, constraint, assertion, record, n-len(res), clmax, comment)
    # Reset the depth of the search record 
    record.decDepth()
    return sorted(res)

def search_not_chainable(qtype, arg1, arg2, constraint, assertion, n=1, clmax=10000):
    return _basic(qtype, arg1, arg2, constraint, assertion, n, clmax, noPadding=True)

def search_optimize_len(qtype, arg1, arg2, constraint, assertion, n=1, clmax=LMAX, enablePreConds=False, \
            record=None, noPadding=False, comment=None):
    """
    Tries to find the shorter ROPChain possible 
    by using dichotomic calls to search() 
    """
    if( clmax <= 0 ):
        return []
    
    lmin = 1 
    lmax = clmax
    best_find = []
    while( lmin != lmax):
        lmoy = (lmin+lmax+1)/2
        res = search(qtype, arg1, arg2, constraint, assertion, n, lmoy, enablePreConds, \
            record, noPadding, comment)
        if( res ):
            # If found we can try shorter 
            best_find = res
            lmax = lmoy-1
        else:
            # If not found we try longer 
            lmin = lmoy
    res = search(qtype, arg1, arg2, constraint, assertion, n, lmax, enablePreConds, \
            record, noPadding, comment)
    if( res ):
        return res
    else:
        return best_find
            
def _basic(qtype, arg1, arg2, constraint, assertion, n=1, clmax=LMAX, noPadding=False):
    """
    Search for gadgets basic method ( without chaining ) 
    Direct Database check  
    """
    # Test clmax
    if( clmax <= 0 ):
        return []
    
    if( not noPadding ):
        maxSpInc = clmax*Arch.octets()
    else:
        maxSpInc = None
    
    # Check for special gadgets
    if( qtype == QueryType.INT80 or qtype == QueryType.SYSCALL):
        gadgets = DBSearch(qtype, arg1, arg2, constraint, assertion, n=1, maxSpInc=maxSpInc)
        res = [ROPChain().addGadget(g) for g in gadgets]
        return res
    
    # Check if the type is IP <- ... 
    # In this case we remove the CHAINABLE constraint which makes no sense 
    if( arg1 == Arch.ipNum() ):
        constraint2 = constraint.remove([CstrTypeID.CHAINABLE])
    else:
        constraint2 = constraint
    
    # Check to add assertions when looking for Memory gadgets
    if( qtype == QueryType.CSTtoMEM or qtype == QueryType.REGtoMEM ):
        assertion2 = assertion.add(RegsNoOverlap([(arg1[0], Arch.spNum())]))
    else:
        assertion2 = assertion
    
    # Regular gadgets 
    # maxSpInc -> +1 because we don't count the ret but -1 because the gadget takes one place 
    gadgets =  DBSearch(qtype, arg1, arg2, constraint2, assertion2, n, maxSpInc=maxSpInc)
    if( noPadding ):
        return [ROPChain().addGadget(g) for g in gadgets]
    else:
        res = []
        padding = constraint2.getValidPadding(Arch.currentArch.octets)
        for g in gadgets: 
            chain = ROPChain().addGadget(g)
            # Padding the chain if possible 
            if( g.spInc > 0 ):
                for i in range(0, g.spInc/Arch.octets() - 1):
                    chain.addPadding(padding)
            # Adding to the result 
            res.append(chain)
    return res

def _chain(qtype, arg1, arg2, constraint, assertion, record, n=1, clmax=LMAX, comment=None, maxdepth=4):
    """
    Search for ropchains by chaining gadgets 
    """
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
        
    # For any types, adjust the returns 
    res += _adjust_ret(qtype, arg1, arg2, constraint, assertion, n, clmax, record, comment)
    
    return res


def _adjust_ret(qtype, arg1, arg2, constraint, assertion, n, clmax=LMAX, record = None, comment=""):
    """
    Search with basic but adjust the bad returns they have 
    """
    # Test clmax
    if( clmax <= 0 ):
        return []
        
    # Test for ip 
    if ( arg1 == Arch.ipNum() ):
        return []
    # Test for search record
    if( record is None ):
        record = SearchRecord()
    
    res = []
    possible = _basic(qtype, arg1, arg2, \
            constraint.add(Chainable(jmp=True, call=True)), assertion, n)        
    padding = constraint.getValidPadding(Arch.currentArch.octets)
    for chain in possible:
        g = chain.chain[0]
        ret_reg = g.retValue.reg.num
        # Check if we already know that ret_reg can't be adjusted
        if( record.impossible_AdjustRet.check(ret_reg)):
            continue
        #Check if ret_reg not modified within the gadget
        if( ret_reg in g.modifiedRegs()):
            continue
        # Check if stack is preserved 
        if( g.spInc is None ):
            continue
            
        # Find adjustment 
        if( g.spInc < 0 ):
            offset = -1 * g.spInc
            padding_length = 0
        else: 
            padding_length = g.spInc
            if( g.retType == RetType.JMP ):
                offset = 0 
            else:
                offset = Arch.octets() 
        adjust_gadgets = search(QueryType.MEMtoREG, Arch.ipNum(), \
                (Arch.spNum(),offset), constraint.add(RegsNotModified([arg1])), assertion, n=1, record=record)
        if( not adjust_gadgets ):
            continue
        else:
            adjust_addr = int(validAddrStr(adjust_gadgets[0].chain[0],\
                    constraint.getBadBytes(), Arch.bits()),  16)
        # Put the gadget address in the register 
        adjust = search(QueryType.CSTtoREG, ret_reg, adjust_addr, \
            constraint.add(RegsNotModified([arg2[0]])), assertion, n=1, clmax=clmax-len(chain),record=record,\
            comment="Address of "+string_bold(str(adjust_gadgets[0].chain[0])))
        if( adjust ):
            res.append(adjust[0].addGadget(g).addPadding(padding, n=padding_length))
            if( len(res) >= n ):
                return res
        else:
            # Update the search record to say that reg_ret cannot be adjusted
            record.impossible_AdjustRet.add(ret_reg)
    return res
        

def _CSTtoREG_pop(reg, cst, constraint, assertion, n=1, clmax=LMAX, comment=None):
    """
    Returns a payload that puts cst into register reg by poping it from the stack
    """ 
    # Test clmax
    if( clmax <= 0 ):
        return []
    # Test n 
    if (n < 1 ):
        return []
    # Check if the cst is incompatible with the constraint
    if( not constraint.badBytes.verifyAddress(cst)):
        return []
    
    if( not comment ):
        comment = "Constant: " +string_bold("0x{:x}".format(cst))
        
    # Direct pop from the stack
    res = []
    if( reg == Arch.ipNum()):
        constraint2 = constraint.remove([CstrTypeID.CHAINABLE])
    else:
        constraint2 =  constraint.add(Chainable(ret=True))
    possible = DBPossiblePopOffsets(reg,constraint2, assertion)
    for offset in sorted(filter(lambda x:x>=0, possible.keys())):
        # If offsets are too big to fit in the lmax just break
        if( offset > clmax*Arch.octets()):
            break 
        # Get possible gadgets
        possible_gadgets = [g for g in possible[offset]\
            if g.spInc >= Arch.octets() \
            and g.spInc - Arch.octets() > offset \
            and (g.spInc/Arch.octets()-1) <= clmax] # Test if padding is too much for clmax
        # Pad the gadgets 
        padding = constraint.getValidPadding(Arch.octets())
        for gadget in possible_gadgets:
            chain = ROPChain([gadget])
            for i in range(0, gadget.spInc-Arch.octets(), Arch.octets()):
                if( i == offset):
                    chain.addPadding(cst, comment)
                else:
                    chain.addPadding(padding)
            if( len(chain) <= clmax ):
                res.append(chain)
            if( len(res) >= n ):
                return res
    return res

def _CSTtoREG_transitivity(reg, cst, constraint, assertion, n=1, clmax=LMAX, comment=None, maxdepth=4):
    """
    Perform REG1 <- CST with REG1 <- REG2 <- CST
    """
    # Test clmax
    if( clmax <= 0 ):
        return []
    
    res = []
    for inter in range(0, Arch.ssaRegCount):
        if( inter == reg or inter in constraint.getRegsNotModified() or inter == Arch.ipNum() or inter == Arch.spNum() ):
            continue
        # Find reg <- inter 
        REGtoREG_record = SearchRecord(maxdepth=maxdepth)
        REGtoREG_record.unusable_REGtoREG.append(reg)
        inter_to_reg = search(QueryType.REGtoREG, reg, (inter,0), constraint, assertion, n, clmax, record=REGtoREG_record)
        if( inter_to_reg ):
            # We found ROPChains s.t reg <- inter
            # Now we want inter <- cst 
            cst_to_inter = _basic(QueryType.CSTtoREG, inter, cst, constraint, assertion, n/len(inter_to_reg)+1, clmax-1)
            for chain2 in inter_to_reg:
                for chain1 in cst_to_inter:
                    if( len(chain1)+len(chain2) <= clmax):
                        res.append(chain1.addChain(chain2, new=True))
            if( len(res) < n ):
                cst_to_inter = _CSTtoREG_pop(inter, cst, constraint, assertion, n/(len(inter_to_reg))+1, clmax-1, comment)
                for chain2 in inter_to_reg:
                    for chain1 in cst_to_inter:
                        if( len(chain1)+len(chain2) <= clmax):
                            res.append(chain1.addChain(chain2, new=True))
                            
        # Did we get enough chains ?             
        if( len(res) >= n ):
            return res[:n]
    # Return what we got 
    return res


def _REGtoREG_transitivity(arg1, arg2, constraint, assertion, record, n=1, clmax=LMAX ):
    """
    Perform REG1 <- REG2+CST with REG1 <- REG3 <- REG2+CST
    """
    # Test clmax
    if( clmax <= 0 ):
        return []
    
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
                constraint, assertion, n, clmax=clmax-1, record=record )
        record.unusable_REGtoREG.remove(arg2[0])
        if( not inter_to_arg1_list ):
            continue
        
        # Find inter_reg <- arg2 without using arg1
        record.unusable_REGtoREG.append(arg1)
        for arg2_to_inter in search(QueryType.REGtoREG, inter_reg, arg2, \
                constraint, assertion, n/len(inter_to_arg1_list)+1, clmax=clmax-1, record=record):
            for inter_to_arg1 in inter_to_arg1_list:
                if( len(inter_to_arg1)+len(arg2_to_inter) <= clmax):
                    res.append(arg2_to_inter.addChain(inter_to_arg1, new=True))
                if( len(res) >= n ):
                    return res
        record.unusable_REGtoREG.remove(arg1)
    return res 

def _REGtoREG_increment(arg1, arg2, constraint, assertion, record, n=1, clmax=LMAX):
    """
    Perform REG1 <- REG2+CST with REG1<-REG2; REG1 += CST
    """
    # Test clmax
    if( clmax <= 0 ):
        return []
    
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

def MEMtoREG_transitivity(reg, arg2, constraint, assertion, n=1, clmax=LMAX):
    if( clmax <= 0 ):
        return []
        
    res = []
    for inter in range(0, Arch.ssaRegCount):
        if( inter == reg or inter in constraint.getRegsNotModified() or inter == Arch.ipNum() or inter == Arch.spNum() ):
                continue    
        
        # Find arg1 <- inter
        REGtoREG_record = SearchRecord(maxdepth=4)
        REGtoREG_record.unusable_REGtoREG.append(reg)
        inter_to_reg = search(QueryType.REGtoREG, reg, (inter,0), constraint, assertion, n, clmax-1, record=REGtoREG_record)
        if (inter_to_reg):
            len_min = min([len(chain) for chain in inter_to_reg])
            # Try to find inter <- arg2
            # First strategy basic 
            arg2_to_inter = _basic(QueryType.MEMtoREG, inter, arg2, constraint, assertion, n, clmax-len_min)
            res += [chain1.addChain(chain2, new=True) for chain1 in arg2_to_inter \
                for chain2 in inter_to_reg if len(chain1)+len(chain2) <= clmax  ]
            # Second strategy read reg (TODO)
            if( len(res) < n ):
                pass
        # Did we get enough chains ? 
        if( len(res) >= n ):
            return res 
    # Return the best we got 
    return res

def CSTtoMEM_write(arg1, cst, constraint, assertion, n=1, clmax=LMAX):
    """
    reg <- cst 
    mem(arg2) <- reg
    """
    if( clmax <= 0 ):
        return []
    
    res = []
    addr_reg = arg1[0]
    addr_cst = arg1[1]
    # 1. First strategy (direct)
    # reg <- cst 
    # mem(arg1) <- reg 
    for reg in range(0, Arch.ssaRegCount ):
        if( reg == Arch.ipNum() or reg == Arch.spNum() or reg == addr_reg ):
            continue
        # Find reg <- cst 
        # maxdepth 3 or it's too slow 
        cst_to_reg_chains = search(QueryType.CSTtoREG, cst, reg, constraint.add(RegsNotModified([addr_reg])), assertion, n, clmax-1, maxdepth=3)
        if( not cst_to_reg_chains ):
            continue
        # Search for mem(arg1) <- reg 
        # We get all reg2,cst2 s.t mem(arg1) <- reg2+cst2 
        print("DEBUG possible")
        possible_mem_writes = DBPossibleMemWrites(addr_reg, addr_cst, constraint, assertion, n=1)
        print("DEBUG possible done")
        # 1.A. Ideally we look for reg2=reg and cst2=0 (direct_writes)
        possible_mem_writes_reg = possible_mem_writes.get(reg) 
        if( possible_mem_writes_reg ):
            direct_writes = possible_mem_writes[reg].get(0, [])
        else:
            direct_writes = []
        padding = constraint.getValidPadding(Arch.octets())
        for gadget in direct_writes:
            # Pad the gadgets 
            chain = ROPChain([gadget])
            for i in range(0, gadget.spInc-Arch.octets(), Arch.octets()):
                chain.addPadding(padding)
            if( len(chain) <= clmax ):
                res.append(chain)
            if( len(res) >= n ):
                return res
        # 1.B. 
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

