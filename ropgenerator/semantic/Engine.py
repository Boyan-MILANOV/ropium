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
from enum import Enum

###################################
# Search functions and strategies #
###################################     

LMAX = 80 # Default max number of elements (padding included) in ROPChains
MAXDEPTH = 6

def search(qtype, arg1, arg2, constraint, assertion, n=1, clmax=LMAX, enablePreConds=False, \
            noPadding=False, CSTtoREG_comment=None, maxdepth=4, optimizeLen=False):
                
    """
    Wrapper for search_first_hit and search_optimize_len
    """
    global MAXDEPTH
    
    env = SearchEnvironment(clmax, constraint, assertion, MAXDEPTH, enablePreConds, noPadding)
    if( CSTtoREG_comment ):
        env.pushComment(StrategyType.CSTtoREG_POP, CSTtoREG_comment)
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
    
    # Make one search with max to see if possible 
    res = _search(qtype, arg1, arg2, env, n)
    if( not res):
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
        # Copy env to reinit it everytime we search 
        other_env = env.copy()
        res = _search(qtype, arg1, arg2, other_env, n)
        if( res ):
            # If found we can try shorter 
            best_find = res
            lmax = max(1, min([len(chain) for chain in best_find])-1)
        else:
            # If not found we try longer 
            lmin = lmoy
    
    # Set env 
    env.setLmax(lmax)
    # Search
    res = _search(qtype, arg1, arg2, env, n)
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
    # Adjust ret must be BEFORE other strategies so that 
    # when they fail we can set impossible queries 
    res += _adjust_ret(qtype, arg1, arg2, env, n-len(res))
            
    ## CSTtoREG
    if( qtype == QueryType.CSTtoREG ):
        res += _CSTtoREG_pop(arg1, arg2, env, n-len(res))
        if( len(res) < n ): 
            res += _CSTtoREG_transitivity(arg1, arg2, env, n-len(res))
    ## REGtoREG 
    elif( qtype == QueryType.REGtoREG):
        # Check if we already tried this query 
        if( env.checkImpossible_REGtoREG(arg1, arg2[0], arg2[1])):
            return res 
        elif( (env.getAssertion() == baseAssertion) and global_impossible_REGtoREG.checkImpossible_REGtoREG(arg1, arg2[0], arg2[1])):
            return res
        # Use chaining strategies 
        if( len(res) < n ):
            res += _REGtoREG_transitivity(arg1, arg2, env,  n-len(res))
        # If unsucceful chaining attempt, record it in the environment 
        if( not res ):
            env.addImpossible_REGtoREG(arg1, arg2[0], arg2[1])
    elif( qtype == QueryType.MEMtoREG ):
        res += _MEMtoREG_transitivity(arg1, arg2, env, n-len(res))
    elif( qtype == QueryType.CSTtoMEM ):
        res += _CSTtoMEM_write(arg1, arg2, env, n-len(res))
    elif( qtype == QueryType.REGtoMEM ):
        res += _REGtoMEM_transitivity(arg1,arg2, env, n-len(res))  
        
    return res

# Types of strategies 
class StrategyType(Enum):
    REGtoREG_TRANSITIVITY = "REGtoREG_transitivity"
    CSTtoREG_POP = "CSTtoREG_pop"
    CSTtoREG_TRANSITIVITY = "CSTtoREG_transitivity"
    MEMtoREG_TRANSITIVITY = "MEMtoREG_transitivity"
    REGtoMEM_TRANSITIVITY = "REGtOMEM_transitivity"
    CSTtoMEM_WRITE = "CSTtoMEM_write"
    ADJUST_RET = "adjust_ret"
    
def _REGtoREG_transitivity(arg1, arg2, env, n=1 ):
    """
    Perform REG1 <- REG2+CST with REG1 <- REG3 <- REG2+CST
    """
    ID = StrategyType.REGtoREG_TRANSITIVITY
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # If reg1 <- reg1 + 0, return 
    elif( arg1 == arg2[0] and arg2[1] == 0 ):
        return []
    # Limit number of calls to REGtoREG transitivity
    elif( env.callsHistory()[-2:] == [ID, ID] ):
        return []

    
    # Set env 
    env.addCall(ID)
    
    # Search 
    res = []
    for inter_reg in Arch.registers():
        if( inter_reg == arg1 or (inter_reg == arg2[0] and arg2[1]==0)\
            or (env.checkImpossible_REGtoREG(arg1, inter_reg, 0))\
            or (env.checkImpossible_REGtoREG(inter_reg, arg2[0], arg2[1]))\
            or inter_reg == Arch.ipNum() or inter_reg == Arch.spNum() ):
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
    
    
def _CSTtoREG_pop(reg, cst, env, n=1):
    """
    Returns a payload that puts cst into register reg by poping it from the stack
    """ 
    ID = StrategyType.CSTtoREG_POP
    
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
    # Get comment 
    if( env.hasComment(ID)):
        envHadComment = True
        comment = env.popComment(ID)
    else:
        envHadComment = False
        comment = "Constant: " +string_bold("0x{:x}".format(cst))
        
    ########################
    # Direct pop from the stack
    res = []
    # Adapt constraint if ip <- cst
    if( reg != Arch.ipNum()):
        constraint2 =  env.getConstraint().add(Chainable(ret=True))
    else:
        constraint2 = env.getConstraint()
        
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
    if( envHadComment ):
        env.pushComment(ID, comment)
    
    return res


def _CSTtoREG_transitivity(reg, cst, env, n=1):
    """
    Perform REG1 <- CST with REG1 <- REG2 <- CST
    """
    ID = StrategyType.CSTtoREG_TRANSITIVITY
    
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


def _MEMtoREG_transitivity(reg, arg2, env, n=1):
    """
    Perform reg <- inter <- mem(arg2)
    """
    ID = StrategyType.MEMtoREG_TRANSITIVITY
    
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


def _REGtoMEM_transitivity(arg1,arg2, env, n=1):
    """
    reg <- arg2
    mem(arg1) <- reg
    """
    ID = StrategyType.REGtoMEM_TRANSITIVITY
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # Limit number of calls to ... 
    elif( env.nbCalls(ID) >= 99 ):
        return []
    # Check if previous call was already REGtoMEM_transitivity
    # Reason: we handle the transitivity with REGtoREG transitivity
    # so no need to do it also recursively with this one ;) 
    elif( env.callsHistory()[-1] == ID ):
        return []

    # Set env 
    env.addCall(ID)
    ###################################
    res = []
    for inter in Arch.registers():
        if( inter == arg2[0] or inter in env.getConstraint().getRegsNotModified() or inter == Arch.ipNum() or inter == Arch.spNum()):
            continue 
        # Find inter <- arg2 
        arg2_to_inter = _search(QueryType.REGtoREG, inter, (arg2[0],arg2[1]), env, n)
        if( arg2_to_inter):
            len_min = min([len(chain) for chain in arg2_to_inter])
            # Try to find mem(arg1) <- inter
            env.subLmax(len_min)
            env.addUnusableReg(arg2[0])
            inter_to_mem = _search(QueryType.REGtoMEM, arg1, (inter, 0), env)
            env.removeUnusableReg(arg2[0])
            env.addLmax(len_min)
            res += [chain1.addChain(chain2, new=True) for chain1 in arg2_to_inter\
                for chain2 in inter_to_mem if len(chain1)+len(chain2) <= env.getLmax()]
            if( len(res) >= n ):
                break
    #####################################
    # Resotre env
    env.removeCall(ID)
    return res

def _CSTtoMEM_write(arg1, cst, env, n=1):
    """
    reg <- cst 
    mem(arg2) <- reg
    """
    ID = StrategyType.CSTtoMEM_WRITE
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # Limit number of calls to ... 
    elif( env.nbCalls(ID) >= 99 ):
        return []

    # Set env 
    env.addCall(ID)
    ######################################
    res = []
    addr_reg = arg1[0]
    addr_cst = arg1[1]
    # 1. First strategy (direct)
    # reg <- cst 
    # mem(arg1) <- reg 
    for reg in Arch.registers():
        if( reg == Arch.ipNum() or reg == Arch.spNum() or reg == addr_reg ):
            continue
        # Find reg <- cst
        constraint = env.getConstraint()
        env.setConstraint(constraint.add(RegsNotModified([addr_reg])))
        env.subLmax(1)
        cst_to_reg_chains = _search(QueryType.CSTtoREG, reg, cst, env, n)
        env.addLmax(1)
        env.setConstraint(constraint)
        if( not cst_to_reg_chains ):
            continue
        # Search for mem(arg1) <- reg 
        # We get all reg2,cst2 s.t mem(arg1) <- reg2+cst2 
        possible_mem_writes = DBPossibleMemWrites(addr_reg, addr_cst, env.getConstraint(), env.getAssertion(), n=1)
        # 1.A. Ideally we look for reg2=reg and cst2=0 (direct_writes)
        possible_mem_writes_reg = possible_mem_writes.get(reg) 
        if( possible_mem_writes_reg ):
            direct_writes = possible_mem_writes[reg].get(0, [])
        else:
            direct_writes = []
        padding = constraint.getValidPadding(Arch.octets())
        for write_gadget in direct_writes:
            for cst_to_reg_chain in cst_to_reg_chains:
                # Pad the gadgets 
                write_chain = ROPChain([write_gadget])
                for i in range(0, write_gadget.spInc-Arch.octets(), Arch.octets()):
                    write_chain.addPadding(padding)
                full_chain = cst_to_reg_chain.addChain(write_chain, new=True)
                if( len(full_chain) <= env.getLmax() ):
                    res.append(full_chain)
                if( len(res) >= n ):
                    break
            if( len(res) >= n ):
                break
        if( len(res) >= n ):
            break
        # 1.B. 
        # To be implemented 
        
    ###################
    # Restore env 
    env.removeCall(ID)
    return res 


    
def _adjust_ret(qtype, arg1, arg2, env, n):
    """
    Search with basic but adjust the bad returns they have 
    """
    global LMAX
    ID = StrategyType.ADJUST_RET
    
    ## Test for special cases 
    # Test lmax
    if( env.getLmax() <= 0 ):
        return []
    # Limit number of calls to ... 
    elif( env.nbCalls(ID) >= 2 ):
        return []
    # Test for ip
    # Reason: can not adjust ip if ip is the 
    # target of the query :/  
    elif ( arg1 == Arch.ipNum() ):
        return []
        
    # Set env 
    env.addCall(ID)
    saved_adjust_ret = env.getImpossible_adjust_ret().copy()
    
    ########################################
    res = []
    padding = env.getConstraint().getValidPadding(Arch.octets())
    # Get possible gadgets
    constraint = env.getConstraint()
    env.setConstraint(constraint.add(Chainable(jmp=True, call=True)))
    possible = _basic(qtype, arg1, arg2, env, 10*n)      
    env.setConstraint(constraint)
    
    # Try to adjust them  
    for chain in possible:
        g = chain.chain[0]
        ret_reg = g.retValue.reg.num
        # Check if we already know that ret_reg can't be adjusted
        if( env.checkImpossible_adjust_ret(ret_reg)):
            continue
        #Check if ret_reg not modified within the gadget
        elif( ret_reg in g.modifiedRegs()):
            continue
        # Check if stack is preserved 
        elif( g.spInc is None ):
            continue
        
        # Find adjustment 
        if( g.spInc < 0 ):
            offset = -1 * g.spInc
            padding_length = 0
        else: 
            padding_length = g.spInc / Arch.octets()
            if( g.retType == RetType.JMP ):
                offset = 0 
            else:
                offset = Arch.octets() 
        if( isinstance(arg1,int)):
            arg1_reg = arg1
        else:
            arg1_reg = arg1[0]
        
        # Get adjustment gadgets 
        env.setConstraint(constraint.add(RegsNotModified([arg1_reg])))
        saved_lmax = env.getLmax()
        env.setLmax(LMAX)
        adjust_gadgets = _search(QueryType.MEMtoREG, Arch.ipNum(), \
                (Arch.spNum(),offset), env, n=1)
        env.setConstraint(constraint)
        env.setLmax(saved_lmax)
        
        if( not adjust_gadgets ):
            continue
        else:
            adjust_addr = int(validAddrStr(adjust_gadgets[0].chain[0],\
                    constraint.getBadBytes(), Arch.bits()),  16)
        
        # Find gadgets to put the gadget address in the jmp/call register 
        if( isinstance(arg2, int)):
            arg2_reg = arg2
        else:
            arg2_reg = arg2[0]
            
        env.setConstraint(constraint.add(RegsNotModified([arg2_reg])))
        env.subLmax(1+padding_length)
        env.pushComment(StrategyType.CSTtoREG_POP, "Address of "+string_bold(str(adjust_gadgets[0].chain[0])))
        adjust = _search(QueryType.CSTtoREG, ret_reg, adjust_addr, env, n=1)
        env.popComment(StrategyType.CSTtoREG_POP)
        env.addLmax(1+padding_length)
        env.setConstraint(constraint)
        if( adjust ):
            res.append(adjust[0].addGadget(g).addPadding(padding, n=padding_length))
            if( len(res) >= n ):
                break
        else:
            # Update the search record to say that reg_ret cannot be adjusted
            env.addImpossible_adjust_ret(ret_reg)
    ########################################
    # Restore env
    env.impossible_adjust_ret = saved_adjust_ret
    env.removeCall(ID)
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
        added = False
        already = False
        for i in range(0, len(self.regs[reg1][reg2][cst])):
            prevNotModInt = self.regs[reg1][reg2][cst][i]
            if( prevNotModInt & newNotModInt == newNotModInt ):
                # new regsNotModified included in the previous ones
                # We replace it (il engloble l'autre)
                self.regs[reg1][reg2][cst][i] = newNotModInt
                added = True
            elif( prevNotModInt & newNotModInt == prevNotModInt ):
                # previous regsNotModified included in the new one
                already = True
                break
        # If new really different from all others, add it 
        if( (not added) and (not already) ):
            self.regs[reg1][reg2][cst].append(newNotModInt)
        self.regs[reg1][reg2][cst] = list(set(self.regs[reg1][reg2][cst]))
            
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
        self.impossible_adjust_ret = RecordAdjustRet()
        self.unusable_regs_REGtoREG = []
        self.comments = dict()

    def __str__(self):
        s = "SearchEnvironment:\n-------------------\n\n"
        s += str(self.constraint) + '\n'
        s += str(self.assertion) + '\n'
        s += "Depth: " + str(self.depth) + '\n'
        s += "Lmax: " + str(self.lmax) + '\n'
        s += "impossibleREGtoREG: " + str(self.impossible_REGtoREG.regs) + '\n'
        s += "Unusable regs REGtoREG " + str(self.unusable_regs_REGtoREG) + '\n'
        s += "Calls history: "
        tab = '\t'
        for call in self.calls_history:
            s += tab+call+'\n'
            tab += '\t'
        return s 
    
    def copy(self):
        new = SearchEnvironment(self.lmax, self.constraint, self.assertion, self.maxdepth,\
            self.enablePreConds, self.noPadding)
        new.depth = self.depth
        new.calls_count = dict(self.calls_count)
        new.calls_history = list(self.calls_history)
        new.impossible_REGtoREG = self.impossible_REGtoREG.copy()
        new.impossible_adjust_ret = self.impossible_adjust_ret.copy()
        new.unusable_regs_REGtoREG = list(self.unusable_regs_REGtoREG)
        new.comments = dict(self.comments)
        return new
    
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
        
    def getImpossible_adjust_ret(self):
        return self.impossible_adjust_ret
    
    def addImpossible_adjust_ret(self, reg):
        self.impossible_adjust_ret.add(reg)
        
    def checkImpossible_adjust_ret(self, reg):
        return self.impossible_adjust_ret.check(reg)
    
    def getUnusableRegs(self):
        return self.unusable_regs_REGtoREG
        
    def addUnusableReg(self, reg):
        self.unusable_regs_REGtoREG.append(reg)
    
    def removeUnusableReg(self, reg):
        self.unusable_regs_REGtoREG.remove(reg)

    def hasComment(self, ID):
        return (len(self.comments.get(ID,[])) > 0)
    
    def pushComment(self, ID, comment):
        if( not ID in self.comments ):
            self.comments[ID] = [comment] 
        else:
            self.comments[ID].append(comment)
        
    def getComment(self, ID):
        return self.comments[ID][-1]
    
    def popComment(self, ID):
        return self.comments[ID].pop()
        

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
                if (reg2 == reg1 or reg2 == Arch.ipNum()):
                    continue
                _search(QueryType.REGtoREG, reg1, (reg2,0), env, n=1)
                if( env.checkImpossible_REGtoREG(reg1, reg2, 0)):
                    impossible_count += 1
        cTime = datetime.now() - startTime
        # Get how many impossible path we found 
        impossible_rate = int(100*(float(impossible_count)/float((len(Arch.registers())-1)*len(Arch.registers()))))
        notify('Optimization rate : {}%'.format(impossible_rate))
        notify("Computation time : " + str(cTime))
    except: 
        print("\n")
        fatal("Exception caught, stopping Semantic Engine init process...\n")
        fatal("Search time might get very long !\n")
        env = SearchEnvironment(INIT_LMAX, Constraint(), baseAssertion, INIT_MAXDEPTH )
        

#########################
# Modle wide accessors ##
#########################

def getBaseAssertion():
    global baseAssertion
    return baseAssertion
