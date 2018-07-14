# -*- coding:utf-8 -*- 
# Engine module: chaining gadgets and building ropchains

from ropgenerator.semantic.ROPChains import ROPChain
from ropgenerator.Database import QueryType, DBSearch

def search(qtype, arg1, arg2, constraint, assertion, n=1, enablePreConds=False):
    """
    Searches for gadgets 
    basic = False means that we don't call _basic_strategy
    chainable = True means that we want only chainable gadgets 
    init = True means the search just started and we have to do some initialization in SearchHelper
    """
    res = _basic(qtype, arg1, arg2, constraint, assertion, n)
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
        for g in gadgets: 
            res.append(ROPChain().addGadget(g))
    return res
