# -*- coding:utf-8 -*- 
# Constraints module: representation of constraints on gadgets
import re


#################################################
# Generic class for different constraint types  #
#################################################

class ConstraintType:
    def __init__(self): 
        pass
    
    def verify(self, gadget):
        """
        Returns (status, list)
        status: True if the gadget CAN verify the constraint
                False if the gadget can NEVER verify the constraint
        list:   list of pre-conditions so that the gadget 
                verifies the constraint 
        """

class BadBytes(ConstraintType):
    def __init__(self, bytesList):
        self.bytes = bytesList
        
    def verify(self, gadget):
        for addr in gadget.addrList:
            addrBytes = re.findall('..','{08:x}'.format(addr))
            for byte in self.bytes:
                if( byte in addrBytes):
                    continue
                # No bad bytes found, so valid address
                return (True, []) 
        return (False, [])

class RegsNotModified(ConstraintType):
    def __init__(self, regsList):
        self.regs = regsList
    
    def verify(self, gadget ):
        preConds = []
        for reg in self.regs:
            pairs = gadget.getSemantics(reg)
            for p in pairs:
                if( p.expr == SSAExpr(reg, 0)):
                    if( not p.cond.isTrue()):
                        preConds.append(p.cond)
                    break # Possibility to keep the register
                return (False, []) # The register is modified 100% 
        return (True, preConds)
