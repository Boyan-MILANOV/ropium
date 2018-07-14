# -*- coding:utf-8 -*- 
# Constraints module: representation of constraints on gadgets
import re
import ropgenerator.Architecture as Arch
from ropgenerator.Gadget import RetType
from ropgenerator.Conditions import CT
from ropgenerator.Expressions import SSAExpr
from enum import Enum

#################################################
# Generic class for different constraint types  #
#################################################

class CstrTypeID(Enum):
    CHAINABLE = "Chainable"
    BAD_BYTES = "Bad Bytes"
    REG_NOT_MODIFIED = "Registers Not Modified"

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

class Chainable(ConstraintType):
    """
    Selected gadgets depending on ow they terminate
    
    if ret = jmp = True && call = False, then select 
        only possible ret and jmp gadgets (no call), etc
    """
    
    def __init__(self, ret=False, jmp=False, call=False):
        self.ret = ret
        self.jmp = jmp
        self.call = call
        
    def verify(self, gadget):
        if( self.ret == self.jmp == self.call == False ):
            return (True, [])
        elif( self.ret and gadget.retType == RetType.RET ):
            return (True, [])
        elif( self.jmp and gadget.retType == RetType.JMP ):
            return (True, [])
        elif( self.call and gadget.retType == RetType.CALL ):
            return (True, [])
            
        # If unknown ret, check if possible 
        for p in gadget.semantics.get(Arch.currentArch.ip):
            if( isinstance(p.expr, MEMExpr)):
                addr = p.expr.addr
                (isInc, inc) = addr.isRegIncrement(sp_num)    
                # Normal ret if the final value of the IP is value that was in memory before the last modification of SP ( i.e final_IP = MEM[final_sp - size_of_a_register )        
                if( self.ret and isInc and inc == (self.spInc - (Arch.currentArch.octets)) ):
                    return (True, [p.cond])
            elif( isinstance(p.expr, SSAExpr )):
                # Try to detect gadgets ending by 'call' 
                if( self.call and gadget.ins[-1]._mnemonic[:4] == "call"):
                    return (True, [p.cond])
                elif( self.jmp):
                    return (True, [p.cond])
        return (False, [])

class BadBytes(ConstraintType):
    def __init__(self, bytesList=[]):
        self.bytes = bytesList
        
    def add(self, bytesList):
        return BadBytes(list(set(self.bytes + bytesList)))
    
    def verify(self, gadget):
        for addr in gadget.addrList:
            addrBytes = re.findall('..','{:08x}'.format(addr))
            ok = True
            for byte in self.bytes:
                if( byte in addrBytes):
                    ok = False
                    break
            # No bad bytes found, so valid address
            if( ok ):
                return (True, []) 
        return (False, [])

class RegsNotModified(ConstraintType):
    def __init__(self, regsList=[]):
        self.regs = regsList
    
    def add(self, regsList):
        return RegsNotModified(list(set(self.regs + regsList)))
    
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

class Constraint:
    def __init__(self, constraintList=[]):
        self.chainable = Chainable()
        self.badBytes = BadBytes()
        self.regsNotModified = RegsNotModified()
        for c in constraintList:
            if( isinstance(c, Chainable)):
                self.chainable = c
            else:
                self.add(c, copy=False) 
    
    def _copy(self):
        new = Constraint()
        new.chainable = self.chainable
        new.badBytes = self.badBytes
        new.regsNotModified = self.regsNotModified
        return new 
         
    def add(self, c, copy=True):
        """
        Add a constrraint type to the main constraint 
        Returns a new instance
        """
        if( copy):
            new = self._copy()
        else:
            new = self
        if( isinstance(c, BadBytes)):
            new.badBytes = self.badBytes.add(c.bytes)
        elif( isinstance(c, RegsNotModified)):
            new.regsNotModified = self.regsNotModified.add(c.regs)
        elif( isinstance(c, Chainable)):
            new.chainable = c
        else:
            raise Exception("Constraint: {} is invalid for add() \function"\
            .format(c))
        return new

    def update(self, c):
        """
        Replace a constraint by another one
        Returns a new instance 
        """
        new = self._copy()
        if( isinstance(c, Chainable)):
            new.chainable = c
        else:
            raise Exception("Constraint: {} is invalid for update() function"\
            .format(c))
        return new
    
    def remove(self, idList):
        new = self._copy()
        for i in idList:
            if i == CstrTypeID.CHAINABLE:
                new.chainable = Chainable()
            elif i == CstrTypeID.BAD_BYTES:
                new.badBytes = BadBytes()
            elif i == CstrTypeID.REG_NOT_MODIFIED:
                new.regsNotModified = RegsNotModified()
        return new 
    
    def list(self):
        return [self.chainable, self.badBytes, self.regsNotModified]
    
    def verify(self, gadget):
        """
        Verifies a gadget against all constraint types 
        """
        resConds = []
        for c in self.list():
            (status, preConds) = c.verify(gadget)
            if( status ):
                resConds += preConds
            else:
                return (False, [])
        return (True, resConds)
        
    def getValidPadding(self, octets):
        """
        Returns a padding made of a valid byte according to the 
        BadBytes ConstraintType
        """
        badBytes = self.badBytes.bytes
        # Getting a valid padding byte 
        hex_chars = 'fedcba9876543210'
        found = False
        for c1 in hex_chars:
            for c2 in hex_chars:
                c = c1+c2
                if( not c in badBytes ):
                    byte = int(c,16)
                    res = 0
                    for i in range(0, octets):
                        res = res*0x100 + byte
                    return res
        return None
    
    def getBadBytes(self):
        return self.badBytes.bytes
        
###################################
# Assertions to verify conditions #
################################### 

class AssertTypeID(Enum):
    """
    Different kind of assertions applicable on gadgets 
    """
    REGS_NO_OVERLAP = "REGS_NO_OVERLAP"
    REGS_EQUAL = "REGS_EQUAL"
        
class AssertionType:
    def __init__(self):
        pass
        
    def validate(constraintList):
        """
        Validate a constraint list
        """
        
class RegsNoOverlap(AssertionType):
    def __init__(self, pairList=[]):
        """
        pairList = list of pairs [reg_num, reg_num]
        """
        self.pairs = pairList
        
    def add(self, pairList):
        return RegsNoOverlap(list(set(self.pairs + pairList)))
      
    def validate(self, condition):
        (left_isInc, left_reg, left_inc)= condition.left.isRegIncrement(-1)
        (right_isInc, right_reg,right_inc)= condition.right.isRegIncrement(-1)
        # If expressions are not REG +- CST, we don't know 
        if( not (left_isInc and right_isInc)):
            return False
        # Check with regs_no_overlap
        if( (left_reg, right_reg) in self.pairs) or\
                    ((right_reg, left_reg) in self.pairs):
            return True
        return False
            
        
class RegsEqual(AssertionType):
    def __init__(self, pairList=[]):
        """
        pairList = list of pairs [reg_num, reg_num]
        """
        self.pairs = pairList
        
    def add(self, pairList):
        return RegsEqual(list(set(self.pairs + pairList)))
      
    def validate(self, condition):
        (left_isInc, left_reg, left_inc)= condition.left.isRegIncrement(-1)
        (right_isInc, right_reg,right_inc)= condition.right.isRegIncrement(-1)
        # If expressions are not REG +- CST, we don't know 
        if( not (left_isInc and right_isInc)):
            return False
        if( not (left_inc == right_inc)):
            return False 
        # Check with regs_no_overlap
        if( ((left_reg, right_reg) in self.pairs) or\
                    ((right_reg, left_reg) in self.pairs)):
            return True
        return False  


class Assertion:
    """
    Assertions types and values:
    REGS_NO_OVERLAP : list of pairs [reg uid, reg uid]
    REGS_EQUAL : list of pairs (reg uid, reg uid)
    """
    
    
    def __init__(self, assertList=[] ):
        self.regsEqual = RegsEqual()
        self.regsNoOverlap = RegsNoOverlap()
        for a in assertList:
            self.add(a, copy=False)
    
    def _copy(self):
        new = Assertion()
        new.regsEqual = self.regsEqual
        new.regsNoOverlap = self.regsNoOverlap
        return new 
    
    def add(self, a, copy=True): 
        """
        Adds a single assertion
        Returns a new Assertion instance
        """
        if( copy ):
            new = self._copy()
        else:
            new = self
        if( isinstance(a, RegsEqual)):
            new.regsEqual = self.regsEqual.add(a.pairs)
        elif( isinstance(a, RegsNoOverlap)):
            new.regsNoOverlap = self.regsNoOverlap.add(a.pairs)
        else:
            raise Exception("Assertion: {} not supported in add() function"\
            .format(a))
        return new
    
    def remove( self, typeList):
        """
        Removes all constraints for a given ConstraintType 
        Returns a new Constraint instance
        """
        new = self._copy()
        for t in typeList:
            if( t == AssertTypeID.REGS_EQUAL ):
                new.regsEqual = RegsEqual()
            elif( t == AssertTypeID.REGS_NO_OVERLAP ):
                new.regsNoOverLap = RegsNoOverlap()
            else:
                raise Exception("Unknown assertion type")
        
    def _validateSingleCond(self, cond):
        """
        Validate a single condition 
        Returns True iff 'condition' is True according to the assertions  
        """
        if( cond.cond == CT.TRUE ):
            return True
        elif( cond.cond == CT.FALSE ):
            return False
        elif( cond.cond in [CT.GE, CT.GT, CT.LT, CT.LE] ):
            return self.regsNoOverlap.validate(cond)
        elif( cond.cond in [CT.EQUAL, CT.NOTEQUAL] ):
            return self.regsEqual.validate(cond)
        elif( cond.cond == CT.AND ):
            return (self._validateSingleCond(cond.left) and self._validateSingleCond(cond.right))
        elif( cond.cond == CT.OR ):
            return (self._validateSingleCond(cond.left) or self._validateSingleCond(cond.right))
        else:
            return False

    def validate(self, condList):
        """
        Validate a list of conditions 
        """
        for cond in condList:
            if( not self._validateSingleCond(cond)):
                return False
        return True
        
    def filter(self, condList):
        res = []
        for cond in condList:
            if( not self._validateSingleCond(cond)):
                res.append(cond)
        return res

