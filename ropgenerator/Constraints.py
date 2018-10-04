# -*- coding:utf-8 -*- 
# Constraints module: representation of constraints on gadgets
import re
import ropgenerator.Architecture as Arch
from ropgenerator.Gadget import RetType, GadgetType
from ropgenerator.Conditions import CT, Cond
from ropgenerator.Expressions import SSAExpr
from enum import Enum

#################################################
# Generic class for different constraint types  #
#################################################

class CstrTypeID(Enum):
    CHAINABLE = "Chainable"
    BAD_BYTES = "Bad Bytes"
    REG_NOT_MODIFIED = "Registers Not Modified"
    VALID_PTR_READ = "Read Memory - Valid pointer"
    VALID_PTR_WRITE = "Write Memory - Valid pointer"
    STACK_POINTER_INCREMENT = "Stack Pointer Increment"

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
    
    if ret = jmp = call = False, then validate any gadget
    
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
            addrBytes = re.findall('..',format(addr, '0'+str(Arch.octets()*2)+'x'))
            ok = True
            for byte in self.bytes:
                if( byte in addrBytes):
                    ok = False
                    break
            # No bad bytes found, so valid address
            if( ok ):
                return (True, []) 
        return (False, [])
        
    def verifyAddress(self, address):
        """
        like verify() but input is already the address 
        address - int
        """
        addrBytes = re.findall('..',('{:'+'{:02d}'\
            .format(Arch.currentArch.octets)+'x}').format(address))
        ok = True
        for byte in self.bytes:
            if( byte in addrBytes):
                return False
        # No bad bytes found, so valid address
        return True

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

class ValidPtrWrite(ConstraintType):
    def __init__(self):
        pass
        
    def verify(self, gadget):
        # DEBUG
        return (True, [])
        return (True, [Cond(CT.VALID_PTR_WRITE, None, mem) for mem in\
        gadget.memoryWrites()])
    
class ValidPtrRead(ConstraintType):
    def __init__(self):
        pass
        
    def verify(self, gadget):
        # DEBUG
        return (True, [])
        return (True, [Cond(CT.VALID_PTR_READ, None, mem) for mem in\
        gadget.memoryReads()])

class StackPointerIncrement(ConstraintType):
    def __init__(self, value=None):
        self.inc = value
        
    def verify(self, gadget):
        if( self.inc == None ):
            return (True, [])
        elif( gadget.spInc is None ):
            return (False, [])
        else:
            return (gadget.spInc == self.inc, [])


class Constraint:
    def __init__(self, constraintList=[]):
        self.chainable = Chainable()
        self.badBytes = BadBytes()
        self.regsNotModified = RegsNotModified()
        self.validPtrRead = ValidPtrRead()
        self.validPtrWrite = ValidPtrWrite()
        self.stackPointerIncrement = StackPointerIncrement()
        for c in constraintList:
            if( isinstance(c, Chainable)):
                self.chainable = c
            elif( isinstance(c, StackPointerIncrement)):
                self.stackPointerIncrement = c
            else:
                self.add(c, copy=False) 
    
    def _copy(self):
        new = Constraint()
        new.chainable = self.chainable
        new.badBytes = self.badBytes
        new.regsNotModified = self.regsNotModified
        new.validPtrRead = self.validPtrRead
        new.validPtrWrite = self.validPtrWrite
        new.stackPointerIncrement = self.stackPointerIncrement
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
        elif( isinstance(c, StackPointerIncrement)):
            new.stackPointerIncrement = c
        else:
            raise Exception("Constraint: {} is invalid for add() function"\
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
        elif( isinstance(c, StackPointerIncrement)):
            new.stackPointerIncrement = c
        else:
            raise Exception("Constraint: {} is invalid for update() function"\
            .format(c))
        return new
    
    def remove(self, idList):
        new = self._copy()
        for i in idList:
            if i == CstrTypeID.CHAINABLE:
                new.chainable = Chainable()
            elif i == CstrTypeID.STACK_POINTER_INCREMENT:
                new.stackPointerIncrement = StackPointerIncrement()
            elif i == CstrTypeID.BAD_BYTES:
                new.badBytes = BadBytes()
            elif i == CstrTypeID.REG_NOT_MODIFIED:
                new.regsNotModified = RegsNotModified()
            else:
                raise Exception("Constraint: {} is invalid for remove() function"\
            .format(str(i)))
        return new 
    
    def list(self):
        return [self.chainable, self.badBytes, self.regsNotModified, \
            self.validPtrRead, self.validPtrWrite, self.stackPointerIncrement]
    
    def verify(self, gadget):
        """
        Verifies a gadget against all constraint types 
        """
        if( gadget.type == GadgetType.INT80 or\
            gadget.type == GadgetType.SYSCALL ):
            return self.badBytes.verify(gadget)
        
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
       
    def getRegsNotModified(self):
        return self.regsNotModified.regs
        
###################################
# Assertions to verify conditions #
################################### 

class AssertTypeID(Enum):
    """
    Different kind of assertions applicable on gadgets 
    """
    REGS_NO_OVERLAP = "REGS_NO_OVERLAP"
    REGS_EQUAL = "REGS_EQUAL"
    REGS_VALID_PTR_READ = "REGS_VALID_PTR_READ"
    REGS_VALID_PTR_WRITE = "REGS_VALID_PTR_WRITE"
        
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

class RegsValidPtrRead(AssertionType):
    def __init__(self, regList=[]):
        """
        regList - list of triples (reg, low, high)
        -> Accesses from reg-low to reg+high are correct !!
        """
        self.regs = regList
        
    def add(self, regList):
        return RegsValidPtrRead(self.regs + regList)
        
    def update(self, regTuple):
        """
        regTuple = (reg, low, high)
        """
        new = []
        for t in self.regs:
            if( t[0] == regTuple[0]):
                new.append(regTuple)
            else:
                new.append(t)
        return RegsValidPtrRead(new)
    
    def validate(self, condition):
        """
        Condition must be CT.VALID_PTR_READ
        """
        (isInc, reg, inc) = condition.right.isRegIncrement(-1)
        if( not isInc ):
            return False
        for e in self.regs:  
            if( e[0] == reg and inc > e[1] and inc < e[2]):
                return True
        return False

class RegsValidPtrWrite(AssertionType):
    """
    regList - list of triples (reg, low, high)
    -> Accesses from reg-low to reg+high are correct !!
    """
    def __init__(self, regList=[]):
        self.regs = regList
        
    def add(self, regList):
        return RegsValidPtrWrite(list(set(self.regs + regList)))
        
    def update(self, regTuple):
        """
        regTuple = (reg, low, high)
        """
        new = []
        for t in self.regs:
            if( t[0] == regTuple[0]):
                new.append(regTuple)
            else:
                new.append(t)
        return RegsValidPtrWrite(new)
    
    def validate(self, condition):
        """
        Condition must be CT.VALID_PTR_WRITE
        """
        (isInc, reg, inc ) = condition.right.isRegIncrement(-1)
        if( not isInc ):
            return False
        for e in self.regs:
            if( e[0] == reg and inc > e[1] and inc < e[2]):
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
        self.regsValidRead = RegsValidPtrRead()
        self.regsValidWrite = RegsValidPtrWrite()
        for a in assertList:
            self.add(a, copy=False)
    
    def _copy(self):
        new = Assertion()
        new.regsEqual = self.regsEqual
        new.regsNoOverlap = self.regsNoOverlap
        new.regsValidRead = self.regsValidRead
        new.regsValidWrite = self.regsValidWrite
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
        elif( isinstance(a, RegsValidPtrRead)):
            new.regsValidRead = self.regsValidRead.add(a.regs)
        elif( isinstance(a, RegsValidPtrWrite)):
            new.regsValidWrite = self.regsValidWrite.add(a.regs)
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
            elif( t == AssertTypeID.REGS_VALID_PTR_READ ):
                new.regsValidRead = RegsValidPtrRead()
            elif( t == AssertTypeID.REGS_VALID_PTR_WRITE ):
                new.regsValidWrite = RegsValidPtrWrite()
            else:
                raise Exception("Unknown assertion type")
        return new 
        
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
        elif( cond.cond == CT.VALID_PTR_READ ):
            # We can read where we can write ;) 
            return (self.regsValidRead.validate(cond) or \
                    self.regsValidWrite.validate(cond))
        elif( cond.cond == CT.VALID_PTR_WRITE ):
            return self.regsValidWrite.validate(cond)
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

