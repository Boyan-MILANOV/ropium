# ROPGenerator - Constraints module 
# Managing constraints while chaining gadgets

from enum import Enum
from ropgenerator.Logs import log
import ropgenerator.Expr as Expr
from ropgenerator.Cond import CT


class ConstraintException( Exception ):
    def __init__( self, msg ):
        self.msg = msg
        log(self.msg)
    def __str__(self):
        return self.msg


    
###########################
# Assertions for handling #
# conditionnal gadgets    #
###########################
    
class AssertionType(Enum):
    """
    Different kind of assertions applicable on gadgets 
    """
    REGS_NO_OVERLAP = "REGS_NO_OVERLAP"
    REGS_EQUAL = "REGS_EQUAL"
        
class Assertion:
    """
    Assertions types and values:
    REGS_NO_OVERLAP : list of pairs [reg uid, reg uid]
    REGS_EQUAL : list of pairs (reg uid, reg uid)
    """
    
    
    def __init__(self):
        self.assertions = dict()
    
    def __str__(self):
        res = ''
        res += "Assertion:\n"
        for atype, alist in self.assertions.iteritems():
            res += '\t'+str(atype)+': '+str(alist)+'\n'
        return res
    
    def add(self, assert_type, assert_list ): 
        """
        Adds a single assertion
        Returns a new Assertion instance
        """
        new_assert = Assertion()
        new_assert.assertions = dict(self.assertions)
        if( not assert_type in new_assert.assertions):
            new_assert.assertions[assert_type] = assert_list
        else:
            new_assert.assertions[assert_type] = list(set(new_assert.assertions[assert_type] + assert_list))
        return new_assert
    
    def remove_all( self, assert_type):
        """
        Removes all constraints for a given ConstraintType 
        Returns a new Constraint instance
        """
        new_assert = Assertion()
        new_assert.assertions = dict(self.assertions)
        new_assert.assertions.pop(assert_type, None)
        return new_assert
        
    def validate(self, condition):
        """
        Returns True iff 'condition' is True according to the assertions  
        """
        # Base cases
        cond = condition.cond
        if( cond == CT.TRUE ):
            return True
        elif( cond == CT.FALSE ):
            return False
        elif( cond in [CT.GE, CT.GT, CT.LT, CT.LE] ):
            (left_isInc, left_reg, left_inc)= condition.left.isRegIncrement(-1)
            (right_isInc, right_reg,right_inc)= condition.right.isRegIncrement(-1)
            # If expressions are not REG +- CST, we don't know 
            if( not (left_isInc and right_isInc)):
                return False
            # Check with regs_no_overlap
            no_overlap = self.assertions.get(AssertionType.REGS_NO_OVERLAP, [])
            if( ([left_reg, right_reg] not in no_overlap) and\
                        ([right_reg, left_reg] not in no_overlap)):
                return False
        elif( cond in [CT.EQUAL, CT.NOTEQUAL] ):
            # NOT SUPPORTED
            return False
        elif( cond == CT.AND ):
            return (self.validate(condition.left) and self.validate(condition.right))
        elif( cond == CT.OR ):
            return (self.validate(condition.left) or self.validate(condition.right))
            
        # All tests passed with assertions 
        return True


##########################
# Constraints on gadgets #
##########################

class ConstraintType(Enum):
    """
    Different kind of constraints applicable on gadgets 
    """
    REGS_NOT_MODIFIED="REGS_NOT_MODIFIED"
    REGS_VALID_POINTER_READ="REGS_VALID_POINTER_READ"
    REGS_VALID_POINTER_WRITE="REGS_VALID_POINTER_WRITE"
    BAD_BYTES="BAD_BYTES"
    CHAINABLE_RET="CHAINABLE_RET"
    

class Constraint:
    """
    A constraint is a set of single constraints stored in a dict()
    Dictionnary keys are ConstraintType
    Dictionnary values depend on the ConstraintType 'ctype' 
        ctype = REGS_NOT_MODIFIED, REGS_VALID_POINTER, then a list of couples (reg UID, CST)
        ctype = BAD_BYTES, then a list of strings representing bad bytes (['00', 'FF', '0A'])
        ctype = CHAINABLE_RET then an empty list 
        /!\ hex letters must be in lower case ! 
    """   
    def __init__(self, context=0):
        self.constraints = dict()
        self.context = context
    
    def __str__(self):
        res = ''
        res += "Constraint ({}):\n".format(self.context)
        for ctype, clist in self.constraints.iteritems():
            res += '\t'+str(ctype)+': '+str(clist)+'\n'
        return res
    
    def add(self, constraint_type, constraint_list ): 
        """
        Adds a single constraint
        Returns a new Constraint instance
        """
        new_constraint = Constraint()
        new_constraint.constraints = dict(self.constraints)
        new_constraint.context = self.context + 1
        if( not constraint_type in new_constraint.constraints):
            new_constraint.constraints[constraint_type] = constraint_list
        else:
            new_constraint.constraints[constraint_type] = list(set(new_constraint.constraints[constraint_type] + constraint_list))
        return new_constraint
    
    def remove_all( self, constraint_type):
        """
        Removes all constraints for a given ConstraintType 
        Returns a new Constraint instance
        """
        new_constraint = Constraint()
        new_constraint.constraints = dict(self.constraints)
        new_constraint.constraints.pop(constraint_type, None)
        return new_constraint
    
    def validate(self, gadget, only_bad_bytes=False, conditionnal=False, ret_assert=Assertion()):
        """
        Returns True iff 'gadget' verifies all the constraints 
        Parameters:
            gadget - Gadget instance
            only_bad_bytes = True <=> We only check the bad_bytes constraint 
            conditionnal = validating a conditionnal gadget, so different handling of the constraints
            ret_assert = the assertion to use to determine if the ret is valid or not ! 
        """
        if( conditionnal ):
            # Conditionnal gadgets
            # Only check bad bytes and regs not modified
            for ctype, clist in self.constraints.iteritems():
                if( ctype == ConstraintType.REGS_NOT_MODIFIED ):
                    if( not self._validate_REGS_NOT_MODIFIED(gadget, clist)):
                        return False
                elif( ctype == ConstraintType.BAD_BYTES):
                    if( not self._validate_BAD_BYTES(gadget, clist)):
                        return False
                else:
                    return True
        
        if( only_bad_bytes ):
            # ONly check for bad bytes constraint 
            if( ConstraintType.BAD_BYTES in self.constraints ):
                return self._validate_BAD_BYTES(gadget, \
                    self.constraints[ConstraintType.BAD_BYTES])
            else:
                return True
        
        # Normal behaviour, check all constraints 
        for ctype, clist in self.constraints.iteritems():
            if( ctype == ConstraintType.REGS_NOT_MODIFIED ):
                if( not self._validate_REGS_NOT_MODIFIED(gadget, clist)):
                    return False
            elif( ctype == ConstraintType.REGS_VALID_POINTER_READ ):
                if( not self._validate_REGS_VALID_POINTER_READ(gadget, clist)):
                    return False
            elif( ctype == ConstraintType.REGS_VALID_POINTER_WRITE ):
                if( not self._validate_REGS_VALID_POINTER_WRITE(gadget, clist)):
                    return False
            elif( ctype == ConstraintType.BAD_BYTES):
                if( not self._validate_BAD_BYTES(gadget, clist)):
                    return False
            elif( ctype == ConstraintType.CHAINABLE_RET):
                if( not self._validate_CHAINABLE_RET(gadget, ret_assert)):
                    return False
            else:
                raise ConstraintException("Invalid constraint type: " + str(ctype))
        return True
        
    def _validate_REGS_NOT_MODIFIED(self, gadget, regs_list):
        for reg in regs_list:
            ssaReg = Expr.SSAReg(reg, gadget.graph.lastMod[reg])
            if( ssaReg in gadget.dep.regDep ):
                regdeps = gadget.dep.regDep[ssaReg]
                # TODO: Check if some bug with empty regdeps in 32 bits ? 
                if( not regdeps ):
                    return False
                if( regdeps[0][1].isTrue() and isinstance(regdeps[0][0], Expr.SSAExpr)):
                    if( not (regdeps[0][0].reg.num == reg and regdeps[0][0].reg.ind == 0 )):
                        return False
                else:
                    return False
        return True
        
    def _validate_REGS_VALID_POINTER_READ(self, gadget, regs_list):
        return False
    
    def _validate_REGS_VALID_POINTER_WRITE(self, gadget, regs_list):
        return False
    
    def _validate_BAD_BYTES(self, gadget, bad_bytes_list):
        for i in range(2, len(gadget.addrStr), 2):
            hex_addr_byte = gadget.addrStr[i:i+2]
            if( hex_addr_byte in bad_bytes_list):
                return False
        return True
      
    def _validate_CHAINABLE_RET(self, gadget, ret_assert=Assertion()):
        # First validate the most important: sp modification
        if( gadget.isValidSpInc()):
            # Then check if the ret is normal 
            if( gadget.hasNormalRet() ):
                return True
            # If not get the condition and validate with the optional assertion
            else:
                (has,condition) = gadget.hasPossibleNormalRet()
                if( has ):
                    return ret_assert.validate(condition)
        # Not valid, return False
        return False
            
    def get(self, ctype):
        """
        Returns the list associated to ctype
        ctype - ConstraintType
        """   
        if( ctype in self.constraints ):
            return self.constraints[ctype]
        else:
            return []
            
