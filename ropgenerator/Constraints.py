# ROPGenerator - Constraints module 
# Managing constraints while chaining gadgets

from enum import Enum
from ropgenerator.Logs import log

class ConstraintException( Exception ):
    def __init__( self, msg ):
        self.msg = msg
        log(self.msg)
    def __str__(self):
        return self.msg


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
        ctype = REGS_NOT_MODIFIED, REGS_VALID_POINTER, then a list of reg UID
        ctype = BAD_BYTES, then a list of strings representing bad bytes (['00', 'FF', '0A'])
        ctype = CHAINABLE_RET then an empty list 
        /!\ hex letters must be in lower case ! 
    """   
    def __init__(self):
        self.constraints = dict()
    
    def __str__(self):
        res = ''
        res += "Constraint:\n"
        for ctype, clist in self.constraints.iteritems():
            res += '\t'+ctype+': '+str(clist)+'\n'
        return res
    
    def add(self, constraint_type, constraint_list ): 
        """
        Adds a single constraint
        Returns a new Constraint instance
        """
        new_constraint = Constraint()
        new_constraint.constraints = dict(self.constraints)
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
    
    def validate(self, gadget):
        """
        Returns True iff 'gadget' verifies all the constraints 
        Parameters:
            gadget - Gadget instance
        """
        for ctype, clist in self.constraints.iteritems():
            if( ctype == ConstraintType.REGS_NOT_MODIFIED ):
                if( not self._validate_REG_NOT_MODIFIED(gadget, clist)):
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
                if( not self._validate_CHAINABLE_RET(gadget)):
                    return False
            else:
                raise ConstraintException("Invalid constraint type: " + str(ctype))
        return True
        
    def _validate_REGS_NOT_MODIFIED(self, gadget, regs_list):
        return False
        
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
      
    def _validate_CHAINABLE_RET(self, gadget):
        return (gadget.hasNormalRet() and gadget.isValidSpInc())
    
    def get(self, ctype):
        """
        Returns the list associated to ctype
        ctype - ConstraintType
        """   
        if( ctype in self.constraints ):
            return self.constraints[ctype]
        else:
            return []
    
    
    
