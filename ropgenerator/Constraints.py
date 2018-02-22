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
    REGS_VALID_POINTER="REGS_VALID_POINTER"
    BAD_BYTES="BAD_BYTES"
    
    
class SingleConstraint:
    """
    A single constraint instance
    Parameters:
        ctype - ConstraintType instance
        constraint_list - depends on ctype (see below)
        
    Type of 'constraint_list'
        ctype = REGS_NOT_MODIFIED, REGS_VALID_POINTER, then a list of reg UID
        ctype = BAD_BYTES, then a list of strings representing bad bytes (['00', 'FF', '0A'])
        /!\ hex letters must be in lower case ! 
    """
    def __init__(self, ctype, constraint_list):
        self.type = ctype
        self.constraint_list = constraint_list
        
        
class Constraint:
    """
    A list of single constraints
    """   
    def __init__(self, single_constraints_list=[]):
        self.constraints_list = single_constraints_list
    
    def add(self, constraint): 
        """
        Add a single constraint 
        """
        self.constraints_list.append(constraint)
    
    
    def validate(self, gadget):
        """
        Returns True iff 'gadget' verifies all the constraints 
        Parameters:
            gadget - Gadget instance
        """
        for c in self.constraints_list:
            if( c.type == ConstraintType.REGS_NOT_MODIFIED ):
                if( not self._validate_REG_NOT_MODIFIED(gadget, c.constraint_list)):
                    return False
            elif( c.type == ConstraintType.REGS_VALID_POINTER ):
                if( not self._validate_REGS_VALID_POINTER(gadget, c.constraint_list)):
                    return False
            elif( c.type == ConstraintType.BAD_BYTES):
                if( not self._validate_BAD_BYTES(gadget, c.constraint_list)):
                    return False
            else:
                raise ConstraintException("Invalid constraint type: " + str(c.type))
        return True
        
    def _validate_REGS_NOT_MODIFIED(self, gadget, regs_list):
        return False
        
    def _validate_REGS_VALID_POINTER(self, gadget, regs_list):
        return False
    
    def _validate_BAD_BYTES(self, gadget, bad_bytes_list):
        for i in range(2, len(gadget.addrStr), 2):
            hex_addr_byte = gadget.addrStr[i:i+2]
            if( hex_addr_byte in bad_bytes_list):
                return False
        return True
        
        
    def get_all_bad_bytes(self):
        res = []
        for c in self.constraints_list:
            if( c.type == ConstraintType.BAD_BYTES ): 
                res += c.constraint_list
        return res
        
    
    
    
