# -*- coding: utf-8 -*- 
# Expressions module : model for arithmetic/logical expressions 

import ropgenerator.Architecture as Arch
from ropgenerator.Conditions import CTrue, Cond, CT
from enum import Enum

class ExprException(Exception):
    """
    Custom Exception type for this module
    """
    def __init__(self, msg):
        self.msg = msg
        
    def __str__(self):
        return self.msg

########################################
# REPRESENTATION OF REGISTERS WITH SSA # 
########################################

class SSAReg:
    """
    Implements generic SSA representation of a register.
    The register itself got an ID that is a integer : self.num
    Then the SSA is obtained by adding another integer : self.ind
    Example : if EAX's ID is 0 then EAX_5 would be (num:0, ind:5) whose
    string represenation is R0_5 
    """
    
    def __init__(self, num, ind):
        self.num = num
        self.ind = ind
        
    def __str__(self):
        return "R%d_%d" % (self.num, self.ind)
        
    def __eq__(self, other):
        return (self.num == other.num and self.ind == other.ind )
        
    def __ne__(self, other):
        return not (self == other)
    
    def __hash__(self): 
        return (self.num+1)*5000 - self.ind

    def prevOcc(self):
        """
        Returns the previous occurence of a SSA register
        prevOcc( R1_2 ) = R1_1
        prevOcc( R1_0 ) = R1_0
        """
        if self.ind == 0:
            return SSAReg(self.num, self.ind)
        else:
            return SSAReg(self.num, self.ind-1)
        

def strToReg(string):
    """
    Converts a string in a SSAReg
    String must be "RX_Y" where X and Y are positive integers
    """
    s1, s2 = string.split("_")
    return SSAReg(int(s1[1:]), int(s2))
    
    
###################################
# Different kinds of expressions  #
###################################


class Expr:
    """
    General class implemeting expressions containing registers and memory accesses
        (self.size) (int) is the number of bits the expression should be stored in
    """

    def __init__(self):
        self.size = -1
        self.args = []
            
    def replaceReg(self, reg, expr):
        """
        This method returns an expression where the occurences of 'reg' are replaced by 'expr'
        
        Parameters :
            reg - (SSAReg) the register that will be replace
            expr - (Expr) the expression that replaces 'var'
        """

    def replaceMultiReg( self, reg_dict):
        """
        This method returns an expression where the occurences of the registers present
        in the reg_dict dictionnary are replaced by their corresponding value in the
        dictionnary
        
        Parameters :
            reg_dict - (Dictionnary) Entries are SSAReg expressions and values are Expr 
        """

    def replaceMemAcc(self, addr, expr ):
        """
        This method replaces every memory access at address 'addr' by the expression 'expr'
        
        Parameters : 
            addr - (Expr)
            expr - (Expr)
        """

    def getRegisters(self, ignoreMemAcc=False):
        """
        Returns a list of SSARegiters that occur in the expression
        Eliminate multiple occurences in the list  
        The ignoreMemAcc option is used to omit registers that appear in memory accesses (e.g MEM[R1_3 + 0x8 + R7_1)
        """

    def getMemAcc(self):
        """
        Returns a list of Expr representing addresses at which memory is accessed
        """
        
    def __hash__(self):
        """
        Hash function
        """

    def replaceITE(self, expr):
        """
        Replace the first ITE found with expression 'expr'
        Parameters :
            expr - (Expr)
        """

    def toArray(self):
        """
        Returns its 'array' representation as a vector V
        Coefficient at position i is the coefficient of register Ri_...
        Last coefficient is a constant
        If the expression can not be converted, [] is returned
        So length of the array will be ssaRegCount + 1
        
        Example : [1, 0, 2, 0, ...,  -8] is R1 + 2*R3 -8
        
        """

    def simplify(self):
        """
        Returns a a simplified version of itself
        """

    def isRegIncrement(self, reg_num):
        """
        If the expression is (REG +- CST)
            Returns (True, CST) if reg_num is an int 
            Returns (True, REG, CST) is reg_num is -1 
        Else
            Returns (False, None)
            or (False, None, None) 
        """

class ConstExpr(Expr):
    """
    Describes a constant value
    """
    
    def __init__(self, value, size):
        Expr.__init__(self)
        if(isinstance(value, int ) or isinstance(value, long)):
            self.value = value
        else:
            self.value = int(value, 16)
        self.size = size

    def __str__(self):
        return "0x%x" % (self.value)

    def replaceReg(self, var, expr):
        return self
        
    def replaceMultiReg(self, reg_dict):
        return self
        
    def replaceMemAcc(self, addr, expr):
        return self
        
    def __eq__(self, other):
        if( not isinstance( other, ConstExpr )):
            return False
        return self.value == other.value
    
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        return []
        
    def getMemAcc(self):
        return []
        
    def __hash__(self):
        return hash(self.value)
    
    def flattenITE(self):
        return [[self, CTrue()]] 
    
    def simplify(self):
        return self
        
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
        
    def toArray(self):
        res = [0 for x in range(0,Arch.ssaRegCount)]
        res.append(self.value)
        return res
        
    def deepcopy(self):
        return ConstExpr(self.value, self.size)
 
        
class SSAExpr(Expr):
    """
    Represents an expression made out of a single register ( like R5_3 )
    """

    def __init__(self, num, ind=0):
        Expr.__init__(self)
        if( isinstance(num, SSAReg)):
            self.reg = SSAReg(num.num, num.ind)
        else:
            self.reg = SSAReg(num, ind)
        self.size = Arch.currentArch.bits
    
    def __str__(self):
        return str(self.reg)

    def replaceReg(self, reg, expr):
        if( self.reg == reg ):
            return expr
        else:
            return self
            
    def replaceMultiReg(self, reg_dict):
        if( self in reg_dict ):
            return reg_dict[self]
        else:
            return SSAExpr( self.reg )
            
    def replaceMemAcc(self, addr, expr):
        return self    
    
    def __eq__(self, other): 
        if( not isinstance( other, SSAExpr )):
            return False
        return self.reg == other.reg
        
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        return [self.reg]
        
    def getMemAcc(self):
        return []
        
    def __hash__(self):
        return hash(self.reg)
            
    def replaceITE(self, expr):
        return self
                
    def flattenITE(self):
        return [[self, CTrue()]]
    
    def simplify(self):
        return self
        
    def isRegIncrement(self, reg_num):
        """
        If the expression is (REG +- CST)
            Returns (True, CST) if reg_num is an int 
            Returns (True, REG, CST) is reg_num is -1 
        Else
            Returns (False, None)
            or (False, None, None) 
        """
        if( reg_num == -1 ):
            return (True, self.reg.num, 0)
        elif( self.reg.num == reg_num ):
            return (True, 0)
        else:
            return (False, None)
    
    def toArray(self):    
        res = [0 for r in range(0,self.reg.num)]
        res += [1]
        res +=  [0 for r in range(self.reg.num+1, Arch.ssaRegCount+1)]
        return res
        
    def deepcopy(self):
        return SSAExpr(SSAReg(self.reg.num, self.reg.ind))


class MEMExpr(Expr):
    """
    Memory access in an expression. 
    Example : MEM[R3_2 + 0x4]  
    """
    
    def __init__(self, addr, size):
        """
        Parameters: 
            (self.addr) (Expr) is the address at which memory is accessed 
            (self.size) (int) is the size of the memory access in bits
        """
        Expr.__init__(self)
        self.addr = addr
        self.size = size 
        self.simplifiedValue = None

    def __str__(self):
        return "MEM%d[%s]" %(self.size, str(self.addr))
        
    def replaceReg( self, reg, expr ):
        new_addr = self.addr.replaceReg(reg, expr)
        if( new_addr != self.addr ):
            return MEMExpr( self.addr.replaceReg( reg, expr ), self.size)
        else:
            return self
        
    def replaceMultiReg(self, reg_dict):
        res = MEMExpr( self.addr.replaceMultiReg( reg_dict ), self.size ) 
        return res

    def replaceMemAcc(self, addr, expr):
        self.addr = self.addr.simplify()
        addr = addr.simplify()
        if( self.addr == addr ):
            if( expr.size > self.size ):
                # If we write like 32 bits over a 8 bits access, we 
                # extract only the first 8 bits of the 32 bits value
                return Extract(self.size, 0, expr)
            elif( expr.size < self.size ):
                # If we write too little, concat with the previously 
                # stored value that will remain 
                return Concat([expr, MEMExpr(OpExpr(Op.ADD, [addr, ConstExpr(expr.size/8, addr.size)]), self.size-expr.size)])
            else:
                return expr
        else:
            return MEMExpr( self.addr.replaceMemAcc( addr, expr ), self.size )
        
    def __eq__(self, other): 
        if( not isinstance( other, MEMExpr )):
            return False
        return self.addr == other.addr
        
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        if( ignoreMemAcc ):
            return []
        else:
            return list(set(self.addr.getRegisters()))
        
    def getMemAcc(self):
        return list(set([(self.addr, self.size)] + self.addr.getMemAcc()))
        
    def __hash__(self):
        return hash("MEM")*hash(self.addr)
        
    def replaceITE(self, expr):
        return MEMExpr( self.addr.replaceITE(expr), self.size)
        
    def flattenITE(self):
        flat = self.addr.flattenITE()
        return [[MEMExpr( f[0], self.size), f[1]] for f in flat]
    
    def simplify(self):
        if( self.simplifiedValue ):
            return self.simplifiedValue
        
        self.simplifiedValue = MEMExpr(self.addr.simplify(), self.size)
        return self.simplifiedValue
        
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
        
    def toArray(self):
        return []
      
    def deepcopy(self):
        return MEMExpr(self.addr.deepcopy(), self.size) 



class Op(Enum):
    """
    Supported operations 
    """
    ADD = "Add"
    SUB = "Sub"
    MUL = "Mul"
    DIV = "Div"
    MOD = "Mod"
    NOT = "Not"
    AND = "And"
    OR = "Or"
    XOR = "Xor"
    BSH = "Bsh"


class OpExpr(Expr):
    """
    Describes an operation ( with one or many arguments ) on expressions 
    The operation is specified by the attribute 'op' which is a Op string
    The size of the operation is deduced from the size of it's arguments 
    """
    
    def __init__(self, op, args):
        """
        """
        Expr.__init__(self)
        self.op = op
        self.args = args
        self.size = args[0].size 
        # For optimization
        self.regs = None
        self.simplifiedValue = None
        
    def __str__(self):
        return "%s%d(%s)" % ( self.op, self.size, ','.join(str(a) for a in self.args))
        
    def replaceReg( self, reg, expr ):
        newArgs = []
        diff = False
        for arg in self.args:
            newArg = arg.replaceReg(reg, expr)
            if( newArg != arg):
                diff = True
            newArgs.append(newArg)
        if( diff ):
            return OpExpr( self.op, newArgs)
        else:
            return self
        
    def replaceMultiReg(self, reg_dict):
        newArgs = [arg.replaceRegMultiReg( reg_dict ) for arg in self.args]
        return OpExpr( self.op, newArgs)
        
    def replaceMemAcc( self, addr, expr ):
        newArgs = [arg.replaceMemAcc( addr, expr ) for arg in self.args]
        return OpExpr( self.op, newArgs) 
        
    def __eq__(self, other):
        if( not isinstance( other, OpExpr )):
            return False 
        elif( len(self.args) != len(other.args)):
            return False
        elif( self.op != other.op ):
            return False
        elif( self.size != other.size ):
            return False    
            
        for ind, arg in enumerate(self.args):
            if( arg != other.args[ind] ):
                return False
        return True 
        
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        if( self.regs is None ):
            self.regs = list(set(self.args[0].getRegisters(ignoreMemAcc) +\
                        self.args[1].getRegisters(ignoreMemAcc)))
        return self.regs
        
    def getMemAcc(self):
        return list(set(self.args[0].getMemAcc() + self.args[1].getMemAcc()))
         
    def __hash__(self):
        return hash(str(self.op))*( hash(self.args[0]) - hash(self.args[1]))
        
    def replaceITE(self, expr):
        newArgs = [arg.replaceITE(expr) for arg in self.args]
        return Op( self.op, self.size, newArgs)
        
    def flattenITE(self):
        """
        ! Works only for unary or binary operations 
        """
        res = []
        if( len(self.args) == 2 ):
            flatLeft = self.args[0].flattenITE()
            flatRight = self.args[1].flattenITE()
            for f in flatLeft:
                for f2 in flatRight:
                    res.append([ OpExpr(self.op,[ f[0], f2[0]]), Cond(CT.AND, f[1], f2[1]) ])
            return res
        elif( len(self.args) == 1 ):
            flat = self.args[0].flattenITE()
            return [[OpExpr(self.op, self.size, f[0]), f[1]] for f in flat]
        else:
            raise ExprException(" flattenITE can not be used with an operator on more than 2 arguments (%d here) " % len(self.args))
    
    def simplify(self):
        # Check if already simplified 
        if( self.simplifiedValue ):
            return self.simplifiedValue
        
        # If not, simplify it !
        simpArgs = [arg.simplify() for arg in self.args]
        op = self.op 
        left = simpArgs[0]
        if( len(simpArgs) == 2 ):
            right = simpArgs[1]
        
        # The result without structrual simplifications 
        res = OpExpr( op, simpArgs )
        # Simplifications 
        if( op == Op.NOT ):
            if( isinstance( left, OpExpr ) and left.op == Op.NOT ):
                res = left.args[0]
        
        elif( op == Op.ADD ):
            const = None
            subAdd = None
            subSub = None
            # Check for constant 
            if( isinstance( left, ConstExpr ) ):
                if( left.value == 0 ):
                    res = right
                elif( isinstance( right, ConstExpr )):
                    res = ConstExpr( left.value + right.value, left.size )
                else:
                    const = left
            elif( isinstance( right, ConstExpr )):
                if( right.value == 0 ):
                    res = left
                else:
                    const = right
            
            # Check for a sub-expression that is an Addition or Substraction
            if( isinstance( left, OpExpr ) and left.op == Op.ADD ):
                subAdd = left 
            elif( isinstance( right, OpExpr ) and right.op == Op.ADD ):
                subAdd = right 
            elif( isinstance( left, OpExpr ) and left.op == Op.SUB ):
                subSub = left 
            elif( isinstance( right, OpExpr ) and right.op == Op.SUB ):
                subSub = right 
            # Simplifications if possible     
            if( const != None and subAdd != None ):
                if( isinstance( subAdd.args[0], ConstExpr )):
                    res = OpExpr( Op.ADD, [ConstExpr( const.value + subAdd.args[0].value, const.size ), subAdd.args[1]]).simplify()
                elif( isinstance( subAdd.args[1], ConstExpr )):
                    res = OpExpr( Op.ADD, [ConstExpr( const.value + subAdd.args[1].value, const.size ), subAdd.args[0]] ).simplify()
            if( const != None and subSub != None ):
                if( isinstance( subSub.args[1], ConstExpr )):
                    newConst = const.value - subSub.args[1].value
                    if( newConst != 0 ):
                        res = OpExpr( Op.ADD, [ConstExpr( newConst, const.size ), subSub.args[0] ])
                    else:
                        res= subSub.args[0]
        
        elif( op == Op.SUB ):
            if( isinstance(right, ConstExpr) and right.value == 0 ):
                res = left
            elif( isinstance(right, ConstExpr) and isinstance(left, OpExpr) and\
                    left.op == Op.SUB and isinstance(left.args[1], ConstExpr)):
                res = OpExpr(Op.SUB, [left.args[0], \
                    ConstExpr(left.args[1].value+right.value, right.size)]).simplify()
            elif( isinstance(right, ConstExpr) and isinstance(left, OpExpr) and\
                    left.op == Op.ADD and isinstance(left.args[1], ConstExpr)):
                res = OpExpr(Op.ADD, [left.args[0], ConstExpr(left.args[1].value-right.value, right.size)]).simplify()
            elif( isinstance( left, ConstExpr) and isinstance(right, OpExpr) and\
                    right.op == Op.ADD):
                if( isinstance(right.args[0], ConstExpr)):
                    res = OpExpr(Op.SUB, [ConstExpr(left.value - right.args[0].value, left.size),\
                    right.args[1]]).simplify()
                elif( isinstance(right.args[1], ConstExpr)):
                    res = OpExpr(Op.SUB, [ConstExpr(left.value - right.args[1].value, left.size),\
                    right.args[0]]).simplify()
            
            elif( isinstance( left, ConstExpr) and isinstance(right, OpExpr) and\
                    right.op == Op.SUB):
                if( isinstance(right.args[0], ConstExpr)):
                    res = OpExpr(Op.ADD, [ConstExpr(left.value - right.args[0].value, left.size),\
                    right.args[1]]).simplify()
                elif( isinstance(right.args[1], ConstExpr)):
                    res = OpExpr(Op.SUB, [ConstExpr(left.value + right.args[1].value, left.size),\
                    right.args[0]]).simplify()
            elif( isinstance( left, ConstExpr) and isinstance(right, ConstExpr) and\
                left.value == right.value):
                res = ConstExpr(0, left.size)
        
        elif( op == Op.MUL ):
            if( isinstance(left, ConstExpr) and left.value == 0 ):
                res = ConstExpr(0, left.size)
            elif( isinstance(left, ConstExpr) and left.value == 1 ):
                res = right
            elif( isinstance(right, ConstExpr) and right.value == 1 ):
                res = left        
            elif( isinstance(right, ConstExpr) and right.value == 0 ):
				res = ConstExpr(0, left.size)
        
        elif( op == Op.XOR ):
            if( isinstance(left, ConstExpr) and left.value == 0 ):
                res = right
            elif( isinstance(right, ConstExpr) and right.value == 0 ):
                res = left
            elif( left == right ):
                res = ConstExpr(0, left.size)
            
        self.simplifiedValue = res
        return res
            
    def isRegIncrement(self, reg_num):
        """
        If the expression is (REG +- CST)
            Returns (True, CST) if reg_num is an int 
            Returns (True, REG, CST) is reg_num is -1 
        Else
            Returns (False, None) 
        """
        if( self.op != Op.ADD and self.op != Op.SUB):
            if( reg_num == -1 ):
                return (False, None, None)
            else:
                return (False, None)
        elif( len(self.args) != 2 ):
            if( reg_num == -1 ):
                return (False, None, None)
            else:
                return (False, None)
        else:
            left = self.args[0]
            right = self.args[1]
        
        if( self.op == Op.ADD ):
            factor = 1
        else:
            factor = -1
        
        # Search for a particular register
        if( reg_num != -1 ):           
            if( isinstance(left, SSAExpr)):
                if( isinstance( right, ConstExpr) and left.reg.num == reg_num):
                    return (True, factor*right.value)
                else:
                    return (False, None)
            elif( isinstance(right, SSAExpr) and right.reg.num == reg_num):
                if( isinstance( left, ConstExpr)):
                    return (True, factor*left.value)
                else:
                    return (False, None)
            else:
                return (False, None)
        # Or search for any register increment 
        else:           
            if( isinstance(left, SSAExpr)):
                if( isinstance( right, ConstExpr)):
                    return (True, left.reg.num, factor*right.value)
                else:
                    return (False, None, None)
            elif( isinstance(right, SSAExpr)):
                if( isinstance( left, ConstExpr)):
                    return (True, right.reg.num, factor*left.value)
                else:
                    return (False, None, None)
            else:
                return (False, None, None)
        
    def toArray(self):
        if( self.op == Op.ADD ):
            left = self.args[0].toArray()
            right = self.args[1].toArray()
            if( left == [] or right == []):
                return []
            res = [left[i]+right[i] for i in range(0, Arch.ssaRegCount+1) ]
            return res
        elif( self.op == Op.SUB ):
            left = self.args[0].toArray()
            right = self.args[1].toArray()
            if( left == [] or right == []):
                return []
            res = [left[i]-right[i] for i in range(0, Arch.ssaRegCount+1) ]
            return res
        elif( self.op == Op.MUL):
            if( isinstance(self.args[0], ConstExpr)):
                factor = self.args[0].value
                right = self.args[1].toArray()
                if( not right ):
                    return []
                res = [factor*coeff for coeff in right]
                return res
            elif( isinstance(self.args[1], ConstExpr)):
                factor = self.args[1].value
                left = self.args[0].toArray()
                if( not left ):
                    return []
                res = [factor*coeff for coeff in left]
                return res
        elif( self.op == Op.DIV):
            if( isinstance(self.args[0], ConstExpr)):
                factor = self.args[0].value
                right = self.args[1].toArray()
                if( not right ):
                    return []
                res = [coeff//factor for coeff in right]
                return res
            elif( isinstance(self.args[1], ConstExpr)):
                factor = self.args[1].value
                left = self.args[0].toArray()
                if( not left ):
                    return []
                res = [coeff//factor for coeff in left]
                return res
        else:
            return []
    
    def deepcopy(self):
        return OpExpr(self.op, [arg.deepcopy() for arg in self.args])
        


class Convert(Expr):
    """
    Used to make widening and narrowing conversions of expressions 
    """
    
    def __init__(self, to, expr, signed=False):
        """
        to - (int) the size the expression must be converted into 
        signed - (bool) specifies if the widening conversions must keep the sign ( default : False )
        """
        Expr.__init__(self)
        self.args = [expr]
        self.size = to
        self.signed = signed 
        # For optimisations
        self.simplifiedValue = None
        
    def __str__(self):
        if( self.signed ):
            return "%sSto%s(%s)" % ( self.args[0].size, self.size, ','.join(str(a) for a in self.args))
        else:
            return "%sUto%s(%s)" % ( self.args[0].size, self.size, ','.join(str(a) for a in self.args))
        
    def replaceReg( self, reg, expr ):
        return Convert( self.size, self.args[0].replaceReg(reg, expr), self.signed)
        
    def replaceMultiReg(self, reg_dict):
        return Convert( self.size, self.args[0].replaceMultiReg( reg_dict), self.signed )
        
    def replaceMemAcc( self, addr, expr ):
        return Convert( self.size, self.args[0].replaceMemAcc( addr, expr ), self.signed) 
        
    def __eq__(self, other):
        if( not isinstance( other, Convert )):
            return False 
        return self.args[0] == other.args[0]
        
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        return list(set(self.args[0].getRegisters(ignoreMemAcc)))
        
    def getMemAcc(self):
        return list(set(self.args[0].getMemAcc()))
         
    def __hash__(self):
        return hash(self.signed)*hash(self.size)*hash(self.args[0])    
        
    def replaceITE(self, expr):
        return Convert( self.size, self.args[0].replaceITE(expr), self.signed)
        
    def flattenITE(self):
        flat = self.args[0].flattenITE()
        return [[Convert(self.size, f[0], self.signed), f[1]] for f in flat ]
        
    def simplify(self):
        # Check if already simplified 
        if( self.simplifiedValue ):
            return self.simplifiedValue
            
        # if not, simplify !
        simpExpr = self.args[0].simplify()
        if( isinstance( simpExpr, Convert ) and self.signed == simpExpr.signed ):
            res = Convert( self.size, simpExpr.args[0], self.signed ) 
        else:
            res = Convert( self.size, simpExpr, self.signed )
        if( res.size == res.args[0].size ):
            res = res.args[0]
        if( isinstance(res, Convert) and isinstance(res.args[0], ConstExpr) and not res.signed ):
            res = ConstExpr(res.args[0].value, res.size)
        self.simplifiedValue = res
        return res
        
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
    
    def toArray(self):
        return []
        
    def deepcopy(self):
        return Convert(self.size, self.args[0].deepcopy(), self.signed)

class Concat(Expr):
    """
    Represents the concatenation of several expressions
    """
    def __init__(self, args):
        """
        args - array of the expressions to concatenate. 
        The first one is stored on the left, i.e bits de poids fort 
        The values of the 'self.args' array are couples ( expression, offset )
        """
        Expr.__init__(self)
        self.args = []
        self.size = 0
        self.simplifiedValue = None
        for a in args:
            if( a != None ):
                self.args.append( [a, self.size] )
                self.size += a.size 
        
    def __str__(self):
        return "Concat%d(%s)" % ( self.size, ','.join(str(a[0]) for a in self.args))
        
    def replaceReg( self, reg, expr ):
        self.args = [[a[0].replaceReg(reg, expr), a[1]] for a in self.args]
        return self
        
    def replaceMultiReg( self, reg_dict):
        self.args = [[a[0].replaceMultiReg(reg_dict), a[1]] for a in self.args]
        return self
        
    def replaceMemAcc( self, addr, expr ):
        return Concat([a[0].replaceMemAcc(addr, expr) for a in self.args])
        self.args = [[a[0].replaceMemAcc(addr, expr), a[1]] for a in self.args]
        return self
        
    def __eq__(self, other):
        if( not isinstance( other, Concat )):
            return False 
        for i in range(0,len(self.args)):
            if( other.args[i] != self.args[i] ):
                return False
        return True
        
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        l = []
        for a in self.args:
            l += a[0].getRegisters(ignoreMemAcc)
        return list(set(l))
        
    def getMemAcc(self):
        l = []
        for a in self.args:
            l += a[0].getMemAcc()
        return list(set(l))
         
    def __hash__(self):
        return sum([hash(a[0]) for a in self.args ])    
        
    def replaceITE(self, expr):
        self.args = [a[0].replaceITE(expr) for a in self.args]
        return self
        
    def flattenITE(self):
        newArgs = [a[0].flattenITE() for a in self.args]
        listArgs = [[[],CTrue()]]
        tmp = []
        for listA in newArgs:
            for a in listA:
                for arg in listArgs:
                    tmp.append( arg[0] + [a[0]], Cond(CT.AND,arg[1],a[1]))
                listArgs = tmp
        # listArgs contains now an array of couples ( list, condition )
        res = [[Concat(a[0]), a[1]] for a in listArgs]
        return res 

    def simplify(self):
        if( self.simplifiedValue ):
            return self.simplifiedValue
            
        newArgs = [a[0].simplify() for a in self.args]
        # SImplify expressions like
        # concat(extract(reg,...), op(ADD/SUB, extract(reg,...), CST)
        # into op(ADD/SUB, reg, CST)
        # DEBUG TODO 
        #if( isinstance(newArgs[0], Extract) and isinstance(newArgs[0].args[0], ))
        
        
        self.simplifiedValue = Concat(newArgs)
        return self.simplifiedValue
    
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
        
    def toArray(self):
        return []
        
    def deepcopy(self):
        return Concat([arg[0].deepcopy() for arg in self.args]) 


class Extract(Expr):
    """
    Represent the extraction of some bits of an expression 
    """
    def __init__(self, high, low, expr):
        """
        (high) (int) higher bit to be taken 
        (low) (int) lower bit to be taken 
        """
        if( high < 0 or low < 0 or high > expr.size-1 or high < low ):
            raise ExprException("Invalid extract in Extract(%d,%d,%s)"%(high, low, str(expr)))
        Expr.__init__(self)
        self.size = high - low + 1 
        self.high = high
        self.low = low
        self.args = [expr]
        self.simplifiedValue = None
        
    def __str__(self):
        return "Extract%d(%d,%d,%s)" % (self.size, self.high, self.low,','.join(str(a) for a in self.args))
        
    def replaceReg( self, reg, expr ):
        return Extract(self.high, self.low, self.args[0].replaceReg(reg, expr))
        
    def replaceMultiReg( self, reg_dict ):
        return Extract(self.high, self.low, self.args[0].replaceMultiReg(reg_dict))
        
    def replaceMemAcc( self, addr, expr ):
        return Extract(self.high, self.low, self.args[0].replaceMemAcc(addr,expr))
        
    def __eq__(self, other):
        if( not isinstance( other, Extract )):
            return False 
        return self.high == other.high and self.low == other.low and self.args[0] == other.args[0]
        
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        return list(set(self.args[0].getRegisters(ignoreMemAcc)))
        
    def getMemAcc(self):
        return list(set(self.args[0].getMemAcc()))
         
    def __hash__(self):
        return hash(str("extr"))*hash(self.args[0])    
        
    def replaceITE(self, expr):
        return Extract(self.high, self.low, self.args[0].replaceITE(expr))
        
        
    def flattenITE(self):
        flat = self.args[0].flattenITE()
        return [[Extract(self.high, self.low, f[0]), f[1]] for f in flat ]
        
    def simplify(self):
        if( self.simplifiedValue ):
            return self.simplifiedValue
        
        if( self.low == 0 and self.high == self.args[0].size -1 ):
            return self.args[0].simplify()
        simpExpr = self.args[0].simplify()
        # BAsic result without optimisations 
        res = Extract( self.high, self.low, simpExpr)
        # SImplifications to do : 
        if( isinstance( simpExpr, Extract ) ):
            res = Extract( self.high + simpExpr.low, self.low + simpExpr.low, simpExpr.args[0] )
        elif( isinstance( simpExpr, OpExpr ) and simpExpr.op == Op.BSH ):
            # Simplification that occur often because of the BARF pointers and jump mechanisms... 
            # This removes in fact "double shifts " in expressions such as 
            # Extract64( 71, 8, Bsh72( R1_0, 8 ))  
            if( isinstance( simpExpr.args[1], ConstExpr )):
                shiftVal = simpExpr.args[1].value
                if(  self.high == simpExpr.size -1 and self.low == shiftVal ):
                    if( isinstance( simpExpr.args[0], Convert)):
                        res = simpExpr.args[0].args[0]
                    else:
                        res = simpExpr.args[0]
        elif( isinstance( simpExpr, MEMExpr ) and (self.low % 8 == 0)  and self.size != simpExpr.size ):
            # If we extract from the same address (from bit 0 )
            res = MEMExpr(OpExpr(Op.ADD, [simpExpr.addr, ConstExpr(self.low/8,simpExpr.addr.size)]).simplify(), self.size)
        self.simplifiedValue = res 
        return res
    
    def isRegIncrement(self, reg_num):
        """
        Returns (True, CST) iff this expression is (REG +/- CST)
        Returns (False, None) otherwise 
        """
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
        
    def toArray(self):
        return []
        
    def deepcopy(self):
        return Extract(self.high, self.low, self.args[0].deepcopy())

class ITE(Expr):
    """
    Describes an IF-THEN-ELSE construction 
        self.cond - (Condition) is the condition of the IF statement. The class Condition is defined in Condition.py module
        self.args[0] - (Expr) is the value returned if the condition self.cond is evaluated to True 
        self.args[1] - (Expr) is the value returned if the condition self.cond is evaluated to False
        
    Example : ITE( c1, t3, t2 )
    """
    
    def __init__(self, cond, iftrue, iffalse):
        """
        cond, iftrue, iffalse : temporary values 
        """
        Expr.__init__(self)
        self.cond = cond
        self.args = [iftrue, iffalse]
        self.size = iftrue.size
        
    def __str__(self):
        return "ITE(%s,%s,%s)" % ( self.cond, self.args[0], self.args[1])
        
    def replaceReg( self, reg, expr ):
        return ITE( self.cond.replaceReg(reg,expr), self.args[0].replaceReg(reg,expr), self.args[1].replaceReg(reg,expr))
        
    def replaceMemAcc( self, addr, expr ):
        return ITE( self.cond.replaceMemAcc(addr,expr), self.iftrue.replaceMemAcc(addr,expr), self.iffalse.replaceMemAcc(addr,expr)) 
        
    def __eq__(self, other):
        if( not isinstance( other, ITE )):
            return False 
        return ( self.cond == other.cond 
            and self.args[0] == other.args[0] 
            and self.args[1] == other.args[1] )
        
    def __ne__(self, other):
        return not (self == other)
    
    def getRegisters(self, ignoreMemAcc=False):
        return list(set(self.args[0].getRegisters(ignoreMemAcc) + self.args[1].getRegisters(ignoreMemAcc)))
        
    def getMemAcc(self):
        return list(set(self.args[0].getMemAcc() + self.args[1].getMemAcc()))
    
    def getRegistersTrue(self,ignoreMemAcc=False):
        return self.args[0].getRegisters(ignoreMemAcc)
        
    def getRegistersFalse(self,ignoreMemAcc=False):
        return self.args[1].getRegisters(ignoreMemAcc)
        
    def getMemAccTrue(self):
        return self.args[0].getMemAcc()
        
    def getMemAccFalse(self):
        return self.args[1].getMemAcc()
         
    def __hash__(self):
        return hash(str(self.cond))*( hash(self.args[0])- hash(self.args[1])) + 400
        
    def replaceITE(self, expr):
        return expr
        
    def flattenITE(self):
        return [[self.args[0], self.cond], [self.args[1], self.cond.invert()]]
    
    def simplify(self):
        newArgs = [arg.simplify() for arg in self.args]
        return ITE( self.cond, newArgs[0], newArgs[1] )
        
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
        
    def toArray(self):
        return []
        
    def deepcopy(self):
        return ITE(self.cond, self.args[0].deepcopy(), self.args[1].deepcopy())

####################################
# PARSING A STRING INTO AN EXPR    #
#################################### 

def remove_last_parenthesis(string):
    """
    Removes the last parenthesis of a string
    If the string does not finish by ')', return None
    
    Usage:  this function is used by the parseStrToExpr() function which 
            expects well formed expressions as strings. So returning 'None' 
            when no end parenthesis is found helps detecting bad formed 
            expression strings  
    """
    if( string[len(string)-1] == ')' ):
        return string[:-1]
    else:
        return None

def parseStrToExpr( string, regNamesTable ):
    """
    Parses a string into an Expr
    Returns a tuple (True, Expr) or (False, ErrorMessage/str)
    """
    if( not string ):
        return (False, "Invalid expression")

    depth_lvl = 0
    for i in reversed(range(0,len(string))):
        if( (string[i] == "+" or string[i] == "-") and depth_lvl == 0 ):
            if( i+1 < len(string)):
                right = string[i+1:]
            else:
                return (False, "Missing right operand")
            if( i-1 >= 0 ):
                left = string[:i]
            else:
                return (False, "Missing left operand")
            (left_success, left_expr) = parseStrToExpr(left, regNamesTable)
            (right_success, right_expr) = parseStrToExpr(right, regNamesTable)
            if( not left_success ):
                return (False, left_expr)
            elif( not right_success ):
                return (False, right_expr)
            else:
                if( string[i] == "+" ):
                    return ( True, OpExpr(Op.ADD, [left_expr, right_expr]))
                else:
                    return ( True, OpExpr(Op.SUB, [left_expr, right_expr]))
        elif(string[i] == "("):
            depth_lvl = depth_lvl - 1
            if( depth_lvl < 0 ):
                return (False, "Error. Parenthesis error in expression")
        elif( string[i] == ")"):
            depth_lvl = depth_lvl + 1
        
    depth_lvl = 0            
    for i in range(0, len(string)):
        if( (string[i] == "*" or string[i] == "/") and depth_lvl == 0 ):    
            left = string[:i]
            if( i+1 < len(string)):
                right = string[i+1:]
            else:
                return (False, "Missing right operand")
            (left_success, left_expr) = parseStrToExpr(left, regNamesTable)
            (right_success, right_expr) = parseStrToExpr(right, regNamesTable)
            if( not left_success ):
                return (False, left_expr)
            elif( not right_success ):
                return (False, right_expr)
            else:
                if( string[i] == "*" ):
                    return (True, OpExpr(Op.MUL, [left_expr, right_expr]))
                else:
                    return (True, OpExpr(Op.DIV, [left_expr, right_expr]))
        elif(string[i] == "("):
            depth_lvl = depth_lvl + 1
        elif( string[i] == ")"):
            depth_lvl = depth_lvl - 1
        
    if( string[0] == "(" ):
        return parseStrToExpr( remove_last_parenthesis(string[1:]), regNamesTable)

    
    if( string[:4] == "mem(" ):
        (success,addr) = parseStrToExpr( remove_last_parenthesis(string[4:]), regNamesTable)
        if( not success ):
            return (False, addr)
        else:
            return (True, MEMExpr(addr, Arch.currentArch.bits ))
            
    # It is register or cst ? 
    if( string in regNamesTable ):
        return (True, SSAExpr( SSAReg( regNamesTable[string], 0)))
    else:
        try:
            value = int(string)
        except:
            try:
                value = int(string, 16)
            except:
                try:
                    value = int(string, 2)
                except:
                    return (False, "Invalid operand: " + string )
        return (True, ConstExpr( value, Arch.currentArch.bits))


