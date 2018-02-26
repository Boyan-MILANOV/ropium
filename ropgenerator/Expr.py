"""
ROPGenerator - Expr.py module
Implements the data structure to represent arithmetical and logical 
expressions using abstract values for registers and memory.
"""

from z3 import BitVec, BitVecVal, BitVecNumRef, Concat, Extract, Array, BitVecSort, SignExt, ZeroExt, LShR, simplify
from ropgenerator.Cond import Cond, CT, CTrue, CFalse
from ropgenerator.Logs import log
INTEGRITY_CHECK = False 




# Size of the registers - this variable must be set when architecture is known
class REGSIZE:
    size = -1
# number of registers
nb_regs = None

# Variables used to make the Z3 SMT modelisation
regToSMT = {} # Keys : ( SSARegister ), Values : Z3 BitVec
memorySMT = None

def set_memorySMT(regsize):
    global memorySMT
    memorySMT = Array( "MEM", BitVecSort(regsize), BitVecSort(8)) # Z3 Array of bitVec

# Custom exception type
class ExprException(Exception):
    def __init__(self, msg):
        self.msg = msg
        log(msg)
    def __str__(self):
        return self.msg
    
########################################
# REPRESENTATION OF REGISTERS WITH SSA #
########################################
    
class SSAReg:
    """
    Implements generic SSA representation of a register.
    The register itself got an ID that is a integer : self.num
    Then the SSA is obtained by adding another integer : self.ind
    The total number of registers in use is available in variable 'ssaRegCount'

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
        
    def __hash__(self): 
        return (self.num+1)*5000 - self.ind
        
    def toZ3(self):
        if regToSMT.get(self) == None:
            regToSMT[self] = BitVec( str(self), REGSIZE.size)
        return regToSMT[self]

def strToReg(string):
    """
    Converts a string in a SSAReg
    String must be "RX_Y" where X and Y are positive integers
    """
    s1, s2 = string.split("_")
    return SSAReg(int(s1[1:]), int(s2))
    
def prevOcc(reg):
    """
    Returns the previous occurence of a register
    prevOcc( R1_2 ) = R1_1
    prevOcc( R1_0 ) = R1_0
    """
    if reg.ind == 0:
        return SSAReg(reg.num, reg.ind)
    else:
        return SSAReg(reg.num, reg.ind-1)
        
        
#################################
# REPRESENTATION OF EXPRESSIONS #
#################################



class Expr:
    """
    General class implemeting expressions containing registers and memory accesses
        (self.size) (int) is the number of bits the expression should be stored in
    """

    def __init__(self):
        self.size = -1
        self.z3 = None
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
        This method returns an expression where the occurences of the registers present in the reg_dict dictionnary are replaced by their corresponding value in the dictionnary
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

    def flattenITE(self):
        """
        Transforms an expression in a list of couples ( Expr, Cond ) by flattening the If-Then-Else expressions
        """

    def toZ3(self):
        """
        Returns the translation in Z3 of the expression
        The expression returned will be a BiVec() of size 'self.size'
        """
    def toArray(self):
        """
        Returns its 'array' representation as a vector V
        Coefficient at position i is the coefficient of register Ri_...
        Last coefficient is a constant
        If the expression can not be converted, [] is returned

        So length of the array will be Expr.nb_regs + 1
        
        Example : [1, 0, 2, 0, ...,  -8] is R1 + 3*R -8
        
        """

    def simplify(self):
        """
        Tries some simplifications on itself 
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
        (self.value) (int) is the constant value stored
    """
    
    def __init__(self, value, size):
        Expr.__init__(self)
        if(isinstance(value, int ) or isinstance(value, long)):
            self.value = value
        else:
            self.value = int(value, 16)
        self.size = size 
        self.z3 = BitVecVal(value, size )

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
    
    def getRegisters(self, ignoreMemAcc=False):
        return []
        
    def getMemAcc(self):
        return []
        
    def __hash__(self):
        return hash(self.value)
        
    def toZ3(self):
        return self.z3
        
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
        res = [0 for x in range(0,nb_regs)]
        res.append(self.value)
        return res
        
class SSAExpr(Expr):
    """
    Represents an expression made out of a single register ( like R5_3 )
        (self.reg) (SSARegister)
        (self.size) (int)
    """
    def __init__(self, reg):
        Expr.__init__(self)
        self.reg = reg
        self.size = REGSIZE.size
    
    def __str__(self):
        return str(self.reg)

    def replaceReg(self, reg, expr):
        if( self.reg == reg ):
            return expr
        else:
            return SSAExpr( self.reg )
            
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
        
    def getRegisters(self, ignoreMemAcc=False):
        return [self.reg]
        
    def getMemAcc(self):
        return []
        
    def __hash__(self):
        return hash(self.reg)
            
    def replaceITE(self, expr):
        return self
        
    def toZ3(self):
        return self.reg.toZ3()
        
    def flattenITE(self):
        return [[self, CTrue()]]    
        
    def simplify(self):
        return SSAExpr( self.reg )
        
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
        res +=  [0 for r in range(self.reg.num+1, nb_regs+1)]
        return res

class MEMExpr(Expr):
    """
    Memory access in an expression.
        (self.addr) (Expr) is the address at which memory is accessed 
        (self.size) (int) is the size of the memory access in bits 
    Example : MEM[R3_2 + 0x4]  
    """
    
    def __init__(self, addr, size):
        Expr.__init__(self)
        self.addr = addr
        self.size = size 

    def __str__(self):
        return "MEM%d[%s]" %(self.size, str(self.addr))
        
    def replaceReg( self, reg, expr ):
        res = MEMExpr( self.addr.replaceReg( reg, expr ), self.size)
        return res
        
    def replaceMultiReg(self, reg_dict):
        res = MEMExpr( self.addr.replaceMultiReg( reg_dict ), self.size ) 
        return res

    def replaceMemAcc(self, addr, expr):
        self.addr = self.addr.simplify()
        addr = addr.simplify()
        if( self.addr == addr ):
            return expr
        else:
            return MEMExpr( self.addr.replaceMemAcc( addr, expr ), self.size )
        
    def __eq__(self, other): 
        if( not isinstance( other, MEMExpr )):
            return False
        return self.addr == other.addr
        
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
        
    def toZ3(self):
        global memorySMT
        if( self.z3 == None ):
            addr = self.addr.toZ3()
            res = memorySMT[addr]
            for i in range(1,self.size/8):
                i_z3 = BitVecVal(i, self.addr.size)
                test = memorySMT[addr+i_z3]
                res = Concat( memorySMT[addr+i_z3], res )
            self.z3 = res    
        return self.z3
        
    def flattenITE(self):
        flat = self.addr.flattenITE()
        return [[MEMExpr( f[0], self.size), f[1]] for f in flat]
        
    def simplify(self):
        return MEMExpr( self.addr.simplify(), self.size )
        
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
        
    def toArray(self):
        return []
        
class Op(Expr):
    """
    Describes an operation ( with one or many arguments ) on expressions 
    The operation is specified by the attribute 'op' which is a string 
    The size of the operation is deduced from the size of it's arguments 
    """
    
    def __init__(self, op, args):
        """
        """
        Expr.__init__(self)
        self.op = op
        self.args = args
        self.size = args[0].size 
        if( op != "Not" and len(args) < 2 ):
            raise ExprException("Error, binop with only one arg : %s"%str(args))
        
    def __str__(self):
        return "%s%d(%s)" % ( self.op, self.size, ','.join(str(a) for a in self.args))
        
    def replaceReg( self, reg, expr ):
        newArgs = [arg.replaceReg(reg, expr) for arg in self.args]
        return Op( self.op, newArgs)
        
    def replaceMultiReg(self, reg_dict):
        newArgs = [arg.replaceRegMultiReg( reg_dict ) for arg in self.args]
        return Op( self.op, newArgs)
        
    def replaceMemAcc( self, addr, expr ):
        newArgs = [arg.replaceMemAcc( addr, expr ) for arg in self.args]
        return Op( self.op, newArgs) 
        
    def __eq__(self, other):
        if( not isinstance( other, Op )):
            return False 
        if( len(self.args) != len(other.args)):
            return False
        for ind, arg in enumerate(self.args):
            if( arg != other.args[ind] ):
                return False
        return True 
        
    def getRegisters(self, ignoreMemAcc=False):
        return list(set(self.args[0].getRegisters(ignoreMemAcc) + self.args[1].getRegisters(ignoreMemAcc)))
        
    def getMemAcc(self):
        return list(set(self.args[0].getMemAcc() + self.args[1].getMemAcc()))
         
    def __hash__(self):
        return hash(str(self.op))*( hash(self.args[0]) - hash(self.args[1]))
        
    def replaceITE(self, expr):
        newArgs = [arg.replaceITE(expr) for arg in self.args]
        return Op( self.op, self.size, newArgs)
        
    def toZ3(self):
        if( self.z3 == None ):
            self.z3 = opToZ3( self.op,  self.args )
        return self.z3
        
    def flattenITE(self):
        """
        !!! Works only for unary or binary operations 
        """
        res = []
        if( len(self.args) == 2 ):
            flatLeft = self.args[0].flattenITE()
            flatRight = self.args[1].flattenITE()
            for f in flatLeft:
                for f2 in flatRight:
                    res.append([ Op(self.op,[ f[0], f2[0]]), Cond(CT.AND, f[1], f2[1]) ])
            return res
        elif( len(self.args) == 1 ):
            flat = self.args[0].flattenITE()
            return [[Op(self.op, self.size, f[0]), f[1]] for f in flat]
        else:
            raise ExprException(" flattenITE can not be used with an operator on more than 2 arguments (%d here) " % len(self.args))
        
    def simplify(self):
        # ! must update the Z3
        self.z3 = None
        simpArgs = [arg.simplify() for arg in self.args]
        op = self.op 
        left = simpArgs[0]
        if( len(simpArgs) == 2 ):
            right = simpArgs[1]
        
        # The result without structrual simplifications 
        res = Op( self.op, simpArgs )
        # Simplifications 
        if( op == "Not" ):
            if( isinstance( left, Op ) and Op.op == "Not" ):
                res = left.args[0]
        elif( op == "Add" ):
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
            if( isinstance( right, ConstExpr )):
                if( right.value == 0 ):
                    res = left
                else:
                    const = right
            # Check for a sub-expression that is an Addition 
            if( isinstance( left, Op ) and left.op == "Add" ):
                subAdd = left 
            elif( isinstance( right, Op ) and right.op == "Add" ):
                subAdd = right 
            elif( isinstance( left, Op ) and left.op == "Sub" ):
                subSub = left 
            elif( isinstance( right, Op ) and right.op == "Sub" ):
                subSub = right 
            # SImplifications if possible     
            if( const != None and subAdd != None ):
                if( isinstance( subAdd.args[0], ConstExpr )):
                    res = Op( "Add", [ConstExpr( const.value + subAdd.args[0].value, const.size ), subAdd.args[1]])
                elif( isinstance( subAdd.args[1], ConstExpr )):
                    res = Op( "Add", [ConstExpr( const.value + subAdd.args[1].value, const.size ), subAdd.args[0]] )
            if( const != None and subSub != None ):
                if( isinstance( subSub.args[1], ConstExpr )):
                    newConst = const.value - subSub.args[1].value
                    if( newConst != 0 ):
                        res = Op( "Add", [ConstExpr( newConst, const.size ), subSub.args[0] ])
                    else:
                        res= subSub.args[0]
            
        
        elif( op == "Sub" ):
            if( isinstance(right, ConstExpr) and right.value == 0 ):
                res = left            
        elif( op == "Mul" ):
            if( isinstance(left, ConstExpr) and left.value == 0 ):
                res = left
            elif( isinstance(left, ConstExpr) and left.value == 1 ):
                res = right
            elif( isinstance(right, ConstExpr) and right.value == 1 ):
                res = left        
        elif( op == "Xor" ):
            if( isinstance(left, ConstExpr) and left.value == 0 ):
                res = right
            elif( isinstance(right, ConstExpr) and right.value == 0 ):
                res = left
            elif( left == right ):
                res = ConstExpr(0, left.size)
            
        return res
            
    def isRegIncrement(self, reg_num):
        """
        If the expression is (REG +- CST)
            Returns (True, CST) if reg_num is an int 
            Returns (True, REG, CST) is reg_num is -1 
        Else
            Returns (False, None) 
        """
        if( self.op != "Add" and self.op != "Sub"):
            return (False, None)
        elif( len(self.args) != 2 ):
            return (False, None)
        else:
            left = self.args[0]
            right = self.args[1]
        
        if( self.op == "Add" ):
            factor = 1
        else:
            factor = -1
        
        # Search for a particular register
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
        # Or search for any register increment 
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
        if( self.op == "Add" ):
            left = self.args[0].toArray()
            right = self.args[1].toArray()
            if( left == [] or right == []):
                return []
            res = [left[i]+right[i] for i in range(0, nb_regs+1) ]
            return res
        elif( self.op == "Sub" ):
            left = self.args[0].toArray()
            right = self.args[1].toArray()
            if( left == [] or right == []):
                return []
            res = [left[i]-right[i] for i in range(0, nb_regs+1) ]
            return res
        elif( self.op == "Mul"):
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
        elif( self.op == "Div"):
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
        
    def toZ3(self):
        if( self.z3 == None):
            self.z3 = If( self.cond.toZ3(), self.args[0].toZ3(size), self.args[1].toZ3(size))
        return self.z3
        
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
            
class Convert(Expr):
    """
    Used to make widening and narrowing conversions of expressions 
    Is considered as an unary operator 
    """
    
    def __init__(self, to, expr, signed=False):
        """
        to - (int) the size the expression must be converted into 
        signed - (bool) specifies if the widening conversions must keep the sign ( default : False )
        """
        Expr.__init__(self)
        self.op = "to"
        self.args = [expr]
        self.size = to
        self.signed = signed 
        
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
        
    def getRegisters(self, ignoreMemAcc=False):
        return list(set(self.args[0].getRegisters(ignoreMemAcc)))
        
    def getMemAcc(self):
        return list(set(self.args[0].getMemAcc()))
         
    def __hash__(self):
        return hash(str(self.op))*hash(self.args[0])    
        
    def replaceITE(self, expr):
        return Convert( self.size, self.args[0].replaceITE(expr), self.signed)
        
    def toZ3(self):
        if( self.z3 == None ):
            self.z3 = convertToZ3( self.size, self.args[0], self.signed )
        return self.z3
        
    def flattenITE(self):
        flat = self.args[0].flattenITE()
        return [[Convert(self.size, f[0], self.signed), f[1]] for f in flat ]
        
    def simplify(self):
        simpExpr = self.args[0].simplify()
        if( isinstance( simpExpr, Convert ) and self.signed == simpExpr.signed ):
            res = Convert( self.size, simpExpr.args[0], self.signed ) 
        else:
            res = Convert( self.size, simpExpr, self.signed )
        if( res.size == res.args[0].size ):
            res = res.args[0]
        if( isinstance(res, Convert) and isinstance(res.args[0], ConstExpr) and not res.signed ):
            res = ConstExpr(res.args[0].value, res.size)
        return res 
        
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
    
    def toArray(self):
        return []
        
class Cat(Expr):
    """
    Represents the concatenation of several expressions
    """
    def __init__(self, args):
        """
        args - array of the expressions to concatenate. The first one is stored on the left, i.e bits de poids fort 
        The values of the array are couples ( expression, offset )
        """
        Expr.__init__(self)
        self.args = []
        self.size = 0
        for a in args:
            if( a != None ):
                self.args.append( [a, self.size] )
                self.size += a.size 
        
    def __str__(self):
        return "Cat%d(%s)" % ( self.size, ','.join(str(a[0]) for a in self.args))
        
    def replaceReg( self, reg, expr ):
        self.args = [[a[0].replaceReg(reg, expr), a[1]] for a in self.args]
        return self
        
    def replaceMultiReg( self, reg_dict):
        self.args = [[a[0].replaceMultiReg(reg_dict), a[1]] for a in self.args]
        return self
        
    def replaceMemAcc( self, addr, expr ):
        self.args = [[a[0].replaceMemAcc(addr, expr), a[1]] for a in self.args]
        return self
        
    def __eq__(self, other):
        if( not isinstance( other, Cat )):
            return False 
        for i in range(0,len(self.args)):
            if( other.args[i] != self.args[i] ):
                return False
        return True
        
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
        
    def toZ3(self):
        if( self.z3 == None ):
            tmp = self.args[0][0].toZ3()
            for i in range(1, len(self.args)):
                tmp = Concat(tmp, self.args[i][0].toZ3())
            self.z3 = tmp
        return self.z3
        
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
        res = [[Cat(a[0]), a[1]] for a in listArgs]
        return res 
        
    def simplify(self):
        newArgs = [a[0].simplify() for a in self.args]
        return Cat(newArgs)
    
    def isRegIncrement(self, reg_num):
        if( reg_num == -1 ):
            return (False, None, None)
        else:
            return (False, None)
        
    def toArray(self):
        return []
        
class Extr(Expr):
    """
    Represent the extraction of some bits of an expression 
    """
    def __init__(self, high, low, expr):
        """
        (high) (int) higher bit to be taken 
        (low) (int) lower bit to be taken 
        """
        if( high < 0 or low < 0 or high > expr.size-1 or high < low ):
            raise ExprException("Invalid extract in Extr(%d,%d,%s)"%(high, low, str(expr)))
        Expr.__init__(self)
        self.size = high - low + 1 
        self.high = high
        self.low = low
        self.args = [expr]
        
    def __str__(self):
        return "Extract%d(%d,%d,%s)" % (self.size, self.high, self.low,','.join(str(a) for a in self.args))
        
    def replaceReg( self, reg, expr ):
        return Extr(self.high, self.low, self.args[0].replaceReg(reg, expr))
        
    def replaceMultiReg( self, reg_dict ):
        return Extr(self.high, self.low, self.args[0].replaceMultiReg(reg_dict))
        
    def replaceMemAcc( self, addr, expr ):
        return Extr(self.high, self.low, self.args[0].replaceMemAcc(addr,expr))
        
    def __eq__(self, other):
        if( not isinstance( other, Convert )):
            return False 
        return self.high == other.high and self.low == other.low and self.args[0] == other.args[0]
        
    def getRegisters(self, ignoreMemAcc=False):
        return list(set(self.args[0].getRegisters(ignoreMemAcc)))
        
    def getMemAcc(self):
        return list(set(self.args[0].getMemAcc()))
         
    def __hash__(self):
        return hash(str("extr"))*hash(self.args[0])    
        
    def replaceITE(self, expr):
        return Extr(self.high, self.low, self.args[0].replaceITE(expr))
        
    def toZ3(self):
        if( self.z3 == None ):
            self.z3 = Extract( self.high, self.low, self.args[0].toZ3() )
        return self.z3
        
    def flattenITE(self):
        flat = self.args[0].flattenITE()
        return [[Extr(self.high, self.low, f[0]), f[1]] for f in flat ]
        
    def simplify(self):
        if( self.low == 0 and self.high == self.args[0].size -1 ):
            return self.args[0].simplify()
        simpExpr = self.args[0].simplify()
        # BAsic result without optimisations 
        res = Extr( self.high, self.low, simpExpr)
        # SImplifications to do : 
        if( isinstance( simpExpr, Extr ) ):
            res = Extr( self.high + simpExpr.low, self.low + simpExpr.low, simpExpr.args[0] )
        elif( isinstance( simpExpr, Op ) and simpExpr.op == "Bsh" ):
            # Simplification that occur often because of the BARF pointers and jump mechanisms... 
            # This removes in fact "double shifts " in expressions such as 
            # Extract64( 71, 8, Bsh72( R1_0, 8 ))  
            if( isinstance( simpExpr.args[1], Convert ) ):
                if( isinstance( simpExpr.args[1].args[0], ConstExpr)):
                    shiftVal = simpExpr.args[1].args[0].value
            elif( isinstance( simpExpr.args[1], ConstExpr )):
                shiftVal = simpExpr.args[1].value
            else:
                return res    
            if(  self.high == simpExpr.size -1 and self.low == shiftVal ):
                res = simpExpr.args[0]
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
#################################################
# FUNCTIONS FOR TRANSLATION INTO SMT Z3 OBJECTS #
#################################################

def opToZ3( op, args):
    """
    Translates a unary or binary operator expression into Z3 representation
    Parameters : 
        op - (str) the string representation of the operation
        args - (Array(Expr)) the arguments to which the operator is applied  
    """
    left = args[0].toZ3()
    if( len(args) == 2 ):
        right = args[1].toZ3()
    elif( len(args) > 2 ):
        raise ExprException("Translation into Z3 not supported for operators on more than 2 arguments (%d here)" % len(args))
    
    if( op == "Not" ):
        res = left.__neg__()
    elif( op == "Add" ):
        res = left.__add__(right) 
    elif( op == "Sub" ):
        res = left.__sub__(right) 
    elif( op == "Mul" ):
        res = left.__mul__(right) 
    elif( op == "Div" ):
        res = UDiv( left, right ) 
    elif( op == "Mod" ):
        res =  left.__mod__(right)
    elif( op == "Or" ):
        res =  left.__or__(right) 
    elif( op == "And" ):
        res = left.__and__(right) 
    elif( op == "Xor" ):
        res = left.__xor__(right) 
    elif( op == "Shl" ):
        res =  left.__lshift__( right ) 
    elif( op == "Shr" ):
        res =  LShR( left, right ) 
    elif( op == "Sar" ):
        res =  left.rshift( right ) 
    elif( op == "CmpEQ" ):
        res = If( left == right , BitVecVal(1, 8), BitVecVal(0, 8) ) 
    elif( op == "CmpNE" ):
        res =  If( left == right, BitVecVal(0, 8), BitVecVal(1, 8) )
    elif( op == "Bsh" ):
        # The BARF bsh operation is quite tricky
        # It can be used by barf itelf to emulate some instrucions
        # But aslo to translate directly a SHL or SHR assembly instruction 
        # BSH( a, b )     = ( a << b ) iff b > 0 
        #        = ( a >> b ) iff b < 0
        # So if b is not a constant but a complex expression we have to use some tricks to determine whether the shift should be left or right
        # At first we try to simplify the expression into a constant BitVevNumRef 
        #Cast attempt 
        if( not isinstance( right, BitVecNumRef )):
            s = simplify(right)
            if( isinstance( s, BitVecNumRef )):
                val = s.as_signed_long()
                right = BitVecVal( val, right.size() ) 
        # If the cast failed, we just create an if-then-else statement... 
        if( not isinstance( right, BitVecNumRef )):
            zero = BitVecVal( 0, right.size() )
            return If( right.__gt__(zero), simplify( left.__lshift__(right) ), simplify( LShR( left, right)))
            #raise ExprException("Unable to determine the sign of BSH operand ")    
        # If the cast was successful, we return the expression 
        else:
            dec = right.as_signed_long()
            if( dec > 0 ):
                res =  left.__lshift__(right) 
            elif( dec < 0 ):
                res =  LShR( left, BitVecVal( -dec, right.size() ))
            else:
                res =  left
    else:
        raise ExprException("Operation %s not supported for Z3 translation"%op)
    # The return value is res
    # Maybe some more operations can be done before return ( simplify, etc )
    return res 
    
def convertToZ3( to, expr, signed ):
    """
    Converts a conversion operation into Z3 
    Parameters:
        to - (int) the size to which the expression is translated 
        expr - (Expr) the expression that is translated
        signed - (Bool) true <=> the widening conversions keep the sign of the operand 
    """
    s = expr.size 
    exprZ3 = expr.toZ3()
    if( s == to ):
        res = exprZ3
    elif( s > to ):
        res = Extract( to-1, 0, exprZ3 )
    else: 
        if( signed ):
            res = SignExt( to - s, exprZ3 )
        else:
            res = ZeroExt( to - s, exprZ3 ) 
    return res 

####################################
# FUCTIONS FOR PARSING EXPRESSIONS #
#################################### 

def remove_last_parenthesis(string):
    """
    Removes the last parenthesis of a string
    If the string does not finish by ')', return None
    
    Usage:     this function is used by the parseStrToExpr() function which expects well formed expressions as strings
        returning 'None' when no end parenthesis is found helps detecting bad formed expression strings  
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
    if( string == [] or string == None ):
        return (False, "Invalid expression")

    depth_lvl = 0
    for i in range(0,len(string)):
        if( (string[i] == "+" or string[i] == "-") and depth_lvl == 0 ):
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
                if( string[i] == "+" ):
                    return ( True, Op("Add", [left_expr, right_expr]))
                else:
                    return ( True, Op("Sub", [left_expr, right_expr]))
        elif(string[i] == "("):
            depth_lvl = depth_lvl + 1
        elif( string[i] == ")"):
            depth_lvl = depth_lvl - 1
        
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
                    return (True, Op("Mul", [left_expr, right_expr]))
                else:
                    return (True, Op("Div", [left_expr, right_expr]))
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
            return (True, MEMExpr(addr, REGSIZE.size ))
            
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
        return (True, ConstExpr( value, REGSIZE.size))
