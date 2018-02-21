# ROPGenerator - Cond.py module 
# Implements the data structure to represent arithmetical and logical conditions on abstract values for registers and memory. 
 
from z3 import *
from ropgenerator.Expr import *
from ropgenerator.Logs import log
import signal 
import operator 

def CondException( Exception ):
    def __init__(self, msg):
        self.msg = msg 
        log(msg)
    def __str__(self):
        return self.msg 
    


def TimeOutRaiser(signum, frame):
    """
    Function used to limit the time used by the z3 solver
    It is is the handler for the signal sent in isTrue() and isFalse() functions 
    """
    if( Z3running ):
        raise Exception("z3 solver is too slow")

# Z3 SImplification 
debug_solver_count = 0     # Number of calls to the solver 
def hardSimplify( condZ3 ):
    """
    Simplify a condition using the z3 solver 
    """
    global debug_solver_count
    debug_solver_count = debug_solver_count + 1
    return Then('simplify', 'propagate-values')(condZ3).as_expr()
    # Could use also , 'ctx-solver-simplify' strategy 
 
##############################
# TYPES OF CONDITIONS ( CT ) #
##############################
 
class CT:
    """
    Enum class who defines the different logical/aritmetical operators available
    This class isn't meant to be used outside low-level condition manipulation 
    """
    
    EQUAL = "="
    NOTEQUAL = "!="
    GT = ">"
    LT = "<"
    GE = ">="
    LE = "<="
    AND = "&&"
    OR = "||"
    TRUE = "TRUE"
    FALSE = "FALSE"
    NOT = "NOT"
    
def invert(cond):
    """
    invert : Returns the 'opposite' CT of a CT
    Parameters :
        cond - (CT)    
    """
    if (cond == CT.EQUAL):
        return CT.NOTEQUAL
    elif (cond == CT.NOTEQUAL):
        return CT.EQUAL
    elif (cond == CT.AND):
        return CT.OR
    elif (cond == CT.OR):
        return CT.AND
    elif ( cond == CT.TRUE ):
        return CT.FALSE
    elif( cond == CT.FALSE ):
        return CT.TRUE
    elif( cond == CT.NOT ):
        raise CondException( "Condition NOT cannot be inverted ")
    elif( cond == CT.GT ):
        return CT.LE
    elif( cond == CT.LT ):
        return CT.GE
    elif( cond == CT.GE ):
        return CT.LT
    elif( cond == CT.LE ):
        return CT.GT
    else:
        raise CondException("Unknown condition '%s' cannot be inverted " % cond )

def isArithmeticComp( cond ):
    if( cond == CT.EQUAL or cond == CT.NOTEQUAL or cond == CT.GT or cond == CT.GE or cond == CT.LT or cond == CT.LE ):
        return True
    else:
        return False
        
def isLogicalOp( cond ):
    """
    Returns true iff the condition is the application of a logical operator ( OR, AND, NOT )
    """
    if( cond == CT.AND or cond == CT.OR or cond == CT.NOT ):
        return True
    else:
        return False
        
def isLogicalConst( cond ):
    """
    Returns True iff the condition is a constant TRUE or FALSE 
    """
    if( cond == CT.TRUE or cond == CT.FALSE ):
        return True
    else:
        return False 
        
        
class CE: # Condition Evaluation 
    """
    Class used to represent the evaluation of a condition during simplification
        TRUE - the condition have been simplified into TRUE
        FALSE - the condition have been simplified into FALSE
        UNKWN - the condition could not be evaluated as a logical constant 
        This class is used for instance by the Cond.simplify() function
    """
    TRUE = True
    FALSE = False
    UNKNW = "UNKNW"

################################
# REPRESENTATION OF CONDITIONS #
################################
        
class Cond:
    """
    Represents a condition on registers and/or memory 
        (self.cond) : (CT) is the condition 
        (self.left), (self.right): either (Condition, Condition) with self.cond a logical condition ( AND, OR, etc )
                    or (Expr, Expr) with self.cond an arithmetic condition ( EQUAL, NOTEQUAL, GT, LE , etc )
                    or (None, None) if self.cond is NONE or TRUE or FALSE
                    or (None, Condition) if self.cond is NOT  
        (self.simplifiedSoft) - (Bool) True <=> self.z3 have been simplified using a soft simplification function
        (self.Z3Simplified) - (Bool) True <=> self.z3 have been simplified using the hard simplification function 
        (self.cleaned) - (Bool) True <=> The condition have been cleaned ( call to self.clean() function ) 
        (self.checked) - (Bool) True <=> self.z3 have been utterly checked for True or False using Z3 solver

    """
    
    def __init__(self, condObject):
        self.cond = condObject.cond
        self.left = condObject.left
        self.right = condObject.right
        self.z3 = condObject.z3
        self.customSimplified = condObject.customSimplified
        self.customSimplifiedValue = condObject.customSimplifiedValue
        self.Z3Simplified = condObject.Z3Simplified
        self.cleaned = condObject.cleaned
        self.checked = condObject.checked
    
    def __init__(self, cond, left, right, z3 = None, cleaned = False, checked = False ):
        self.cond = cond
        self.left = left
        self.right = right
        self.z3 = z3
        self.customSimplified = False
        self.customSimplifiedValue = None
        self.Z3Simplified = False
        self.cleaned = cleaned 
        self.checked = checked 

                
    def __eq__(self, other ):
        if( self.cond != other.cond ):
            return False
        if( isLogicalConst( self.cond ) ):
            return True
        else:
            return ( self.left == other.left and self.right == other.right )
            
    def __str__(self):
        if( self.cond == CT.NOT ):
            return "(NOT %s)" % str(self.right)
        elif( not isLogicalConst(self.cond) ):
            return "(%s %s %s)" % ( str(self.left), self.cond, str(self.right) )
        else:
            return str(self.cond)
            
    def getRegisters(self):
        """
        Returns a list of SSARegiters that occur in the condition
        Eliminate multiple occurences in the list  
        """
        if( self.cond == CT.NOT ):
            return self.right.getRegisters()
        elif( not isLogicalConst(self.cond) ):
            return list(set( self.left.getRegisters() + self.right.getRegisters()))
        else:
            return []
            
    def invert(self):
        """
        Returns the opposite condition of oneself 
        """
        if( self.cond == CT.NOT ):
            return Cond(self.cond.right)
        elif( isLogicalConst(self.cond) ):
            return Cond( invert(self.cond), None, None, cleaned = self.cleaned )
        elif ( isLogicalOp(self.cond) ):
            return Cond( invert(self.cond), self.left.invert(), self.right.invert(), cleaned = self.cleaned )
        else:
            return Cond( invert(self.cond), self.left, self.right, cleaned = self.cleaned )
            
    def replaceReg(self, var, expr ):
        """
        Replaces every occurence of a register by a given expression
        Parameters :
            var - (SSAReg) that will be replaced 
            expr - (z3) that will replace 'var' 
        """
        # newZ3 = substitute( self.z3, (z3from, z3to) )
        if( self.cond == CT.NOT ):
            return Cond( CT.NOT, None, self.right.replaceReg( var, expr ), self.cleaned)        
        elif( isArithmeticComp(self.cond)):
            return Cond(self.cond, self.left.replaceReg( var, expr ), self.right.replaceReg( var, expr ), cleaned = self.cleaned)
        elif( isLogicalOp(self.cond) ):
            return Cond(self.cond, self.left.replaceReg( var, expr), self.right.replaceReg( var, expr), cleaned = self.cleaned)
        else:
            return Cond(self.cond, self.left, self.right)
            
    def flattenITE(self):
        """
        Returns a condition in which the If-Then-Else expressions have been flattened 
        """
        if( isLogicalConst(self.cond) ):
            return Cond( self.cond, None, None )
        elif( isArithmeticComp(self.cond) ):
            flatLeft = self.left.flattenITE()
            flatRight = self.right.flattenITE()
            res = Cond( CT.FALSE, None, None )
            for l in flatLeft:
                for r in flatRight:
                    res = Cond( CT.OR, res, Cond( CT.AND, Cond( CT.AND, Cond( self.cond, l[0], r[0]), l[1] ), r[1] ))
            return res        
        else:
            return Cond( self.cond, self.left.flattenITE(), self.right.flattenITE() )
        
    def toZ3( self ): 
        """
        Returns the translation in Z3 of the condition 
        """
        if( self.z3 != None ):
            return self.z3
            
        if( self.cond == CT.NOT ):
            self.z3 = Not( self.right.toZ3() )
        elif (self.cond == CT.EQUAL):
            self.z3 = (self.left.toZ3() == (self.right.toZ3()))
        elif (self.cond == CT.NOTEQUAL):
            self.z3 = Not(self.left.toZ3() == (self.right.toZ3()))
        elif( self.cond == CT.GT ):
            self.z3 = (self.left.toZ3() > (self.right.toZ3()))
        elif( self.cond == CT.GE ):
            self.z3 = (self.left.toZ3() >= (self.right.toZ3()))
        elif( self.cond == CT.LT ):
            self.z3 = (self.left.toZ3() < (self.right.toZ3()))
        elif( self.cond == CT.LE ):
            self.z3 = (self.left.toZ3() <= (self.right.toZ3()))
        elif (self.cond == CT.AND):
            self.z3 = And(( self.left.toZ3(), self.right.toZ3()))
        elif (self.cond == CT.OR):
            self.z3 = Or( self.left.toZ3(), self.right.toZ3())
        elif ( self.cond == CT.TRUE ):
            self.z3 = BoolSort().cast(True) 
        elif( self.cond == CT.FALSE ):
            self.z3 = BoolSort().cast(False) 
        else:
            raise CondException("Condition type %s cannot be converted into Z3 format " % self.cond)
        return self.z3     
            
            
    def clean(self):
        """
        This cleans the condition IN PLACE, by removing trivial conditions and stuff like this.  
        """ 
        res = CE.UNKNW
        # AND simplification 
        if( self.cond == CT.AND ):
            left = self.left.clean()
            right = self.right.clean()
            if( left == CE.FALSE or right == CE.FALSE ):
                self.setFalse()
                res = CE.FALSE
            elif( left == CE.TRUE):
                if( right == CE.TRUE ):
                    self.setTrue()
                    res = CE.TRUE
                else:
                    # We cut the left member
                    self.cond = self.right.cond
                    self.left = self.right.left
                    self.z3 = self.right.z3
                    self.right = self.right.right
                    res = CE.UNKNW
            elif( right == CE.TRUE ):
                if( left == CE.TRUE ):
                    self.setTrue()
                    res = CE.TRUE 
                else:
                    self.cond = self.left.cond
                    self.right = self.left.right
                    self.z3 = self.left.z3
                    self.left = self.left.left
                    res = CE.UNKNW
        # OR Simplification 
        elif( self.cond == CT.OR ):
            left = self.left.clean()
            right = self.right.clean()
            if( left == CE.TRUE or right == CE.TRUE ):
                self.setTrue()
                res =  CE.TRUE
            elif( left == CE.FALSE ):
                if( right == CE.FALSE ):
                    self.setFalse()
                    res = CE.FALSE
                else:
                    self.cond = self.right.cond
                    self.left = self.right.left 
                    self.z3 = self.right.z3
                    self.right = self.right.right
                    res = CE.UNKNW
            elif( right == CE.FALSE ):
                if( left == CE.FALSE ):
                    self.setFalse()
                    res = CE.FALSE
                else:
                    self.cond = self.left.cond
                    self.right = self.left.right
                    self.z3 = self.left.z3
                    self.left = self.left.left 
                    res =  CE.UNKNW 
                
        # NOT Simplification 
        elif( self.cond == CT.NOT ):
            right = self.right.clean()
            if( right == CE.TRUE ):
                self.setFalse()
                res =  CE.FALSE
            elif( right == CE.FALSE ):
                self.setTrue()
                res =  CE.TRUE
            else:
                res = CE.UNKNW
        
        # Arithmetic comparators simplification         
        elif( isArithmeticComp(self.cond)):
            # We look if the left part is equal to the right part 
            # !!! We DO NOT perform any simplification when left != right because '==' 
            # corresponds to structural equality between two expressions BUT NOT semantic
            # equivalence. I.e we can have self.right != self.left from the == omparator function 
            # but still have self.right == self.left in the real world 
            self.right = self.right.simplify()
            self.left = self.left.simplify()
            if( self.right == self.left ):
                if( self.cond == CT.EQUAL or self.cond == CT.GE or self.cond == CT.LE ):
                    self.setTrue()
                    res = CE.TRUE
                elif( self.cond == CT.NOTEQUAL or self.cond == CT.GT or self.cond == CT.LT ):
                    self.setFalse()
                    res = CE.FALSE
                else:
                    res = CE.UNKNW
            else:
                res = CE.UNKNW
        # Boolean constants simplifications 
        elif( self.cond == CT.TRUE ):
             res = CE.TRUE
        elif( self.cond == CT.FALSE ):
            res = CE.FALSE
        else:
            raise CondException("Condition type %d not supported by function Cond.clean() yet", self.cond)
        
        # Return the evaluation status ( CE value )
        self.cleaned = True
        return res
        
    def customSimplify(self):
        """
        Simplifies a condition using custom rules and methods ! 
        When the condition is a comparison between 2 expressions, the Expr.toArray() method is used to compare them 
        When the condition is a logical formula, usual rules are applied 
        
        The condition is simplified IN PLACE
        
        Returns a CE (CE.TRUE, CE.FALSE, CE.UNKNW) 
        """            
        def simplifyArrayEquality(a1,a2, condtype):
            """
            Simplifies arrays for a1 == a2
            """
            found_diff = False  
            # Check for all registers but not the constant value 
            for i in range(0,len(a1)):
                if(a1[i] != a2[i]):
                    # If two differences in the arrays then we don't know .... 
                    if(found_diff):
                        return CE.UNKNW
                    else:
                        found_diff = True
            # If only one difference, then not equal 
            if( found_diff ):
                if( condtype == CT.EQUAL ):
                    return CE.FALSE
                else:
                    return CE.TRUE
            else:
                if( condtype == CT.EQUAL ):
                    return CE.TRUE
                else:
                    return CE.FALSE
                
            
        
        def simplifyArrayInequality(a1,a2,comp):
            for i in range(0,len(a1)-1):
                if(a1[i] != a2[i]):
                    # If one difference in the arrays then we don't know .... 
                    return CE.UNKNW
            if( comp(a1[-1], a2[-1])):
                return CE.TRUE
            else:
                return CE.FALSE
            
            
        
        if( self.customSimplified ):
            return self.customSimplifiedValue
                
        if( isLogicalConst(self.cond)):
            return ( self.cond == CT.TRUE )
        elif( isArithmeticComp(self.cond)):
            # Choose the correspondign operator for comparison 
            if( self.cond == CT.GT ):
                comp = operator.gt
            elif( self.cond == CT.GE ):
                comp = operator.ge
            elif( self.cond == CT.LE ):
                comp = operator.le
            elif( self.cond == CT.LT ):
                comp = operator.lt
            leftArray = self.left.toArray()
            rightArray = self.right.toArray()
            if( leftArray == [] or rightArray == [] ):
                res = CE.UNKNW
            else:
                if( self.cond == CT.EQUAL or self.cond == CT.NOTEQUAL ):
                    res = simplifyArrayEquality( leftArray, rightArray, self.cond)
                else:
                    res = simplifyArrayInequality( leftArray, rightArray, comp)
                
            if( res == CE.TRUE ):
                self.setTrue()
            elif( res == CE.FALSE ):
                self.setFalse()
            else:
                self.customSimplified = True
                self.customSimplifiedValue = CE.UNKNW
            return res        
        elif( isLogicalOp(self.cond)):
            if( self.cond == CT.AND ):
                left = self.left.customSimplify()
                if( left != CE.TRUE):
                    self.customSimplified = True
                    self.customSimplifiedValue = left
                    return left 
                right = self.right.customSimplify()
                res = right 
            elif( self.cond == CT.OR ):
                left = self.left.customSimplify()
                if( left == CE.TRUE ):
                    self.setTrue()
                    return CE.TRUE
                right = self.right.customSimplify()
                res = right 
            elif( self.cond == CT.NOT ):
                right = self.right.customSimplify()
                if( right == CE.UNKNW ):
                    return CE.UNKWN
                else:
                    if( right == CE.TRUE ):
                        res = CE.FALSE
                    else:
                        res = CE.TRUE
            if( res == CE.TRUE ):
                self.setTrue()
            elif( res == CE.FALSE ):
                self.setFalse()
            else:
                self.customSimplified = True
                self.customSimplifiedValue = CE.UNKNW
            return res 
        else:
            raise CondException("Condition type " + str(self.cond) + " not supported by customSimplify() yet")
        
    def simplifyZ3(self):
        """
        Simplifies oneself's z3 representation 
        
        THIS FUNCTION SHOULD NOT BE USED YET 
        
        /!\ The IR ( i.e Cond AST ) stays the same, even if the self.z3 is modified
        /!\ After calling this function, the self.z3 object will no more correspond to a direct 
        /!\     translation of the AST representation into a z3 expression  
        
        Parameters:
            /!\ Notice that a 'hard simplification' is way more expensive than a 'soft simplification' but can
            return better results 
        """

        if( self.Z3Simplified ):         
            return self.z3
        
        condZ3 = self.toZ3()
        self.z3 = hardSimplify(condZ3)
        if( self.z3 == BoolSort().cast(True)):
            self.setTrue()
        elif( self.z3 == BoolSort().cast(False)):
            self.setFalse()
        self.Z3Simplified = True
        return self.z3 
                
    def isTrue(self, hard=False):
        """
        Checks if a condition is always true 
        If hard = False : Returns True if the condition is simplified to "True" using customSimplify(). Some actual true conditions can be missed 
        If hard = True : Returns True if the condition is always verified by checking for its negation to be unsat with Z3 check() function
        """
        global debug_solver_count
        
        if( self.cond == CT.TRUE ):
            return True
        elif( self.cond == CT.FALSE ):
            return False
        
        if( hard == False ):
            res = self.customSimplify()
            return ( res == CE.TRUE )
        else:
            condZ3 = self.simplifyZ3()
            self.checked = True
            v = Solver()
            v.add(Not(condZ3))
            signal.signal(signal.SIGALRM, TimeOutRaiser)
            #signal.setitimer(signal.ITIMER_REAL, 1)
            try:        
                res = str(v.check())
            except Exception as e:
                log("z3 Failed to check the following condition: " + str(Not(condZ3)))
                res = "sat"
            debug_solver_count = debug_solver_count + 1
            if( str(res) == "unsat" ):
                self.setTrue()
                return True
            else:
                return False
        
    def isFalse( self, hard=False):
        """
        Checks if a condition is always false
        If hard = False : Returns True if the condition is simplified to "False" using  customSimplify(). Some actual false conditions can be missed 
        If hard = True : Returns True if the condition is never verified by checking for it to be unsat with Z3 check() function
        """
        global debug_solver_count
        
        if( self.cond == CT.TRUE ):
            return False
        elif( self.cond == CT.FALSE ):
            return True
        
        if( hard == False ):
            res = self.customSimplify()
            return ( res == CE.FALSE )

        else:
            condZ3 = self.simplifyZ3()
            self.checked = True
            v = Solver()
            v.add(condZ3)
            signal.signal(signal.SIGALRM, TimeOutRaiser)
            #signal.setitimer(signal.ITIMER_REAL, 1)
            try:        
                res = str(v.check())
            except Exception as e:
                res = "sat"
            
            debug_solver_count = debug_solver_count + 1
            if( str(res) == "unsat" ):
                self.setFalse()
                return True
            else:
                return False
                
                
    def setTrue(self):
        """
        Sets the condition to TRUE in place
        """
        self.cond = CT.TRUE
        self.left = self.right = None
        self.z3 = BoolSort().cast(True)
        self.cleaned = self.Z3Simplified = self.customSimplified = self.checked = True
        self.customSimplifiedValue = CE.TRUE
        
        
    def setFalse(self):
        """
        Sets the condition to FALSE in place 
        """
        self.cond = CT.FALSE
        self.left = self.right = None
        self.z3 = BoolSort().cast(False)
        self.customSimplifiedValue = CE.FALSE
        self.cleaned = self.Z3Simplified = self.customSimplified = self.checked = True
    
def CTrue():
    """
    Returns a TRUE condition 
    """
    return Cond(CT.TRUE, None, None, z3=BoolSort().cast(True), cleaned=True, checked=True )
    
def CFalse():
    """
    Returns a FALSE condition 
    """
    return Cond(CT.FALSE, None, None, z3=BoolSort().cast(False), cleaned=True, checked=True)
    

            
        
