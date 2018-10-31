# -*- coding: utf-8 -*- 
# Conditions module: model for arithmetical and logical conditions 

from enum import Enum
import operator

def CondException( Exception ):
    def __init__(self, msg):
        self.msg = msg 
        log(msg)
    def __str__(self):
        return self.msg 
 
##############################
# TYPES OF CONDITIONS ( CT ) #
##############################
 
class CT(Enum):
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
    VALID_PTR_WRITE = "VALID_POINTER_WRITE"
    VALID_PTR_READ = "VALID_POINTER_READ"
    
    
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
    return ( cond == CT.EQUAL or cond == CT.NOTEQUAL or\
    cond == CT.GT or cond == CT.GE or cond == CT.LT or cond == CT.LE )
        
def isPointerCond( cond ):
    return ( cond == CT.VALID_PTR_READ or cond == CT.VALID_PTR_WRITE )
       
        
def isLogicalOp( cond ):
    """
    Returns true iff the condition is the application of a logical operator ( OR, AND, NOT )
    """
    return ( cond == CT.AND or cond == CT.OR or cond == CT.NOT )
        
def isLogicalConst( cond ):
    """
    Returns True iff the condition is a constant TRUE or FALSE 
    """
    return ( cond == CT.TRUE or cond == CT.FALSE )

class CE: # Condition Evaluation 
    """
    Class used to represent the evaluation of a condition during simplification
        TRUE - the condition have been simplified into TRUE
        FALSE - the condition have been simplified into FALSE
        UNKNOWN - the condition could not be evaluated as a logical constant 
        This class is used for instance by the Cond.simplify() function
    """
    TRUE = True
    FALSE = False
    UNKNOWN = "UNKNOWN"        



################################
# REPRESENTATION OF CONDITIONS #
################################
        
class Cond:
    """
    Represents a condition on registers and/or memory 
        (self.cond) : (CT) is the condition 
        (self.left), (self.right): either 
            (Condition, Condition) with self.cond a logical condition ( AND, OR, etc )
            or (Expr, Expr) with self.cond an arithmetic condition  (EQUAL, LT, etc)
            or (None, None) if self.cond is NONE or TRUE or FALSE
            or (None, Condition) if self.cond is NOT  
        (self.cleaned) - (Bool) True <=> The condition have been 
                                        cleaned ( call to self.clean() function ) 
    """
    
    def __init__(self, condObject):
        self.cond = condObject.cond
        self.left = condObject.left
        self.right = condObject.right
        self.customSimplified = condObject.customSimplified
        self.customSimplifiedValue = condObject.customSimplifiedValue
        self.cleaned = condObject.cleaned
    
    def __init__(self, cond, left, right, cleaned = False, checked = False ):
        self.cond = cond
        self.left = left
        self.right = right
        self.customSimplified = False
        self.customSimplifiedValue = None
        self.cleaned = cleaned 

                
    def __eq__(self, other ):
        """
        Structural equality 
        """
        if( self.cond != other.cond ):
            return False
        if( isLogicalConst( self.cond ) ):
            return True
        else:
            return ( self.left == other.left and self.right == other.right )
            
    def __str__(self):
        if( self.cond == CT.NOT ):
            return "(NOT %s)" % str(self.right)
        elif( isPointerCond(self.cond)):
            return "({} {})".format(str(self.cond), str(self.right))
        elif( not isLogicalConst(self.cond) ):
            return "(%s %s %s)" % ( str(self.left), self.cond, str(self.right) )
        else:
            return str(self.cond)
            
    def getRegisters(self):
        """
        Returns a list of SSARegiters that occur in the condition
        Eliminate multiple occurences in the list  
        """
        if( self.cond == CT.NOT or isPointerCond(self.cond)):
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
        elif( isPointerCond(self.cond)):
            return CTrue()
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
            expr - (Expr) that will replace 'var' 
        """
        if( self.cond == CT.NOT ):
            return Cond( CT.NOT, None, self.right.replaceReg( var, expr ), self.cleaned)        
        elif( isPointerCond(self.cond)):
            return Cond(self.cond, None, self.right.replaceReg(var, expr), self.cleaned)
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
        elif( isPointerCond(self.cond)):
            flatRigth = self.right.flattenITE()
            res = CFalse()
            for r in flatRight:
                res = Cond(CT.OR, res, Cond( CT.AND, Cond(self.cond, None, r[0]), r[1]))
            return res
        else:
            return Cond( self.cond, self.left.flattenITE(), self.right.flattenITE() )
    
    def clean(self):
        """
        This cleans the condition IN PLACE, by removing trivial conditions and stuff like this.  
        """ 
        res = CE.UNKNOWN
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
                    self.right = self.right.right
                    res = CE.UNKNOWN
            elif( right == CE.TRUE ):
                if( left == CE.TRUE ):
                    self.setTrue()
                    res = CE.TRUE 
                else:
                    self.cond = self.left.cond
                    self.right = self.left.right
                    self.left = self.left.left
                    res = CE.UNKNOWN
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
                    self.right = self.right.right
                    res = CE.UNKNOWN
            elif( right == CE.FALSE ):
                if( left == CE.FALSE ):
                    self.setFalse()
                    res = CE.FALSE
                else:
                    self.cond = self.left.cond
                    self.right = self.left.right
                    self.left = self.left.left 
                    res =  CE.UNKNOWN 
                
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
                res = CE.UNKNOWN
        
        # Arithmetic comparators simplification         
        elif( isArithmeticComp(self.cond)):
            # We look if the left part is equal to the right part 
            # !!! We DO NOT perform any simplification when left != right because '==' 
            # corresponds to structural equality between two expressions BUT NOT semantic
            # equivalence. I.e we can have self.right != self.left from the == comparator function 
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
                    res = CE.UNKNOWN
            else:
                res = CE.UNKNOWN
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
        
        Returns a CE (CE.TRUE, CE.FALSE, CE.UNKNOWN) 
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
                        return CE.UNKNOWN
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
                    return CE.UNKNOWN
            if( comp(a1[-1], a2[-1])):
                return CE.TRUE
            else:
                return CE.FALSE
        
        
        if( self.customSimplified ):
            return self.customSimplifiedValue
        
        if( not self.cleaned ):
            self.clean()
               
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
                res = CE.UNKNOWN
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
                self.customSimplifiedValue = CE.UNKNOWN
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
                if( right == CE.UNKNOWN ):
                    self.customSimplified = True
                    self.customSimplifiedValue = CE.UNKNOWN
                    return CE.UNKOWN
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
                self.customSimplifiedValue = CE.UNKNOWN
            return res 
        else:
            raise CondException("Condition type " + str(self.cond) + " not supported by customSimplify() yet")

    def isTrue(self):
        """
        Checks if the condition is always true 
        """
        if( self.cond == CT.TRUE ):
            return True
        elif( self.cond == CT.FALSE ):
            return False
        
        if( not self.cleaned ):
            self.clean()
            
        res = self.customSimplify()
        return ( res == CE.TRUE )
        
    def isFalse( self):
        """
        Checks if the condition is always false
        """  
        if( self.cond == CT.TRUE ):
            return False
        elif( self.cond == CT.FALSE ):
            return True
        
        if( not self.cleaned ):
            self.clean()
            
        res = self.customSimplify()
        return ( res == CE.FALSE )
        
                
    def setTrue(self):
        """
        Sets the condition to TRUE in place
        """
        self.cond = CT.TRUE
        self.left = self.right = None
        self.cleaned = self.customSimplified = True
        self.customSimplifiedValue = CE.TRUE
        
        
    def setFalse(self):
        """
        Sets the condition to FALSE in place 
        """
        self.cond = CT.FALSE
        self.left = self.right = None
        self.customSimplifiedValue = CE.FALSE
        self.cleaned = self.customSimplified = True
    
    
# Functions to rapidly create logical constants :) 
def CTrue():
    """
    Returns a TRUE condition 
    """
    return Cond(CT.TRUE, None, None, cleaned=True, checked=True )
    
def CFalse():
    """
    Returns a FALSE condition 
    """
    return Cond(CT.FALSE, None, None, cleaned=True, checked=True)
