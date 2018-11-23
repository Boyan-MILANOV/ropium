# -*- coding: utf-8 -*- 
# Semantics module: structure to store gadget semantics
from ropgenerator.Conditions import Cond, CT, CTrue, CFalse
from ropgenerator.Expressions import SSAReg, Concat, Extract, SSAExpr, Op, OpExpr, ConstExpr
from ropgenerator.Architecture import r2n

class SPair:
    """
    SPair = Semantics pair = (Expression, Condition)
    """
    def __init__(self, expr, cond):
        self.expr = expr
        self.cond = cond
            
    def __str__(self):
        return '\t> Value: {}\n\t> Condition: {}\n'.format(self.expr, self.cond)

class Semantics:
    """
    Represents semantics of a gadget
    
    self.registers[<SSAReg>] = list of SPair for this register 
    self.memory[<Expr>] = list of SPair for this mem location
    self.final[<reg number>] = bigger index for the register
    """
    def __init__(self):
        self.registers = dict()
        self.memory = dict()
        self.final = dict()
        self.simplified = False
        # Keep track of simplified semantics
        self.simplifiedRegs = dict()
    
    def __str__(self):
        res = 'Semantics\n'
        res += '---------\n'
        
        for reg in self.registers:
            res += '\n\t{} {} semantics:\n'.format(reg, r2n(reg.num))
            res += '\t--------------\n'
            for p in self.registers[reg]:
                res += str(p)+'\n'
            
        for addr in self.memory:
            res += '\n\tmem[{}] semantics:\n'.format(addr)
            res += '\t-----------------\n'
            for p in self.memory[addr]:
                res += str(p)+'\n'
        return res
    
    def get(self, value):
        if( isinstance(value, SSAReg)):
            return self.registers.get(value, [])
        else:
            return self.memory.get(value, [])
    
    def set(self, value, spair_list):
        if( isinstance(value, SSAReg)):
            self.registers[value] = spair_list
        else:
            self.memory[value] = spair_list
    
    def simplifyValues(self):
        """
        Simplifies basic operations, conditions, etc, in order to have
        only basic values left ('basic' is the initial state variables,
        so Expr with SSA forms of R?_0)
        """
    
        def simplifyReg(semantics, ssaReg):
            """
            Compute the basic value for the register
            """
            res = []
            tmpRes = []
            if( ssaReg.ind == 0 ):
                semantics.simplifiedRegs[ssaReg] = True
                return 
            
            # For each possible value 
            for pair in semantics.registers[ssaReg]:
                newPairs = [pair]
                # (1) For each sub register in expressions 
                for subReg in pair.expr.getRegisters():
                    # Simplify values for sub register
                    if( not subReg in semantics.simplifiedRegs ):
                        simplifyReg(self, subReg)
                    # And replace by its possible values 
                    tmp = []
                    for p in newPairs:
                        if( not subReg in p.expr.getRegisters()):
                            continue
                        for subPair in semantics.registers[subReg]:     
                            tmp.append(SPair(p.expr.replaceReg(subReg, subPair.expr),\
                                             Cond(CT.AND, subPair.cond, p.cond)))
                            
                    newPairs = tmp
                tmpRes += newPairs

                # (2) For each sub register in conditions 
                for subReg in pair.cond.getRegisters():
                    # Simplify values for sub register
                    if( not subReg in semantics.simplifiedRegs ):
                        simplifyReg(semantics, subReg)
                    # And replace by its possible values 
                    tmp = []
                    for subPair in semantics.registers[subReg]:
                        for p in tmpRes:
                            tmp.append(SPair(p.expr, Cond(CT.AND, \
                                    p.cond.replaceReg(subReg, subPair.expr), subPair.cond)))
                    tmpRes = tmp
                res = tmpRes
                
            # Dont forget to save and mark it as simplified ;) 
            semantics.registers[ssaReg] = res 
            semantics.simplifiedRegs[ssaReg] = True   
                    
        # Initialize replaceTable
        for reg in self.registers.keys():
            if( len(self.registers[reg]) == 1):
                self.simplifiedRegs[reg] = True
        
        # Replace interatively registers until 
        for reg in self.registers:
            simplifyReg(self, reg)
        
        # Replace registers in memory accesses 
        newMemory = dict()
        for addr in self.memory:
            # (1) First we simplify what we write
            memoryValues = []
            for pair in self.memory[addr]:
                # First we replace registers in expression fields
                newPairs = [pair]
                for subReg in pair.expr.getRegisters():
                    tmp = []
                    for subPair in self.registers[subReg]:
                        for p in newPairs:
                            tmp.append(SPair(p.expr.replaceReg(subReg, subPair.expr),\
                                            Cond(CT.AND, p.cond, subPair.cond)))
                    newPairs = tmp
                # Then we replace registers in the condition fields
                for subReg in pair.cond.getRegisters():
                    tmp = []
                    for subPair in self.registers[subReg]:
                        for p in newPairs:
                            tmp.append( SPair(p.expr,Cond(CT.AND, subPair.cond,\
                                        p.cond.replaceReg(subReg, subPair.expr))))
                    newPairs = tmp
                memoryValues += newPairs
    
            # (2) Then simplify where we write 
            addrValues = [SPair(addr, CTrue())]
            for subReg in addr.getRegisters():
                for subPair in self.registers[subReg]:
                    addrValues = [SPair(p.expr.replaceReg(subReg, subPair.expr), \
                        Cond(CT.AND, subPair.cond, p.cond)) for p in addrValues]
                        
            # Combine memoryValues and addressValues
            for addrPair in addrValues:
                tmp = [SPair(p.expr,Cond(CT.AND, p.cond, addrPair.cond)) for p in memoryValues]
                newAddr = addrPair.expr.simplify()
                newMemory[newAddr] = tmp
        # Update memory semantics with the new ones 
        self.memory = newMemory
    
    
    def customSemanticAdjust(self):
        """
        Make some adjustments in semantics so that it is easier to process by the search engine 
        """
        def adjustSemantic(spair):
            """
            returns a list of SPair
            """
            expr = spair.expr
            cond  = spair.cond
            if( isinstance(expr, Concat) and len(expr.args) == 2):
                upper = expr.args[0][0]
                lower = expr.args[1][0]
                if( isinstance(upper, ConstExpr) and upper.value == 0):
                    if( isinstance(lower, OpExpr)):
                        left = lower.args[0]
                        right = lower.args[1]
                        # IF there is a Const it will be on the right ;)
                        if( not isinstance(right, ConstExpr)):
                            tmp = left
                            left = right
                            right = left
                        # Reg + cst 
                        if( lower.op == Op.ADD and (isinstance(left, Extract) and isinstance(left.args[0], SSAExpr) and left.low == 0)\
                            and isinstance(right, ConstExpr)):
                                new_cond = Cond(CT.AND, 
                                            Cond(CT.AND, cond, Cond(CT.LT, left.args[0], \
                                                ConstExpr((0x1<<(left.high+1))-right.value, left.args[0].size))), 
                                            Cond(CT.GE, left.args[0], ConstExpr(0, left.args[0].size)))
                                new_cond.customSimplify()
                                new_expr = OpExpr(Op.ADD,[left.args[0], ConstExpr(right.value,left.args[0].size)])
                                return [SPair(new_expr, new_cond)]
                        
                        # Reg - cst... 
                        elif( lower.op == Op.SUB and (isinstance(left, Extract) and isinstance(left.args[0], SSAExpr) and left.low == 0)\
                            and isinstance(right, ConstExpr)):
                                new_cond = Cond(CT.AND, 
                                            Cond(CT.AND, cond, Cond(CT.LT, left.args[0], \
                                                ConstExpr(0x1<<(left.high+1),left.args[0].size ))), 
                                            Cond(CT.GE, left.args[0], ConstExpr(right.value, left.args[0].size)))
                                new_cond.customSimplify()
                                new_expr = OpExpr(Op.SUB,[left.args[0], ConstExpr(right.value,left.args[0].size)])
                                return [SPair(new_expr, new_cond)]
                        # Other cases ? :) 
                        else:
                            pass
            return []
                
        ## Adjust semantics 
        for reg in self.registers.keys():
            newPairs = [] 
            for p in self.registers[reg]:
                newPairs += adjustSemantic(p)
            self.registers[reg] += newPairs
        for addr in self.memory.keys():
            newPairs = [] 
            for p in self.memory[addr]:
                newPairs += adjustSemantic(p)
            self.memory[addr] += newPairs
    
    
    def simplifyConditions(self):
        """
        Simplifies the dependencies according to the conditions evaluated 
        to True/False (removes impossible dependencies)
        """
        if( self.simplified ):
            return 
        for reg in self.registers.keys():
            newPairs = [] 
            for p in self.registers[reg]:
                if( p.cond.isTrue()):    
                    pass
                if( not p.cond.isFalse()):
                    p.expr = p.expr.simplify()
                    newPairs.append( p )
            self.registers[reg] = newPairs
        for addr in self.memory.keys():
            newPairs = [] 
            for p in self.memory[addr]:
                if( p.cond.isTrue()):    
                    pass
                if( not p.cond.isFalse()):
                    p.expr = p.expr.simplify()
                    newPairs.append( p )
            self.memory[addr] = newPairs
      
        self.simplified = True
        
    def flattenITE( self ):
        """
        Flattens the If-Then-Else statements in dependencies 
        """
        for reg in self.registers.keys():
            self.registers[reg] = [SPair(p.expr, p.cond.flattenITE()) for p in self.registers[reg]]

        for addr in self.memory.keys():
            self.memory[addr] = [SPair(p.expr, p.cond.flattenITE()) for p in self.memory[addr]]
    
            
        
