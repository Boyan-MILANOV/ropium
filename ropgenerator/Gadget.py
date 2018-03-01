# ROPGenerator - GadgetBarf.py module 
# Implements the data structure to represent gadgets
# And building functions for creating them from BARF IR 

from ropgenerator.Expr import ConstExpr, SSAExpr, MEMExpr, Op, SSAReg, Cat, Extr, Convert, strToReg, ITE, REGSIZE, memorySMT
from ropgenerator.Cond import Cond, CT, CTrue, CFalse, simplify
from ropgenerator.Graph import Graph, Arc, GadgetDependencies, CurrentAnalysis, MEMNode, SSANode, ConstNode, ITENode
from z3 import Array, BitVecSort
import ropgenerator.Analysis as Analysis 
from ropgenerator.Logs import log
from ropgenerator.Constraints import Constraint, ConstraintType
from enum import Enum

from barf.core.reil import *
    
class GadgetException( Exception ):
    def __init__( self, msg ):
        self.msg = msg
        log(self.msg)
    def __str__(self):
        return self.msg
        
        
class GadgetType(Enum):
    REGtoREG = "REGtoREG"   # reg = reg
    CSTtoREG = "CSTtoREG"    # reg = cst
    MEMtoREG = "MEMtoREG"    # reg = mem(reg)
    EXPRtoREG = "EXPRtoREG"    # reg = expr
    MEMEXPRtoREG = "MEMEXPRtoREG "    # reg = mem(expr)
    
    REGtoMEM = "REGtoMEM"    # mem(expr) = reg
    CSTtoMEM = "CSTtoMEM"    # mem(expr) = cst
    EXPRtoMEM = "EXPRtoMEM"    # mem(expr) = expr
    MEMEXPRtoMEM = "MEMEXPRtoMEM" # mem(expr) = mem(expr)
    
class RetType(Enum):
    UNKNOWN = "UNKNOWN"
    RET = "RET"
    CALL_REG = "CALL_REG"
    JMP_REG = "JMP_REG"   
    
# List of gadgets already analyzed !!     
# Keys are gadget.asmStr 
# Values are a pair (dep, graph) = (pointer to GadgetDependencies object, pointer to the related graph) 
# /!\ DIfferent gadgets will share the same GadgetDependencies object
analyzed_raw_to_gadget = dict()


##############################
# REPRESENTATION OF A GADGET #
##############################

class Gadget:
    """
    Gadget : This class represents a gadget and several informations about it
        (self.graph) : (Graph) is the graph modeling the instructions of the gadget
        (self.addr) : (int) is the address of the gadget 
        (self.regCount) : Dictionnary( Keys are integers, values are integers )
                regCount[2] = 0 <=> R2_0 have appeared but R2_1 not yet
        (self.spInc) : (int) The number of bytes the stack pointer will increase during execution of the gadget ( not imp yet )
        (self.num) : (int) an integer that identifies the gadget among other 
        (self.hexStr) : (str) The string of the opcodes 
        (self.asmStr) : (str) The string of the assembly instructions 
        (self.dep) : (GadgetDependencies) The dependencies of the gadget 
    """
    global analyzed_raw_to_gadget
    
    def __init__(self, num, addr, raw):
        """
        (raw) is the raw string of the instructions of the gadget 
        """
        # irsb is an array of BARF instructions
        # ins is an array of Assembly instructions 
        
        if( raw in analyzed_raw_to_gadget ):
            self._copy_gadget( num, addr, analyzed_raw_to_gadget[raw] )
        else:
            try:
                (irsb,ins) = Analysis.getIR( raw, addr )
            except Analysis.AnalysisException as e:
                raise GadgetException(str(e))
            
            self.duplicate = None # If the gadget is a copy of another gadget, then self.duplicate = pointer to the original gadget ! 
            # Some strings representations 
            self.asmStr = "; ".join(str(i) for i in ins)
            self.hexStr = "\\x"+ "\\x".join("{:02x}".format(ord(c)) for c in raw)
            # Initializing the memory in Z3 for this gadget 
            self.addr = addr # int
            # Get the string for the address, depends on the architecture size 
            self.addrStr = '0x'+format(addr, '0'+str(Analysis.ArchInfo.bits/4)+'x')
            self.regCount = {} # Keys are integers, values are integers. regCount[2] = 0 <=> R2_0 have appeared but R2_1 not yet 
            self.spInc = None # How much have Stack Pointer been incremented by 
            self.num = num # Identifier or the gadget
            self.ret = RetType.UNKNOWN # Type of the last instruction of the gadget (ret, call, ... )
            self.retValue = None # (int) register to jmp to if ret is CALL_REG or JMP_REG  
            self.nbInstr = 0 # Number of REIL instructions of this gadget 
            self.dep = None
            self.valuesTable = {} # Used dinamically when building graph
            self.validPreConstraint = None # If the preconstraint is valid or not
            self.preConstraint = None
            # Building graph and computing the dependencies 
            self.graph = Graph()
            self.buildGraph(irsb)
            self.getDependencies()
            analyzed_raw_to_gadget[raw] = self
        
        
    def _copy_gadget( self, new_num, new_addr, same_gadget ):
        """
        Copies the gadget 'same_gadget' into the current gadget and changes
        only the number and the address
        
        This function is used to avoid computing dependencies twice for 
        identical gadgets that have different addresses 
        """
        self.asmStr = same_gadget.asmStr
        self.hexStr = same_gadget.hexStr
        # Initializing the memory in Z3 for this gadget
        self.addr = new_addr # int
        # Get the string for the address, depends on the architecture size 
        self.addrStr = '0x'+format(new_addr, '0'+str(Analysis.ArchInfo.bits/4)+'x')
        self.regCount = same_gadget.regCount # Keys are integers, values are integers. regCount[2] = 0 <=> R2_0 have appeared but R2_1 not yet 
        self.spInc = same_gadget.spInc # How much have Stack Pointer been incremented by 
        self.num = new_num # Identifier or the gadget
        self.ret = same_gadget.ret # True iff the gadgets ends up by a normal ret; instruction 
        self.retValue = same_gadget.retValue
        self.validPreConstraint = same_gadget.validPreConstraint
        self.preConstraint = same_gadget.preConstraint
        self.nbInstr = same_gadget.nbInstr # Number of REIL instructions of this gadget 
        self.valuesTable = same_gadget.valuesTable # Used dinamically when building graph 
        # Copying graph and computing the dependencies 
        self.graph = same_gadget.graph
        self.dep = same_gadget.dep
        self.duplicate = same_gadget
        
    def _getReg( self, regStr):
        """
        Given a register name ( eax, edx, ... ) this function translates it into a generic R0_ R1_ ...
        This is meant to return the current state of a register under the form of a SSA register, by checking into the regCount dictionnary. If eax ( whose id is 2 for example ) have been modified 2 times, then the current value of eax will be _getReg("eax") = SSAReg(2,2)
        If the register had never occured before, either in the gadget, or during the whole analysis, then it's ID is created and added to the regNamesTable. 
        If the argument does not depict a full register the translation of the full register is returned
        ---> e.g _getReg("AH") -> _getReg("RAX") -> R3
        Parameters :
            regStr - (str) The string of the register we want to get 
        """
        # We first find the corresponding full register ( like AH ---> RAX )
        aliasMapper = Analysis.ArchInfo.currentArchInfo.alias_mapper
        if( aliasMapper.get(regStr ) != None ):
            if( aliasMapper[regStr][0] != "rflags" ):
                fullReg = aliasMapper[regStr] # Couple (reg, offset)
                regStr = fullReg[0]
        
        # If first occurence of this register in analysis : we translate it in the table 
        if( Analysis.regNamesTable.get(regStr) == None ):
            Analysis.regNamesTable[regStr] = Analysis.ssaRegCount
            Analysis.revertRegNamesTable[Analysis.ssaRegCount] = regStr
            self.regCount[Analysis.ssaRegCount] = 0
            reg = SSAReg( Analysis.ssaRegCount, 0 )
            regExpr = SSAExpr( reg )
            Analysis.ssaRegCount += 1
            # Create basic node
            node = SSANode( reg, regExpr)
            node.jmpLvl = 0
            self.graph.nodes[str(reg)] = node
        # Else if register already have an ID 
        else:
            reg = SSAReg( Analysis.regNamesTable[regStr], None )
            # First occurence in this gadget -> ind set to 0 and node created 
            if( self.regCount.get(reg.num) == None ):
                reg.ind = 0
                self.regCount[reg.num] = 0
                # Create basic node
                node = SSANode( reg, SSAExpr( reg ))
                node.jmpLvl = 0
                self.graph.nodes[str(reg)] = node 
            else:
                reg.ind = self.regCount[reg.num]
                if( self.graph.nodes.get(str(reg)) ==  None ):
                    self.graph.nodes[str(reg)] = SSANode( reg, SSAExpr( reg ))        
        # Returning corresponding expression
        return SSAExpr( reg )
        
        
    def buildGraph( self, irsb ):
        # (1) Initialisations...
        self.valuesTable = {} # Keys are whatever, Values are Expr 
        self.graph = Graph() # Empty graph 
        CurrentAnalysis.gadget = self
        CurrentAnalysis.graph = self.graph
        self.regCount = {}
        # Update the index counts and nodes for registers that already have a translation into generic IR 
        for reg in Analysis.regNamesTable.values():
            self.regCount[reg] = 0
            node = SSANode( SSAReg(reg,0), SSAExpr( SSAReg(reg,0)))
            self.graph.nodes["R%d_0"%reg] = node
        self.graph.nodes["MEM"] = MEMNode()
        memAccCount = 0    # Hold the number of the next arc incoming/outgoing to/from the memory node

        # (2) Graph construction...
        # Iterate through all reill instructions : 
        for i in range(0, len(irsb)) :
            instr = irsb[i]
            self.nbInstr = self.nbInstr + 1
            # Translating different types of instructions
            if( instr.mnemonic == ReilMnemonic.NOP ):
                pass
            # Basic operations ( ADD, SUB, MUL, etc )
            elif( isCalculationInstr(instr.mnemonic)):
                if(  instr.operands[2]._name[0] == "t" ):
                    expr = self.barfCalculationToExpr( instr.mnemonic, instr.operands[0], instr.operands[1], instr.operands[2].size )
                    self.valuesTable[instr.operands[2]._name] = expr
                else:
                    expr = self.barfCalculationToExpr( instr.mnemonic, instr.operands[0], instr.operands[1], instr.operands[2].size )
                    regExpr = self._getReg( instr.operands[2]._name )
                    reg = regExpr.reg
                    expr = self.translateFullRegAssignement( expr, instr.operands[2] )
                    reg = SSAReg( reg.num, reg.ind + 1 )
                    self.valuesTable[str(reg)] = expr
                    # Adding the node 
                    node = SSANode( reg, expr )
                    # Adding arcs toward other nodes and memory 
                    for dep in expr.getRegisters():
                        # Dep is a SSAReg on which node depends
                        node.outgoingArcs.append( Arc(self.graph.nodes[str(dep)] ))
                    for mem in expr.getMemAcc():
                        addr = mem[0]
                        size = mem[1]
                        node.outgoingArcs.append( Arc(self.graph.nodes["MEM"], memAccCount, addr, size ))
                        memAccCount += 1
                    self.graph.nodes[str(reg)] = node
                    self.regCount[reg.num] += 1

            # Memory load instruction 
            elif( isLoadInstr(instr.mnemonic)):
                expr = self.barfLoadToExpr( instr.operands[0], instr.operands[2] )
                if( instr.operands[2]._name[0] == "t" ):
                    self.valuesTable[instr.operands[2]._name] = expr
                else:
                    regExpr = self._getReg(instr.operands[2]._name)
                    reg = regExpr.reg
                    expr = self.translateFullRegAssignement( expr, instr.operands[2] )
                    reg.ind += 1
                    self.regCount[reg.num] += 1
                    self.valuesTable[str(reg)] = expr
                    # Adding node towards memory
                    node = SSANode( reg, expr )
                    for mem in expr.getMemAcc():
                        addr = mem[0]
                        size = mem[1]
                        node.outgoingArcs.append( Arc(self.graph.nodes["MEM"], memAccCount, addr, size ) )
                        memAccCount += 1
                    self.graph.nodes[str(reg)] = node
            
            # Memory store instruction         
            elif( isStoreInstr( instr.mnemonic )):
                expr = self.barfOperandToExpr( instr.operands[0] ).simplify()
                addr = self.barfOperandToExpr( instr.operands[2] ).simplify()
                #if( isinstance( instr.operands[0], ReilImmediateOperand )):
                    #node = ConstNode( instr.operands[0].immediate, instr.operands[0].size )
                    #self.graph.nodes["MEM"].outgoingArcs.append( Arc( node, memAccCount, addr, expr.size ))
                if( isinstance(expr, ConstExpr)):
                    node = ConstNode(expr.value, expr.size)
                    self.graph.nodes["MEM"].outgoingArcs.append( Arc( node, memAccCount, addr, expr.size ))
                elif( not expr.getRegisters()):
                    raise GadgetException("Expression is neither ConstExpr nor has registers and should be written in memory ? - not yet supported!") 
                else:
                    self.graph.nodes["MEM"].outgoingArcs.append( Arc( self.graph.nodes[str(expr.getRegisters()[0])], memAccCount,addr, expr.size ))
                self.graph.nodes["MEM"].storedValues[memAccCount] = expr
                memAccCount += 1 
                
            
            # Transfer value into register         
            elif( isPutInstr( instr.mnemonic )):
                if( instr.operands[2]._name[0] == "t" ):
                    expr = self.barfOperandToExpr( instr.operands[0] )
                    if( instr.operands[2].size != expr.size ):
                        expr = Convert( instr.operands[2].size, expr )
                    self.valuesTable[instr.operands[2]._name] = expr
                else:    
                    regExpr = self._getReg( instr.operands[2]._name )
                    reg = regExpr.reg
                    expr = self.barfOperandToExpr( instr.operands[0] )
                    if( instr.operands[0].size < instr.operands[2].size ):
                        expr = self.translateFullRegAssignement( expr, instr.operands[2] )
                    else:
                        expr = Convert(instr.operands[2].size, expr)
                    if( instr.operands[2].size != REGSIZE.size ):
                        expr = self.translateFullRegAssignement( expr, instr.operands[2] )
                    regDep = expr.getRegisters()
                    memDep = expr.getMemAcc()
                    
                    # Adding node and arcs to the graph
                    reg = SSAReg( reg.num, reg.ind + 1 )
                    node = SSANode( reg, expr )
                    for r in regDep:
                        node.outgoingArcs.append( Arc( self.graph.nodes[str(r)]))
                    for mem in memDep:
                        addr = mem[0]
                        size = mem[1]
                        node.outgoingArcs.append( Arc( self.graph.nodes["MEM"], memAccCount, addr, size ))
                        memAccCount += 1
                    self.graph.nodes[str(reg)] = node
                    self.regCount[reg.num] += 1
                    self.valuesTable[str(reg)] = expr
        
            # Boolean IS Zero instrution 
            # BISZ( a, b ) has the following effects :
            #    b <- 1 if a == 0
            #    b <- 0 if a != 0 
            elif( instr.mnemonic == ReilMnemonic.BISZ ):
                zero = ConstExpr(0, instr.operands[0].size)
                ifzero = ConstExpr(1, instr.operands[2].size )
                ifnotzero = ConstExpr(0,instr.operands[2].size )
                testedValue = self.barfOperandToExpr(instr.operands[0])
                # If operands[0] == 0 then the value assigned to operands[2] is 1. 
                # If operands[0] != 0 then operands[2] becomes 0 
                cond = Cond( CT.EQUAL, testedValue, zero )
                expr = ITE( cond, ifzero, ifnotzero )    
                if( instr.operands[2]._name[0] == "t" ):
                    self.valuesTable[instr.operands[2]._name] = expr
                else:
                    regExpr = self._getReg( instr.operands[2]._name )
                    reg = regExpr.reg
                    reg.ind += 1
                    self.regCount[reg.num] += 1
                    self.valuesTable[str(reg)] = expr
                    # Adding node to the graph 
                    # Creation of the ite node
                    iteNode = ITENode( cond, ifzero, ifnotzero )
                    # Link the real node to the ITE node 
                    node = SSANode( reg, Convert( REGSIZE.size, expr))
                    node.outgoingArcs.append( Arc(iteNode) )
                    self.graph.nodes[str(reg)] = node

            # Conditionnal jump 
            elif( instr.mnemonic == ReilMnemonic.JCC ):
                # Determine the address where to jmp 
                # If jmp to a fixed location 
                if( isinstance( instr.operands[2], ReilImmediateOperand ) and instr.operands[2].size != 40 and instr.operands[2].size != 72 ):
                    addr = ConstExpr(instr.operands[2].immediate)
                    addr.size = REGSIZE.size
                # If it is a pointer 
                elif( instr.operands[2].size == 40 or instr.operands[2].size == 72 ):
                    #We test if the value is less than 0x100
                    # If yes, then we ignore the condition because unable to compute dependencies 
                    # This kind of small values depict an instruction simulated in many basic blocks
                    # We do not handle conditions for the Instr Pointer INSIDE a gadget 
                    if( isinstance(instr.operands[2], ReilImmediateOperand ) and (instr.operands[2].immediate>>8) - self.addr < 0x1 ):
                        raise GadgetException("REIL instruction(s) too complicated to emulate in gadget:\n" + self.asmStr )
                    # We also test if there is a jump inside the bounds of the gadget
                    # For now those are also not supported 
                    # Sadly, this also suppresses some conditional conditions  
                    if( isinstance( instr.operands[2], ReilImmediateOperand ) and (instr.operands[2].immediate>>8) - self.addr < (len(self.hexStr)/4) ):
                        
                        raise GadgetException("Jumps inside the gadget are not handled yet in gadget:\n" + self.asmStr)
                    # Get the real return/jump address with an 8 bit SHR
                    expr = self.barfOperandToExpr(instr.operands[2])
                    addr = Extr( expr.size-1, 8, expr )
                else:
                    addr = self.barfOperandToExpr( instr.operands[2] )
                ip = self._getReg(Analysis.ArchInfo.ip).reg # Get the instruction pointer         
                ip.ind += 1
                # Quick check if simple 'ret' so the expression is easier to read
                # A jump is always taken if first argument is a constant != 0 
                if( isinstance( instr.operands[0], ReilImmediateOperand ) and instr.operands[0].immediate != 0 ):
                    self.valuesTable[str(ip)] = addr
                    expr = addr
                    node = SSANode( ip, Convert(REGSIZE.size, addr))
                    for dep in addr.getRegisters(ignoreMemAcc=True):
                        node.outgoingArcs.append( Arc( self.graph.nodes[str(dep)]))
                    for mem in addr.getMemAcc():
                        address = mem[0]
                        size = mem[1]
                        node.outgoingArcs.append( Arc( self.graph.nodes["MEM"], memAccCount, address, size))
                        memAccCount += 1
                    self.regCount[ip.num] += 1 
                    self.graph.nodes[str(ip)] = node
                # Else processing conditional jump 
                else:
                    # Create node and stuff
                    reg = ip
                    zero = ConstExpr(0,instr.operands[0].size )
                    cond = Cond(CT.NOTEQUAL, self.barfOperandToExpr(instr.operands[0]) , zero) 
                    # Update the info about conditional jumps in Graph.py module 
                    self.graph.condJmps.append( cond )
                    self.graph.condPath.append( Cond( CT.AND, cond.invert(), self.graph.condPath[self.graph.countCondJmps]))
                    # TODO : this seems not to put the good address into nextInstrAddr ??? 
                    nextInstrAddr = ConstExpr(irsb[i+1].address >> 8, REGSIZE.size) 
                    # 1 - FIRST STEP : ITE Node to say : IP takes new value OR stays the same
                    expr = ITE(cond, addr, ConstExpr(instr.address >> 8, REGSIZE.size))
                    self.valuesTable[str(reg)] = expr
                    # Adding node to the graph 
                    # Creation of the ite node
                    # We consider that either the jump is taken ( to addr )
                    #   or the value stays the one of the current instruction ( instr.address >> 8 )
                    iteNode = ITENode( cond, addr, ConstExpr(instr.address >> 8, REGSIZE.size) )
                    for dep in addr.getRegisters():
                        iteNode.outgoingArcs.append( Arc( self.graph.nodes[str(dep)] ))
                    for mem in addr.getMemAcc():
                        address = mem[0]
                        size = mem[1]
                        iteNode.outgoingArcs.append( Arc( self.graph.nodes["MEM"], memAccCount, address, size))
                        memAccCount += 1
                    #iteNode.outgoingArcsCond.append( Arc( self.graph.nodes[str(prevOcc(reg))], -1, None))
                    # Link the real node to the ITE node 
                    node = SSANode( reg, expr)
                    node.outgoingArcs.append( Arc(iteNode))
                    self.graph.nodes[str(reg)] = node 
                    # And do not forget 
                    self.regCount[reg.num] += 1 
                    self.graph.countCondJmps += 1
                    # 2 - SECOND STEP 
                    # We update the register again with the address of the next instruction 
                    reg = SSAReg( reg.num, reg.ind + 1 )
                    node = SSANode( reg, nextInstrAddr)
                    self.graph.nodes[str(reg)] = node
                    self.regCount[reg.num] += 1
            else:
                raise GadgetException("REIL operation <%s>  not supported in gadget:\n%s" % (ReilMnemonic.to_string(instr.mnemonic), self.asmStr ))
                
    
                
    def barfOperandToExpr(self, op):
        """
        Translate a barf operand into an expression (Expr from Expr.py)
        Parameters :
            op - (ReilOperand) should be either an immediate or a register 
        """
        if( isinstance( op, ReilImmediateOperand )):
            res = ConstExpr( op._immediate, op.size )
            return res 
        elif( isinstance( op, ReilRegisterOperand )):
            if( op._name[0] == "t" ):
                res = self.valuesTable[op._name]
                if( op.size == res.size ):
                    return res
                else:
                    return Convert(op.size, res)
            else:
                fullExpr = self._getReg(op._name)
                if( op.size == REGSIZE.size ):
                    return fullExpr
                else:
                    (reg, offset) = barfGetAlias( op._name )
                    if( reg == "rflags" ):
                        return Convert( op.size, fullExpr )
                    else:
                        return Extr( op.size + offset -1, offset, fullExpr )
        else:
            raise GadgetException("Operand %s neither register nor immediate", str(op))
            
    
    def barfCalculationToExpr( self, mnemonic, op1, op2, size ):
        """
        Translates a barf calculus expression into an intern representation expression ( Expr from Expr.py )
        Parameters : 
            mnemonic - ( int ) The code for the operation to be performed 
            op1,op2 - (ReilOperand ) left and right operands ( op1 is left )
            size - (int) The size wanted for the result ( 8, 16, 32, ... )
        Return value : 
            Expr() instance
        """
        if( mnemonic == ReilMnemonic.ADD ):
            res = Op( "Add", [self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        elif( mnemonic == ReilMnemonic.SUB ):
            res= Op( "Sub", [self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        elif( mnemonic == ReilMnemonic.MUL ):
            res = Op( "Mul", [self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        elif( mnemonic == ReilMnemonic.BSH ):    
            # Binary shift needs custom size adjustement 
            left = self.barfOperandToExpr(op1)
            if( left.size == size ):
                return Op( "Bsh", [left , self.barfOperandToExpr( op2 )])
            else:
                return Op( "Bsh", [Convert(size, left ),  Convert( size, self.barfOperandToExpr( op2 ))])
        elif( mnemonic == ReilMnemonic.AND ):
            res = Op( "And", [self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        elif( mnemonic == ReilMnemonic.OR ):
            res = Op( "Or",[ self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        elif( mnemonic == ReilMnemonic.XOR ):
            res = Op( "Xor", [self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        elif( mnemonic == ReilMnemonic.MOD ):
            res = Op( "Mod" , [self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        elif( mnemonic == ReilMnemonic.DIV ):
            res = Op( "Div" , [self.barfOperandToExpr( op1 ), self.barfOperandToExpr( op2 )])
        else:
            raise GadgetException("Operation %s not supported yet "% ReilMnemonic.to_string(mnemonic))
        # Size adjustements 
        if( res.size != size ):
            res = Convert( size, res )
        return res
        
        
    def barfLoadToExpr( self, addr, reg ):
        """
        Translates a memory load into expression ( Expr in Expr.py )
        Parameters :
            addr - (ReilOperand) The address where memory is read
            reg - (ReilOperand) The register where the read value is stored 
        """
        if( addr.size != REGSIZE.size ):
            raise GadgetException("Addressing expression of size %d is incompatible with registers of size %d in %s architecture" %(addr.size, REGSIZE.size, Analysis.ArchInfo.currentArch))
        expr = self.barfOperandToExpr( addr )
        res = MEMExpr( expr, reg.size )
        return res 
        

    def translateFullRegAssignement( self, expr, op ):
        """
        Translates an expression into another expression so it is assigned to a whole register
        This is used when assigning sub-registers such as AH, BL, CX, ... 
        Example: In 64 bits, if AL is assigned the value 0xFF, this function gets the new value for RAX  
             RAX_1 <- Cat( Extr( 63, 8, RAX_0 ), ConstExpr(0xFF, 8) )
             So expr = ConstExpr(0xFF,8) is transoformed into "Cat( Extr( 63, 8, RAX_0 ), ConstExpr(0xFF, 8) )"
        Parameters :
            expr - (Expr) the value to convert
            op - (ReilOperand) the register in which value should be stored 
            
        """
        if( expr.size == REGSIZE.size ):
            return expr
        # reg is the full register name 
        # offset is the offset at which 'op' starts in the register 
        # For example for BH in 32 bits we get ( reg = EBX, offset = 8 )    
        if( op._name in Analysis.ArchInfo.currentArchInfo.alias_mapper ):
            (reg, offset) = Analysis.ArchInfo.currentArchInfo.alias_mapper[op._name]
        else:
            reg = op._name
            offset = 0
        # Special treatement of the flags
        if(reg == "rflags"):
            return Convert( REGSIZE.size, expr)
        # Else we translate :
        else:
            oldReg = self._getReg(op.name)
            high = Extr( oldReg.size-1, offset+expr.size, oldReg )
            if( offset > 0 ):
                low = Extr( offset-1, 0, oldReg )
            else:
                low = None
            res = Cat( [high, expr, low] )
            return res
            
    def printInstr(self):
        """
        Print the instruction in assembly
        """
        print "[+] Instructions"
        print self.asmStr
    
    def printHex(self):
        """
        Print the instructions in a hex chain format 
        """
        print "[+] Hex format : " + self.hexStr
        
        
    def calculateSpInc(self):
        """
        Compute how much the stack pointer has advanced after this gadget is executed 
        """
        
        if( self.duplicate ):
            self.spInc = self.duplicate.spInc
            return 
        
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp]
        if( not sp_num in self.graph.lastMod ):
            self.spInc = 0
            return 
        
        sp = SSAReg(sp_num, self.graph.lastMod[sp_num])
        if( not sp in self.dep.regDep ): 
            self.spInc = 0
            return 
            
        for dep in self.dep.regDep[sp]:
            if( dep[1].isTrue() ):
                (isInc, inc) = dep[0].isRegIncrement(sp.num)
                if( isInc ):
                    self.spInc = inc
                    return
                else:
                    self.spInc = None
                    return
        
    def isValidSpInc(self):
        return self.spInc != None and self.spInc >= 0
        
    def calculateRet(self):
        """
        Computes the return address, checks if it is valid or not... 
        /!\ MUST be called after calculateSpInc()
        
        """
        
        if( self.duplicate ):
            self.ret = self.duplicate.ret
            self.retValue = self.duplicate.retValue
            return 
           
        ip = SSAReg(Analysis.regNamesTable[Analysis.ArchInfo.ip], self.graph.lastMod[Analysis.regNamesTable[Analysis.ArchInfo.ip]])
        sp_num = Analysis.regNamesTable[Analysis.ArchInfo.sp]
        if( self.spInc == None ):
            self.ret = RetType.UNKNOWN
            return 
        
        if( not ip in self.dep.regDep ):
            self.ret = RetType.UNKNOWN
            return 
            
        for dep in self.dep.regDep[ip]:
            if( dep[1].isTrue()):
                if( isinstance(dep[0], MEMExpr)):
                    addr = dep[0].addr
                    (isInc, inc) = addr.isRegIncrement(sp_num)    
                    # Normal ret if the final value of the IP is value that was in memory before the last modification of SP ( i.e final_IP = MEM[final_sp - size_of_a_register )        
                    if( isInc and inc == (self.spInc - (Analysis.ArchInfo.bits/8)) ):
                        self.ret = RetType.RET
                    else:
                        self.ret = RetType.UNKNOWN
                elif( isinstance(dep[0], SSAExpr )):
                    self.retValue = dep[0].reg.num
                    self.ret = RetType.JMP_REG
                return 
        self.ret = RetType.UNKNOWN
        
    def hasNormalRet(self):
        return self.ret == RetType.RET
        
    def hasJmpReg(self):
        if( self.ret == RetType.JMP_REG ):
            return (True, self.retValue)
        else:
            return (False, None) 
        
    def hasCallReg(self):
        if( self.ret == RetType.CALL_REG ):
            return (True, self.retValue)
        else:
            return (False, None) 
    
    def getDependencies(self):
        """
        Get the dependencies of the gadget 
        """
        if( self.dep != None ):
            return self.dep
        else:
            CurrentAnalysis.gadget = self
            CurrentAnalysis.graph = self.graph
            self.dep = self.graph.getDependencies()
            return self.dep
         
        
    def calculatePreConstraint(self):
        """
        Generates a constraint that must be verified before the gadget
        is executed so that it doesn't crash
        If a constraint is successfuly generated :
            - self.validPreConstraint <- True
            - self.preCOnstraint <- Constraint instance
        otherwise
            - self.validPreConstraint <- False
        """
        if( self.duplicate ):
            self.preConstraint = self.duplicate.preConstraint
            self.validPreConstraint = self.duplicate.validPreConstraint
        else:
            # Generate the constraint 
            constraint = Constraint()
            # Go through memory dependencies ( mem <- expr )
            for addr in self.getDependencies().memDep.keys():
                (isInc, reg, inc) = addr.isRegIncrement(-1)
                if( isInc ):
                    constraint.add(ConstraintType.REGS_VALID_POINTER_WRITE, [reg])
                else:
                    self.validPreConstraint = False
                    return
            # Go through dependencies that include MEMExpr
                # Todo  
            
            self.validPreConstraint = True
            self.preConstraint = constraint
    
    def hasValidPreConstraint(self):
        """
        Generates a constraint that must be verified before the gadget
        is executed so that it doesn't crash
        """
        return self.validPreConstraint
            
        
        
         
####################################
# BARF/REIL MANIPULATION FUNCTIONS #
####################################

def barfGetAlias( regStr ):
    """
    Gets the barf alias structure ( name, offset ) for register regStr
    Parameters :
        (regStr) - (str) the register for which the alias is needed
    Return value :
        (alias) - ( str, int )
    """
    if( Analysis.ArchInfo.currentArchInfo.alias_mapper.get(regStr) != None ):
        return Analysis.ArchInfo.currentArchInfo.alias_mapper.get(regStr)
    else:
        raise GadgetException("BARF does not handle register %s for computation"%regStr)

def isCalculationInstr( mnemonic ):
    return mnemonic > 0 and mnemonic < 10
    
def isLoadInstr( mnemonic ):
    return mnemonic == ReilMnemonic.LDM
    
def isStoreInstr( mnemonic ):
    return mnemonic == ReilMnemonic.STM
    
def isPutInstr( mnemonic ):
    return mnemonic == ReilMnemonic.STR        
        
    
    
#############################
# REINITIALIZATION FUNCTION #
#############################
def reinit():
    global analyzed_raw_to_gadget
    analyzed_raw_to_gadget = dict()
