# -*- coding: utf-8 -*- 
# Graph module: implements graph representation of gadgets 
from ropgenerator.Semantics import SPair
from ropgenerator.Expressions import SSAReg, OpExpr, Op, Extract, Concat, SSAExpr, ConstExpr, Convert, MEMExpr, ITE
from ropgenerator.Conditions import CTrue, CFalse, Cond, CT
import ropgenerator.Architecture as Arch

from barf.core.reil import ReilMnemonic, ReilImmediateOperand, ReilRegisterOperand

#################################################
# REPRESENTATION OF A GADGET IN GRAPH FORMALISM #
#################################################
    
class Graph:
    """
    Graph that represents a gadget and his data dependency  
        (self.nodes) - Dictionary of nodes, keys are the SSAReg or representations or the string "MEM"
        (self.lastMod) - Dictionnary. Keys are integers ( that represent registers, like R0, R1, R2, ... ).
                Values are integers. lastMod[2] = 3 means that so far, R2 have been modified 3 times exactly in the gadget 
        (self.countCondJmps) - (int) Counter of the number of branching instructions met in the gadget 
        (self.condJmps) - List of conditions. condJmps[i] is the condition that must be TRUE for the jmp i to be taken 
        (self.condPath) - List of conditions. condPath[i] is the condition that must be TRUE so that all the jmps befoe jmp i haven't been taken  
    """
    def __init__(self):
        self.nodes = {}
        self.lastMod = {} # LastMod contains the number of times a register has been modified ( i.e undergone an assignement )
        # Information to conditional jumps handling when depedency computation 
        self.countCondJmps = 0 # Number of conditional jumps encountered in the gadget so far
        self.condJmps = [CTrue()]
        self.condPath = [CTrue()]
        
    def __str__(self):
        res = ''
        for n in self.nodes.keys():
            res += str(self.nodes[n])+'\n'
        return res 
    
    def regBeforeLastJmp(self, reg, jmpLvl):
        """
        Returns the SSA occurence of the register 'reg' that corresponds to
        it's value just before the jump number 'jmpLvl' was taken 
        
        Parameters:
            (reg) (SSAReg) The register 'after last jump'
            (jmpLvl) (int) The jump level we want to go before 
        """
        ind = reg.ind
        num = reg.num
        while( ind != 0 and self.nodes[SSAReg(num, ind)].jmpLvl >= jmpLvl ):
            ind -= 1
        return SSAReg(num ,ind)
        
    def getReg( self, regStr):
        """
        Given a register name ( eax, edx, ... ) this function translates it into a generic R0_ R1_ ...
        This is meant to return the current state of a register under the form of a SSA register, 
        by checking into the regCount dictionnary. If eax ( whose id is 2 for example ) have been 
        modified 2 times, then the current value of eax will be _getReg("eax") = SSAReg(2,2)
        
        If the register had never occured before, either in the gadget, or during the whole analysis, 
        then it's ID is created and added to the regNumToName. 
        If the argument does not depict a full register the translation of the full register is returned
        ---> e.g _getReg("AH") -> _getReg("RAX") -> R3
        Parameters :
            regStr - (str) The string of the register we want to get 
        """
        # We first find the corresponding full register ( like AH ---> RAX )
        aliasMapper = Arch.currentArch.archInfo.alias_mapper
        if( aliasMapper.get(regStr) != None ):
            if( aliasMapper[regStr][0] != "rflags" and aliasMapper[regStr][0] != "eflags" ):
                fullReg = aliasMapper[regStr] # Couple (reg, offset)
                regStr = fullReg[0]
        
        # If first occurence of this register in analysis : we translate it in the table 
        if( Arch.regNameToNum.get(regStr) is None ):
            Arch.regNameToNum[regStr] = Arch.ssaRegCount # Create a new SSA register 
            Arch.regNumToName[Arch.ssaRegCount] = regStr
            self.lastMod[Arch.ssaRegCount] = 0
            reg = SSAReg( Arch.ssaRegCount, 0 )
            regExpr = SSAExpr( reg )
            Arch.ssaRegCount += 1
            # Create basic node
            node = SSANode( reg, regExpr, jmpLvl=0)
            self.nodes[reg] = node
        # Else if register already have an ID 
        else:
            regNum = Arch.n2r(regStr)
            # First occurence in this gadget -> ind set to 0 and node created 
            if( self.lastMod.get(regNum) is None ):
                reg = SSAReg( Arch.regNameToNum[regStr], 0 )
                self.lastMod[reg.num] = 0
                # Create basic node
                node = SSANode( reg, SSAExpr( reg ), jmpLvl=0)
                self.nodes[reg] = node 
            else:
                reg = SSAReg( regNum, self.lastMod[regNum])
                if( self.nodes.get(reg) is None ):
                    self.nodes[reg] = SSANode( reg, SSAExpr( reg ))        
        # Returning corresponding expression
        return reg
    
#####################################
# GRAPH COMPONENTS (Arcs and Nodes) #
#####################################

class Arc:
    """ 
    Models an arc of a graph. The arc is defined by only the node it is directed towards.
    The arc can be labeled with an arithmetic/logical expression using constants, registers, and usual operators on registers 
    The arc can be given a number ( used for arcs bounded to the Memory Node )     
    /!\ However, labeling and numbering are not necessary
    
        (self.num) : (int) If destNode = MEM then num is the time of the memory access -> 0 is first access, 1 is the second...
        (self.label) : (Expr) interpretation depends on context. If bounded to a memory node, label is the address at whom memory is accessed 
        (self.size) : (int) The size read in memory if the node is directed towards the MEM node 
        (self.dest) : (Node) The node towards which the arc is directed 
        (self.jmpLvl) : (int) Used internaly for dependency computation when conditionnal branch instructions occur 
    """
    
    def __init__(self, graph, destNode, num = -1, label = None, size = None):
        self.dest = destNode
        self.num = num
        self.label = label
        self.size = size
        self.jmpLvl = graph.countCondJmps
        
    def __cmp__(self, other):
        return self.num - other.num

class Node:
    """
    General class representing the node of a graph. 
        (self.outgoingArcs) : Array(Arc) contains all the arcs that are outgoing of the node.
        (self.jmpLvl): Int, used to handle conditionnal jumps in a gadget 
    """
    def __init__(self, jmpLvl=None):
        self.outgoingArcs = []
        self.jmpLvl = jmpLvl

class ConstNode(Node):
    """
    Node modeling a constant value
        (self.value) is the constant
    """
    def __init__(self, value, size):
        """
        value : (int)
        size : (in) size in the memory in bits 
        """
        self.value = value
        self.size = size
        self.name = "Const:"+str(value)
    
    def __str__(self):
        return '\nConstNode: {}\n----------------\n'.format(self.value)    
    
    def getSemantics( self ):
        return [SPair(ConstExpr( self.value, self.size ),CTrue())]

class SSANode(Node):
    """
    Node that represents a register in SSA form 
        (self.reg) - (SSAReg) register modeled
        (self.expr) - (Expr) if the register is not 'basic' i.e ind != 0, then \
                        self.expr stores the expression that have been assigned to \
                        the register ( e.g self.expr = Add32( R1_0, R3_4 ) ) 
    """
    def __init__(self, reg, expr, jmpLvl=0):
        Node.__init__(self, jmpLvl=jmpLvl)
        self.reg = SSAReg(reg.num, reg.ind)
        self.expr = expr
        self.name = str(reg)
    
    def __str__(self):
        res = "\nNode {}\n".format(self.name)
        res += '-----------\n\n'
        res += '\tExpression: {}\n'.format(self.expr)
        res += '\tDepends from:\n'
        for a in self.outgoingArcs:
            res += '\t'+a.dest.name+'\n'
        return res 
    
    def getSemantics( self,  semantics, graph):
        """
        Computes semantics for this register, and store them into 'semantics'
        'graph' is the graph to which the node belongs 
        Return the semantics list (list of SPair)
        """
        # If semantics already calculated 
        if( semantics.get(self.reg) != None ):
            return semantics.get(self.reg)
                 
        # Else we compute it :
        # If ind is 0 then we reached a leaf of the graph because it's the initial value of the register 
        if( self.reg.ind == 0 ):
            res = [SPair(SSAExpr(self.reg), CTrue())]
            semantics.set(self.reg, res)
            return res
        # TODO -> check the below bug 
        # Else we test if bad node 
        # -> this is an un-understandable but harmless bug, additionnal empty nodes are added to the graph 
        # don't know why they are created yet .... :/     
        if( len(self.outgoingArcs) == 0 and isinstance( self.expr, SSAExpr ) and self.reg == self.expr.reg):
            return []
        # Here we know there are dependencies to compute, so we continue to explore the graph
        
        # We take into account the potential previous conditional jmps 
        resCond = graph.condPath[self.jmpLvl]
        resExpr = self.expr
        # TODO --> what ???
        # WARNING : we suppose that each node has only one or no arc towards MEM, not more !
        resPrec = [SPair(self.expr, resCond)]
        # For each arc, we replace step by step the expressions       
        for a in self.outgoingArcs:
            res = []
            # For each arc we get a list replacement value and the condition
            if( isinstance( a.dest, MEMNode )):
                subpairs = a.dest.getSemantics( a.num, a.label, a.size, gadgetDep )
            else:
                subpairs = a.dest.getSemantics( semantics, graph )
            for pair in subpairs:
                if ( isinstance( a.dest, MEMNode )):
                    res += [SPair(p.expr.replaceMemAcc(a.label, pair.expr), Cond(CT.AND, p.cond,pair.cond)) for p in resPrec ]
                elif( isinstance( a.dest, ITENode )):
                    res += [SPair(p.expr.replaceITE(pair.expr), Cond(CT.AND, p.cond,pair.cond)) for p in resPrec ] 
                else:
                    res += [SPair(p.expr.replaceReg( a.dest.reg, pair.expr ), Cond(CT.AND, p.cond,pair.cond)) for p in resPrec ]
            resPrec = res
                
        if( len(res) == 0 ):
            res = [SPair(self.expr, resCond)]
        
        # Taking into account the potential conditionnal jumps     
        # We add the case when the jump had not been taken 
        if( self.jmpLvl > 0 ):
            pairs = graph.nodes[graph.regBeforeLastJmp(self.reg, self.jmpLvl)].getSemantics( semantics, graph )
            for p in pairs:
                res.append( [p.expr, Cond(CT.AND, p.cond, graph.condJmps[self.jmpLvl])]) 

        semantics.set(self.reg, res)
        return res

class ITENode(Node):
    """
    ITENode : Node that represents an IF THEN ELSE statement.....
        (self.cond) - (Cond) is the condition of the IF statement 
        (self.outgoingArcs) - (List(Arc)) is the arcs of dependency when cond is evaluated to TRUE
        (self.outgoingArcsFalse) - (List(Arc)) is the arcs when cond is computed to FALSE 
        (self.iftrue) - (Expr) is the value if cond is evaluated to True
        (self.iffalse) - (Expr) is the value if cond is evaluated to False
    """
    def __init__(self, cond, iftrue, iffalse):
        Node.__init__(self)
        self.outgoingArcsCond = [] 
        self.cond = cond
        self.iftrue = iftrue
        self.iffalse = iffalse
        self.name = "ITENode"
        
    def __str__(self):
        res = '\nITENode\n'
        res += '-----------\n\n'
        res += '\tCond: {}\n'.format(self.cond)
        res += '\tIf True: {}\n'.format(self.iftrue)
        res += '\tIf False: {}\n'.format(self.iffalse)
        return res 
        
    def getDependencies(self, semantics, graph ):
        resPrec = [[self.iftrue, self.cond]]
        # We first compute when the condition is TRUE :
        # For each arc, we replace step by step the expressions 
        for a in self.outgoingArcs:
            resTrue = []
            # For each arc we get a list replacement value and the condition
            if( isinstance( a.dest, MEMNode )):
                subpairs = a.dest.getSemantics( a.num, a.label, a.size, gadgetDep )
            else:
                subpairs = a.dest.getSemantics( semantics, graph )
            for pair in subpairs:
                if ( isinstance( a.dest, MEMNode )):
                    resTrue += [[p.expr.replaceMemAcc(a.label, pair.expr), Cond(CT.AND, p.expr,pair.cond)] for p in resPrec]
                else:
                    resTrue += [[p.expr.replaceReg( a.dest.reg, pair.expr ), Cond(CT.AND, p.cond,pair.cond)] for p in resPrec ]
            resPrec = resTrue

        res = resPrec
        resPrec = [[self.iffalse, self.cond.invert()]]
        # Then the case when the condition is FALSE
        # For each arc, we replace step by step the expressions 
        for a in self.outgoingArcsFalse:
            resFalse = []
            # For each arc we get a list replacement value and the condition
            if( isinstance( a.dest, MEMNode )):
                subpairs = a.dest.getDependedsdsncies(  a.num, a.label, a.size, gadgetDep )
            else:
                subpairs = a.dest.getSemantics( semantics, graph )
            for pair in subpairs:
                if ( isinstance( a.dest, MEMNode )):
                    resFalse += [[p.expr.replaceMemAcc(a.label, pair.expr), Cond(CT.AND, p.cond,pair.cond)] for p in resPrec]
                else:
                    resFalse += [[p.expr.replaceReg( a.dest.reg, pair.expr ), Cond(CT.AND, p.cond,pair.cond)] for p in resPrec]
            resPrec = resFalse
        res +=  resPrec
        return res

class MEMNode(Node):
    """
    Node that represents the whole memory
        (self.storedValues) - Dictionnary( Keys are integer, Values are Expressions ) 
                    stores the expression stored in memory
                    storedValues[i] = expression stored by the arc number i access   
    
    """
    def __init__(self):
        Node.__init__(self)
        self.storedValues = {}
        self.name = "MEMNode"
    
    def __str__(self):
        res = '\nMemory semantics\n'
        res += '----------------\n\n'
        for addr in sorted(self.storedValues.keys()):
            res += "\tmem[{}] <- {}\n".format(addr, self.storedValues[addr])
        return res 
    
    def compatibleAccesses( self, dict1, dict2 ):
        """
        Checks if the two dictionnaries of a case memoire dependencies are compatible or not 
        Dictionnaries are organised this way : 
            - keys are strings representing expressions (like R0_2 + 0x8) 
            - the values are either : 
                - integers : this is an offset in bytes. It models the constaint " key == value " 
                - couples ( low, high ) : this is an intervalle, the expresion must not be within ( strictly ) ( out constraint ). It models a constraint like " key doesn't belong to interval [low,high] " 
            This helps to check for optimisations by detecting some incompatible conditions 
        The same expression can occur in dict1 and dict2 but give different constraints, this function determines if those are compatible or not. E.g : R0_2 == 0x6   and R0_2 included in  [0x8 .. 0xff] are not compatible ;) 
        """
        for k1 in dict1.keys():
            v2 = dict2.get(k1)
            v1 = dict1[k1]
            if( v2 != None ):
                # if value is an integer then constraint is type : value == offset
                # if it is a couple, then this is an out constraint and the couple is ( caseNum, storeLen )
                #   in this case the value MUST be STRICTLY outside [ caseNum-storeLen+1, caseNum]
                if( isinstance( v2, int)):
                    if( isinstance( v1, int )):
                        if( v1 != v2 ):
                            return False
                    else:
                        low = v1[0]
                        high = v1[1]
                        if( v2 <= high and v2 >= low ):
                            return False
                else:
                    if( isinstance( v1, int )):
                        low = v2[0]
                        high = v2[1]
                        if( v1 <= high and v1 >= low ):
                            return False
                    else:
                        # If both out, condition can always be verified 
                        pass 
        return True
        
    def dictFusion( self, dict1, dict2 ):
        """
        Returns a new dictionnary that fusions the constraints of the two parameters 
        Precondition : dict1 and dict2 hold compatible consraints ( see compatibleAccesses() function )
        """
        newDict = {}
        for k1 in dict1.keys():
            v1 = dict1[k1]
            v2 = dict2.get(k1)
            if( v2 == None ):
                newDict[k1] = dict1[k1]
            elif( not isinstance( v2, int )):
                if( isinstance( v1, int )):
                    newDict[k1] = v1
                else:
                    # We choose the broadest !!! TODO ( this is some hack )
                    if( v1[1] > v2[1]):
                        newDict[k1] = v1
                    else:
                        newDict[k1] = v2
            else:
                newDict[k1] = v2
        return newDict
    
    def filterOffset(self, offset, storeLen, readLen ):
        """
        This function is used to select only relevant memory accesses when computing dependencies, given the number of bytes read, the numbers of bytes writen by a previous memory access, and the offset between the read and write addresses 
        The function returns "True" iff this write case should be taken into account for dependency computation 
        This helps reducing the combinaisons and possibilities, thus fastening the execution 
        Parameters :
            (readLen) (int) is the size of memory read
            (storeLen) (int) is the size of a memory write than can affect the read
            (offset) (int) is the difference between the address of the write and the address of the read
        """
        return (offset == 0)
        
    
    def overWrite( self, offset, val, prev ):
        """
        Simulate a write of a value 'val' over a previous value 'prev'
        /!\ The offset parameter is in bytes, and must be in the valid range for an overwrite of at least 1 byte  
        /!\ Works only for little endian arch 
        """
        offset = offset*8
        if( val.size == prev.size ):
            if( offset == 0 ):
                res = val 
            elif( offset < 0 ):
                res = Cat( [Extr( prev.size-1, val.size-offset, prev), Extr( val.size-1,-1*offset, val)])
            else:
                res = Cat( [Extr( prev.size-1-offset, offset, val ), Extr( offset-1, 0, prev )])
        elif( val.size < prev.size ):
            if( val.size + offset >= prev.size ):
                res = Cat( [Extr( prev.size-1-offset, 0, val ), Extr( offset-1, 0, prev )])
            elif( offset > 0 ):
                res = Cat( [Extr( prev.size-1, offset+val.size, prev ), val, Extr(offset-1, 0, prev )])
            else:
                res = Cat( [Extr( prev.size-1, offset+val.size, prev ), Extr( val.size-1, -1*offset, val )])
        else:
            if( offset > 0 ):
                res = Cat( [Extr( prev.size-1-offset, 0, val ), Extr( offset-1, 0, prev )])
            elif( offset >= prev.size-val.size):
                res = Extr( offset+prev.size-1, offset, val )
            else:
                res =  Cat( [Extr( prev.size-1, offset+val.size, prev ), Extr( val.size-1, -1*offset )])
        offset = offset/8 
        if( res.size % 8 != 0 ):
            raise GraphException("Error, overWrite() function returning a value not multiple of 8 ( size = %d )", res.size)
        return res     
    
    
    def getSemantics( self, num, addr, size, semantics, graph ):
        """
        Extract dependencies from memory at a certain time 
        Parameters:
            (num) (int) The number of the arc in the graph that represents the load operation 
            (addr) (Expr) The address at which memory is read 
            (size) (int) The size in bits of the read
            (semantics) (Semantics) The structure used to compute dependencies 
            (graph) (Graph) The graph containing the MEMNode
        """
        res = []
        tmp = num
        readLenBytes = size / 8 
        addrID = -1 # Used to optimise combinations without calling the solver...
        addrKey = str(addr.simplify())
        readDict = {addrKey:0} # Basic constraint for optimisation 
        resTmp = [[MEMExpr(addr, size), CTrue(), readDict]]
        tmpCond = None
        # For each outgoing arc, i.e for each memory write  
        for a in sorted( self.outgoingArcs, reverse=False):
            writeKey = str(a.label.simplify()) # key for the store address for optimisation 
            # If a.num > num, then we have checked all memory writes 
            # before the read we stop there
            if( a.num >= num ):
                break
            # Get the semantics for the register written in memory 
            pairs = a.dest.getSemantics( semantics, graph )
            # We adjust the semantics in case we stored an expression 
            # and not only a register or constant 
            if( isinstance(a.dest, SSANode)):
                pairs = [SPair(self.storedValues[a.num].replaceReg(a.dest.reg, p.expr), p.cond) for p in pairs ]    
            
            # Handle previous conditional jumps 
            if( tmpCond is None ):
                # If first memory access, then we get the condPath for the 
                # adequate level (condition that must be true so that we 
                # haven't jumped out from the gadget) 
                tmpCond = graph.condPath[a.jmpLvl]
            else:
                # Else we only add the condJump corresponding to this level 
                tmpCond = Cond( CT.AND, tmpCond, graph.condJmps[a.jmpLvl].invert() )
            storeLenBytes = a.size / 8 # Number of bytes written by this arc 
            # For each possibility, we update the resTmp into some new list of SPairs
            # We deal with memory so we model memory overwritting ;) 
            # A store operation might overwriting previous memory contents 
            newResTmp = []
            # For each case, update possibilities 
            for prev in resTmp:
                # For each dependency of the register written in memory 
                for p in pairs:
                    # We consider every possibility of memory overwrite ( offset between the read and write ). Some could modify 1 byte, others 2 bytes, etc... 
                    for offset in range( 1-storeLen, readLen-1  ):
                        writeAddr = OpExpr( Op.ADD, [addr, ConstExpr( offset, addr.size )])
                        newDict = {optWriteKey:offset}
                        if( self.compatibleAccesses( prev[2], newDict ) and self.filterOffset( offset, storeLenBytes, readLenBytes )):
                            newValue = self.overWrite( offset, p.expr, prev[0] )
                            addrCond = Cond( CT.EQUAL, a.label, writeAddr )
                            newCond = Cond( CT.AND, Cond(CT.AND, prev[1], addrCond ), d.cond )
                            newResTmp.append( [newValue, newCond, self.dictFusion(newDict, prev[2])])
            # We keep the previous ones if the store is made out of the bounds of the read 
            higher = OpExpr( Op.ADD, [addr, ConstExpr(readLenBytes, addr.size)] )
            lower = OpExpr( Op.SUB, [addr, ConstExpr( storeLenBytes, addr.size )])
            outCond = Cond( CT.OR, Cond( CT.GE, a.label, higher ), Cond( CT.LE, a.label, lower ))
            newDict = {optWriteKey:[1-storeLenBytes, readLenBytes-1]}
            for prev in resTmp:
                if( self.compatibleAccesses( prev[2], newDict )):
                    newResTmp.append( [prev[0], Cond( CT.AND, outCond, prev[1]), self.dictFusion(newDict, prev[2])] )
            # give resTmp its new value 
            resTmp = newResTmp
        # Extract only the values and conditions 
        res = [[d[0], d[1]] for d in resTmp]
        return res

# TODO getMemSemantics ;) 



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
    if( Arch.currentArch.archInfo.alias_mapper.get(regStr) != None ):
        return Arch.currentArch.archInfo.alias_mapper.get(regStr)
    else:
        raise GraphException("BARF does not handle register %s for computation"%regStr)

def isCalculationInstr( mnemonic ):
    return mnemonic > 0 and mnemonic < 10
    
def isLoadInstr( mnemonic ):
    return mnemonic == ReilMnemonic.LDM
    
def isStoreInstr( mnemonic ):
    return mnemonic == ReilMnemonic.STM
    
def isPutInstr( mnemonic ):
    return mnemonic == ReilMnemonic.STR 

def barfOperandToExpr(op, valuesTable, graph):
    """
    Translate a barf operand into an expression (Expr from Expr.py)
    Parameters :
        op - (ReilOperand) should be either an immediate or a register
        valuesTable - (Dict) the valuesTable used by the REILtoGraph function 
        graph - (Graph) The graph we are working with 
    """
    if( isinstance( op, ReilImmediateOperand )):
        res = ConstExpr( op._immediate, op.size )
        return res 
    elif( isinstance( op, ReilRegisterOperand )):
        if( op._name[0] == "t" ):
            res = valuesTable[op._name]
            if( op.size == res.size ):
                return res
            else:
                return Convert(op.size, res)
        else:
            fullExpr = SSAExpr(graph.getReg(op._name))
            if( op.size == Arch.currentArch.bits ):
                return fullExpr
            else:
                (reg, offset) = barfGetAlias( op._name )
                if( reg == "rflags" or reg == "eflags"):
                    return Convert( op.size, fullExpr )
                else:
                    return Extr( op.size + offset -1, offset, fullExpr )
    else:
        raise GraphException("Operand %s neither register nor immediate", str(op))

def barfCalculationToExpr( mnemonic, op1, op2, size, valuesTable, graph):
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
        res = OpExpr( Op.ADD, [barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    elif( mnemonic == ReilMnemonic.SUB ):
        res= OpExpr( Op.SUB, [barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    elif( mnemonic == ReilMnemonic.MUL ):
        res = OpExpr( Op.MUL, [barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    elif( mnemonic == ReilMnemonic.BSH ):    
        # Binary shift needs custom size adjustement 
        left = barfOperandToExpr(op1, valuesTable, graph)
        if( left.size == size ):
            return OpExpr( Op.BSH, [left , barfOperandToExpr( op2, valuesTable, graph )])
        else:
            return OpExpr( Op.BSH, [Convert(size, left ),  Convert( size, barfOperandToExpr( op2, valuesTable, graph ))])
    elif( mnemonic == ReilMnemonic.AND ):
        res = OpExpr( Op.AND, [barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    elif( mnemonic == ReilMnemonic.OR ):
        res = OpExpr( Op.OR,[ barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    elif( mnemonic == ReilMnemonic.XOR ):
        res = OpExpr( Op.XOR, [barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    elif( mnemonic == ReilMnemonic.MOD ):
        res = OpExpr( Op.MOD , [barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    elif( mnemonic == ReilMnemonic.DIV ):
        res = OpExpr( Op.DIV , [barfOperandToExpr( op1, valuesTable, graph ), barfOperandToExpr( op2, valuesTable, graph )])
    else:
        raise GadgetException("Operation %s not supported yet "% ReilMnemonic.to_string(mnemonic))
    # Size adjustements 
    if( res.size != size ):
        res = Convert( size, res )
    return res
    
    
def barfLoadToExpr( addr, size, valuesTable, graph):
    """
    Translates a memory load into expression ( Expr in Expr.py )
    Parameters :
        addr - (ReilOperand) The address where memory is read
        size - number of bits read 
    """
    if( addr.size != Arch.currentArch.bits ):
        raise GadgetException("Addressing expression of size {} is\
         incompatible with registers of size {} in {} architecture".\
         format(addr.size, Arch.currentArch.bits, Arch.currentArch.name))
    return MEMExpr( barfOperandToExpr( addr, valuesTable, graph ), size ) 
    
def translateFullRegAssignement( expr, op , graph):
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
    if( expr.size == Arch.currentArch.bits ):
        return expr
    
    if( op._name in Arch.currentArch.archInfo.alias_mapper ):
        (reg, offset) = Arch.currentArch.archInfo.alias_mapper[op._name]
    else:
        reg = op._name 
        offset = 0 
    # Special treatement for the flags registers 
    if(reg == "rflags" or reg == "eflags"):
        return Convert( Arch.currentArch.bits, expr)
    # If normal registers, we translate :
    else:
        oldReg = SSAExpr(graph.getReg(op.name))
        high = Extr( oldReg.size-1, offset+expr.size, oldReg )
        if( offset > 0 ):
            return Concat( [high, expr, Extract( offset-1, 0, oldReg )] )
        else:
            return Concat( [high, expr, low] )

    
#######################################
# REIL TO GRAPH TRANSLATION FUNCTIONS #
#######################################
    

def REILtoGraph( irsb):
    """
    irsb - REIL instructions 
    """
    # (1) Initialisations...
    valuesTable = {} # Keys are whatever, Values are Expr 
    graph = Graph() # Empty graph
    graph.nodes["MEM"] = MEMNode()
    # Update the index counts and nodes for registers that already have a translation into generic IR 
    # for reg in Analysis.regNamesTable.values():
        # self.regCount[reg] = 0
        # node = SSANode( SSAReg(reg,0), SSAExpr( SSAReg(reg,0)))
        # self.graph.nodes["R%d_0"%reg] = node
    # graph.nodes["MEM"] = MEMNode()
    memAccCount = 0    # Hold the number of the next arc incoming/outgoing to/from the memory node

    # (2) Graph construction...
    # Iterate through all reill instructions : 
    for i in range(0, len(irsb)) :
        instr = irsb[i]
        # Translating different types of instructions
        if( instr.mnemonic == ReilMnemonic.NOP ):
            pass
        # Basic operations ( ADD, SUB, MUL, etc )
        elif( isCalculationInstr(instr.mnemonic)):
            # Temporary value
            if(  instr.operands[2]._name[0] == "t" ):
                expr = barfCalculationToExpr( instr.mnemonic, instr.operands[0], \
                instr.operands[1], instr.operands[2].size, valuesTable, graph )
                valuesTable[instr.operands[2]._name] = expr
            # Actual Register 
            else:
                expr = barfCalculationToExpr( instr.mnemonic, instr.operands[0],\
                 instr.operands[1], instr.operands[2].size, valuesTable, graph )
                reg = graph.getReg( instr.operands[2]._name )
                expr = translateFullRegAssignement( expr, instr.operands[2], graph )
                valuesTable[str(reg)] = expr
                # Adding the node 
                reg = SSAReg(reg.num, reg.ind + 1 )
                graph.lastMod[reg.num] += 1
                node = SSANode( reg, expr )
                # Adding arcs toward other nodes and memory 
                for subReg in expr.getRegisters():
                    # subReg is a SSAReg on which node depends
                    node.outgoingArcs.append( Arc(graph, graph.nodes[subReg] ))
                for mem in expr.getMemAcc():
                    addr = mem[0]
                    size = mem[1]
                    node.outgoingArcs.append( Arc(graph, graph.nodes["MEM"], memAccCount, addr, size ))
                    memAccCount += 1
                graph.nodes[reg] = node

        # Memory load instruction 
        elif( isLoadInstr(instr.mnemonic)):
            expr = barfLoadToExpr( instr.operands[0], instr.operands[2].size, valuesTable, graph  )
            if( instr.operands[2]._name[0] == "t" ):
                valuesTable[instr.operands[2]._name] = expr
            else:
                reg = graph.getReg(instr.operands[2]._name)
                expr = translateFullRegAssignement( expr, instr.operands[2], graph )
                reg = SSAReg(reg.num, reg.ind + 1 )
                graph.lastMod[reg.num] += 1
                valuesTable[str(reg)] = expr
                # Adding node towards memory
                node = SSANode( reg, expr )
                for mem in expr.getMemAcc():
                    addr = mem[0]
                    size = mem[1]
                    node.outgoingArcs.append( Arc(graph, graph.nodes["MEM"], memAccCount, addr, size ) )
                    memAccCount += 1
                graph.nodes[reg] = node
        
        # Memory store instruction         
        elif( isStoreInstr( instr.mnemonic )):
            expr = barfOperandToExpr( instr.operands[0], valuesTable, graph )
            addr = barfOperandToExpr( instr.operands[2], valuesTable, graph )
            if( isinstance(expr, ConstExpr)):
                node = ConstNode(expr.value, expr.size)
                graph.nodes["MEM"].outgoingArcs.append( Arc( graph, node, memAccCount, addr, expr.size ))
            elif( not expr.getRegisters()):
                raise GraphException("Expression is neither ConstExpr nor\
                 has registers and should be written in memory ? - not yet supported!") 
            else:
                graph.nodes["MEM"].outgoingArcs.append( Arc( graph,graph.nodes[expr.getRegisters()[0]], \
                memAccCount, addr, expr.size ))
            graph.nodes["MEM"].storedValues[memAccCount] = expr
            memAccCount += 1 
        
        # Transfer value into register         
        elif( isPutInstr( instr.mnemonic )):
            if( instr.operands[2]._name[0] == "t" ):
                expr = barfOperandToExpr( instr.operands[0], valuesTable, graph )
                if( instr.operands[2].size != expr.size ):
                    expr = Convert( instr.operands[2].size, expr )
                valuesTable[instr.operands[2]._name] = expr
            else:    
                reg = graph.getReg( instr.operands[2]._name )
                expr = barfOperandToExpr( instr.operands[0], valuesTable, graph )
                if( instr.operands[0].size < instr.operands[2].size ):
                    expr = translateFullRegAssignement( expr, instr.operands[2], graph )
                else:
                    expr = Convert(instr.operands[2].size, expr)
                if( instr.operands[2].size != Arch.currentArch.bits ):
                    expr = translateFullRegAssignement( expr, instr.operands[2], graph )
                subRegs = expr.getRegisters()
                subMems = expr.getMemAcc()
                
                # Adding node and arcs to the graph
                reg = SSAReg( reg.num, reg.ind + 1 )
                node = SSANode( reg, expr )
                for r in subRegs:
                    node.outgoingArcs.append( Arc( graph, graph.nodes[r]))
                for mem in subMems:
                    addr = mem[0]
                    size = mem[1]
                    node.outgoingArcs.append( Arc( graph, graph.nodes["MEM"], memAccCount, addr, size ))
                    memAccCount += 1
                graph.nodes[reg] = node
                graph.lastMod[reg.num] += 1
                valuesTable[str(reg)] = expr
    
        # Boolean IS Zero instrution 
        # BISZ( a, b ) has the following effects :
        #    b <- 1 if a == 0
        #    b <- 0 if a != 0 
        elif( instr.mnemonic == ReilMnemonic.BISZ ):
            zero = ConstExpr(0, instr.operands[0].size)
            ifzero = ConstExpr(1, instr.operands[2].size )
            ifnotzero = ConstExpr(0,instr.operands[2].size )
            testedValue = barfOperandToExpr(instr.operands[0], valuesTable, graph)
            # If operands[0] == 0 then the value assigned to operands[2] is 1. 
            # If operands[0] != 0 then operands[2] becomes 0 
            cond = Cond( CT.EQUAL, testedValue, zero )
            expr = ITE( cond, ifzero, ifnotzero )
            if( instr.operands[2]._name[0] == "t" ):
                valuesTable[instr.operands[2]._name] = expr
            else:
                reg = graph.getReg( instr.operands[2]._name )
                reg.ind += 1
                graph.lastMod[reg.num] += 1
                valuesTable[str(reg)] = expr
                # Adding node to the graph 
                # Creation of the ite node
                iteNode = ITENode( cond, ifzero, ifnotzero )
                # Link the real node to the ITE node 
                node = SSANode( reg, Convert( REGSIZE.size, expr))
                node.outgoingArcs.append( Arc(graph, iteNode) )
                graph.nodes[reg] = node

        # Conditionnal jump
        elif( instr.mnemonic == ReilMnemonic.JCC ):
            # Determine the address where to jmp
            # If jmp to a fixed location 
            if( isinstance( instr.operands[2], ReilImmediateOperand ) and instr.operands[2].size != 40 and instr.operands[2].size != 72 ):
                addr = ConstExpr(instr.operands[2].immediate)
                addr.size = Arch.currentArch.bits
            # If it is a pointer 
            elif( instr.operands[2].size == 40 or instr.operands[2].size == 72 ):
                #We test if the value is less than 0x100
                # If yes, then we ignore the condition because unable to compute dependencies 
                # This kind of small values depict an instruction simulated in many basic blocks
                # We do not handle conditions for the Instr Pointer INSIDE a gadget 
                #if( isinstance(instr.operands[2], ReilImmediateOperand ) and (instr.operands[2].immediate>>8) - addr < 0x1 ):
                    #raise GraphException("REIL instruction(s) too complicated to emulate in gadget:\n" + self.asmStr )
                # We also test if there is a jump inside the bounds of the gadget
                # For now those are also not supported 
                # Sadly, this also suppresses some conditional conditions  
                #if( isinstance( instr.operands[2], ReilImmediateOperand ) and (instr.operands[2].immediate>>8) - addr < (len(self.hexStr)/4) ):
                    
                    #raise GraphException("Jumps inside the gadget are not handled yet in gadget:\n" + self.asmStr)
                # Get the real return/jump address with an 8 bit SHR
                expr = barfOperandToExpr(instr.operands[2], valuesTable, graph)
                addr = Extract( expr.size-1, 8, expr )
            else:
                addr = barfOperandToExpr( instr.operands[2], valuesTable, graph )
            ip = graph.getReg(Arch.currentArch.ip) # Get the instruction pointer         
            ip = SSAReg(ip.num, ip.ind+1)
            # Quick check if simple 'ret' so the expression is easier to read
            # A jump is always taken if first argument is a constant != 0 
            if( isinstance( instr.operands[0], ReilImmediateOperand ) and instr.operands[0].immediate != 0 ):
                valuesTable[str(ip)] = addr
                expr = addr
                node = SSANode( ip, Convert(Arch.currentArch.bits, addr))
                for r in addr.getRegisters(ignoreMemAcc=True):
                    node.outgoingArcs.append( Arc( graph, graph.nodes[r]))
                for mem in addr.getMemAcc():
                    address = mem[0]
                    size = mem[1]
                    node.outgoingArcs.append( Arc( graph, graph.nodes["MEM"], memAccCount, address, size))
                    memAccCount += 1
                graph.lastMod[ip.num] += 1 
                graph.nodes[ip] = node
            # Else processing conditional jump 
            else:
                # Create node and stuff
                reg = ip
                zero = ConstExpr(0,instr.operands[0].size )
                cond = Cond(CT.NOTEQUAL, barfOperandToExpr(instr.operands[0], valuesTable, graph) , zero) 
                # Update the info about conditional jumps in Graph.py module 
                graph.condJmps.append( cond )
                graph.condPath.append( Cond( CT.AND, cond.invert(), graph.condPath[graph.countCondJmps]))
                # TODO : this seems not to put the good address into nextInstrAddr ??? 
                nextInstrAddr = ConstExpr(irsb[i+1].address >> 8, Arch.currentArch.bits) 
                # 1 - FIRST STEP : ITE Node to say : IP takes new value OR stays the same
                expr = ITE(cond, addr, ConstExpr(instr.address >> 8, Arch.currentArch.bits))
                valuesTable[str(reg)] = expr
                # Adding node to the graph 
                # Creation of the ite node
                # We consider that either the jump is taken ( to addr )
                #   or the value stays the one of the current instruction ( instr.address >> 8 )
                iteNode = ITENode( cond, addr, ConstExpr(instr.address >> 8, Arch.currentArch.bits) )
                for r in addr.getRegisters():
                    iteNode.outgoingArcs.append( Arc( graph, graph.nodes[r] ))
                for mem in addr.getMemAcc():
                    address = mem[0]
                    size = mem[1]
                    iteNode.outgoingArcs.append( Arc( graph, graph.nodes["MEM"], memAccCount, address, size))
                    memAccCount += 1
                # Link the real node to the ITE node 
                node = SSANode( reg, expr)
                node.outgoingArcs.append( Arc(graph, iteNode))
                graph.nodes[reg] = node 
                # And do not forget 
                graph.lastMod[reg.num] += 1 
                graph.countCondJmps += 1
                # 2 - SECOND STEP 
                # We update the register again with the address of the next instruction 
                reg = SSAReg( reg.num, reg.ind + 1 )
                node = SSANode( reg, nextInstrAddr)
                graph.nodes[reg] = node
                graph.lastMod[reg.num] += 1
        else:
            raise GraphException("REIL operation {}  not supported"\
                    .format(ReilMnemonic.to_string(instr.mnemonic)))

    return graph 
