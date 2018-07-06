# -*- coding: utf-8 -*- 
# Graph module: implements graph representation of gadgets 
from ropgenerator.Semantics import SPair
from ropgenerator.Expressions import SSAReg
from ropgenerator.Conditions import CTrue, CFalse, Cond, CT

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
    
    def __init__(self, destNode, num = -1, label = None, size = None):
        self.dest = destNode
        self.num = num
        self.label = label
        self.size = size
        self.jmpLvl = CurrentAnalysis.graph.countCondJmps
        
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
    def __init__(self, reg, expr):
        Node.__init__(self)
        self.reg = SSAReg(reg.num, reg.ind)
        self.expr = expr
        
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
	
lass MEMNode(Node):
    """
    Node that represents the whole memory
        (self.storedValues) - Dictionnary( Keys are integer, Values are Expressions ) 
                    stores the expression stored in memory
                    storedValues[i] = expression stored by the arc number i access   
    
    """
    def __init__(self):
        Node.__init__(self)
        self.storedValues = {}
    
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
    
    
    def getDependencies( self, num, addr, size, gadgetDep ):
        """
        Extract dependencies from memory
        Parameters:
            (num) (int) The number of the arc in the graph that represents the load operation 
            (addr) (Expr) The address at which memory is read 
            (size) (int) The size in bits of the read
            (gadgetDep) (GadgetDependencies) The structure used to compute dependencies 
        """
        res = []
        tmp = num
        readLen = size / 8 
        addrID = -1 # Used to optimise combinations without calling the solver...
        addrKey = str(addr.simplify())
        readDict = {addrKey:0} # Basic constraint for optimisation 
        value = MEMExpr( addr, size )
        resTmp = [[MEMExpr(addr, size), CTrue(), readDict]]
        tmpCond = None
        # For each outgoing arc, i.e for each memory write  
        for a in sorted( self.outgoingArcs, reverse=False):
            optWriteKey = str(a.label.simplify()) # key for the store address for optimisation 
            # If a.num > num, then we have checked all memory writes before the read we compute dependencies for 
            if( a.num >= num ):
                break
            # Get the dependencies for the register written in memory 
            dep = a.dest.getDependencies( gadgetDep )
            # We correct the dependencies in case we stored an expression and not only a register or constant 
            if( isinstance(a.dest, SSANode)):
                dep = [[self.storedValues[a.num].replaceReg(a.dest.reg, d[0]), d[1]] for d in dep ]    
            
            
            # Handle previous conditional jumps 
            if( tmpCond is None ):
                # If first memory access, then we get the condPath for the adequate level (condition that must be true so that we haven't jumper out from the gadget) 
                tmpCond = CurrentAnalysis.graph.condPath[a.jmpLvl]
            else:
                # Else we only add the condJump corresponding to this level 
                tmpCond = Cond( CT.AND, tmpCond, CurrentAnalysis.graph.condJmps[a.jmpLvl].invert() )
            storeLen = a.size / 8 # Number of bytes written by this arc 
            # For each dependency, we update the resTmp into some new array of dependencies 
            # This models a store operation overwriting previous memory contents 
            newResTmp = []
            # For each case, update possibilities 
            for prev in resTmp:
                # For each dependency of the register written in memory 
                for d in dep:
                    # We consider every possibility of memory overwrite ( offset between the read and write ). Some could modify 1 byte, others 2 bytes, etc... 
                    for offset in range( 1-storeLen, readLen-1  ):
                        writeAddr = Op( "Add", [addr, ConstExpr( offset, addr.size )])
                        newDict = {optWriteKey:offset}
                        if( self.compatibleAccesses( prev[2], newDict ) and self.filterOffset( offset, storeLen, readLen )):
                            newValue = self.overWrite( offset, d[0], prev[0] )
                            addrCond = Cond( CT.EQUAL, a.label, writeAddr )
                            newCond = Cond( CT.AND, Cond(CT.AND, prev[1], addrCond ), d[1] )
                            newResTmp.append( [newValue, newCond, self.dictFusion(newDict, prev[2])])
            # We keep the previous ones if the store is made out of the bounds of the read 
            higher = Op( "Add", [addr, ConstExpr(readLen, addr.size)] )
            lower = Op( "Sub", [addr, ConstExpr( storeLen, addr.size )])
            outCond = Cond( CT.OR, Cond( CT.GE, a.label, higher ), Cond( CT.LE, a.label, lower ))
            newDict = {optWriteKey:[1-storeLen, readLen-1]}
            for prev in resTmp:
                if( self.compatibleAccesses( prev[2], newDict )):
                    newResTmp.append( [prev[0], Cond( CT.AND, outCond, prev[1]), self.dictFusion(newDict, prev[2])] )
            # give resTmp its new value 
            resTmp = newResTmp
        # Extract only the values and conditions 
        res = [[d[0], d[1]] for d in resTmp]
        
return res

