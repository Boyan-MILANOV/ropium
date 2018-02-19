# ROPGenerator - Cond.py module 
# Implements the data structure useful for the representation of a gadget using graph theory 
# Provides primitives to extract dependencies from a given graph 

from ropgenerator.Expr import ConstExpr, SSAExpr, MEMExpr, Op, SSAReg, Cat, Extr, Convert, strToReg
from ropgenerator.Cond import Cond, CT, CTrue, CFalse, simplify
from ropgenerator.Analysis import revertRegNamesTable
from ropgenerator.Logs import log

class GraphException( Exception ):
    def __init__(self, msg):
        self.msg = msg 
        log(msg)
    def __str__(self):
        return str(self.msg)
                
###############################################################
# IMPLEMENTATION OF A STRUCTURE THAT STORES DATA DEPENDENCIES #
###############################################################

class GadgetDependencies:
    """
    Stores the dependencies for a gadget/graph 
        (self.regDep) - Dictionnary. Keys are (SSAReg)
                Values are lists of couples ( Expr, Cond). Each couple C models one conditional dependency.
                C[0] is the Expression, C[1] is the condition
        (self.memDep) - Dictionnary. Keys are (Expr) Values are the same than for self.regDep
                memDep[addr] are the dependencies of the memory at address 'addr'       
        (self.simpified) is set to true if self.simplifyConditions() has already been called !        
    """
    def __init__(self):
        self.regDep = {} # Keys are (SSAReg)
        self.memDep = {} # Keys are (Expr) 
        self.simplifiedCond = False
        
    def flattenITE( self ):
        """
        Flattens the If-Then-Else statements in dependencies 
        """
        for reg in self.regDep.keys():
            self.regDep[reg] = [[d[0], d[1].flattenITE()] for d in self.regDep[reg]]

        for addr in self.memDep.keys():
            self.memDep[addr] = [[d[0], d[1].flattenITE()] for d in self.memDep[addr]]


    def simplifyDependencies( self ):
        """
        Simplifies basic operations, conditions... in order to have only basic dependencies 
        A 'basic' dependency is an expression in which SSA Registers have only null indexes ( R?_0 )
        """    
        
        # (1) First compute basic dependencies for registers 
        
        # replaceTable stores the registers that could be replaced by a basic dependency 
        replaceTable = {}
        
        
        
        # For each register get the best basic dep we have
        for reg in CurrentAnalysis.graph.getRegisters():
            # if only one dependency, i.e no other possibility of end-value 
            if( self.regDep.get(reg) != None and len(self.regDep[reg]) == 1 ):
                replaceTable[reg] = self.regDep[reg][0][0]
                self.regDep[reg][0][1] = CTrue()
                
        # Repeated procedure until no register with index > 0 is found 
        stop = False
        while( not stop):
            stop = True
            # I know... the code below is very nasty
            # ---> should at least rename variables 
            # For each register 'reg' we simplifify its dependencies   
            for reg in self.regDep.keys():
                # At the end of the loop, 'newDeps' shall be new dependencies of register 'reg' 
                newDeps = []
                # For each dependency 'dep' of 'reg'
                for dep in self.regDep[reg]:
                    # At the end of the loop, 'newDepDeps' shall be the dependency 'dep' simplified in one or many dependencies 
                    newDepDeps = [[dep[0], dep[1]]] # Here newDepdeps <=> [dep]
                    # We start by simplifying the value
                    # For each register in the expression 
                    for register in dep[0].getRegisters():
                        if( register.ind > 0 ):
                            stop = False
                            # We replace it by its own dependencies 
                            # If 'register' has only one dependency -> direct replacement 
                            if( replaceTable.get(register) != None ):
                                newDepDeps[0][0] = dep[0].replaceReg( register, replaceTable[register] )
                            # Else we go through them and make the replacement 
                            else:
                                tmpDep = []
                                for depdep in self.regDep[register]:
                                    for newDepDep in newDepDeps:
                                        depVal = newDepDep[0].replaceReg( register, depdep[0] )
                                        depCond = Cond( CT.AND, newDepDep[1], depdep[1])
                                        tmpDep.append( [depVal, depCond])
                                newDepDeps = tmpDep    
                    # Then same thing for the condition
                    # !! The only condition of the dependency 'dep' can now have been transformed into several ones depdending on the previous simplification of the value, into list newDepDeps
                    # So we iterate into 'dep' transformed into a list of dependencies 'gDep' ( Generated DEPendencies )
                    newResTruc = []
                    for gDep in newDepDeps:
                        newDepDepsF = [[gDep[0], gDep[1]]]
                        # Same operation than before 
                        for register in gDep[1].getRegisters():
                            if( register.ind > 0 ):
                                stop = False
                                if( replaceTable.get(register) != None ):
                                    newDepDepsF[0][1] = gDep[1].replaceReg( register, replaceTable[register])
                                else:
                                    tmpDep = []
                                    for depdep in self.regDep[register]:
                                        for newDepDep in newDepDepsF:
                                            depVal = newDepDep[0]
                                            depCond = Cond( CT.AND, newDepDep[1].replaceReg(register,depdep[0]) , depdep[1])
                                            tmpDep.append( [depVal, depCond] )
                                    newDepDepsF = tmpDep
                        newResTruc += newDepDepsF
                    newDepDepsF = newResTruc
                            
                    # Adding the simplified 'dep' in the dependency list of 'reg' 
                    newDeps += newDepDepsF
                # The new dependencies of 'reg' are 'newDeps' ;-) 
                self.regDep[reg] = newDeps
        
        # (2) Then basic dependencies for the memory 
        
        for addr, deps in self.memDep.iteritems():
            newMemDep = dict()
            newDepsForAddr = []
            # Compute the basic dependency for the dependency list 
            # First for registers 
            for val, cond in deps:
                # Replace all registers in the value field
                # To get a new list of (val, cond)
                newDepsForVal = [[val, cond]]
                # For each register, we replace in all dependencies 
                for reg in val.getRegisters():
                    # Replace by all the possible values for this register 
                    for regdep in self.regDep[reg]:
                        tmpNewDepsForVal = []
                        # Update the temporary results 
                        for tmpDep in newDepsForVal:
                            tmpNewDepsForVal.append([tmpDep[0].replaceReg( reg, regdep[0] ), Cond(CT.AND, regdep[1], tmpDep[1])])
                        newDepsForVal = tmpNewDepsForVal

                # Replace all registers in condition fields
                newDepsForCond = newDepsForVal
                for reg in cond.getRegisters():
                    for regdep in self.regDep[reg]:
                        tmpNewDepsForCond = []
                        # Update the temporary results
                        for tmpDep in newDepsForCond:
                            tmpNewDepsForCond.append( [tmpDep[0], Cond(CT.AND, regdep[1], tmpDep[1].replaceReg(reg, regdep[0]))])
                        newDepsForCond = tmpNewDepsForCond
                    
                # Update the list of dependencies (now basic) for addr
                newDepsForAddr += newDepsForCond
                
            # Compute the basic dependencies for the memory address addr
            addrDeps = [[addr, CTrue()]]
            for reg in addr.getRegisters():
                for regdep in self.regDep[reg]:
                    tmpAddrDeps = []
                    for tmpDep in addrDeps:
                        tmpAddrDeps.append([tmpDep[0].replaceReg(reg, regdep[0]), Cond(CT.AND, tmpDep[1], regdep[1]) ])
                    addrDeps = tmpAddrDeps
                    
            # TODO : SIMPLIFY EXPRESSIONS HERE, OR IN THE BEGGINIG OF THE FUNCTION ??? 
            # Now combine the addrDeps and the newDepsForAddr in the final result for the gadget
            for newAddrDep in addrDeps:
                updateNewAddrDeps = []
                for dep in newDepsForAddr:
                    updateNewAddrDeps.append([dep[0], Cond(CT.AND, dep[1], newAddrDep[1])])
                newAddr = newAddrDep[0].simplify()
                newMemDep[newAddr] = updateNewAddrDeps
            self.memDep = newMemDep
            
            
            
        # Remove the dependencies for intermediate registers ( we don't care about R1_1 anymore if we have R1_3 in the end :/ )
        for reg in self.regDep.keys():
            if( reg.ind < CurrentAnalysis.gadget.regCount[reg.num]):
                del self.regDep[reg]
        
        # Cleaning and simplifying  
        for reg in self.regDep.keys():
            for dep in self.regDep[reg]:
                dep[0] = dep[0].simplify()
                dep[1].clean()
        for addr, deps in self.memDep.iteritems():
            for dep in deps:
                dep[0] = dep[0].simplify()
                dep[1].clean()
                    
        
        
    def simplifyConditions( self, hard=False ):
        """
        Simplifies the dependencies according to the conditions evaluated to True/False (removes impossible dependencies)
        /!\ Should be called only after all gadgets have been loaded !!! otherwise Expr.nb_regs is still unknown 
        """
        if( self.simplifiedCond ):
            return 
        for reg in self.regDep.keys():
            newDeps = [] 
            for dep in self.regDep[reg]:
                if( not dep[1].isFalse(hard=False) ):
                    newDeps.append( dep )
            self.regDep[reg] = newDeps
        for expr in self.memDep.keys():
            newDeps = [] 
            for dep in self.memDep[expr]:
                if( not dep[1].isFalse(hard=False) ):
                    newDeps.append( dep )
            self.memDep[expr] = newDeps
        
        self.simplifiedCond = True

    def printRegDeps(self):
        """
        Print the dependencies for the registers 
        """
        printAllRegDep(self.regDep)
        
    def printMemDeps(self):
        """
        Print the dependencies for the memory 
        """
        printAllMemDep(self.memDep)


## 'Pretty' print functions 
def printDep(d):
    print "\tValue : " + str(d[0])
    print "\tCondition : "+ str(d[1]) + "\n"

def printAllRegDep(regDep):
    for reg,dep in regDep.iteritems():
        print "[-] %s_%d dependencies:" % (revertRegNamesTable[reg.num], reg.ind)
        [printDep(x) for x in dep]
        
def printAllMemDep(memDep):
    for addr, dep in memDep.iteritems():
        print "[-] MEM[" + str(addr) + "] dependencies:"
        [printDep(x) for x in dep]



##########################
# CONTEXTUAL INFORMATION #
##########################

class CurrentAnalysis:
    graph = None # The graph currently being analyzed 
    gadget = None # The gadget currently being analyzed 

#################################################
# REPRESENTATION OF A GADGET IN GRAPH FORMALISM #
#################################################

class Graph:
    """
    Graph that represents a gadget and his data dependency  
        (self.nodes) - Dictionary of nodes, keys are the string representations of the register or the memory ( e.g "R2_0", "MEM" )
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
            
    def getRegisters( self ):
        """
        Returns all the registers that have got a corresponding SSANode in the graph
        """
        resNames = self.nodes.keys()
        res = []
        for reg in resNames:
            if( reg != "MEM" ):
                # Note that there is no check for duplication
                # but should not happen since every reg have one and only one node in the graph    
                res.append( strToReg( reg ))
        return res
                
    def getDependencies( self ):
        """
        Retrieves dependencies from the graph
        Returns a (GadgetDependencies) instance 
        """
        CurrentAnalysis.graph = self
        gadgetDep = GadgetDependencies()
        for reg in self.nodes.keys():
            node = self.nodes[str(reg)]
            if( not( isinstance(node, MEMNode) and not isinstance(node,ITENode))):
                node.getDependencies( gadgetDep )
                if( self.lastMod.get(node.reg.num) != None ):
                    self.lastMod[node.reg.num] = max( self.lastMod[node.reg.num], int(str(reg).split('_')[1]))
                else:
                    self.lastMod[node.reg.num] = node.reg.ind
            elif( isinstance(node, MEMNode)):
                try:
                    node.getMemDependencies(gadgetDep) 
                except GraphException as e:
                    pass
                    
        gadgetDep.flattenITE()
        gadgetDep.simplifyDependencies()
        return gadgetDep
        

#######################################
# GRAPH COMPONENTS ( ARCS AND NODES ) #
#######################################

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
    def __init__(self):
        self.outgoingArcs = []
        self.jmpLvl = CurrentAnalysis.graph.countCondJmps
        

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
        
    def getDependencies( self, gadgetDep ):
        return [[ConstExpr( self.value, self.size ),CTrue()]]


class SSANode(Node):
    """
    Node that represents a register in SSA form 
        (self.reg) - (SSAReg) register modeled
        (self.size) - (int) 8, 16, 32, 64 ( to access AL, AX, ... ) is the size of the access 
        (self.expr) - (Expr) if the register is not 'basic' i.e ind != 0, then self.expr stores the expression that have been assigned to the register ( e.g self.expr = Add32( R1_0, R3_4 ) ) 
    """
    def __init__(self, reg, expr):
        Node.__init__(self)
        self.reg = SSAReg(reg.num, reg.ind)
        self.expr = expr
        
    def getDependencies( self,  gadgetDep ):
        """
        getDependencies : Computes dependencies for this register, and store them into gadgetDep
                  Return the dependencies as a list of couples ( Expression, Condition )
        """
        # If dependency already calculated 
        if( gadgetDep.regDep.get(self.reg) != None ):
            return gadgetDep.regDep[self.reg]
                 
        # Else we build it :
        # If ind is 0 then we reached a leaf of the graph because it's the initial value of the register 
        if( self.reg.ind == 0 ):
            res = [[SSAExpr(self.reg), CTrue() ]]
            gadgetDep.regDep[self.reg] = res
            return res
        # Else we test if bad node 
        # -> this is an un-understandable but harmless bug, additionnal empty nodes are added to the graph 
        # don't know why they are created yet .... :/     
        if( len(self.outgoingArcs) == 0 and isinstance( self.expr, SSAExpr ) and self.reg == self.expr.reg):
            return []
        # Here we know there are dependencies to compute, so we continue to explore the graph
        
        # We take into account the potential previous conditional jmps 
        resCond = CurrentAnalysis.graph.condPath[self.jmpLvl]
        resExpr = self.expr
        # WARNING : we suppose that each node has only one or no arc towards MEM, not more !
        resPrec = [[self.expr, resCond]]
        # For each arc, we replace step by step the expressions 
        res = []
            
        for a in self.outgoingArcs:
            res = []
            # For each arc we get a list replacement value and the condition
            if( isinstance( a.dest, MEMNode )):
                dep = a.dest.getDependencies( a.num, a.label, a.size, gadgetDep )
            else:
                dep = a.dest.getDependencies( gadgetDep )
            for path in dep:
                if ( isinstance( a.dest, MEMNode )):
                    res += [[p[0].replaceMemAcc(a.label, path[0]), Cond(CT.AND, p[1],path[1])] for p in resPrec ]
                elif( isinstance( a.dest, ITENode )):
                    res += [[p[0].replaceITE(path[0]), Cond(CT.AND, p[1],path[1])] for p in resPrec ] 
                else:
                    res += [[p[0].replaceReg( a.dest.reg, path[0] ), Cond(CT.AND, p[1],path[1])] for p in resPrec ]
            resPrec = res
                
        if( len(res) == 0 ):
            res = [[self.expr, resCond]]
        
        # Taking into account the potential conditionnal jumps     
        # We add the case when the jump had not been taken 
        if( self.jmpLvl > 0 ):
            dep = CurrentAnalysis.graph.nodes[str(regBeforeLastJmp(self.reg, self.jmpLvl))].getDependencies( gadgetDep )
            for d in dep:
                res.append( [d[0], Cond(CT.AND, d[1], CurrentAnalysis.graph.condJmps[self.jmpLvl])]) 

        gadgetDep.regDep[self.reg] = res
            
        return res


class ITENode(Node):
    """
    ITENode : Node that represents an IF THEN ELSE statement.....
        (self.cond) - (Cond) is the condition of the IF statement 
        (self.outgoingArcs) - (List(Arc)) is the arcs of dependency when cond is evaluated to TRUE
        (self.outgoingArcsCond) - (List(Arc)) is the arcs when cond is computed to FALSE 
        (self.iftrue) - (Expr) is the value if cond is evaluated to True
        (self.iffalse) - (Expr) is the value if cond is evaluated to False
    """
    def __init__(self, cond, iftrue, iffalse):
        Node.__init__(self)
        self.outgoingArcsCond = [] 
        self.cond = cond
        self.iftrue = iftrue
        self.iffalse = iffalse
        
    def getDependencies(self, gadgetDep ):
        resPrec = [[self.iftrue, self.cond]]
        # We first compute when the condition is TRUE :
        # For each arc, we replace step by step the expressions 
        for a in self.outgoingArcs:
            resTrue = []
            # For each arc we get a list replacement value and the condition
            if( isinstance( a.dest, MEMNode )):
                dep = a.dest.getDependencies( a.num, a.label, a.size, gadgetDep )
            else:
                dep = a.dest.getDependencies( gadgetDep )
            for path in dep:
                if ( isinstance( a.dest, MEMNode )):
                    resTrue += [[p[0].replaceMemAcc(a.label, path[0]), Cond(CT.AND, p[1],path[1])] for p in resPrec]
                else:
                    resTrue += [[p[0].replaceReg( a.dest.reg, path[0] ), Cond(CT.AND, p[1],path[1])] for p in resPrec ]
            resPrec = resTrue

        res = resPrec
        resPrec = [[self.iffalse, self.cond.invert()]]
        # Then the case when the condition is FALSE
        # For each arc, we replace step by step the expressions 
        for a in self.outgoingArcsCond:
            resFalse = []
            # For each arc we get a list replacement value and the condition
            if( isinstance( a.dest, MEMNode )):
                dep = a.dest.getDependencies(  a.num, a.label, a.size, gadgetDep )
            else:
                dep = a.dest.getDependencies( gadgetDep )
            for path in dep:
                if ( isinstance( a.dest, MEMNode )):
                    resFalse += [[p[0].replaceMemAcc(a.label, path[0]), Cond(CT.AND, p[1],path[1])] for p in resPrec]
                else:
                    resFalse += [[p[0].replaceReg( a.dest.reg, path[0] ), Cond(CT.AND, p[1],path[1])] for p in resPrec]
            resPrec = resFalse
        res = res + resPrec
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
        addrKey = str(simplify(addr.toZ3()))
        readDict = {addrKey:0} # Basic constraint for optimisation 
        value = MEMExpr( addr, size )
        resTmp = [[MEMExpr(addr, size), CTrue(), readDict]]
        tmpCond = None
        # For each outgoing arc, i.e for each memory write  
        for a in sorted( self.outgoingArcs, reverse=False):
            optWriteKey = str(simplify(a.label.toZ3())) # key for the store address for optimisation 
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
        
    def getMemDependencies( self, gadgetDep ):
        """
        Extract dependencies from memory
        Dependencies of the memory are returned in the form of a dictionnary of lists of couples
            - Dictionnary entries are addresses where the memory is accessed ( like R7_0 + R6_0 + 0x56 ) 
            - Dictionnary values are lists that are classical dependencies. This means lists of couples [value, condition] 
            
        Parameters:
            (gadgetDep) (GadgetDependencies) The structure where to store the memory dependencies 
        """
    
        #raise GraphException("Function getMemDependencies() not yet implemented, sorry !")
        
        # The three dictionnaries below MUST have the exact same keys 
        res = dict() # Key: Expr (address of store), Value: list of dependencies 
        previousStoreSizes = dict() # Key: Expr (address of store), Value: size of the store   
        

        tmpCond = None
        # We go through memory-writes in chronological order 
        for a in sorted(self.outgoingArcs):
            # Key to manipulate the current store address 
            addrKey = str(simplify(a.label.toZ3()))
            # We get the dependency for the node that is written in memory 
            dep = a.dest.getDependencies(gadgetDep)
            # !!! HERE WE DON'T NEED TO CORRECT THE DEPENDENCIES WITH THE self.storedValues BECAUSE IT HAS ALREADY BEEN DONE FOR REGISTERS AND WE USE THEIR FINAL DEPENDENCIES DIRECTLY 
            if( isinstance(a.dest, SSANode)):
                dep = [[self.storedValues[a.num].replaceReg(a.dest.reg, d[0]), d[1]] for d in dep ]    
            
            # Handling conditionnal jumps 
            if( tmpCond is None ):
                # If first memory access, then we get the condPath for the adequate level (condition that must be true so that we haven't jumper out from the gadget) 
                tmpCond = CurrentAnalysis.graph.condPath[a.jmpLvl]
            else:
                # Else we only add the condJump corresponding to this level 
                tmpCond = Cond( CT.AND, tmpCond, CurrentAnalysis.graph.condJmps[a.jmpLvl].invert() )
            storeLen = a.size / 8 # Number of bytes written by this arc
            previousStoreSizes[a.label] = storeLen
            #readDict = {addrKey:0} # Basic constraint for optimisation 
            
            # Create a new dependency for this 
            
            # Updating dependencies for the previous memory-store
            resTmp = dict()
            for writeAddr, prevDep in res.iteritems():
                # 1st Case Preparation : New store doesn't affect old store
                # Get the size of the previous by looking at one dependency (little hack and not so clean but heh)
                previousStoreSize = previousStoreSizes[writeAddr] 
                higher = Op( "Add", [writeAddr, ConstExpr(previousStoreSize, writeAddr.size)] ) 
                lower = Op( "Sub", [writeAddr, ConstExpr( a.size, writeAddr.size )]) 
                outCond = Cond( CT.OR, Cond( CT.GE, a.label, higher ), Cond( CT.LE, a.label, lower ))
                newDict = {addrKey:[1-storeLen, previousStoreSize-1]}
                
                newDep = []
                # Update each old dependency 
                for prev in prevDep:
                    # 1st Case Still...
                    if( self.compatibleAccesses( prev[2], newDict )):
                        newDep.append( [prev[0], Cond( CT.AND, outCond, prev[1]), self.dictFusion(newDict, prev[2])]) 
                
                    # Now 2d Case: New store overwrites old store  
                    # ...
                    # Offset = current store - previous store 
                    for offset in range(1-storeLen, previousStoreSize-1):
                        newDict = {addrKey:offset}
                        newStorePossibleValue = Op("Add", [writeAddr, ConstExpr(offset, writeAddr.size)] )
                        addrCond = Cond( CT.EQUAL, a.label, newStorePossibleValue )
                        if( self.compatibleAccesses( newDict, prev[2] ) and self.filterOffset( offset, previousStoreSize, storeLen )):
                            # For each dep of the new store, we update with the case where it overwrites the previous stores 
                            for d in dep:
                                newValue = self.overWrite( offset, d[0], prev[0] )
                                newCond = Cond( CT.AND, Cond(CT.AND, prev[1], addrCond ), d[1] )
                                newDep.append( [newValue, newCond, self.dictFusion(newDict, prev[2])])
                                
                
                
                
                
                resTmp[writeAddr] = newDep
                
            # New dependency:
            resTmp[a.label] = []
            newStoreDict={addrKey:0}
            for d in dep:
                resTmp[a.label].append([d[0], d[1], newStoreDict])
            
            # Save everything 
            res = resTmp
            # ... 
            
        # Clean the deps from dictionnaries 
        for addr, dep in res.iteritems():
            dep = [[].append([d[0], d[1]]) for d in dep ]
        
        # Replace the memory addresses of the stores by their basic dependencies
        # So far we have MEM[expr] where expr doesn't necessarily have basic dependencies, so we want to express everything with the basic dependencies 
        
        gadgetDep.memDep = res
        
            
        
def regBeforeLastJmp(reg, jmpLvl):
    """
    Returns the SSA occurence of the register 'reg' that corresponds to it's value just before the jump number 'jmpLvl' was taken 
    Parameters:
        (reg) (SSAReg) The regiter we are considering 
        (jmpLvl) (int) The jump level we want to go before 
    """
    ind = reg.ind
    num = reg.num
    while( ind != 0 and CurrentAnalysis.graph.nodes[str(SSAReg(num, ind))].jmpLvl >= jmpLvl ):
        ind -= 1
    return SSAReg(num ,ind)

