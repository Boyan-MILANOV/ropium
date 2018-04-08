from ropgenerator.Database import *
from    barf import *
from ropgenerator.Gadget import *
from ropgenerator.Graph import *
import ropgenerator.Analysis as Analysis
import ropgenerator.Expr as Expr

def show_dep(d):
    print "\tValue : " + str(d[0])
    print "\tIn Z3 : " + str(d[0].toZ3())
    print "\tCondition : "+ str(d[1]) 
    print "\tIn Z3 : " + str(simplify(d[1].toZ3())) + "\n"

def show_res(res):
    print "\n\n*** Dependencies with simplification *** \n"
    for reg,dep in res.regDep.iteritems():
        #if( reg.ind == tmp.currentGadget.regCount[reg.reg] ):
        print "[-] %s_%d dependencies:" % (revertRegNamesTable[reg.num], reg.ind)
        [show_dep(x) for x in dep]

# "\x50\xC7\x06\x00\x00\x00\x00\x5B\xC3"  "\x10\x5b\x5d\x41\x5c\x48\x0f\x45\xc2\xc3" 
# "\x50\x83\xC1\x01\x89\x0E\x5B\xC3" 
# "\x50\x67\xC7\x46\x01\x00\x00\x00\x00\x5B\xC3"
# \x89\xe5\xff\xd0
# \xff\x75\x9c\x48\x89\xf8\xc3   TEST FOR MEMORY DEPENDENCIES WITH EXPRESSION 
# \xb6\xd2\x0f\xb6\xc0\x29\xd0\xc3 TEST FOR STRANGE CAT40 
# Boucle infinie 39\xc8\x19\xc0\x83\xd8\xff\x5e\x5b\xc3
asm = "\x5b\x0a\x0e\x14\x41\xc3"
Analysis.setArch( "X86" )
#try:
gadget = Gadget(0, 0, asm)
Expr.nb_regs = Analysis.ssaRegCount-1
gadget.printHex()
gadget.printInstr()
gadget.calculateSpInc()
gadget.calculateRet()
gadget.getDependencies().printRegDeps()
Analysis.printRegTranslation()
gadget.printInstr()

print "MEMORY DEPENDENCIES"
gadget.getDependencies().printMemDeps()
print "ESP INC " + str(gadget.spInc)    


#except Exception as e:
#    print "Bad gadget ignored : " + str(e)
        

