from Database import *
from barf import *
from Gadget import *
from Graph import *
import Analysis
import Expr


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
# \x48\x89\xD8\x50\x48\x83\xEC\x08\x59\x5A\xFF\x16  TEST for call qword ptr [rsi] bug
# \xFF\x16 Only call qword ptr [rsi
#  \x8e\x22\x00\x02\x00\x00\x00\xe8\xca\x3b\x00 bug with fs  
# \xe8\x8f\xc3\xfe\xff\xe8\xca\xc3 bug with str() failing from BARF
# \x0f\x95\x05\xe3\x16\x25\x00\xc3   bug avec MEM et lis_index out of range 


asm = "\x0f\x95\x05\xe3\x16\x25\x00\xc3"  
setArch( "X86_64" )
#try:
gadget = Gadget(0, 0, asm)
Expr.nb_regs = Analysis.ssaRegCount-1
gadget.printHex()
gadget.printInstr()
printRegTranslation()
gadget.getDependencies().simplifyConditions()
gadget.calculateSpInc()
print("REG DEPENDENCIES")
gadget.getDependencies().printRegDeps()
print "MEMORY DEPENDENCIES"
gadget.getDependencies().printMemDeps()
print "SP INC " + str(gadget.spInc)
	


#except Exception as e:
#	print "Bad gadget ignored : " + str(e)
		

