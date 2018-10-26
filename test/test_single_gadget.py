# -*- coding:utf-8 -*- 

from ropgenerator.Database import *
from barf import *
from ropgenerator.Gadget import *
from ropgenerator.Graph import *
import ropgenerator.Architecture as Arch
import ropgenerator.Expressions as Expr
from ropgenerator.Constraints import Constraint, CstrTypeID, Chainable

# "\x50\xC7\x06\x00\x00\x00\x00\x5B\xC3"  "\x10\x5b\x5d\x41\x5c\x48\x0f\x45\xc2\xc3" 
# "\x50\x83\xC1\x01\x89\x0E\x5B\xC3" 
# "\x50\x67\xC7\x46\x01\x00\x00\x00\x00\x5B\xC3"
# \x89\xe5\xff\xd0
# \xff\x75\x9c\x48\x89\xf8\xc3  TEST FOR MEMORY DEPENDENCIES WITH EXPRESSION 
# \xb6\xd2\x0f\xb6\xc0\x29\xd0\xc3 TEST FOR STRANGE CAT40 
# Boucle infinie 39\xc8\x19\xc0\x83\xd8\xff\x5e\x5b\xc3
#"\x01\x41\x88\x48\xff\x49\x83\xc2\x01\x49"
#\x01\x41\x88\x48\xff\x49\x83
# \x18\x09\x00\x00\x11\x00\x1a\x00\xc2\x7b\x26 erreur Extract invalide 
# \x48\x89\xF7\xFF\xE0 Erreur calcul du spInc 
# "\x89\x08\x89\xD0\xC3" Condition not passed (32bits)
# \x48\x89\x03\x48\x83\xC4\x08\x5B\x5D\xC3 mem(rbx) <- rax not found by engine 


asm = "\x48\x89\x03\x48\x83\xC4\x08\x5B\x5D\xC3"
Arch.currentArch = Arch.ArchX64
#try:
gadget = Gadget([0], asm) 
print(gadget.semantics)
print(gadget.spInc)

c = Constraint([Chainable(ret=True)])
(ok, conds) = c.verify(gadget)
print(ok)
print(conds)

#except Exception as e:
#    print "Bad gadget ignored : " + str(e)
