# -*- coding:utf-8 -*-

from ropgenerator.Conditions import *
from ropgenerator.Constraints import *
from ropgenerator.Expressions import * 

Arch.currentArch = Arch.ArchX86

# Create expressions 
r0 = SSAExpr(3,0)
r1 = SSAExpr(4,0)
r2 = OpExpr(Op.ADD, [SSAExpr(5,0), ConstExpr(3,32)])

# Create conditions 
c0 = Cond(CT.EQUAL, r0, r1)
c1 = Cond(CT.LE, r1, r2)

# Create assertions 
a = Assertion([RegsEqual([(0,1)]), RegsNoOverlap([(2,1)])])

print(a.validate([c0]))
print(a.validate([c0,c1]))
