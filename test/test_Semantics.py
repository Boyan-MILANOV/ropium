from ropgenerator.Semantics import SPair, Semantics
from ropgenerator.Expressions import *
from ropgenerator.Conditions import CTrue, CFalse

Arch.currentArch = Arch.ArchX86
size = 32

r0_0 = SSAExpr(0,0)
r1_0 = SSAExpr(1,0)
r1_1 = SSAExpr(1,1)
r1_2 = SSAExpr(1,2)
r2_0 = SSAExpr(2,0)
r2_1 = SSAExpr(2,1)


expr1_1 = OpExpr(Op.ADD, [r0_0, ConstExpr(4,size)])
expr2_1 = OpExpr(Op.ADD, [r2_0, r1_1])
expr3_1 = Concat([r2_1, OpExpr(Op.SUB, [r0_0, r0_0])])

s = Semantics()
s.registers[SSAReg(0,0)] = [SPair(r0_0, CTrue())]
s.registers[SSAReg(1,0)] = [SPair(r1_0, CTrue())]
s.registers[SSAReg(1,1)] = [SPair(r0_0, CTrue())]
s.registers[SSAReg(2,1)] = [SPair(expr2_1, CTrue())]
s.registers[SSAReg(2,0)] = [SPair(r2_0, CTrue()), SPair(r0_0, CFalse())]
s.registers[SSAReg(3,1)] = [SPair(expr3_1, CTrue())]

print(s)
s.simplifyValues()
print(s)
s.simplifyConditions()
print(s)
