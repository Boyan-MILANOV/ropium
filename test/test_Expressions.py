from ropgenerator.Expressions import *

Arch.currentArch = Arch.ArchX86

r1_0 = SSAExpr(1,0)
r1_1 = SSAExpr(1,1)
r1_2 = SSAExpr(1,2)
r0_0 = SSAExpr(0,0)
r2_0 = SSAExpr(2,0)
r2_1 = SSAExpr(2,1)

expr0 = OpExpr(Op.ADD, [r1_0, r0_0])
expr1 = OpExpr(Op.ADD, [expr0, OpExpr(Op.ADD, [ConstExpr(3,32), ConstExpr(5,32)])])
expr1 = OpExpr(Op.SUB, [ConstExpr(7, 32), expr1])
expr2 = OpExpr(Op.MUL, [expr1, r2_0])
expr3 = MEMExpr(expr2, 32)
expr4 = Convert(16, expr1)
expr5 = Concat([expr4, ConstExpr(12, 16)])
expr6 = Extract(15,0, expr5)
expr7 = OpExpr(Op.NOT, [OpExpr(Op.NOT, [expr6])])

expr8a = OpExpr(Op.ADD, [r2_1, ConstExpr(7,32)])
expr8b = OpExpr(Op.ADD, [ConstExpr(7,32), r2_1 ])
expr8c = OpExpr(Op.SUB, [ConstExpr(7,32), r2_1])
expr8d = OpExpr(Op.SUB, [r2_1,ConstExpr(7,32)])

expr9 = OpExpr(Op.SUB, [ConstExpr(8,32), expr8a])
expr10 = OpExpr(Op.SUB, [ConstExpr(8,32), expr8b])
expr11 = OpExpr(Op.SUB, [ConstExpr(8,32), expr8c])
expr12 = OpExpr(Op.SUB, [ConstExpr(8,32), expr8d])

expressions = [expr1, expr2, expr3, expr4, expr5, expr6, expr7, expr9, expr10, expr11, expr12]

print("Expressions tests")
print("-----------------\n")

op = OpExpr(Op.SUB, [r1_0, ConstExpr(54,32)])
print(op.toArray())
