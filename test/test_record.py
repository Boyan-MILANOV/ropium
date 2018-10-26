from ropgenerator.semantic.Engine import RecordREGtoREG

r = RecordREGtoREG()
r.add(0,1,0, [0,1,16,15])
print(r.regs)
r.add(0,1,0, [1,16])
print(r.regs)
print( r.check(0,1,0,[1,16,17])  ) 
