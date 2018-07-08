from ropgenerator.Graph import *

Arch.currentArch = Arch.ArchX86

#raw = "\x89\xD8\xC3"
raw = "\x89\xD8\x50\x59\xC3"
(irsb, ins) = Arch.currentArch.asmToREIL(raw)

for instr in irsb:
    print(instr)
for i in ins:
    print(i)
    
graph = REILtoGraph(irsb)
#print(graph.nodes.keys())
print(graph)

s = graph.getSemantics()
print(s)
