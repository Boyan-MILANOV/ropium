from ropgenerator.Gadget import *

Arch.currentArch = Arch.ArchX86

#raw = "\x89\xD8\x50\x59\xC3"
raw = "\x50\x89\x0E\x5B\xC3"

gadget = Gadget(0, raw)
print(gadget.semantics)
print(gadget.spInc)
print(gadget.retType)
print(gadget.retValue)
print(gadget.modifiedRegs())
print(gadget.memoryWrites())
print(gadget.getSemantics("eax"))
