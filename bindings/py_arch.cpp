#include "python_bindings.hpp"
#include "arch.hpp"
#include "compiler.hpp"

void init_arch(PyObject* module){
    /* ARCH enum */
    PyObject* arch_enum = PyDict_New();
    PyDict_SetItemString(arch_enum, "X86", PyLong_FromLong((int)ArchType::X86));
    PyDict_SetItemString(arch_enum, "X64", PyLong_FromLong((int)ArchType::X64));
    PyDict_SetItemString(arch_enum, "ARM32", PyLong_FromLong((int)ArchType::ARM32));
    PyDict_SetItemString(arch_enum, "ARM64", PyLong_FromLong((int)ArchType::ARM64));
    PyObject* arch_class = create_class(PyUnicode_FromString("ARCH"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "ARCH", arch_class);
    
    /* ABI enum */
    PyObject* abi_enum = PyDict_New();
    PyDict_SetItemString(abi_enum, "X86_CDECL", PyLong_FromLong((int)ABI::X86_CDECL));
    PyDict_SetItemString(abi_enum, "X86_STDCALL", PyLong_FromLong((int)ABI::X86_STDCALL));
    PyDict_SetItemString(abi_enum, "X64_SYSTEM_V", PyLong_FromLong((int)ABI::X64_SYSTEM_V));
    PyDict_SetItemString(abi_enum, "X64_MS", PyLong_FromLong((int)ABI::X64_MS));
    PyDict_SetItemString(abi_enum, "NONE", PyLong_FromLong((int)ABI::NONE));
    PyObject* abi_class = create_class(PyUnicode_FromString("ABI"), PyTuple_New(0), abi_enum);
    PyModule_AddObject(module, "ABI", abi_class);
    
    /* X86 registers enum */
    PyObject* x86_enum = PyDict_New();
    PyDict_SetItemString(x86_enum, "EAX", PyLong_FromLong(X86_EAX));
    PyDict_SetItemString(x86_enum, "EBX", PyLong_FromLong(X86_EBX));
    PyDict_SetItemString(x86_enum, "ECX", PyLong_FromLong(X86_ECX));
    PyDict_SetItemString(x86_enum, "EDX", PyLong_FromLong(X86_EDX));
    PyDict_SetItemString(x86_enum, "EDI", PyLong_FromLong(X86_EDI));
    PyDict_SetItemString(x86_enum, "ESI", PyLong_FromLong(X86_ESI));
    PyDict_SetItemString(x86_enum, "EBP", PyLong_FromLong(X86_EBP));
    PyDict_SetItemString(x86_enum, "ESP", PyLong_FromLong(X86_ESP));
    PyDict_SetItemString(x86_enum, "EIP", PyLong_FromLong(X86_EIP));
    PyDict_SetItemString(x86_enum, "CS", PyLong_FromLong(X86_CS));
    PyDict_SetItemString(x86_enum, "DS", PyLong_FromLong(X86_DS));
    PyDict_SetItemString(x86_enum, "ES", PyLong_FromLong(X86_ES));
    PyDict_SetItemString(x86_enum, "FS", PyLong_FromLong(X86_FS));
    PyDict_SetItemString(x86_enum, "GS", PyLong_FromLong(X86_GS));
    PyDict_SetItemString(x86_enum, "SS", PyLong_FromLong(X86_SS));
    PyDict_SetItemString(x86_enum, "CF", PyLong_FromLong(X86_CF));
    PyDict_SetItemString(x86_enum, "PF", PyLong_FromLong(X86_PF));
    PyDict_SetItemString(x86_enum, "AF", PyLong_FromLong(X86_AF));
    PyDict_SetItemString(x86_enum, "ZF", PyLong_FromLong(X86_ZF));
    PyDict_SetItemString(x86_enum, "SF", PyLong_FromLong(X86_SF));
    PyDict_SetItemString(x86_enum, "TF", PyLong_FromLong(X86_TF));
    PyDict_SetItemString(x86_enum, "IF", PyLong_FromLong(X86_IF));
    PyDict_SetItemString(x86_enum, "DF", PyLong_FromLong(X86_DF));
    PyDict_SetItemString(x86_enum, "OF", PyLong_FromLong(X86_OF));
    PyDict_SetItemString(x86_enum, "IOPL", PyLong_FromLong(X86_IOPL));
    PyDict_SetItemString(x86_enum, "NT", PyLong_FromLong(X86_NT));
    PyDict_SetItemString(x86_enum, "RF", PyLong_FromLong(X86_RF));
    PyDict_SetItemString(x86_enum, "VM", PyLong_FromLong(X86_VM));
    PyDict_SetItemString(x86_enum, "AC", PyLong_FromLong(X86_AC));
    PyDict_SetItemString(x86_enum, "VIF", PyLong_FromLong(X86_VIF));
    PyDict_SetItemString(x86_enum, "VIP", PyLong_FromLong(X86_VIP));
    PyDict_SetItemString(x86_enum, "ID", PyLong_FromLong(X86_ID));
    PyDict_SetItemString(x86_enum, "TSC", PyLong_FromLong(X86_TSC));
    PyDict_SetItemString(x86_enum, "NB_REGS", PyLong_FromLong(X86_NB_REGS));
    PyObject* x86_class = create_class(PyUnicode_FromString("X86"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "X86", x86_class);
    
    /* X64 registers enum */
    PyObject* x64_enum = PyDict_New();
    PyDict_SetItemString(x64_enum, "RAX", PyLong_FromLong(X64_RAX));
    PyDict_SetItemString(x64_enum, "RBX", PyLong_FromLong(X64_RBX));
    PyDict_SetItemString(x64_enum, "RCX", PyLong_FromLong(X64_RCX));
    PyDict_SetItemString(x64_enum, "RDX", PyLong_FromLong(X64_RDX));
    PyDict_SetItemString(x64_enum, "RDI", PyLong_FromLong(X64_RDI));
    PyDict_SetItemString(x64_enum, "RSI", PyLong_FromLong(X64_RSI));
    PyDict_SetItemString(x64_enum, "RBP", PyLong_FromLong(X64_RBP));
    PyDict_SetItemString(x64_enum, "RSP", PyLong_FromLong(X64_RSP));
    PyDict_SetItemString(x64_enum, "RIP", PyLong_FromLong(X64_RIP));
    PyDict_SetItemString(x64_enum, "R8", PyLong_FromLong(X64_R8));
    PyDict_SetItemString(x64_enum, "R9", PyLong_FromLong(X64_R9));
    PyDict_SetItemString(x64_enum, "R10", PyLong_FromLong(X64_R10));
    PyDict_SetItemString(x64_enum, "R11", PyLong_FromLong(X64_R11));
    PyDict_SetItemString(x64_enum, "R12", PyLong_FromLong(X64_R12));
    PyDict_SetItemString(x64_enum, "R13", PyLong_FromLong(X64_R13));
    PyDict_SetItemString(x64_enum, "R14", PyLong_FromLong(X64_R14));
    PyDict_SetItemString(x64_enum, "R15", PyLong_FromLong(X64_R15));
    PyDict_SetItemString(x64_enum, "CS", PyLong_FromLong(X64_CS));
    PyDict_SetItemString(x64_enum, "DS", PyLong_FromLong(X64_DS));
    PyDict_SetItemString(x64_enum, "ES", PyLong_FromLong(X64_ES));
    PyDict_SetItemString(x64_enum, "FS", PyLong_FromLong(X64_FS));
    PyDict_SetItemString(x64_enum, "GS", PyLong_FromLong(X64_GS));
    PyDict_SetItemString(x64_enum, "SS", PyLong_FromLong(X64_SS));
    PyDict_SetItemString(x64_enum, "CF", PyLong_FromLong(X64_CF));
    PyDict_SetItemString(x64_enum, "PF", PyLong_FromLong(X64_PF));
    PyDict_SetItemString(x64_enum, "AF", PyLong_FromLong(X64_AF));
    PyDict_SetItemString(x64_enum, "ZF", PyLong_FromLong(X64_ZF));
    PyDict_SetItemString(x64_enum, "SF", PyLong_FromLong(X64_SF));
    PyDict_SetItemString(x64_enum, "TF", PyLong_FromLong(X64_TF));
    PyDict_SetItemString(x64_enum, "IF", PyLong_FromLong(X64_IF));
    PyDict_SetItemString(x64_enum, "DF", PyLong_FromLong(X64_DF));
    PyDict_SetItemString(x64_enum, "OF", PyLong_FromLong(X64_OF));
    PyDict_SetItemString(x64_enum, "IOPL", PyLong_FromLong(X64_IOPL));
    PyDict_SetItemString(x64_enum, "NT", PyLong_FromLong(X64_NT));
    PyDict_SetItemString(x64_enum, "RF", PyLong_FromLong(X64_RF));
    PyDict_SetItemString(x64_enum, "VM", PyLong_FromLong(X64_VM));
    PyDict_SetItemString(x64_enum, "AC", PyLong_FromLong(X64_AC));
    PyDict_SetItemString(x64_enum, "VIF", PyLong_FromLong(X64_VIF));
    PyDict_SetItemString(x64_enum, "VIP", PyLong_FromLong(X64_VIP));
    PyDict_SetItemString(x64_enum, "ID", PyLong_FromLong(X64_ID));
    PyDict_SetItemString(x64_enum, "TSC", PyLong_FromLong(X64_TSC));
    PyDict_SetItemString(x64_enum, "NB_REGS", PyLong_FromLong(X64_NB_REGS));
    PyObject* x64_class = create_class(PyUnicode_FromString("X64"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "X64", x64_class);
};
