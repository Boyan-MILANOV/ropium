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
};
