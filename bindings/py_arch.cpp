#include "python_bindings.hpp"
#include "arch.hpp"

void init_arch(PyObject* module){
    /* ARCH enum */
    PyObject* arch_enum = PyDict_New();
    PyDict_SetItemString(arch_enum, "X86", PyLong_FromLong((int)ArchType::X86));
    PyDict_SetItemString(arch_enum, "X64", PyLong_FromLong((int)ArchType::X64));
    PyDict_SetItemString(arch_enum, "ARM32", PyLong_FromLong((int)ArchType::ARM32));
    PyDict_SetItemString(arch_enum, "ARM64", PyLong_FromLong((int)ArchType::ARM64));
    PyObject* arch_class = create_class(PyUnicode_FromString("ARCH"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "ARCH", arch_class);
};
