#include "Python.h"
#include "python_bindings.hpp"

/* Module methods */
PyMethodDef module_methods[] = {
    {"ROPium", (PyCFunction)ropium_ROPium, METH_VARARGS, "Create a new ROPium instance"},
    {NULL}
};

/* Module information */
PyModuleDef ropium_module_def = {
    PyModuleDef_HEAD_INIT,
    "ropium",
    nullptr,
    -1,      // m_size
    module_methods, // m_methods
    nullptr, // m_slots
    nullptr, // m_traverse
    nullptr, // m_clear
    nullptr  // m_free    
};

PyMODINIT_FUNC PyInit_ropium(){
    Py_Initialize();
    PyObject* module = PyModule_Create(&ropium_module_def);
    
    init_arch(module);
    init_ropchain(module);
    return module;
}
