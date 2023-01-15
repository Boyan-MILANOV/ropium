#ifndef PYTHON_BINDINGS_INCLUDE_H
#define PYTHON_BINDINGS_INCLUDE_H
#define PY_SSIZE_T_CLEAN

#include "Python.h"
#include "structmember.h"
#include "exception.hpp"
#include "arch.hpp"
#include "database.hpp"
#include "compiler.hpp"
#include "systems.hpp"

/* -------------------------------------------------
 *                     Utils
 * ------------------------------------------------- */

PyObject* create_class(PyObject* name, PyObject* bases, PyObject* dict);

/* --------------------------------------------------
 *                   Arch
 *  -------------------------------------------------- */

void init_arch(PyObject* module);

/* --------------------------------------------------
 *                   Ropium
 *  -------------------------------------------------- */

typedef struct{
    PyObject_HEAD
    Arch* arch;
    GadgetDB* gadget_db;
    ROPCompiler* compiler;
    Constraint* constraint;
    ABI abi;
    System system;
} ROPium_Object;
PyObject* get_ROPium_Type();
PyObject* ropium_ROPium(PyObject* self, PyObject* args);
#define as_ropium_object(x)  (*((ROPium_Object*)x))

/* --------------------------------------------------
 *                   ROPChain
 *  -------------------------------------------------- */

void init_ropchain(PyObject* module);

typedef struct{
    PyObject_HEAD
    ROPChain* ropchain;
} ropchain_Object;
PyObject* get_ropchain_Type();
PyObject* Pyropchain_FromROPChain(ROPChain* chain);
#define as_ropchain_object(x)  (*((ropchain_Object*)x))


#endif
