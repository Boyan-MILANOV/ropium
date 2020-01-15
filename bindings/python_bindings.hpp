#ifndef PYTHON_BINDINGS_INCLUDE_H
#define PYTHON_BINDINGS_INCLUDE_H

#include "Python.h"
#include "structmember.h"
#include "exception.hpp"
#include "expression.hpp"
#include "simplification.hpp"
#include "arch.hpp"

/* -------------------------------------------------
 *                     Utils
 * ------------------------------------------------- */

PyObject* create_class(PyObject* name, PyObject* bases, PyObject* dict);

/* --------------------------------------------------
 *                   Arch
 *  -------------------------------------------------- */

void init_arch(PyObject* module);


#endif
