#include "python_bindings.hpp"
#include <cstdio>

/* -------------------------------------
 *          ROPChain object
 * ------------------------------------ */

static void ropchain_dealloc(PyObject* self){
    delete ((ropchain_Object*)self)->ropchain;  ((ropchain_Object*)self)->ropchain = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* ropchain_str(PyObject* self){
    stringstream ss;
    ss << *(as_ropchain_object(self).ropchain);
    return PyUnicode_FromString(ss.str().c_str());
};

static int ropchain_print(PyObject* self){
    std::cout << *(as_ropchain_object(self).ropchain);
    return 0;
};

static PyObject* ropchain_repr(PyObject* self){
    return ropchain_str(self);
};

static PyObject* ropchain_dump(PyObject* self, PyObject* args, PyObject* keywords){
    char* arg = "pretty"; // Default
    string fmt;
    stringstream ss;
    int color = 1;
    vector<uint8_t> raw;
    PyObject* res;
    char* tab = "";

    char* keywd[] = {"", "tab", "color", NULL};

    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "|ssp", keywd, &arg, &tab, &color)){
        return NULL;
    }

    fmt = string(arg);

    if(!color){
        disable_colors();
    }

    if( fmt == "pretty" ){
        as_ropchain_object(self).ropchain->print_pretty(ss, string(tab));
        res = PyUnicode_FromString(ss.str().c_str());
    }else if( fmt == "python" ){
        as_ropchain_object(self).ropchain->print_python(ss, string(tab));
        res = PyUnicode_FromString(ss.str().c_str());
    }else if( fmt == "raw" ){
        as_ropchain_object(self).ropchain->dump_raw(raw);
         // Translate vector into python bytes
        res = PyBytes_FromStringAndSize((char*)raw.data(), raw.size());
    }else
        return PyErr_Format(PyExc_ValueError, "Unknown dump format: %s", arg);

    enable_colors();
    
    if( res == NULL ){
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to dump ropchain");
    }

    return res;
}

static PyMethodDef ropchain_methods[] = {
    {"dump", (PyCFunction)ropchain_dump, METH_VARARGS | METH_KEYWORDS, "dump(fmt='pretty', tab='', color=True) \nDump the ropchain in various formats. Available formats: 'pretty', 'python', 'raw'"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef ropchain_members[] = {
    {NULL}
};

static PyNumberMethods ropchain_operators; // Empty PyNumberMethods, will be filled in the init function

/* Type description for python Expr objects */
PyTypeObject ropchain_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ropchain",                         /* tp_name */
    sizeof(ropchain_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)ropchain_dealloc,       /* tp_dealloc */
    (printfunc)ropchain_print,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    ropchain_repr,                            /* tp_repr */
    &ropchain_operators,                      /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    ropchain_str,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "ROPChain object",                        /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    ropchain_methods,                         /* tp_methods */
    ropchain_members,                         /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_ropchain_Type(){
    return (PyObject*)&ropchain_Type;
};

/* Constructor */
PyObject* Pyropchain_FromROPChain(ROPChain* chain){
    ropchain_Object* object;

    // Create object
    PyType_Ready(&ropchain_Type);
    object = PyObject_New(ropchain_Object, &ropchain_Type);
    if( object != nullptr ){
        object->ropchain = chain;
    }
    return (PyObject*)object;
}

// Adding two ropchains
/* Number methods & Various Constructors */
static PyObject* ropchain_nb_add(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(ropchain_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '+'");
    }
    ROPChain * rop = new ROPChain(as_ropchain_object(self).ropchain->arch);
    rop->add_chain(*(as_ropchain_object(self).ropchain));
    rop->add_chain(*(as_ropchain_object(other).ropchain));
    return Pyropchain_FromROPChain(rop);
}

/* -------------------------------------
 *          Init function
 * ------------------------------------ */
void init_ropchain(PyObject* module){
    /* Add number operators to ropchain */
    ropchain_operators.nb_add = ropchain_nb_add;
}
