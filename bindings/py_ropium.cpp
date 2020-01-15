#include "python_bindings.hpp"

/* -------------------------------------
 *          ROPium object
 * ------------------------------------ */

static void ROPium_dealloc(PyObject* self){
    delete ((ROPium_Object*)self)->compiler;  ((ROPium_Object*)self)->compiler = nullptr;
    delete ((ROPium_Object*)self)->arch;  ((ROPium_Object*)self)->arch = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyMethodDef ROPium_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyMemberDef ROPium_members[] = {
    {NULL}
};

/* Type description for python Expr objects */
PyTypeObject ROPium_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ROPium",                         /* tp_name */
    sizeof(ROPium_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)ROPium_dealloc,       /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "ROPium: automatic ropchain finder",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    ROPium_methods,                   /* tp_methods */
    ROPium_members,                   /* tp_members */
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

PyObject* get_ROPium_Type(){
    return (PyObject*)&ROPium_Type;
};

/* Constructor */
PyObject* ropium_ROPium(PyObject* self, PyObject* args){
    ROPium_Object* object;
    int arch;

    // Parse arguments
    if( ! PyArg_ParseTuple(args, "i", &arch) ){
        return NULL;
    }

    // Create object
    try{
        PyType_Ready(&ROPium_Type);
        object = PyObject_New(ROPium_Object, &ROPium_Type);
        if( object != nullptr ){
            // Set architecture
            switch ( (ArchType)arch){
                case ArchType::X86: object->arch = new ArchX86(); break;
                case ArchType::X64: object->arch = new ArchX64(); break;
                default: return PyErr_Format(PyExc_ValueError, "This architecture isn't supported yet");
            }
            // Set compiler
            object->compiler = new ROPCompiler(object->arch, &(object->gadget_db));
        }
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return (PyObject*)object;
}
