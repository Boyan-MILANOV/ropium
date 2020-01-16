#include "python_bindings.hpp"
#include <cstdio>

/* -------------------------------------
 *          ROPium object
 * ------------------------------------ */

static void ROPium_dealloc(PyObject* self){
    delete ((ROPium_Object*)self)->compiler;  ((ROPium_Object*)self)->compiler = nullptr;
    delete ((ROPium_Object*)self)->arch;  ((ROPium_Object*)self)->arch = nullptr;
    delete ((ROPium_Object*)self)->gadget_db;  ((ROPium_Object*)self)->gadget_db = nullptr;
    delete ((ROPium_Object*)self)->constraint;  ((ROPium_Object*)self)->constraint = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* ROPium_load(PyObject* self, PyObject* args){
    const char* filename;
    int filename_len;
    string gadget_file = string(".raw_gadgets.ropium");
    vector<RawGadget>* raw = nullptr;

    if( ! PyArg_ParseTuple(args, "s#", &filename, &filename_len) ){
        return NULL;
    }

    try{
        // Try to load binary and get gadgets using ROPgadget for now
        if( ! ropgadget_to_file(gadget_file, filename)){
            return PyErr_Format(PyExc_RuntimeError, "Couldn't analyse binary with ROPgadget");
        }
        raw = raw_gadgets_from_file(gadget_file);
        as_ropium_object(self).gadget_db->analyse_raw_gadgets(*raw, as_ropium_object(self).arch);
        delete raw; raw = nullptr; 
        remove(gadget_file.c_str());
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    Py_RETURN_NONE;
};

static PyObject* ROPium_compile(PyObject* self, PyObject* args){
    const char* query;
    int query_len;
    ROPChain* ropchain;

    if( ! PyArg_ParseTuple(args, "s#", &query, &query_len) ){
        return NULL;
    }

    try{
        // TODO Return proper ropchain
        ropchain = as_ropium_object(self).compiler->compile( string(query, query_len), as_ropium_object(self).constraint); 
        if( ropchain ){
            std::cout << "Found:" <<  std::endl << *ropchain << std::endl;
        }else{
            std::cout << "No ropchain found" << std::endl; 
        }
    }catch(il_exception& e){
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    Py_RETURN_NONE;
};

static PyMethodDef ROPium_methods[] = {
    {"load", (PyCFunction)ROPium_load, METH_VARARGS, "Load and analyse gadgets from a binary"},
    {"compile", (PyCFunction)ROPium_compile, METH_VARARGS, "Compile a semantic query into a ropchain"},
    {NULL, NULL, 0, NULL}
};

// Get/Set Attributes
static PyObject* ROPium_get_bad_bytes(PyObject* self, void* closure){
    PyObject* list;
    
    list = PyList_New(0);
    if( list == NULL ){
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    // Add bad bytes to list
    for (int i = 0; i < 0x100; i++){
        if( !as_ropium_object(self).constraint->bad_bytes.is_valid_byte(i) ){
            if( PyList_Append(list, PyLong_FromLong(i)) == -1){
                return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add bad byte to python list");
            }
        }
    }
    return list;
}

static int ROPium_set_bad_bytes(PyObject* self, PyObject* list, void* closure){
    PyObject *item;
    Py_ssize_t size;

    if( ! PyList_Check(list)){
        PyErr_SetString(PyExc_RuntimeError, "Expected a list of integers");
        return -1;
    }

    size = PyList_Size(list);
    
    // Clear previous bad bytes
    as_ropium_object(self).constraint->bad_bytes.clear();
    
    // Add new bad bytes
    for( int i = 0; i < size; i++){
        item = PyList_GetItem(list, i);
        if( item == NULL ){
            PyErr_SetString(PyExc_RuntimeError, "Error getting item in supplied list");
            return -1;
        }
        if( ! PyLong_Check(item) || PyLong_AsUnsignedLong(item) > 0xff ){
            PyErr_SetString(PyExc_ValueError, "Bad bytes list has incorrect element(s)");
            return -1;
        }
        // Add bad byte
        as_ropium_object(self).constraint->bad_bytes.add_bad_byte(PyLong_AsUnsignedLong(item));
    }

    return 0;
}

static PyObject* ROPium_get_safe_mem(PyObject* self, void* closure){
    
    if( as_ropium_object(self).constraint->mem_safety.is_enforced())
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static int ROPium_set_safe_mem(PyObject* self, PyObject* val, void* closure){

    if( ! PyBool_Check(val)){
        PyErr_SetString(PyExc_RuntimeError, "Excepted a boolean value");
        return -1;
    }
    
    if( val == Py_True ){
        as_ropium_object(self).constraint->mem_safety.force_safe();
    }else{
        as_ropium_object(self).constraint->mem_safety.enable_unsafe();
    }

    return 0;
}

static PyGetSetDef ROPium_getset[] = {
    {"bad_bytes", ROPium_get_bad_bytes, ROPium_set_bad_bytes, "Bad bytes that must not occur in the ropchains", NULL},
    {"safe_mem", ROPium_get_safe_mem, ROPium_set_safe_mem, "Indicates whether ropchains can contain gadgets that perform potentially unsafe register dereferencing", NULL},
    {NULL}
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
    ROPium_methods,                           /* tp_methods */
    ROPium_members,                           /* tp_members */
    ROPium_getset,                            /* tp_getset */
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
            // Set constraint
            object->constraint = new Constraint();
            // Set architecture
            switch ( (ArchType)arch){
                case ArchType::X86: as_ropium_object(object).arch = new ArchX86(); break;
                case ArchType::X64: as_ropium_object(object).arch = new ArchX64(); break;
                default: return PyErr_Format(PyExc_ValueError, "This architecture isn't supported yet");
            }
            // Set gadget db
            as_ropium_object(object).gadget_db = new GadgetDB();
            // Set compiler
            as_ropium_object(object).compiler = new ROPCompiler(object->arch, (object->gadget_db));
        }
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return (PyObject*)object;
}
