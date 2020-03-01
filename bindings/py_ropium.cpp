#include "python_bindings.hpp"
#include <cstdio>
#include <fstream>

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
    int filenum = 0;
    stringstream ss;
    string gadget_file; 
    string ropgadget_tmp_file;
    int max_filenum = 0x7fffffff; 

    vector<RawGadget>* raw = nullptr;

    if( ! PyArg_ParseTuple(args, "s#", &filename, &filename_len) ){
        return NULL;
    }

    // Get available file to dump gadgets
    for( filenum = 0; filenum < max_filenum; filenum++){
        ss.str("");
        ss << ".ropium_raw_gadgets." << filenum;
        gadget_file = ss.str();
        // Test if file exists
        std::ifstream fin(gadget_file);
        if( !fin ){
            break; // File doesn't exist
        }else{
            fin.close(); // Try next filenum
        }
    }

    if( filenum == max_filenum ){
        return PyErr_Format(PyExc_RuntimeError, "Couldn't create new file where to dump gadgets");
    }

    ss.str("");
        ss << ".ropgadget_output." << filenum,
        ropgadget_tmp_file = ss.str();

    try{
        // Try to load binary and get gadgets using ROPgadget for now
        if( ! ropgadget_to_file(gadget_file, ropgadget_tmp_file, filename)){
            return PyErr_Format(PyExc_RuntimeError, "Couldn't analyse binary with ROPgadget");
        }
        raw = raw_gadgets_from_file(gadget_file);
        as_ropium_object(self).gadget_db->analyse_raw_gadgets(*raw, as_ropium_object(self).arch);
        delete raw; raw = nullptr;
        remove(gadget_file.c_str());
        remove(ropgadget_tmp_file.c_str());
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
        ropchain = as_ropium_object(self).compiler->compile( string(query, query_len), 
                as_ropium_object(self).constraint, as_ropium_object(self).abi, as_ropium_object(self).system); 
        if( ropchain ){
            return Pyropchain_FromROPChain(ropchain);
        }
    }catch(il_exception& e){
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(compiler_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    Py_RETURN_NONE;
};

static PyMethodDef ROPium_methods[] = {
    {"load", (PyCFunction)ROPium_load, METH_VARARGS, "load(<filename>) \nLoad and analyse gadgets from a binary"},
    {"compile", (PyCFunction)ROPium_compile, METH_VARARGS, "compile(<query>) \nCompile a semantic query into a ropchain"},
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

static PyObject* ROPium_get_keep_regs(PyObject* self, void* closure){
    PyObject* list;
    
    list = PyList_New(0);
    if( list == NULL ){
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    // Add bad bytes to list
    for (int i = 0; i < as_ropium_object(self).arch->nb_regs; i++){
        if( as_ropium_object(self).constraint->keep_regs.is_kept(i) ){
            if( PyList_Append(list, PyUnicode_FromString( as_ropium_object(self).arch->reg_name(i).c_str())) == -1){
                return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add register name to python list");
            }
        }
    }
    return list;
}

static int ROPium_set_keep_regs(PyObject* self, PyObject* list, void* closure){
    PyObject *item;
    Py_ssize_t size;
    string name;
    int reg_num;

    if( ! PyList_Check(list)){
        PyErr_SetString(PyExc_RuntimeError, "Expected a list of str");
        return -1;
    }

    size = PyList_Size(list);
    
    // Clear previous regs
    as_ropium_object(self).constraint->keep_regs.clear();

    // Add new regs
    for( int i = 0; i < size; i++){
        item = PyList_GetItem(list, i);
        if( item == NULL ){
            PyErr_SetString(PyExc_RuntimeError, "Error getting item in supplied list");
            return -1;
        }
        if( ! PyUnicode_Check(item) ){
            PyErr_SetString(PyExc_ValueError, "Registers must be specified as strings: 'eax', 'ebx', ...");
            return -1;
        }
        name = string((char*)PyUnicode_DATA(item));
        try{
            reg_num = as_ropium_object(self).arch->reg_num(name);
        }catch(runtime_exception& e){
            PyErr_Format(PyExc_ValueError, "Invalid register: %s", name.c_str());
            return -1;
        }
        // Add keep reg
        as_ropium_object(self).constraint->keep_regs.add_keep_reg(reg_num);
    }

    return 0;
}

static PyObject* ROPium_get_arch(PyObject* self, void* closure){
    return PyLong_FromLong((int)(as_ropium_object(self).arch->type));
}

static PyObject* ROPium_get_abi(PyObject* self, void* closure){
    return PyLong_FromLong((int)(as_ropium_object(self).abi));
}

static int ROPium_set_abi(PyObject* self, PyObject* val, void* closure){
    int abi;

    if( ! PyLong_Check(val)){
        PyErr_SetString(PyExc_RuntimeError, "Argument should be a ABI.* enum value");
        return -1;
    }

    abi = PyLong_AsLong(val);
    as_ropium_object(self).abi = (ABI)abi;

    return 0;
}

static PyObject* ROPium_get_os(PyObject* self, void* closure){
    return PyLong_FromLong((int)(as_ropium_object(self).system));
}

static int ROPium_set_os(PyObject* self, PyObject* val, void* closure){
    int system;

    if( ! PyLong_Check(val)){
        PyErr_SetString(PyExc_RuntimeError, "Argument should be a OS.* enum value");
        return -1;
    }

    system = PyLong_AsLong(val);
    as_ropium_object(self).system = (System)system;

    return 0;
}


static PyGetSetDef ROPium_getset[] = {
    {"bad_bytes", ROPium_get_bad_bytes, ROPium_set_bad_bytes, "Bad bytes that must not occur in the ropchains", NULL},
    {"keep_regs", ROPium_get_keep_regs, ROPium_set_keep_regs, "Registers that should not be clobbered by the ropchains", NULL},
    {"safe_mem", ROPium_get_safe_mem, ROPium_set_safe_mem, "Indicates whether ropchains can contain gadgets that perform potentially unsafe register dereferencing", NULL},
    {"arch", ROPium_get_arch, NULL, "Architecture type", NULL},
    {"abi", ROPium_get_abi, ROPium_set_abi, "ABI to use when calling functions", NULL},
    {"os", ROPium_get_os, ROPium_set_os, "OS to target when doing syscalls", NULL},
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
            as_ropium_object(object).abi = ABI::NONE;
            as_ropium_object(object).system = System::NONE;
        }
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return (PyObject*)object;
}
