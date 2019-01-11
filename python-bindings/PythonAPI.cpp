#include <pybind11/pybind11.h>
namespace py = pybind11;
using namespace pybind11::literals

#include "IO.hpp"
#include "Expression.hpp"
#include "Symbolic.hpp"


PYBIND11_MODULE(_ropgenerator_core, m){
    /* IO Bindings */ 
    m.def("info", &info);
    m.def("notify", &notify);
    m.def("error",&error);
    m.def("fatal",&fatal);
    m.def("verbose",&verbose);
    m.def("banner",&banner);

    m.def("str_bold",&str_bold);
    m.def("str_special",&str_special);
    m.def("str_payload",&str_payload);
    m.def("str_ropg",&str_ropg);
    m.def("str_exploit",&str_exploit);
    m.def("str_semantic",&str_semantic);
    m.def("remove_colors",&remove_colors);

    m.def("charging_bar", &charging_bar, "nb_iter"_a, "curr_iter"_a,
        "bar_len"_a=30, "msg"_a="", "c"_a="\u2588");
    
    m.def("disable_colors", &disable_colors);
    m.def("enable_colors", &enable_colors);
    
    /* Symbolic Bindings */ 
    py::enum_<ArgType>(m, "ArgType", py::arithmetic(), "Argument types for IR operations")
        .value("empty", ARG_EMPTY)
        .value("cst", ARG_CST)
        .value("reg", ARG_REG)
        .value("tmp", ARG_TMP)
        .export_values();

    py::class_<ArgEmpty>(m, "ArgEmpty")
        .def(py::init<>());

    py::class_<ArgCst>(m, "ArgCst")
        .def(py::init<cst_t, int>());

    py::class_<ArgReg>(m, "ArgReg")
        .def(py::init<int, int, int, int>())
        .def(py::init<int, int>());

    py::class_<ArgTmp>(m, "ArgTmp")
        .def(py::init<int, int, int, int>())
        .def(py::init<int, int>());

    py::enum_<IROperation>(m, "IROperation", py::arithmetic(), "IR Operation")
        .value("add",IR_ADD)
        .value("and",IR_AND)
        .value("bsh",IR_BSH)
        .value("div",IR_DIV)
        .value("ldm",IR_LDM)
        .value("mod",IR_MOD)
        .value("mul",IR_MUL)
        .value("nop",IR_NOP)
        .value("or",IR_OR)
        .value("stm",IR_STM)
        .value("ldm",IR_LDM)
        .value("sub",IR_SUB) 
        .value("xor",IR_XOR)
        .export_values(); 
        
    py::class_<IRInstruction>(m, "IRInstruction")
        .def(py::init<IROperation, SymArg, SymArg, SymArg>());
        
    
    
    /* Database Bindings */ 
    
    
}


