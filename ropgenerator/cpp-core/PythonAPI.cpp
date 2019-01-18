#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include <pybind11/iostream.h>

namespace py = pybind11;
using namespace pybind11::literals;

#include "IO.hpp"
#include "Expression.hpp"
#include "Symbolic.hpp"
#include "Architecture.hpp"
#include "Gadget.hpp"


PYBIND11_MODULE(ropgenerator_core_, m){
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
    
    py::class_<SymArg>(m, "SymArg");
    
    py::class_<ArgEmpty, SymArg>(m, "ArgEmpty")
        .def(py::init<>());

    py::class_<ArgCst, SymArg>(m, "ArgCst")
        .def(py::init<cst_t, int>());

    py::class_<ArgReg, SymArg>(m, "ArgReg")
        .def(py::init<int, int, int, int>())
        .def(py::init<int, int>());

    py::class_<ArgTmp, SymArg>(m, "ArgTmp")
        .def(py::init<int, int, int, int>())
        .def(py::init<int, int>());

    py::enum_<IROperation>(m, "IROperation", py::arithmetic(), "IR Operation")
        .value("ADD",IR_ADD)
        .value("AND",IR_AND)
        .value("BSH",IR_BSH)
        .value("DIV",IR_DIV)
        .value("LDM",IR_LDM)
        .value("MOD",IR_MOD)
        .value("MUL",IR_MUL)
        .value("NOP",IR_NOP)
        .value("OR",IR_OR)
        .value("STM",IR_STM)
        .value("LDM",IR_LDM)
        .value("STR",IR_STR)
        .value("SUB",IR_SUB) 
        .value("XOR",IR_XOR)
        .value("UNKNOWN", IR_UNKNOWN)
        .export_values(); 
        
    py::class_<IRInstruction>(m, "IRInstruction")
        .def(py::init<IROperation, SymArg, SymArg, SymArg>());
        
    py::class_<IRBlock, shared_ptr<IRBlock>>(m, "IRBlock")
        .def(py::init<>())
        .def("add_instr", &IRBlock::add_instr);
        
    m.def("print_irblock", [](shared_ptr<IRBlock> b){
        py::scoped_ostream_redirect stream(
        std::cout, // std::ostream&
        py::module::import("sys").attr("stdout") // Python output
        );
        (*b).print(std::cout);
        }
    );
        
    /* Architecture bindings */ 
    
    py::enum_<ArchType>(m, "ArchType", py::arithmetic(), "Arch Type")
        .value("ARCH_X86", ARCH_X86)
        .value("ARCH_X64", ARCH_X64)
        .export_values();
        
    py::enum_<EndiannessType>(m, "EndianessType", py::arithmetic(), "Endianness")
        .value("ENDIAN_LITTLE", ENDIAN_LITTLE)
        .value("ENDIAN_BIG", ENDIAN_BIG)
        .export_values();
    
    py::class_<Architecture>(m, "Architecture")
        .def(py::init<ArchType, string, int, int, int, int, int, EndiannessType, int, vector<int>>())
        .def("_type_", &Architecture::type)
        .def("bits", &Architecture::bits)
        .def("octets", &Architecture::octets);
    
    m.def("set_arch", &set_arch);
    m.def("curr_arch_bits", [](){return curr_arch()->bits();});
    m.def("curr_arch_type", [](){return curr_arch()->type();});
    
    
    py::enum_<RegX86>(m, "RegX86", py::arithmetic(), "X86 Registers")
        .value("EAX",X86_EAX).value("EBX",X86_EBX)
        .value("ECX",X86_ECX).value("EDX",X86_EDX)
        .value("ESI",X86_ESI).value("EDI",X86_EDX)
        .value("ESP",X86_ESP).value("EIP",X86_EIP)
        .value("EBP",X86_EBP).value("ZF",X86_ZF)
        .value("CF",X86_CF).value("SF",X86_SF)
        .value("PF",X86_PF).value("AF",X86_AF)
        .value("OF", X86_OF)
        .export_values();
        
    py::enum_<RegX64>(m, "RegX64", py::arithmetic(), "X64 Registers")
        .value("RAX",X64_RAX).value("RBX",X64_RBX).value("RCX",X64_RCX)
        .value("RDX",X64_RDX).value("RSI",X64_RSI).value("RDI",X64_RDI)
        .value("RSP",X64_RSP).value("RBP",X64_RBP).value("RIP",X64_RIP)
        .value("R8",X64_R8).value("R9",X64_R9).value("R10",X64_R10)
        .value("R11",X64_R11).value("R12",X64_R12).value("R13",X64_R13)
        .value("R14",X64_R14).value("R15",X64_R15).value("SF",X64_SF)
        .value("ZF",X64_ZF).value("AF",X64_AF).value("CF",X64_CF)
        .value("DF",X64_DF).value("ES",X64_ES).value("FS",X64_FS)
        .value("OF",X64_OF).value("PF",X64_PF)
        .export_values();
    
    py::enum_<BinType>(m, "BinType", py::arithmetic(), "Binary Type")
        .value("BIN_X86_ELF", BIN_X86_ELF)
        .value("BIN_X64_ELF", BIN_X64_ELF)
        .value("BIN_X86_PE", BIN_X86_PE)
        .value("BIN_X64_PE", BIN_X64_PE)
        .value("BIN_UNKNOWN", BIN_UNKNOWN)
        .export_values();
    
    m.def("set_bin_type", &set_bin_type);
    
    /* Gadget Bindings */ 
    
    py::class_<Gadget, shared_ptr<Gadget>>(m, "Gadget")
        .def(py::init<shared_ptr<IRBlock>>());
    m.def("print_gadget", [](shared_ptr<Gadget> g){
        py::scoped_ostream_redirect stream(
        std::cout, // std::ostream&
        py::module::import("sys").attr("stdout") // Python output
        );
        (*g).print(std::cout);
        }
    );
    
    /* Database Bindings */ 
    
    
}


