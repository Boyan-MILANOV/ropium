#include "disassembler.hpp"
#include <iostream>

Disassembler::~Disassembler(){
        cs_free(_insn, 1);
        _insn = nullptr;
        cs_close(&_handle);
}
