#include "assertion.hpp"
#include <algorithm>


void ValidPointers::add_valid_pointer(int reg){
    _regs.push_back(reg);
}

bool ValidPointers::is_valid_pointer(int reg){
    return std::find(_regs.begin(), _regs.end(), reg) != _regs.end();
}

void ValidPointers::clear(){
    _regs.clear();
}



void Assertion::clear(){
    valid_pointers.clear();
}
