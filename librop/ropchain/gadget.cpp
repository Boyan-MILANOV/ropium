#include "ropchain.hpp"
#include <unordered_map>
#include <iostream>
#include <cstring>

using std::unordered_map;

Gadget::Gadget():semantics(nullptr), bin_num(-1), branch_type(BranchType::NONE){
    memset(modified_regs, 0, sizeof(modified_regs));
}

Gadget::~Gadget(){
    delete semantics;
    semantics = nullptr;
}

void Gadget::add_address(addr_t addr){
    addresses.push_back(addr);
}

void Gadget::print(ostream& os){
    os << "Gadget: " << asm_str << std::endl;
    for( int i = 0; i < semantics->regs->nb_vars(); i++){
        if( modified_regs[i] )
            os << "Reg_" << i << " : " << semantics->regs->get(i) << std::endl;
    }
    os << *(semantics->mem) << std::endl;
}

ostream& operator<<(ostream& os, Gadget& g){
    g.print(os);
    return os;
}

bool Gadget::lthan(Gadget& other){
    if( nb_instr != other.nb_instr ){
        return nb_instr < other.nb_instr;
    }else{
        return nb_instr_ir < other.nb_instr_ir; 
    }
}
