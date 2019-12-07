#include "ropchain.hpp"

Gadget::Gadget():semantics(nullptr), bin_num(-1){}
Gadget::~Gadget(){
    delete semantics;
    semantics = nullptr;
}
void Gadget::print(ostream& os){
    os << asm_str;
}

bool Gadget::lthan(shared_ptr<Gadget> other){
    if( nb_instr != other->nb_instr ){
        return nb_instr < other->nb_instr;
    }else{
        return nb_instr_ir < other->nb_instr_ir; 
    }
}
