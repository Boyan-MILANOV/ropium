#include "Gadget.hpp"

// Constructor 
Gadget::Gadget(IRBlock* irblock){
    _semantics = irblock->compute_semantics();
    // Set the different fields 
    // TODO !!!! 
}
// Accessors 
GadgetType Gadget::type(){return _type;}
vector<addr_t>* Gadget::addresses(){return &_addresses;}
string Gadget::asm_str(){return _asm_str;}
string Gadget::hex_str(){return _hex_str;}
int Gadget::nb_instr(){return _nb_instr;}
int Gadget::nb_instr_ir(){return _nb_instr_ir;}
int Gadget::sp_inc(){return _sp_inc;}
vector<int>* Gadget::reg_modified(){return &_reg_modified;} 
vector<ExprObjectPtr>* Gadget::mem_read(){return &_mem_read;} 
vector<ExprObjectPtr>* Gadget::mem_write(){return &_mem_write;} 
RetType Gadget::ret_type(){return _ret_type;}
Semantics* Gadget::semantics(){return _semantics;}
// Modifiers
void Gadget::add_address(addr_t addr){
    _addresses.push_back(addr);
}

// Destructor 
Gadget::~Gadget(){
    delete _semantics; 
}
