#include "Gadget.hpp"
#include "Architecture.hpp"

// Constructor 
Gadget::Gadget(IRBlock* irblock){
    vector<reg_pair>::iterator reg_it; 
    vector<SPair>::iterator spair_it; 
    vector<SPair>* p;
    int i;
    bool is_inc; 
    cst_t inc; 
    
    // Get the semantics 
    _semantics = irblock->compute_semantics();
    // Set the different fields 
    // Get the registers that have been modified 
    for( i = 0; i < NB_REGS_MAX; i++)
        _reg_modified[i] = false; 
    for( reg_it = _semantics->regs().begin(); reg_it !=  _semantics->regs().end(); reg_it++ ){
        // For each register check if it has been modified
        for( spair_it = reg_it->second->begin(); spair_it != reg_it->second->end(); spair_it++){
            if( spair_it->cond_ptr()->is_true() &&
                spair_it->expr_ptr()->type() == EXPR_REG && 
                spair_it->expr_ptr()->num() == reg_it->first){
                _reg_modified[reg_it->first] = true; 
                break; 
            }
        }
    }
    // Get the sp_inc 
    _valid_sp_inc = false; 
    if( (p = _semantics->get_reg(curr_arch()->sp())) != nullptr){
        for( spair_it = p->begin(); spair_it != p->end(); spair_it++){
            if( spair_it->cond_ptr()->is_true() ){
                std::tie(is_inc, inc) = spair_it->expr_ptr()->is_reg_increment(curr_arch()->sp());
                if( is_inc ){
                    _sp_inc = inc; 
                    _valid_sp_inc = true; 
                    break;
                }
            }
        }
    }else{
        _valid_sp_inc = true;
        _sp_inc = 0; 
    }
    // Get the memory reads and writes from the irblock 
    _mem_read = irblock->mem_reads();
    _mem_write = irblock->mem_writes();
    
}
// Accessors 
GadgetType Gadget::type(){return _type;}
vector<addr_t>* Gadget::addresses(){return &_addresses;}
string Gadget::asm_str(){return _asm_str;}
string Gadget::hex_str(){return _hex_str;}
int Gadget::nb_instr(){return _nb_instr;}
int Gadget::nb_instr_ir(){return _nb_instr_ir;}
int Gadget::sp_inc(){return _sp_inc;}
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
