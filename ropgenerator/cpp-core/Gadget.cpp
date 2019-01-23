#include "Gadget.hpp"
#include "Architecture.hpp"
#include "Expression.hpp"
#include "CommonUtils.hpp"
#include "Exception.hpp"

// Constructor 
Gadget::Gadget(shared_ptr<IRBlock> irblock){
    vector<reg_pair>::iterator reg_it; 
    vector<SPair>::iterator spair_it; 
    vector<SPair>* p;
    int i, ret_reg;
    bool is_inc;
    cst_t inc;

    // Get the semantics 
    _semantics = irblock->compute_semantics(true); 
    // DEBUG
    _semantics->simplify(); 
    _semantics->filter(); 
    
    // Set the different fields 
    // Get the registers that have been modified 
    for( i = 0; i < NB_REGS_MAX; i++)
        _reg_modified[i] = irblock->reg_modified(i); 
        
    // Get the sp_inc 
    _known_sp_inc = false; 
    if( (p = _semantics->get_reg(curr_arch()->sp())) != nullptr){
        for( spair_it = p->begin(); spair_it != p->end(); spair_it++){
            if( spair_it->cond_ptr()->is_true() ){
                std::tie(is_inc, inc) = spair_it->expr_ptr()->is_reg_increment(curr_arch()->sp());
                if( is_inc ){
                    _sp_inc = inc; 
                    _known_sp_inc = true; 
                    break;
                }
            }
        }
    }else{
        _known_sp_inc = true;
        _sp_inc = 0; 
    }
    // Get the memory reads and writes from the irblock 
    _mem_read = irblock->mem_reads();
    _mem_write = irblock->mem_writes();
    // Get the return type
    // Test for call
    // TODO
    // Test for ret/jmp 
    _ret_type = RET_UNKNOWN; 
    if( _known_sp_inc && ((p = _semantics->get_reg(curr_arch()->ip())) != nullptr)){
        for( spair_it = p->begin(); spair_it != p->end(); spair_it++){
            // Is it jmp ? 
            std::tie(is_inc, ret_reg, inc) = spair_it->expr_ptr()->is_reg_increment();
            if( is_inc ){
                _ret_reg = ret_reg;  
                _ret_type = RET_JMP;
                _ret_pre_cond = spair_it->cond();  
                break;
            }else if( spair_it->expr_ptr()->type() == EXPR_MEM ){
                std::tie(is_inc, inc) = spair_it->expr_ptr()->addr_expr_ptr()->is_reg_increment(curr_arch()->sp());
                if( is_inc && (inc == _sp_inc - curr_arch()->octets())){
                    _ret_type = RET_RET; 
                    _ret_reg = -1; 
                    _ret_pre_cond = spair_it->cond(); 
                    break; 
                }
            }
        }
    }
    if( _ret_type == RET_UNKNOWN ){
        _ret_reg = -1; 
        _ret_pre_cond = NewCondFalse(); 
    }
    
}

// Accessors 
GadgetType Gadget::type(){return _type;}
vector<addr_t> Gadget::addresses(){return _addresses;}
string Gadget::asm_str(){return _asm_str;}
string Gadget::hex_str(){return _hex_str;}
int Gadget::nb_instr(){return _nb_instr;}
int Gadget::nb_instr_ir(){return _nb_instr_ir;}
int Gadget::sp_inc(){return _sp_inc;}
bool Gadget::known_sp_inc(){return _known_sp_inc;}
bool* Gadget::modified_regs(){return _reg_modified;}
vector<ExprObjectPtr>* Gadget::mem_read(){return &_mem_read;} 
vector<ExprObjectPtr>* Gadget::mem_write(){return &_mem_write;} 
RetType Gadget::ret_type(){return _ret_type;}
CondObjectPtr Gadget::ret_pre_cond(){return _ret_pre_cond;}
Semantics* Gadget::semantics(){return _semantics;}
// Modifiers
void Gadget::add_address(addr_t addr){
    _addresses.push_back(addr);
}
void Gadget::set_asm_str(string s){
    _asm_str = s;
}
void Gadget::set_hex_str(string s){
    _hex_str = s;
}

// Destructor 
Gadget::~Gadget(){
    delete _semantics; 
}
// Other
void Gadget::print(ostream& os){
    int i;
    vector<addr_t>::iterator it; 
    vector<ExprObjectPtr>::iterator pit; 
    os << "Gadget" << endl; 
    os << "\tAssembly: " << _asm_str << endl; 
    os << "\tHex: " << _hex_str << endl; 
    os << "\tAvailable addresses: "; 
    for( it = _addresses.begin(); it != _addresses.end(); it++)
        os << value_to_hex_str(curr_arch()->octets(), *it);
    os << endl; 
    if( _known_sp_inc )
        os << "\tSP increment: " << _sp_inc << endl; 
    else
        os << "\tSP increment: Unknown" << endl; 
    os << "\tReading memory at: ";
    for( pit = _mem_read.begin(); pit != _mem_read.end(); pit++)
        os << "\n\t\t" << *pit; 
    os << endl; 
    os << "\tWriting memory at: ";
    for( pit = _mem_write.begin(); pit != _mem_write.end(); pit++)
        os << "\n\t\t" << *pit; 
    os << endl; 
    os << "\tModified registers: ";
    for( i = 0; i < NB_REGS_MAX; i++)
        if( _reg_modified[i])
            os << i << " "; 
    _semantics->print(os);
    os << endl;
}

bool Gadget::lthan(shared_ptr<Gadget> other){
    if( _known_sp_inc && other->known_sp_inc() &&
        _sp_inc < other->sp_inc() )
        return true; 
    if( _nb_instr == other->nb_instr() )
        return _nb_instr_ir < other->nb_instr_ir();
    return _nb_instr < other->nb_instr(); 
}

ostream& operator<<(ostream& os, Gadget* g){
    g->print(os); 
    return os;
}
