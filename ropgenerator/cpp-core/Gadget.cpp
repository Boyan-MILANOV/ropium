#include "Gadget.hpp"
#include "Architecture.hpp"
#include "Expression.hpp"
#include "CommonUtils.hpp"
#include "Exception.hpp"
#include "Condition.hpp"
#include <cstring>


/* *********************************************************************
 *                          Global variables
 * ******************************************************************* */
addr_t g_gadgets_offset=0;

void set_gadgets_offset(addr_t offset){
    g_gadgets_offset=offset;
}

addr_t get_gadgets_offset(){
    return g_gadgets_offset;
}

/* *********************************************************************
 *                          Gadget class 
 * ******************************************************************* */

CondObjectPtr generate_mem_pre_cond(vector<ExprObjectPtr>& read_list, vector<ExprObjectPtr>& write_list){
    CondObjectPtr res;
    vector<ExprObjectPtr>::iterator eit;
    bool regs[NB_REGS_MAX];
    
    memset(regs, false, sizeof(regs));

    // Get the pre-conditions
    res = NewCondTrue();
    for( eit = write_list.begin(); eit != write_list.end(); eit++){
        // Check for supported addresses for memory accesses
        // mem(reg)
        if( (*eit)->expr_ptr()->type() == EXPR_REG ){
            if( !regs[(*eit)->expr_ptr()->num()] ) {
                res = res && NewCondPointer(COND_VALID_WRITE, *eit);
                regs[(*eit)->expr_ptr()->num()] = true;
            }
        }//mem(reg +- cst)
        else if( (*eit)->expr_ptr()->type() == EXPR_BINOP && 
                  (*eit)->expr_ptr()->right_expr_ptr()->type() == EXPR_CST &&
                  (*eit)->expr_ptr()->left_expr_ptr()->type() == EXPR_REG &&
                  ((*eit)->expr_ptr()->binop() == OP_ADD || (*eit)->expr_ptr()->binop() == OP_SUB)
                  ){
            if( !regs[(*eit)->expr_ptr()->left_expr_ptr()->num()] ) {
                res = res && NewCondPointer(COND_VALID_WRITE, *eit);
                regs[(*eit)->expr_ptr()->left_expr_ptr()->num()] = true;
            }
        }// others are not supported
        else{
            return NewCondFalse();
        }
    }
    // DO the same for memory reads
    for( eit = read_list.begin(); eit != read_list.end(); eit++){
        // Check for supported addresses for memory accesses
        // mem(reg)
        if( (*eit)->expr_ptr()->type() == EXPR_REG ){
            if( !regs[(*eit)->expr_ptr()->num()] ) {
                res = res && NewCondPointer(COND_VALID_READ, *eit);
                regs[(*eit)->expr_ptr()->num()] = true;
            }
        }//mem(reg +- cst)
        else if( (*eit)->expr_ptr()->type() == EXPR_BINOP && 
                  (*eit)->expr_ptr()->right_expr_ptr()->type() == EXPR_CST &&
                  (*eit)->expr_ptr()->left_expr_ptr()->type() == EXPR_REG &&
                  ((*eit)->expr_ptr()->binop() == OP_ADD || (*eit)->expr_ptr()->binop() == OP_SUB)
                  ){
            if( !regs[(*eit)->expr_ptr()->left_expr_ptr()->num()] ) {
                res = res && NewCondPointer(COND_VALID_READ, *eit);
                regs[(*eit)->expr_ptr()->left_expr_ptr()->num()] = true;
            }
        }// others are not supported
        else{
            return NewCondFalse();
        }
    }
    
    return res;
}


// Special gadget
Gadget::Gadget(GadgetType special_type){
    /* DEBUG FOR LATER: 
     * Maybe keep only specials that have the form <special_instr> + <normal gadget>
     * Then we build a gadget from <normal gadget>, and change the appropriate fields afterwards
     * to make it special. THis way we allow syscall; ret;  or int 0x80; pop rax; ret;  etc...
     *  */ 
    
    int i;
    // Set type
    _type = special_type;
    // Null semantics 
    _semantics = nullptr;
    // Get the registers that have been modified 
    for( i = 0; i < NB_REGS_MAX; i++)
        _reg_modified[i] = false;
        
    // nb instructions (set to 0, o be set later)
    _nb_instr = 1;
    _nb_instr_ir = 1;
        
    // Get the sp_inc 
    _known_sp_inc = true;
    _sp_inc = 0;
    // Get the memory reads and writes from the irblock 
    _mem_pre_cond = NewCondTrue();
    
    // Get the return type
    // Test for ret/jmp 
    _ret_type = RET_UNKNOWN; 
    _ret_reg = -1; 
    _ret_pre_cond = nullptr;
}

// Constructor
Gadget::Gadget(shared_ptr<IRBlock> irblock){
    vector<reg_pair>::iterator reg_it;
    vector<SPair>::iterator spair_it;
    vector<SPair>* p;
    vector<ExprObjectPtr>::iterator eit;
    int i, ret_reg;
    bool is_inc;
    cst_t inc;
    CondObjectPtr tmp;
    // Set the type
    _type = REGULAR; 
    
    // Get the semantics 
    _semantics = irblock->compute_semantics(true); 
    _semantics->simplify(); 
    _semantics->tweak(true);
    //_semantics->filter(); 
    
    // Set the different fields
    // Get the registers that have been modified 
    for( i = 0; i < NB_REGS_MAX; i++)
        _reg_modified[i] = irblock->reg_modified(i); 
    
    // nb instructions (set to 0, o be set later)
    _nb_instr = 0;
    _nb_instr_ir = 0;
        
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
    _mem_pre_cond = generate_mem_pre_cond(_mem_read, _mem_write);
    
    // Get the return type
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
                // We don't break here because if we have a ret we keep the ret 
                // (when both ret and jmp, it's a gadget like mov [mem],reg; ret,
                // with a condition mem==rsp that makes it possibly a jmp to reg...,
                // so we keep only the ret behaviour)
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
    // Test for call in python part 
    if( _ret_type == RET_UNKNOWN ){
        _ret_reg = -1; 
        _ret_pre_cond = NewCondFalse(); 
    }
    
}

// Accessors 
GadgetType Gadget::type(){return _type;}
/* We return a new vector everytime because it changes 
 * depending on the offset :) */  
vector<addr_t>* Gadget::addresses(){
    vector<addr_t>::iterator it;
    vector<addr_t>* res = new vector<addr_t>();
    for( it = _addresses.begin(); it != _addresses.end(); it++){
        res->push_back(*it + g_gadgets_offset);
    }
    return res;
}

string Gadget::asm_str(){return _asm_str;}
string Gadget::hex_str(){return _hex_str;}
int Gadget::nb_instr(){return _nb_instr;}
int Gadget::nb_instr_ir(){return _nb_instr_ir;}
int Gadget::sp_inc(){return _sp_inc;}
bool Gadget::known_sp_inc(){return _known_sp_inc;}
bool* Gadget::modified_regs(){return _reg_modified;}
bool Gadget::modified_reg(int num){return _reg_modified[num];}
vector<ExprObjectPtr>* Gadget::mem_read(){return &_mem_read;} 
vector<ExprObjectPtr>* Gadget::mem_write(){return &_mem_write;} 
RetType Gadget::ret_type(){return _ret_type;}
int Gadget::ret_reg(){return _ret_reg;}
CondObjectPtr Gadget::ret_pre_cond(){return _ret_pre_cond;}
CondObjectPtr Gadget::mem_pre_cond(){return _mem_pre_cond;}
Semantics* Gadget::semantics(){return _semantics;}
// Modifiers
void Gadget::add_address(addr_t addr){
    _addresses.push_back(addr);
}
void Gadget::set_ret_type(RetType t){
    _ret_type = t;
}

void Gadget::set_asm_str(string s){
    _asm_str = s;
}
void Gadget::set_hex_str(string s){
    _hex_str = s;
}
void Gadget::set_nb_instr(int nb){
    _nb_instr = nb;
}
void Gadget::set_nb_instr_ir(int nb){
    _nb_instr_ir = nb;
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
    // Misc 
    os << "Gadget" << endl; 
    os << "\tAssembly: " << _asm_str << endl; 
    os << "\tHex: " << _hex_str << endl; 
    os << "\tAvailable addresses: "; 
    for( it = _addresses.begin(); it != _addresses.end(); it++)
        os << value_to_hex_str(curr_arch()->octets(), *it);
    os << endl; 
    // Return type
    os << "\tReturn type: ";
    if( _ret_type == RET_RET )
        os << "RET";
    else if( _ret_type == RET_JMP)
        os << "JMP " << curr_arch()->reg_name(_ret_reg);
    else if( _ret_type == RET_CALL)
        os << "CALL " << curr_arch()->reg_name(_ret_reg);
    else 
        os << "UNKNOWN";
    os << endl;
    // SP inc
    if( _known_sp_inc )
        os << "\tSP increment: " << _sp_inc << endl; 
    else
        os << "\tSP increment: Unknown" << endl; 
    os << "\tReading memory at: ";
    // Memory acess
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
            os << curr_arch()->reg_name(i) << " "; 
    // Semantics 
    _semantics->print(os);
    os << endl;
}

bool Gadget::lthan(shared_ptr<Gadget> other){
    /* If one doesn't have sp_inc info, the one that has is "smaller" */
    if( !_known_sp_inc && other->known_sp_inc()){
        return false;
    }else if( _known_sp_inc && !other->known_sp_inc()){
        return true;
    /* Else if sp_inc are different, check which one */ 
    }else if( _known_sp_inc && other->known_sp_inc() &&  _sp_inc >= 0 && other->sp_inc() >= 0 && _sp_inc != other->sp_inc()){
        return _sp_inc < other->sp_inc();
    /* Else if equal or both unknown, check other stuff */
    }else if( _nb_instr != other->nb_instr() ){
        return _nb_instr < other->nb_instr();
    }else{
        return _nb_instr_ir < other->nb_instr_ir(); 
    }
    /* TODO: maybe check also pre-conditions and mem accesses, also return types ? */
}

ostream& operator<<(ostream& os, Gadget* g){
    g->print(os); 
    return os;
}

