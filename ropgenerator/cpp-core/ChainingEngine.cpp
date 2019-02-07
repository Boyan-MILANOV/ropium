#include "ChainingEngine.hpp"
#include <cstring>

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */

DestArg::DestArg(DestType t, int r, cst_t c):type(t), reg(r), cst(c){}  /* For DEST_REG */ 
DestArg::DestArg(DestType t, int addr_r, cst_t addr_c, cst_t c ): type(t), 
    addr_reg(addr_r), addr_cst(addr_c), cst(c){} /* For DEST_MEM */
DestArg::DestArg(DestType t, cst_t addr_c, cst_t c): type(t), addr_cst(addr_c), cst(c){} /* For DEST_CSTMEM */

AssignArg::AssignArg(AssignType t, cst_t c):type(t), cst(c){} /* For ASSIGN_CST */
AssignArg::AssignArg(AssignType t, int r, IROperation o, cst_t c):type(t), reg(r), op(o), cst(c){} /* For ASSIGN_REG_BINOP_CST */
AssignArg::AssignArg(AssignType t, int ar, IROperation o, cst_t ac, cst_t c):type(t), addr_reg(ar), addr_cst(ac), op(o), cst(c){} /* For ASSIGN_MEM_BINOP_CST */
AssignArg::AssignArg(AssignType t, cst_t ac, cst_t c):type(t), addr_cst(ac), cst(c){} /* For ASSIGN_CST_MEM */
AssignArg::AssignArg(AssignType t):type(t){} /* For ASSIGN_SYSCALL and INT80 */ 


/* ***************************************************
 *                    FailRecord
 * ************************************************* */ 


FailRecord::FailRecord(){
    _max_len = false;
    memset(_modified_reg, false, NB_REGS_MAX);
}

FailRecord::FailRecord(bool max_len): _max_len(max_len){
    memset(_modified_reg, false, NB_REGS_MAX);
    memset(_bad_bytes, false, 256);
}
 
bool FailRecord::max_len(){ return _max_len;}
bool FailRecord::modified_reg(int reg_num){ return _modified_reg[reg_num];}
bool* FailRecord::bad_bytes(){ return _bad_bytes;}

void FailRecord::set_max_len(bool val){ _max_len = val;}
void FailRecord::add_modified_reg(int reg_num){ _modified_reg[reg_num] = true;}
void FailRecord::add_bad_byte(unsigned char bad_byte){ _bad_bytes[bad_byte] = true; }

/* ***************************************************
 *                RegTransitivityRecord
 * ************************************************* */ 

Binop record_op_list[NB_OP_RECORD] = {OP_ADD, OP_SUB, OP_MUL, OP_DIV};
/* !! If constants are changed, don't forget to chage the *_index() functions implementation
 * in the .c */ 
cst_t record_cst_list_addsub[NB_CST_RECORD] = {-32,-16, -8, -4, -2, -1, 0,1,2,4,8,16,32};
int record_cst_list_addsub_index(cst_t c); // Inverts record_cst_list_addsub
cst_t record_cst_list_muldiv[NB_CST_RECORD] = {2, 3, 4,8,16,32,64, 128, 256, 512, 1024, 2048, 4092};
int record_cst_list_muldiv_index(cst_t c); // Inverts record_cst_list_muldiv
 
int record_cst_list_addsub_index(cst_t c){
    switch(c){
        case -32:
            return 0; 
        case -16:
            return 1; 
        case -8:
            return 2;
        case -4:
            return 3; 
        case -2:
            return 4; 
        case -1:
            return 5; 
        case 0:
            return 6;
        case 1:
            return 7;
        case 2:
            return 8;
        case 4:
            return 9;
        case 8:
            return 10;
        case 16:
            return 11;
        case 32:
            return 12;
        default:
            return -1; 
    }
}

int record_cst_list_muldiv_index(cst_t c){
    switch(c){
        case 2:
            return 0; 
        case 3:
            return 1; 
        case 4:
            return 2;
        case 8:
            return 3; 
        case 16:
            return 4; 
        case 32:
            return 5; 
        case 64:
            return 6;
        case 128:
            return 7;
        case 256:
            return 8;
        case 512:
            return 9;
        case 1024:
            return 10;
        case 2048:
            return 11;
        case 4092:
            return 12;
        default:
            return -1; 
    } 
}

void RegTransitivityRecord::add_fail(int dest_reg, int src_reg, Binop op, cst_t src_cst, Constraint* constr){
    int cst_index;
    vector<cstr_sig_t>::iterator it; 
    cstr_sig_t sig; 
    bool added=false, already=false;
    // Check regs
    if( dest_reg >= NB_REG_RECORD || src_reg >= NB_REG_RECORD )
        return;
    // Check cst and operation
    if( op == OP_ADD || op == OP_SUB ){
        if( (cst_index=record_cst_list_addsub_index(src_cst)) == -1)
            return;
    }else if( op == OP_MUL || op == OP_DIV ){
        if( (cst_index=record_cst_list_muldiv_index(src_cst)) == -1)
            return;
    }else
        return;
    // Insert in the vector...
    sig = constr->signature();
    for( it = _query[dest_reg][src_reg][op][cst_index].begin(); it != _query[dest_reg][src_reg][op][cst_index].end(); it++){
        if( (*it & sig) == sig ){
            // sig included in *it so replace *it by sig
            *it = sig; 
            added = true;
        }else if( (*it & sig) == *it ){
            // previous included in sig so we discard it
            already = true;
            break;
        }
    }
    // If not added and not already here and enough place, add it ! 
    if( (!already) && (!added) && _query[dest_reg][src_reg][op][cst_index].size() < MAX_SIGNATURES_PER_QUERY){
        _query[dest_reg][src_reg][op][cst_index].push_back(sig);
    }
}

bool RegTransitivityRecord::is_impossible(int dest_reg, int src_reg, Binop op, cst_t src_cst, Constraint* constr){
    int cst_index;
    vector<cstr_sig_t>::iterator it; 
    cstr_sig_t sig; 
    // Check regs
    if( dest_reg >= NB_REG_RECORD || src_reg >= NB_REG_RECORD )
        return false;
    // Check cst and operation
    if( op == OP_ADD || op == OP_SUB ){
        if( (cst_index=record_cst_list_addsub_index(src_cst)) == -1)
            return false;
    }else if( op == OP_MUL || op == OP_DIV ){
        if( (cst_index=record_cst_list_muldiv_index(src_cst)) == -1)
            return false;
    }else
        return false;
    // Insert in the vector...
    sig = constr->signature();
    for( it = _query[dest_reg][src_reg][op][cst_index].begin(); it != _query[dest_reg][src_reg][op][cst_index].end(); it++){
        if( (*it & sig) == *it ){
            // previous included in sig 
            return true;
        }
    }
    return false;
}

/* *********************************************************************
 *                         SearchEnvironment 
 * ******************************************************************* */ 

SearchEnvironment::SearchEnvironment(RegTransitivityRecord* reg_trans_record){
    _reg_transitivity_record = reg_trans_record;
    memset(_calls_count, 0, sizeof(_calls_count));
}

SearchEnvironment* SearchEnvironment::copy(){
    SearchEnvironment* res = new SearchEnvironment(_reg_transitivity_record);
    res->_constraint = _constraint;
    res->_assertion = _assertion;
    res->_depth = _depth;
    res->_max_depth = _max_depth;
    memcpy(res->_calls_count, _calls_count, sizeof(_calls_count));
    res->_calls_history = _calls_history;
    res->_lmax = _lmax;
    res->_no_padding = _no_padding;
    res->_fail_record = _fail_record; 
    
    return res; 
}
/* Contextual infos getters/setters */ 
Constraint* SearchEnvironment::constraint(){ return _constraint; }
void SearchEnvironment::set_constraint(Constraint* c){ _constraint = c; }
Assertion* SearchEnvironment::assertion(){return _assertion;}
void SearchEnvironment::set_assertion(Assertion* a){ _assertion = a; }
unsigned int SearchEnvironment::lmax(){return _lmax;}
void SearchEnvironment::set_lmax(unsigned int val){_lmax = val;}
unsigned int SearchEnvironment::depth(){return _depth;}
void SearchEnvironment::set_depth(unsigned int val){_depth = val;}
bool SearchEnvironment::no_padding(){return _no_padding;}
void SearchEnvironment::set_no_padding(bool val){_no_padding = val;}
void SearchEnvironment::add_call(SearchStrategyType type){
    _calls_count[type]++;
    _calls_history.push_back(type);
}
void SearchEnvironment::remove_last_call(){
    SearchStrategyType type = _calls_history.back();
    _calls_count[type]--;
    _calls_history.pop_back();
}
int SearchEnvironment::calls_count(SearchStrategyType type){
    return _calls_count[type];
}
bool SearchEnvironment::reached_max_depth(){
    return _depth > _max_depth;
}

/* Record functions */ 
RegTransitivityRecord* SearchEnvironment::reg_transitivity_record(){
    return _reg_transitivity_record;
}
FailRecord* SearchEnvironment::fail_record(){
    return &_fail_record;
}

