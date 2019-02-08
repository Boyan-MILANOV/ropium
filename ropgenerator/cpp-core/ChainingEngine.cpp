#include "ChainingEngine.hpp"
#include "Constraint.hpp"
#include "Database.hpp"
#include "Architecture.hpp"
#include <cstring>

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */

DestArg::DestArg(DestType t, int r):type(t), reg(r){}  /* For DEST_REG */ 
DestArg::DestArg(DestType t, int addr_r, Binop o, cst_t addr_c): type(t), 
    addr_reg(addr_r), addr_cst(addr_c), addr_op(o){} /* For DEST_MEM */
DestArg::DestArg(DestType t, cst_t addr_c): type(t), addr_cst(addr_c){} /* For DEST_CSTMEM */

AssignArg::AssignArg(AssignType t, cst_t c):type(t), cst(c){} /* For ASSIGN_CST */
AssignArg::AssignArg(AssignType t, int r, Binop o, cst_t c):type(t), reg(r), op(o), cst(c){} /* For ASSIGN_REG_BINOP_CST */
AssignArg::AssignArg(AssignType t, int ar, Binop o, cst_t ac, cst_t c):type(t), addr_reg(ar), addr_cst(ac), op(o), cst(c){} /* For ASSIGN_MEM_BINOP_CST */
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
bool FailRecord::no_valid_padding(){ return _no_valid_padding;}
bool FailRecord::modified_reg(int reg_num){ return _modified_reg[reg_num];}
bool* FailRecord::bad_bytes(){ return _bad_bytes;}

void FailRecord::set_max_len(bool val){ _max_len = val;}
void FailRecord::set_no_valid_padding(bool val){ _no_valid_padding = val;}
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

SearchEnvironment::SearchEnvironment(Constraint* c, Assertion* a, unsigned int lm=DEFAULT_LMAX, 
                                     unsigned int max_depth=DEFAULT_MAX_DEPTH, bool no_padd=false, 
                                     RegTransitivityRecord* reg_trans_record=nullptr){
    _constraint = c;
    _assertion = a;
    _lmax = lm;
    _max_depth = max_depth;
    _no_padding = no_padd;
    if( reg_trans_record != nullptr )
        _reg_transitivity_record = reg_trans_record;
    else
        throw_exception("Implement the global variable");
    memset(_calls_count, 0, sizeof(_calls_count));
}

SearchEnvironment* SearchEnvironment::copy(){
    SearchEnvironment* res = new SearchEnvironment(_constraint, _assertion, _lmax, _max_depth, _no_padding, _reg_transitivity_record);
    res->_depth = _depth;
    memcpy(res->_calls_count, _calls_count, sizeof(_calls_count));
    res->_calls_history = _calls_history;
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
FailType SearchEnvironment::last_fail(){
    return _last_fail;
}
void SearchEnvironment::set_last_fail(FailType t){
    _last_fail = t; 
}

/* *********************************************************************
 *                         Search Parameters Bindings
 * ******************************************************************* */
SearchParametersBinding::SearchParametersBinding(vector<int> k, vector<unsigned char> b, unsigned int l, bool s ):
    keep_regs(k), bad_bytes(b), lmax(l), shortest(s){}

SearchResultsBinding::SearchResultsBinding(){
    found = false;
}

SearchResultsBinding::SearchResultsBinding(ROPChain* c){
    chain = *c;
    found = true;
}

SearchResultsBinding::SearchResultsBinding(FailRecord record){
    fail_record = record;
    found = false;
}

/* **********************************************************************
 *                      Search & Chaining Functions ! 
 * ******************************************************************** */
 
/* Prototypes */ 

ROPChain* search_first_hit(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* basic_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* search(DestArg dest, AssignArg assign, SearchEnvironment* env, bool shortest);

/* Globals */
RegTransitivityRecord g_reg_transitivity_record = RegTransitivityRecord();

/* Function to be used from python */
SearchResultsBinding search(DestArg dest, AssignArg assign,SearchParametersBinding params){
    SearchEnvironment* env;
    Constraint* constraint = new Constraint();
    Assertion* assertion = new Assertion();
    ROPChain* chain;
    SearchResultsBinding res;
    
    /* Building search env */ 
    if( ! params.keep_regs.empty() )
        constraint->add(new ConstrKeepRegs(params.keep_regs), true);
    if( ! params.bad_bytes.empty() )
        constraint->add(new ConstrBadBytes(params.bad_bytes), true);
        
    env = new SearchEnvironment(constraint, assertion, params.lmax, DEFAULT_MAX_DEPTH, false, 
                                &g_reg_transitivity_record);
 
    /* Search */ 
    chain = search(dest, assign, env, params.shortest);
    if( chain == nullptr )
        res = SearchResultsBinding(*(env->fail_record()));
    else
        res = SearchResultsBinding(chain);
    
    /* Deleting variables */ 
    delete chain;
    delete env; 
    delete constraint; 
    delete assertion; 
    
    /* Return res */ 
    return res;
}


ROPChain* search(DestArg dest, AssignArg assign, SearchEnvironment* env, bool shortest){
    ROPChain * res;
    /* Check context */ 
    if( env->reached_max_depth() )
        return nullptr;
    else if( env->lmax() <= 0 ){
        env->set_last_fail(FAIL_LMAX);
        env->fail_record()->set_max_len(true);
        return nullptr;
    }
    /* Set env */ 
    env->set_depth(env->depth()+1);
    
    if( shortest ){
        // DEBUG TODO
        res = nullptr; 
    }else{
        res = search_first_hit(dest, assign, env);
    }
    
    /* Restore env */ 
    env->set_depth(env->depth()-1);
    
    /* Return res */
    return res; 
}


ROPChain* search_first_hit(DestArg dest, AssignArg assign, SearchEnvironment* env){
    ROPChain* res;
    // DEBUG, add chainable ??
    res = basic_db_lookup(dest, assign, env);
    // DEBUG, TODO chain
    return res; 
}

/* Search for gadgets by looking into the gadget database directly */ 
ROPChain* basic_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env){
    vector<int> gadgets;
    Constraint* tmp_constraint = nullptr;
    int nb=1;
    ROPChain* res;
    addr_t padding;
    bool success;
    
    /* Check context */ 
    if( env->lmax() <= 0 ){
        env->set_last_fail(FAIL_LMAX);
        env->fail_record()->set_max_len(true);
        return nullptr;
    }
    
    /* Check if padding is requested */ 
    if( ! env->no_padding() ){
        tmp_constraint = env->constraint()->copy();
        tmp_constraint->add(new ConstrMaxSpInc(env->lmax()*curr_arch()->octets()), true);
    }
    
    /* Set the constraint for the gadgets */ 
    if( tmp_constraint == nullptr ){
        tmp_constraint = env->constraint();
    }
    
    // DEBUG: ADD ASSERTIONS AND CONSTRAINTS ? SEE ROPGENERATOR IN PYTHON 
    
    /* Check type of query and call the appropriate function ! */ 
    if( assign.type == ASSIGN_SYSCALL ){
        throw_exception("TO IMPLEMENT");
    }else if( assign.type == ASSIGN_INT80 ){
        throw_exception("TO IMPLEMENT");
    }else{
        switch(dest.type){
            // reg <- ? 
            case DST_REG:
                switch(assign.type){
                    case ASSIGN_CST: // reg <- cst 
                        gadgets = gadget_db()->find_cst_to_reg(dest.reg, assign.cst, tmp_constraint, env->assertion(), nb); 
                        break;
                    case ASSIGN_MEM_BINOP_CST: // reg <- mem(reg op cst) + cst  
                        gadgets = gadget_db()->find_mem_binop_cst_to_reg(dest.reg, assign.addr_op, assign.addr_reg, assign.addr_cst, assign.cst, tmp_constraint, env->assertion(), nb); 
                        break;
                    case ASSIGN_REG_BINOP_CST: // reg <- reg op cst
                        gadgets = gadget_db()->find_reg_binop_cst_to_reg(dest.reg, assign.op, assign.reg, assign.cst,  tmp_constraint, env->assertion(), nb); 
                        break;
                    default:
                        break;
                }
                break;
            case DST_MEM:
                switch(assign.type){
                    case ASSIGN_CST: // mem(reg op cst) <- cst 
                        gadgets = gadget_db()->find_cst_to_mem(dest.addr_op, dest.addr_reg, dest.addr_cst, assign.cst, tmp_constraint, env->assertion(), nb); 
                        break;
                    case ASSIGN_MEM_BINOP_CST: // mem(reg op cst) <- mem(reg op cst) + cst  
                        gadgets = gadget_db()->find_mem_binop_cst_to_mem(dest.addr_op, dest.addr_reg, dest.addr_cst, 
                                    assign.addr_op, assign.addr_reg, assign.addr_cst, assign.cst, tmp_constraint, env->assertion(), nb); 
                        break;
                    case ASSIGN_REG_BINOP_CST: // mem(reg op cst) <- reg op cst
                        gadgets = gadget_db()->find_reg_binop_cst_to_mem(dest.addr_op, dest.addr_reg, dest.addr_cst, assign.op, assign.reg, assign.cst,
                                    tmp_constraint, env->assertion(), nb); 
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
    }
    /* Check result */ 
    if( gadgets.empty() )
        res = nullptr;
    else{
        res = new ROPChain();
        res->add_gadget(gadgets.at(0));
        if( ! env->no_padding() ){
            std::tie(success, padding) = tmp_constraint->valid_padding();
            if( success )
                res->add_padding(padding, (gadget_db()->get(gadgets.at(0))->sp_inc()/curr_arch()->octets())-1); 
            else{
                env->fail_record()->set_no_valid_padding(true);
                env->set_last_fail(FAIL_NO_VALID_PADDING);
                res = nullptr;
            }
        }
    }
    
    /* Restore env */ 
    if( tmp_constraint != nullptr )
        delete tmp_constraint;
        
    /* Return result */ 
    return res;
}
