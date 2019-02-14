#include "ChainingEngine.hpp"
#include "Constraint.hpp"
#include "Database.hpp"
#include "Architecture.hpp"
#include "IO.hpp"
#include <cstring>
#include <algorithm>

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */

DestArg::DestArg(DestType t, int r):type(t), reg(r){}  /* For DEST_REG */ 
DestArg::DestArg(DestType t, int addr_r, Binop o, cst_t addr_c): type(t), 
    addr_reg(addr_r), addr_cst(addr_c), addr_op(o){} /* For DEST_MEM */
DestArg::DestArg(DestType t, cst_t addr_c): type(t), addr_cst(addr_c){} /* For DEST_CSTMEM */

AssignArg::AssignArg(AssignType t, cst_t c):type(t), cst(c){} /* For ASSIGN_CST */
AssignArg::AssignArg(AssignType t, int r, Binop o, cst_t c):type(t), reg(r), op(o), cst(c){} /* For ASSIGN_REG_BINOP_CST */
AssignArg::AssignArg(AssignType t, int ar, Binop o, cst_t ac, cst_t c):type(t), addr_reg(ar), addr_cst(ac), addr_op(o), cst(c){} /* For ASSIGN_MEM_BINOP_CST */
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
void FailRecord::copy_from(FailRecord* other){
    _max_len = other->_max_len;
    _no_valid_padding = other->_no_valid_padding;
    memcpy(_modified_reg, other->_modified_reg, sizeof(_modified_reg));
    memcpy(_bad_bytes, other->_bad_bytes, sizeof(_bad_bytes)); 
}

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
    for( int i = 0; i < NB_STRATEGY_TYPES; i++ )
        _comment[i] = "";
    _depth = 0;
    _reg_transitivity_unusable = new vector<int>();
}

SearchEnvironment::~SearchEnvironment(){
    delete _reg_transitivity_unusable;
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
vector<SearchStrategyType>& SearchEnvironment::calls_history(){
    return _calls_history;
}
int SearchEnvironment::calls_count(SearchStrategyType type){
    return _calls_count[type];
}
bool SearchEnvironment::reached_max_depth(){
    return _depth > _max_depth;
}
vector<int>* SearchEnvironment::reg_transitivity_unusable(){
    return _reg_transitivity_unusable;
}
void SearchEnvironment::set_reg_transitivity_unusable(vector<int>* vec){
    _reg_transitivity_unusable = vec;
}
bool SearchEnvironment::is_reg_transitivity_unusable(int reg){
    if( _reg_transitivity_unusable == nullptr )
        return false;
    return (std::find(_reg_transitivity_unusable->begin(), _reg_transitivity_unusable->end(), reg) != _reg_transitivity_unusable->end());
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

/* Comments about gadgets */ 
bool SearchEnvironment::has_comment(SearchStrategyType t){
    return ! _comment[t].empty();
}
void SearchEnvironment::push_comment(SearchStrategyType t, string& comment){
    _comment[t] = comment;
}
string SearchEnvironment::pop_comment(SearchStrategyType t){
    string res = _comment[t];
    _comment[t] = "";
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
    chain.copy_from(c);
    found = true;
}

SearchResultsBinding::SearchResultsBinding(FailRecord* record){
    fail_record.copy_from(record);
    found = false;
}

void SearchResultsBinding::operator=(SearchResultsBinding other){
    found = other.found;
    chain.copy_from(&(other.chain));
    fail_record.copy_from(&(other.fail_record));
}




/* **********************************************************************
 *                      Search & Chaining Functions ! 
 * ******************************************************************** */
 
/* Prototypes */ 

ROPChain* search(DestArg dest, AssignArg assign, SearchEnvironment* env, bool shortest);
ROPChain* search_first_hit(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* basic_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_reg_transitivity(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_pop_constant(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_any_reg_transitivity(DestArg dest, AssignArg assign, SearchEnvironment* env);

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
    /* Add chainable constraint if the query dest isn't the instruction 
     * pointer */
    constraint->add(new ConstrReturn(true, false, false), true);
    
    env = new SearchEnvironment(constraint, assertion, params.lmax, DEFAULT_MAX_DEPTH, false, 
                                &g_reg_transitivity_record);

    /* Search */ 
    chain = search(dest, assign, env, params.shortest);
    if( chain == nullptr ){
        res = SearchResultsBinding(env->fail_record());
    }else{
        res = SearchResultsBinding(chain);
    }
    
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
    else if( env->lmax() == 0 ){
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
    res = basic_db_lookup(dest, assign, env);
    if( res == nullptr ){
        res = chain(dest, assign, env);
    }
    return res; 
}

/* Search for gadgets by looking into the gadget database directly */ 
ROPChain* basic_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env){
    vector<int> gadgets;
    Constraint* tmp_constraint = nullptr, *prev_constraint=env->constraint();
    int nb=1;
    ROPChain* res;
    addr_t padding;
    bool success;
    
    /* Check context */ 
    if( env->lmax() == 0 ){
        env->set_last_fail(FAIL_LMAX);
        env->fail_record()->set_max_len(true);
        return nullptr;
    }
    
    /* Check if padding is requested */ 
    if( ! env->no_padding() ){
        tmp_constraint = env->constraint()->copy();
        tmp_constraint->add(new ConstrMaxSpInc(env->lmax()*curr_arch()->octets()), true);
    }
    
    /* If the destination is the instruction pointer, remove the chainable
     * constraint. 
     * This is possible because all those functions are not used directly, 
     * so we assume we know what we are doing when requesting to assign 
     * the instruction pointer :) */ 
    if( (dest.type == DST_REG) && (dest.reg == curr_arch()->ip()) ){
        if( tmp_constraint == nullptr ){
            tmp_constraint = env->constraint()->copy();
        }
        tmp_constraint->add(new ConstrReturn(true, true, true), true);
    }
    
    /* Set the constraint if not yet done */ 
    if( tmp_constraint == nullptr ){
        tmp_constraint = env->constraint();
    }
    
    // DEBUG: ADD ASSERTIONS AND CONSTRAINTS ? SEE ROPGENERATOR IN PYTHON 
    
    /* Check type of query and call the appropriate function ! */ 
    if( assign.type == ASSIGN_SYSCALL ){
        throw_exception("DEBUG TO IMPLEMENT");
    }else if( assign.type == ASSIGN_INT80 ){
        throw_exception("DEBUG TO IMPLEMENT");
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
        res->add_gadget(gadgets.at(0)); // We use the first one
        if( ! env->no_padding() ){
            std::tie(success, padding) = tmp_constraint->valid_padding();
            if( success )
                res->add_padding(padding, (gadget_db()->get(gadgets.at(0))->sp_inc()/curr_arch()->octets())-1); 
            else{
                env->fail_record()->set_no_valid_padding(true);
                env->set_last_fail(FAIL_NO_VALID_PADDING);
                delete res;
                res = nullptr;
            }
        }
    }
    
    /* Restore env */ 
    if( tmp_constraint != nullptr && tmp_constraint != prev_constraint)
        delete tmp_constraint;
        
    /* Return result */ 
    return res;
}

/* Chain gadgets together in more complex rop-chain */ 
ROPChain* chain(DestArg dest, AssignArg assign, SearchEnvironment* env){
    ROPChain* res = nullptr;
    switch(dest.type){
        // reg <- ? 
        case DST_REG:
            switch(assign.type){
                case ASSIGN_CST: // reg <- cst 
                    res = chain_pop_constant(dest, assign, env);
                    if( res == nullptr )
                        res = chain_any_reg_transitivity(dest, assign, env);
                    break;
                case ASSIGN_REG_BINOP_CST: // reg <- reg op cst
                    res = chain_reg_transitivity(dest, assign, env);
                    break;
                case ASSIGN_MEM_BINOP_CST: // reg <- mem(reg op cst) + cst  
                    res = chain_any_reg_transitivity(dest, assign, env);
                    break;
                case ASSIGN_CSTMEM_BINOP_CST:
                    res = chain_any_reg_transitivity(dest, assign, env);
                    break;
                default:
                    break;
            }
            break;
        case DST_MEM:
            switch(assign.type){
                case ASSIGN_CST: // mem(reg op cst) <- cst 
                    res = chain_any_reg_transitivity(dest, assign, env);
                    break;
                case ASSIGN_REG_BINOP_CST: // mem(reg op cst) <- reg op cst
                    res = chain_any_reg_transitivity(dest, assign, env);
                    break;
                case ASSIGN_MEM_BINOP_CST: // mem(reg op cst) <- mem(reg op cst) + cst  
                    res = chain_any_reg_transitivity(dest, assign, env);
                    break;
                case ASSIGN_CSTMEM_BINOP_CST:
                    res = chain_any_reg_transitivity(dest, assign, env);
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
    return res;
}

/* Useful function */
bool is_identity_assign(int dest_reg, int reg, Binop op, cst_t cst){
    if( dest_reg == reg ){ 
        if( cst == 0 && (op == OP_ADD || op == OP_SUB || op == OP_BSH ))
            return true;
        else if( cst == 1 && (op == OP_MUL || op == OP_DIV ))
            return true;
    }
    return false;
}


/* Register transitivity strategy */
ROPChain* chain_reg_transitivity(DestArg dest, AssignArg assign, SearchEnvironment* env){
    SearchStrategyType strategy = STRATEGY_REG_TRANSITIVITY;
    vector<SearchStrategyType>& prev_calls = env->calls_history();
    vector<int>* prev_reg_transitivity_unusable, *new_reg_transitivity_unusable = nullptr;
    int inter_reg;
    ROPChain * inter_to_dest, *assign_to_inter, *res=nullptr;
    bool added_unusable=false;
    unsigned int prev_lmax = env->lmax();
    
    /* Check for special cases */
    /* Identity search (e.g r1 <- r1) */ 
    if( is_identity_assign(dest.reg, assign.reg, assign.op, assign.cst) )
        return nullptr;
    /* Limit numbers of consecutive calls to this function 
     * Checking the 2 last <=> 2 intermediate regs at max */
    if( prev_calls.size() >= 2 && prev_calls.at(prev_calls.size()-1) == strategy &&
        prev_calls.at(prev_calls.size()-2) == strategy){
        return nullptr;
    }
    
    /* Setting env */
    env->add_call(strategy);
    if( (!prev_calls.empty()) && prev_calls.back() != strategy){
        /* We come from another strategy, so we can cancel the reg_transitivity_unusable... */
        prev_reg_transitivity_unusable = env->reg_transitivity_unusable();
        new_reg_transitivity_unusable = new vector<int>();
        env->set_reg_transitivity_unusable(new_reg_transitivity_unusable);
    }
    
    
    /* Chaining... */
    for( inter_reg = 0; inter_reg < curr_arch()->nb_regs(); inter_reg++ ){
        /* Check for forbidden regs */
        if( curr_arch()->is_ignored_reg(inter_reg) || 
        env->is_reg_transitivity_unusable(inter_reg) || 
        env->constraint()->keep_reg(inter_reg) || 
        inter_reg == curr_arch()->sp() || 
        inter_reg == curr_arch()->ip() || 
        inter_reg == dest.reg || 
        is_identity_assign(inter_reg, assign.reg, assign.op, assign.cst ) || 
        env->reg_transitivity_record()->is_impossible(inter_reg, assign.reg, assign.op, assign.cst, env->constraint()) || 
        env->reg_transitivity_record()->is_impossible(dest.reg, inter_reg, OP_ADD, 0, env->constraint())
        ){
            continue;
        }
        /* 1. Try dest.reg <- inter_reg without using assign.reg IF operation is trivial */
        if( is_identity_assign(assign.reg, assign.reg, assign.op, assign.cst )){
            env->reg_transitivity_unusable()->push_back(assign.reg);
            added_unusable=true;
        }
        inter_to_dest = search(dest, AssignArg(ASSIGN_REG_BINOP_CST, inter_reg, OP_ADD, 0), env);
        if( added_unusable ){
            env->reg_transitivity_unusable()->pop_back();
            added_unusable = false;
        }
        if( inter_to_dest == nullptr ){
            continue;
        }
        /* 2. We found dest <- inter, try now inter <- assign */
        env->set_lmax(env->lmax() - inter_to_dest->len());
        env->reg_transitivity_unusable()->push_back(dest.reg);
        assign_to_inter = search(DestArg(DST_REG, inter_reg), assign, env);
        env->set_lmax(prev_lmax);
        env->reg_transitivity_unusable()->pop_back();
        if( assign_to_inter == nullptr ){
            delete inter_to_dest;
            continue;
        }
        /* 3. We found both, stop looking */ 
        assign_to_inter->add_chain(inter_to_dest);
        res = assign_to_inter;
        delete inter_to_dest; // Delete it because we keep only one
        break;
    }
    
    /* Restore env */
    env->remove_last_call();
    if( new_reg_transitivity_unusable != nullptr ){
        /* Set the previous reg_transitivity_unusable info */
        delete new_reg_transitivity_unusable;
        env->set_reg_transitivity_unusable(prev_reg_transitivity_unusable);
    }
    
    /* Return result */
    return res;
}

/* Poping constant into register from the stack */
ROPChain* chain_pop_constant(DestArg dest, AssignArg assign, SearchEnvironment* env){
    ROPChain *res = nullptr, *pop=nullptr;
    cst_t offset;
    bool prev_no_padding = env->no_padding();
    bool success, had_comment; 
    addr_t padding=0;
    SearchStrategyType strategy = STRATEGY_POP_CONSTANT;
    string comment;
    char val_str[128];

    /* Check for special cases */
    /* If constant contains bad bytes */
    if( ! env->constraint()->verify_address((addr_t)assign.cst) )
        return nullptr;

    /* Setting env */ 
    env->add_call(strategy);
    env->set_no_padding(true);
    /* Check for comments */
    had_comment = env->has_comment(strategy);
    if( had_comment ){
        comment = env->pop_comment(strategy);
    }else{
        snprintf(val_str, sizeof(val_str), "0x%llx", (addr_t)assign.cst);
        comment = "Constant: " + str_bold(string(val_str));
    }
    
    /* Chaining... */
    /* We check all possible offsets ! */
    for( offset = 0; offset < env->lmax(); offset += curr_arch()->octets() ){
        /* Get gadget that does dest.reg <- mem(rsp+offset)+0 */ 
        pop = basic_db_lookup(dest, AssignArg(ASSIGN_MEM_BINOP_CST, curr_arch()->sp(), OP_ADD, offset, 0), env);
        if( pop != nullptr ){
            /* If found, padd it and return */ 
            res = pop; 
            std::tie(success, padding) = env->constraint()->valid_padding();
            if( success ){
                res->add_padding(padding, offset/8);
                res->add_padding(assign.cst, 1, comment);
                /* sp_inc - 2*arch_octets for the return and the const, -offset because we already added*/ 
                res->add_padding(padding, (gadget_db()->get(pop->chain().at(0))->sp_inc()-offset-(2*curr_arch()->octets()))/8 );
                break;
            }else{
                env->fail_record()->set_no_valid_padding(true);
                env->set_last_fail(FAIL_NO_VALID_PADDING);
                delete res;
                res = nullptr;
                break;
            }
        }
    }
    
    /* Restore env */
    env->remove_last_call();
    env->set_no_padding(prev_no_padding);
    /* Restore comment */
    if( had_comment ){
        env->push_comment(strategy, comment);
    }
    
    /* Return result */ 
    return res;
}

/* Assign something to register by using register transitivity 
 * Note: should not be used for reg_binop_cst_to_reg (uses 
 * chain_reg_transitivity() instead ) */
ROPChain* chain_any_reg_transitivity(DestArg dest, AssignArg assign, SearchEnvironment* env){
    SearchStrategyType strategy = STRATEGY_ANY_REG_TRANSITIVITY;
    ROPChain *res=nullptr, *inter_to_dest=nullptr, *assign_to_inter=nullptr;
    int inter_reg;
    unsigned int prev_lmax = env->lmax();
    
    /* Check for special cases */
    /* Don't call this strategy consecutively, transitivity is handled
     * via reg_transitivity() so no need to do it within this function 
     * too */
     if( !env->calls_history().empty() && env->calls_history().back() == strategy)
        return nullptr;
    
    /* Setting env */
    env->add_call(strategy);
    
    /* Chaining... */
    for( inter_reg = 0; inter_reg < curr_arch()->nb_regs(); inter_reg++ ){
        /* Check for forbidden regs */
        if( curr_arch()->is_ignored_reg(inter_reg) || 
        env->constraint()->keep_reg(inter_reg) || 
        inter_reg == curr_arch()->sp() || 
        inter_reg == curr_arch()->ip() || 
        inter_reg == dest.reg || 
        env->reg_transitivity_record()->is_impossible(dest.reg, inter_reg, OP_ADD, 0, env->constraint())
        ){
            continue;
        }
        
        /* 1. Search dest <- inter_reg */ 
        inter_to_dest = search(dest, AssignArg(ASSIGN_REG_BINOP_CST, inter_reg, OP_ADD, 0), env );
        if( inter_to_dest == nullptr){
            continue;
        }
        /* 2. Search inter_reg <- assign */
        env->set_lmax(env->lmax()- inter_to_dest->len());
        assign_to_inter = search(DestArg(DST_REG, inter_reg), assign, env);
        env->set_lmax(prev_lmax);
        if( assign_to_inter == nullptr ){
            delete inter_to_dest;
            continue;
        }
        /* 3. We found both, stop looking */
        assign_to_inter->add_chain(inter_to_dest);
        delete inter_to_dest;
        res = assign_to_inter;
        break;
    }
    
    /* Restore env */ 
    env->remove_last_call();
    
    /* Return res */
    return res;
}

