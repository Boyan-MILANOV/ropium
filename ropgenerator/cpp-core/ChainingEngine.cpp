#include "ChainingEngine.hpp"
#include "Constraint.hpp"
#include "Database.hpp"
#include "Architecture.hpp"
#include "IO.hpp"
#include "ROPChain.hpp"
#include "Exception.hpp"
#include <cstring>
#include <algorithm>
#include <csignal> 

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */
 
/* Don't forget to initialize unused reg fields to -1 */ 

DestArg::DestArg():type(DST_INVALID), addr_reg(-1), reg(-1){} /* DEFAULT ONE */ 
/* For DEST_MEM */
DestArg::DestArg(DestType t, int addr_r, Binop o, cst_t addr_c): type(t), 
    addr_reg(addr_r), addr_cst(addr_c), addr_op(o), reg(-1){} 
/* For both DST_REG and DST_CSTMEM because the program doesn't make the 
 * difference between cst_t and int so it always calls the DST_REG constructor
 * even for CST_MEM :(. It's ugly, I know, fuck it. */ 
DestArg::DestArg(DestType t, cst_t val): type(t), addr_reg(-1){
    if( t == DST_REG ){
        reg = val;
    }else if( t == DST_CSTMEM ){
        addr_cst = val;
    }
}

bool DestArg::operator==(DestArg& other){
    if( type != other.type ){
        return false;
    }
    switch( type ){
        case DST_REG:
            return (reg == other.reg);
        case DST_MEM:
            return (addr_reg == other.addr_reg && addr_op == other.addr_op && addr_cst == other.addr_cst);
        case DST_CSTMEM:
            return (addr_cst == other.addr_cst);
        default:
            throw_exception("Unsupported assign type in DestArg::operator==");
    }
}

AssignArg::AssignArg():type(ASSIGN_INVALID), addr_reg(-1), reg(-1){} /* DEFAULT ONE */
AssignArg::AssignArg(AssignType t, cst_t c):type(t), addr_reg(-1), reg(-1), cst(c){} /* For ASSIGN_CST */
AssignArg::AssignArg(AssignType t, int r, Binop o, cst_t c):type(t), addr_reg(-1), reg(r), op(o), cst(c){} /* For ASSIGN_REG_BINOP_CST */
AssignArg::AssignArg(AssignType t, int ar, Binop o, cst_t ac, cst_t c):type(t), addr_reg(ar), addr_cst(ac), addr_op(o), reg(-1), cst(c){} /* For ASSIGN_MEM_BINOP_CST */
AssignArg::AssignArg(AssignType t, cst_t ac, cst_t c):type(t), addr_reg(-1), addr_cst(ac), reg(-1), cst(c){} /* For ASSIGN_CSTMEM_BINOP_CST */
AssignArg::AssignArg(AssignType t):type(t), addr_reg(-1), reg(-1){} /* For ASSIGN_SYSCALL and INT80 */ 
bool AssignArg::operator==(AssignArg& other){
    if( type != other.type ){
        return false;
    }
    switch(type){
        case ASSIGN_CST:
            return (cst == other.cst);
        case ASSIGN_REG_BINOP_CST:
            return (cst == other.cst && op == other.op && reg == other.reg);
        case ASSIGN_MEM_BINOP_CST:
            return (cst == other.cst && addr_cst == other.addr_cst && addr_op == other.addr_op && addr_reg == other.addr_reg);
        case ASSIGN_CSTMEM_BINOP_CST:
            return (cst == other.cst && addr_cst == other.addr_cst);
        case ASSIGN_SYSCALL:
        case ASSIGN_INT80:
            return true;
        default:
            throw_exception("Unsupported assign type in AssignArg::operator==");
    }
}


/* ***************************************************
 *                    FailRecord
 * ************************************************* */ 


FailRecord::FailRecord(){
    _max_len = false;
    _no_valid_padding = false;
    memset(_modified_reg, false, NB_REGS_MAX);
    memset(_bad_bytes, false, sizeof(_bad_bytes));
    memset(_bad_bytes_index, -1, sizeof(_bad_bytes_index));
}

FailRecord::FailRecord(bool max_len): _max_len(max_len){
    _no_valid_padding = false;
    memset(_modified_reg, false, NB_REGS_MAX);
    memset(_bad_bytes, false, sizeof(_bad_bytes));
    memset(_bad_bytes_index, -1, sizeof(_bad_bytes_index));
}
 
bool FailRecord::max_len(){ return _max_len;}
bool FailRecord::no_valid_padding(){ return _no_valid_padding;}
bool FailRecord::modified_reg(int reg_num){ return _modified_reg[reg_num];}
bool* FailRecord::bad_bytes(){ return _bad_bytes;}
bool FailRecord::bad_byte(unsigned char bad_byte){ return _bad_bytes[bad_byte];}
int FailRecord::bad_byte_index(unsigned char bad_byte){return _bad_bytes_index[bad_byte];}

void FailRecord::set_max_len(bool val){ _max_len = val;}
void FailRecord::set_no_valid_padding(bool val){ _no_valid_padding = val;}
void FailRecord::add_modified_reg(int reg_num){ _modified_reg[reg_num] = true;}
void FailRecord::add_bad_byte(unsigned char bad_byte, int index){ 
	_bad_bytes[bad_byte] = true; 
	_bad_bytes_index[bad_byte] = index;
}

void FailRecord::copy_from(FailRecord* other){
    _max_len = other->_max_len;
    _no_valid_padding = other->_no_valid_padding;
    memcpy(_modified_reg, other->_modified_reg, sizeof(_modified_reg));
    memcpy(_bad_bytes, other->_bad_bytes, sizeof(_bad_bytes));
    memcpy(_bad_bytes_index, other->_bad_bytes_index, sizeof(_bad_bytes_index));
}
void FailRecord::merge_with(FailRecord* other){
    unsigned int i;
    _max_len |= other->_max_len;
    _no_valid_padding |= other->_no_valid_padding;
    for( i = 0; i < sizeof(_modified_reg); i++){
        _modified_reg[i] |= other->_modified_reg[i];
    }
    for( i = 0; i < sizeof(_bad_bytes); i++){
        _bad_bytes[i] |= other->_bad_bytes[i];
		if( _bad_bytes[i] && (_bad_bytes_index[i] < other->_bad_bytes_index[i]) )
			_bad_bytes_index[i] = other->_bad_bytes_index[i];
    }
}
void FailRecord::reset(){
    _max_len = false;
    _no_valid_padding = false;
    memset(_modified_reg, false, NB_REGS_MAX);
    memset(_bad_bytes, false, 256);
    memset(_bad_bytes_index, -1, 256);
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

void RegTransitivityRecord::add_fail(int dest_reg, int src_reg, Binop op, cst_t src_cst, SearchEnvironment* env){
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
    sig = env->constraint()->signature(env);
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

bool RegTransitivityRecord::is_impossible(int dest_reg, int src_reg, Binop op, cst_t src_cst, SearchEnvironment* env){
    int cst_index;
    vector<cstr_sig_t>::iterator it; 
    cstr_sig_t sig; 
    /* Check regs, if they are not supported we don't know if they are impossible
     * so we return false
     * */
    if( dest_reg >= NB_REG_RECORD || src_reg >= NB_REG_RECORD || 
        dest_reg < 0 || src_reg < 0)
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
        
    sig = env->constraint()->signature(env);
    for( it = _query[dest_reg][src_reg][op][cst_index].begin(); it != _query[dest_reg][src_reg][op][cst_index].end(); it++){
        if( (*it & sig) == *it ){
            // previous included in sig, so lesser constraints already failed :/
            return true;
        }
    }
    return false;
}


/* *********************************************************************
 *                          Adjust Ret Record 
 * ******************************************************************* */ 

AdjustRetRecord::AdjustRetRecord(){
    memset(_regs, false, sizeof(_regs));
}
void AdjustRetRecord::add_fail(int reg_num){
    _regs[reg_num] = true;
}
bool AdjustRetRecord::is_impossible(int reg_num){
    return _regs[reg_num];
}
void AdjustRetRecord::reset(){
    memset(_regs, false, sizeof(_regs));
}


/* *********************************************************************
 *                         SearchEnvironment 
 * ******************************************************************* */

SearchEnvironment::SearchEnvironment(Constraint* c, Assertion* a, unsigned int lm=DEFAULT_LMAX, 
                                     unsigned int max_depth=DEFAULT_MAX_DEPTH, bool no_padd=false, bool single=false,
                                     RegTransitivityRecord* reg_trans_record=nullptr){
    _constraint = c;
    _assertion = a;
    _lmax = lm;
    _max_depth = max_depth;
    _no_padding = no_padd;
    _single_gadget = single;
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
void SearchEnvironment::set_lmax(unsigned int val){
    if( val >= 40000 )
        throw_exception("Ooops lmax is really big, UNEXPECTED ERROR?");
    _lmax = val;
}
unsigned int SearchEnvironment::depth(){return _depth;}
void SearchEnvironment::set_depth(unsigned int val){_depth = val;}
bool SearchEnvironment::no_padding(){return _no_padding;}
void SearchEnvironment::set_no_padding(bool val){_no_padding = val;}
bool SearchEnvironment::single_gadget(){return _single_gadget;}
void SearchEnvironment::set_single_gadget(bool val){_single_gadget = val;}
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
AdjustRetRecord* SearchEnvironment::adjust_ret_record(){
    return &_adjust_ret_record;
}
void SearchEnvironment::set_adjust_ret_record(AdjustRetRecord* rec){
    _adjust_ret_record = *rec;
}
FailRecord* SearchEnvironment::fail_record(){
    return &_fail_record;
}

/* Comments about gadgets */ 
bool SearchEnvironment::has_comment(SearchStrategyType t){
    return ! _comment[t].empty();
}
void SearchEnvironment::push_comment(SearchStrategyType t, string comment){
    _comment[t] = comment;
}
string SearchEnvironment::pop_comment(SearchStrategyType t){
    string res = _comment[t];
    _comment[t] = "";
    return res;
}


/* *********************************************************************
 *                         Search Parameters Bindings
 * ******************************************************************* */
SearchParametersBinding::SearchParametersBinding(vector<int> k, vector<unsigned char> b, unsigned int l, bool s, bool np, bool sg  ):
    keep_regs(k), bad_bytes(b), lmax(l), shortest(s), no_padding(np), single_gadget(sg){}

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
 
/* Global variables */
bool g_search_verbose = false; 
void set_search_verbose(bool val){
    g_search_verbose = val;
}
 
/* Prototypes */
ROPChain* search(DestArg dest, AssignArg assign, SearchEnvironment* env, bool shortest);
ROPChain* search_first_hit(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* search_shortest(DestArg dest, AssignArg assign, SearchEnvironment* env);
vector<int> _gadget_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env, int nb);
ROPChain* basic_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_reg_transitivity(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_pop_constant(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_any_reg_transitivity(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_adjust_ret(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_adjust_store(DestArg dest, AssignArg assign, SearchEnvironment* env);
ROPChain* chain_adjust_load(DestArg dest, AssignArg assign, SearchEnvironment* env);

/* Globals */
RegTransitivityRecord g_reg_transitivity_record = RegTransitivityRecord();
FailRecord g_fail_record = FailRecord();

/* Function to be used from python */
SearchResultsBinding search(DestArg dest, AssignArg assign,SearchParametersBinding params){
    SearchEnvironment* env;
    Constraint* constraint = new Constraint();
    Assertion* assertion = new Assertion();
    ROPChain* chain;
    SearchResultsBinding res;
    
    /* Initialize the global fail record */ 
    g_fail_record.reset();
    
    /* Building search env */ 
    if( ! params.keep_regs.empty() )
        constraint->add(new ConstrKeepRegs(params.keep_regs), true);
    if( ! params.bad_bytes.empty() )
        constraint->add(new ConstrBadBytes(params.bad_bytes), true);
    /* Add chainable constraint if the query dest isn't the instruction 
     * pointer */
    constraint->add(new ConstrReturn(true, false, false), true);
    
    /* Add basic assertions */
    /* Always valid to write to stack pointer */ 
    assertion->add(new AssertValidWrite(curr_arch()->sp()), true);
    /* If the query has memory addresses, make it valid */
    if( dest.type == DST_MEM ){
        assertion->add(new AssertValidWrite(dest.addr_reg), true);
        assertion->add(new AssertRegsNoOverlap(dest.addr_reg, curr_arch()->sp()), true);
    }
    if( assign.type == ASSIGN_MEM_BINOP_CST ){
        assertion->add(new AssertValidRead(assign.addr_reg), true);
    }
    
    env = new SearchEnvironment(constraint, assertion, params.lmax, DEFAULT_MAX_DEPTH, params.no_padding, params.single_gadget,
                                &g_reg_transitivity_record);
    
    /* Search */ 
    chain = search(dest, assign, env, params.shortest);
    if( chain == nullptr ){
        res = SearchResultsBinding(&g_fail_record);
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
    /* Reset fail record */ 
    env->fail_record()->reset();

    if( shortest ){
        res = search_shortest(dest, assign, env);
    }else{
        res = search_first_hit(dest, assign, env);
    }
    
    /* Return res */
    return res;
}


ROPChain* search_first_hit(DestArg dest, AssignArg assign, SearchEnvironment* env){
    ROPChain* res = nullptr;
    FailRecord local_fail_record;
    
    /* Check context */ 
    if( env->reached_max_depth() ){
        return nullptr;
    }else if( env->lmax() == 0 ){
        env->fail_record()->set_max_len(true);
        return nullptr;
    }
    
    /* Set env */ 
    env->set_depth(env->depth()+1);
    
    /* Try basic search */
    res = basic_db_lookup(dest, assign, env);
    /* Try chaining */ 
    if( res == nullptr && !env->single_gadget()){
        local_fail_record.merge_with(env->fail_record());
        res = chain(dest, assign, env);
    }
    if( res == nullptr ){
        env->fail_record()->merge_with(&local_fail_record);
    }else{
        env->fail_record()->reset();
    }
    /* Update records*/
    /* If we didn't find a chain, update the reg_transitivity record 
     * we need to test for lmax fail reason. If there is lmax, 
     * then maybe a longer length would ahve allowed the chain, so we
     * don't update the fail_record.  */
    if( res == nullptr && !env->fail_record()->max_len() &&
            dest.type == DST_REG && assign.type == ASSIGN_REG_BINOP_CST &&
            !env->single_gadget()){
        env->reg_transitivity_record()->add_fail(dest.reg, assign.reg, assign.op, assign.cst, env);
    }
    /* Restore env */
    env->set_depth(env->depth()-1);
	
    return res;
}

/* Constants for printing when doing a shortest search */
string g_ANSI_back_one_line = "\x1b[F";
string g_blank_line = string(50, ' ');

ROPChain* search_shortest(DestArg dest, AssignArg assign, SearchEnvironment* env){
    ROPChain* best_res = nullptr;
    ROPChain* res = nullptr;
    unsigned int lmoy;
    unsigned int lmin = 1;
    unsigned int lmax = env->lmax();
    unsigned int saved_lmax = env->lmax();
    bool wrote_status=false;
    bool finished=false;
    
    /* Dichotomy on max length */
    while( !finished && lmax > 0){
        /* Test for last case */ 
        if( lmin == lmax ){
			if( res == nullptr )
				/* If we didn't find it at the last step, it means that now
				 * lmin = prev_lmoy = lmax so we actually tried it last time
				 * no need to try again */
				break;
            else
				/* If we found one at last time, means that we still have the 
				 * last one to find */
				finished = true; // Last one to do then exit loop
        }
        
        lmoy = (lmin+lmax+1)/2;
        
        /* If requested, display info */ 
        /* Erase previous if any */
        if( g_search_verbose ){
            if( wrote_status){
                cout << g_ANSI_back_one_line << g_ANSI_back_one_line;
                cout << g_blank_line << endl << g_blank_line << endl; 
                cout << g_ANSI_back_one_line << g_ANSI_back_one_line;
            }else{
                cout << endl;
            }
            cout.flush();
            wrote_status = true;
            notify("Trying: " + str_special(std::to_string(lmoy*8) + " bytes"));
            notify("Best chain: " + ( best_res == nullptr ? str_exploit("-"): str_ropg((std::to_string(best_res->len()*8) + " bytes"))));
        }
        
        /* Set lmax for env */
        env->set_lmax(lmoy);
        /* Reset the adjust_ret record every time.
         * This is because we approximate the adjust_ret_record so
         * when reaching small sizes a lot of fails because of lmax
         * will induce too many false positives for other lengthes
         * */ 
		env->adjust_ret_record()->reset();
        
        /* Search */ 
        res = search(dest, assign, env);
        if( res != nullptr ){
            /* Found */ 
            delete best_res; 
            best_res = res;
            lmax =  res->len()-1;
        }else{
            /* If fail is not because of lmax, don't continue */
            if( ! g_fail_record.max_len() )
                break;
            /* Not found */
            lmin = lmoy;
        }
    }

    /* If we had verbose output, erase it */
    if( g_search_verbose ){
        cout << g_ANSI_back_one_line << g_ANSI_back_one_line;
        cout << g_blank_line << endl << g_blank_line << endl; 
        cout << g_ANSI_back_one_line << g_ANSI_back_one_line << g_ANSI_back_one_line;
        cout.flush();
    }

    /* Restore env */
    env->set_lmax(saved_lmax);
    
    /* Return our best find */ 
    return best_res;
    
}

vector<int> _gadget_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env, int nb=1){
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
                        return gadget_db()->find_cst_to_reg(dest.reg, assign.cst, env->constraint(), env->assertion(), nb, env->fail_record()); 
                    case ASSIGN_MEM_BINOP_CST: // reg <- mem(reg op cst) + cst  
                        return gadget_db()->find_mem_binop_cst_to_reg(dest.reg, assign.addr_op, assign.addr_reg, assign.addr_cst, assign.cst, env->constraint(), env->assertion(), nb, env->fail_record()); 
                    case ASSIGN_REG_BINOP_CST: // reg <- reg op cst
                        return gadget_db()->find_reg_binop_cst_to_reg(dest.reg, assign.op, assign.reg, assign.cst,  env->constraint(), env->assertion(), nb, env->fail_record()); 
                    default:
                        break;
                }
                break;
            case DST_MEM:
                switch(assign.type){
                    case ASSIGN_CST: // mem(reg op cst) <- cst 
                        return gadget_db()->find_cst_to_mem(dest.addr_op, dest.addr_reg, dest.addr_cst, assign.cst, env->constraint(), env->assertion(), nb, env->fail_record()); 
                    case ASSIGN_MEM_BINOP_CST: // mem(reg op cst) <- mem(reg op cst) + cst  
                        return gadget_db()->find_mem_binop_cst_to_mem(dest.addr_op, dest.addr_reg, dest.addr_cst, 
                                    assign.addr_op, assign.addr_reg, assign.addr_cst, assign.cst, env->constraint(), env->assertion(), nb, env->fail_record()); 
                    case ASSIGN_REG_BINOP_CST: // mem(reg op cst) <- reg op cst
                        return gadget_db()->find_reg_binop_cst_to_mem(dest.addr_op, dest.addr_reg, dest.addr_cst, assign.op, assign.reg, assign.cst,
                                    env->constraint(), env->assertion(), nb, env->fail_record()); 
                    default:
                        break;
                }
                break;
            default:
                break;
        }
    }
    return vector<int>();
}

/* Search for gadgets by looking into the gadget database directly */ 
ROPChain* basic_db_lookup(DestArg dest, AssignArg assign, SearchEnvironment* env){
    vector<int> gadgets;
    Constraint* tmp_constraint = nullptr, *prev_constraint=env->constraint();
    int nb=1;
    ROPChain* res;
    addr_t padding;
    bool success;
    
    /* Reset fail record */
    env->fail_record()->reset();
    
    /* Check context */ 
    if( env->lmax() == 0 ){
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
    
    /* Set env constraint */
    env->set_constraint(tmp_constraint);
    
    gadgets = _gadget_db_lookup(dest, assign, env, nb);
    /* Check result */ 
    if( gadgets.empty() ){
        res = nullptr;
    }else{
        res = new ROPChain();
        res->add_gadget(gadgets.at(0)); // We use the first one
        if( ! env->no_padding() ){
            std::tie(success, padding) = tmp_constraint->valid_padding();
            if( success )
                res->add_padding(padding, (gadget_db()->get(gadgets.at(0))->sp_inc()/curr_arch()->octets())-1); 
            else{
                env->fail_record()->set_no_valid_padding(true);
                delete res;
                res = nullptr;
            }
        }
    }
    
    /* Restore env */ 
    if( tmp_constraint != nullptr && tmp_constraint != prev_constraint){
        delete tmp_constraint;
        env->set_constraint(prev_constraint);
    }
        
    /* Return result */ 
    return res;
}

/* Chain gadgets together in more complex rop-chain */ 
ROPChain* chain(DestArg dest, AssignArg assign, SearchEnvironment* env){
    ROPChain* res = nullptr;
    FailRecord local_fail_record;

    /* Reset fail record */
    env->fail_record()->reset();

    switch(dest.type){
        // reg <- ?
        case DST_REG:
            switch(assign.type){
                case ASSIGN_CST: // reg <- cst 
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
                        res = chain_pop_constant(dest, assign, env);
                    }
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
                        res = chain_any_reg_transitivity(dest, assign, env);
                    }
                    break;
                case ASSIGN_REG_BINOP_CST: // reg <- reg op cst
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
                        res = chain_reg_transitivity(dest, assign, env);
                    }
                    break;
                case ASSIGN_MEM_BINOP_CST: // reg <- mem(reg op cst) + cst  
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
                        res = chain_adjust_load(dest, assign, env);
                    }
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
                        res = chain_any_reg_transitivity(dest, assign, env);
                    }
                    break;
                case ASSIGN_CSTMEM_BINOP_CST:
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
                        res = chain_adjust_load(dest, assign, env);
                    }
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
                        res = chain_any_reg_transitivity(dest, assign, env);
                    }
                    break;
                default:
                    break;
            }
            break;
        case DST_MEM:
            switch(assign.type){
                case ASSIGN_CST: // mem(reg op cst) <- cst 
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                case ASSIGN_REG_BINOP_CST: // mem(reg op cst) <- reg op cst
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                case ASSIGN_MEM_BINOP_CST: // mem(reg op cst) <- mem(reg op cst) + cst  
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                case ASSIGN_CSTMEM_BINOP_CST:
                    res = chain_adjust_ret(dest, assign, env);
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                default:
                    break;
            }
            break;
        case DST_CSTMEM:
			/* Here we don't use any_reg_transitivity because it would be 
			 * redondant with adjust_store. When setting registers in adjust_store
			 * we already do any_reg_transitivity */
			switch(assign.type){
                case ASSIGN_CST: // mem(reg op cst) <- cst 
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                case ASSIGN_REG_BINOP_CST: // mem(reg op cst) <- reg op cst
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                case ASSIGN_MEM_BINOP_CST: // mem(reg op cst) <- mem(reg op cst) + cst  
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                case ASSIGN_CSTMEM_BINOP_CST:
                    if( res == nullptr ){
                        local_fail_record.merge_with(env->fail_record());
						res = chain_adjust_store(dest, assign, env);
                    }
                    break;
                default:
                    break;
            }
			break;
        default:
            break;
    }
    
    if( res == nullptr ){
        env->fail_record()->merge_with(&local_fail_record);
        g_fail_record.merge_with(env->fail_record());
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
    FailRecord local_fail_record;
    
    /* Reset env fail record */ 
    env->fail_record()->reset();
    
    /* Check for special cases */
    /* Identity search (e.g r1 <- r1) */ 
    if( is_identity_assign(dest.reg, assign.reg, assign.op, assign.cst) ){
        return nullptr;
    }
    /* Limit numbers of consecutive calls to this function 
     * Checking the 2 last <=> 4 intermediate regs at max because
     * 2 for dest<-inter and 2 for inter<-assign */
    if( prev_calls.size() >= 2 && prev_calls.at(prev_calls.size()-1) == strategy &&
        prev_calls.at(prev_calls.size()-2) == strategy){
        return nullptr;
    }
    /* If lmax is 1, impossible to use two gagets */
    if( env->lmax() <= 1 ){
        env->fail_record()->set_max_len(true);
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
        env->constraint()->keep_reg(inter_reg, &local_fail_record) || 
        inter_reg == curr_arch()->sp() || 
        inter_reg == curr_arch()->ip() || 
        inter_reg == dest.reg || 
        is_identity_assign(inter_reg, assign.reg, assign.op, assign.cst ) || 
        env->reg_transitivity_record()->is_impossible(inter_reg, assign.reg, assign.op, assign.cst, env) || 
        env->reg_transitivity_record()->is_impossible(dest.reg, inter_reg, OP_ADD, 0, env)
        ){
            continue;
        }
        /* 1. Try dest.reg <- inter_reg without using assign.reg IF operation is trivial */
        if( is_identity_assign(assign.reg, assign.reg, assign.op, assign.cst )){
            env->reg_transitivity_unusable()->push_back(assign.reg);
            added_unusable=true;
        }
        env->set_lmax(prev_lmax-1);
        inter_to_dest = search(dest, AssignArg(ASSIGN_REG_BINOP_CST, inter_reg, OP_ADD, 0), env);
        env->set_lmax(prev_lmax);
        if( added_unusable ){
            env->reg_transitivity_unusable()->pop_back();
            added_unusable = false;
        }
        if( inter_to_dest == nullptr ){
            local_fail_record.merge_with(env->fail_record());
            continue;
        }
        
        /* 2. We found dest <- inter, try now inter <- assign */
        env->set_lmax(prev_lmax - inter_to_dest->len());
        env->reg_transitivity_unusable()->push_back(dest.reg);
        assign_to_inter = search(DestArg(DST_REG, inter_reg), assign, env);
        env->set_lmax(prev_lmax);
        env->reg_transitivity_unusable()->pop_back();
        if( assign_to_inter == nullptr ){
            delete inter_to_dest;
            inter_to_dest = nullptr;
            local_fail_record.merge_with(env->fail_record());
            continue;
        }
        /* 3. We found both, stop looking */ 
        assign_to_inter->add_chain(inter_to_dest);
        res = assign_to_inter;
        delete inter_to_dest; // Delete it because we keep only one
        inter_to_dest = nullptr;
        break;
    }
    
    /* Restore env */
    env->remove_last_call();
    if( new_reg_transitivity_unusable != nullptr ){
        /* Set the previous reg_transitivity_unusable info */
        delete new_reg_transitivity_unusable;
        env->set_reg_transitivity_unusable(prev_reg_transitivity_unusable);
    }
    /* Merge fail record with global */
    if( res == nullptr ){
        env->fail_record()->merge_with(&local_fail_record);
        g_fail_record.merge_with(&local_fail_record);
    }else{
        env->fail_record()->reset();
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
    Constraint *prev_constraint = env->constraint(), *tmp_constraint=nullptr;
    FailRecord local_fail_record;

    /* Reset env fail record */ 
    env->fail_record()->reset();

    /* Check for special cases */
    /* If constant contains bad bytes */
    if( ! env->constraint()->verify_address((addr_t)assign.cst, env->fail_record()) ){
        return nullptr;
    }
    /* Check length, we need at least two */
    if( env->lmax() <= 1){
        env->fail_record()->set_max_len(true);
        return nullptr;
    }

    /* Setting env */ 
    env->add_call(strategy);
    env->set_no_padding(true);
    /* Check for comments */
    had_comment = env->has_comment(strategy);
    if( had_comment ){
        comment = env->pop_comment(strategy);
    }else{
        snprintf(val_str, sizeof(val_str), "0x%lx", (addr_t)assign.cst);
        comment = "Constant: " + str_bold(string(val_str));
    }
    
    /* Chaining... */
    /* We check all possible offsets ! */
    for( offset = 0; offset < env->lmax(); offset += curr_arch()->octets() ){
        /* Set constraint on sp_inc to avoid gadgets like
         * pop rax; jmp rax; which have a valid ret and valid semantics
         * but don't work in practice :( */ 
        delete tmp_constraint;
        tmp_constraint = prev_constraint->copy();
        tmp_constraint->add(new ConstrMinSpInc(offset+(dest.reg==curr_arch()->ip()?1:2)*(curr_arch()->octets())), true);
        tmp_constraint->add(new ConstrMaxSpInc(env->lmax()*curr_arch()->octets()), true);
        env->set_constraint(tmp_constraint);
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
                delete res;
                res = nullptr;
                break;
            }
        }else{
			local_fail_record.merge_with(env->fail_record());
		}
    }
    
    /* Restore env */
    env->remove_last_call();
    env->set_no_padding(prev_no_padding);
    delete tmp_constraint;
    env->set_constraint(prev_constraint);

    /* Restore comment */
    if( had_comment ){
        env->push_comment(strategy, comment);
    }
    /* Merge fail record with global */ 
    if( res == nullptr ){
		env->fail_record()->merge_with(&local_fail_record);
        g_fail_record.merge_with(env->fail_record());
    }else{
        env->fail_record()->reset();
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
    Constraint *prev_constraint=env->constraint(), *tmp_constraint=nullptr;
    int dest_used_reg=-1; // The reg that is used in dest
    FailRecord local_fail_record;
    
    /* Reset env fail record */ 
    env->fail_record()->reset(); 
    
    /* Check for special cases */
    /* Don't call this strategy too many times, transitivity is handled
     * via reg_transitivity() so no need to do it within this function 
     * too */
     if( !env->calls_history().empty() && env->calls_history().back() == strategy ){
		 return nullptr;
	 }
     
     if( env->calls_count(strategy) > 2 ){
        return nullptr;
    }
    /* If lmax is 1, impossible to use two gagets */
    if( env->lmax() <= 1 ){
        env->fail_record()->set_max_len(true);
        return nullptr;
    }

    /* Get the regs that must be kept, depends on the DestType */ 
    if( dest.type == DST_REG )
        dest_used_reg = dest.reg;
    else if( dest.type == DST_MEM )
        dest_used_reg = dest.addr_reg;
    else
        return nullptr;
        
    /* Setting env */
    env->add_call(strategy);
    
    /* Chaining... */
    for( inter_reg = 0; inter_reg < curr_arch()->nb_regs(); inter_reg++ ){
        /* Check for forbidden regs */
        if( curr_arch()->is_ignored_reg(inter_reg) ||
        env->constraint()->keep_reg(inter_reg, &local_fail_record) ||
        inter_reg == curr_arch()->sp() ||
        inter_reg == curr_arch()->ip() ||
        inter_reg == dest_used_reg ||
        (dest.type == DST_REG && env->reg_transitivity_record()->is_impossible(dest.reg, inter_reg, OP_ADD, 0, env))
        ){
            continue;
        }
        
        /* 1. Search dest <- inter_reg */ 
        /* Set env */
        env->set_lmax(prev_lmax-1);
        inter_to_dest = search(dest, AssignArg(ASSIGN_REG_BINOP_CST, inter_reg, OP_ADD, 0), env );
        env->set_lmax(prev_lmax);
        if( inter_to_dest == nullptr){
            local_fail_record.merge_with(env->fail_record());
            continue;
        }
        
        /* 2. Search inter_reg <- assign */
        /* Set env */ 
        /* Check if we assign memory, if yes, we should not modify 
		 * the address registers when chaining */
		if( dest.type == DST_MEM ){
			tmp_constraint = prev_constraint->copy();
			tmp_constraint->add(new ConstrKeepRegs(dest.addr_reg), true);
			env->set_constraint(tmp_constraint);
		}
        env->set_lmax(prev_lmax- inter_to_dest->len());
        assign_to_inter = search(DestArg(DST_REG, inter_reg), assign, env);
        /* Restore env */
        env->set_lmax(prev_lmax);
        if( tmp_constraint != nullptr ){
			delete tmp_constraint;
			tmp_constraint = nullptr;
			env->set_constraint(prev_constraint);
		}
        if( assign_to_inter == nullptr ){
            delete inter_to_dest;
            inter_to_dest = nullptr;
            local_fail_record.merge_with(env->fail_record());
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
    if( tmp_constraint != nullptr ){
        env->set_constraint(prev_constraint);
        delete tmp_constraint;
        tmp_constraint = nullptr;
    }
    /* Merge fail record with global */ 
    if( res == nullptr ){
        env->fail_record()->merge_with(&local_fail_record);
        g_fail_record.merge_with(env->fail_record());
    }else{
        env->fail_record()->reset();
    }
    
    /* Return res */
    return res;
}


/* Adjust return for gadgets that match but finish with 
 * ret or jmp */ 
#define ADJUST_RET_MAX_POSSIBLE_GADGETS 3
#define ADJUST_RET_MAX_ADJUST_GADGETS 3
#define ADJUST_RET_MAX_ADDRESS_TRY 3
ROPChain* chain_adjust_ret(DestArg dest, AssignArg assign, SearchEnvironment* env){
    
    SearchStrategyType strategy = STRATEGY_ADJUST_RET;
    ROPChain *res=nullptr, *set_ret_reg_chain=nullptr; 
    Constraint* prev_constraint = env->constraint(), *tmp_constraint=nullptr;
    //AdjustRetRecord prev_adjust_ret = *(env->adjust_ret_record());
    vector<int> possible_gadgets, adjust_gadgets;
    vector<int>::iterator it, it2;
    vector<addr_t>::iterator ait;
    vector<addr_t>* addr_list=nullptr;
    shared_ptr<Gadget> gadget;
    int ret_reg; 
    cst_t offset;
    unsigned int padding_len;
    unsigned int prev_lmax = env->lmax();
    bool found = false;
    int addr_count;
    addr_t padding;
    bool success_padding;
    FailRecord local_fail_record;
    
    /* Reset env fail record */ 
    env->fail_record()->reset();
    
    /* Check for special cases */
    /* Accept only two recursive calls */ 
    if( env->calls_count(strategy) > 1 ){
        return nullptr;
    }
    /* Can never adjust ip */
    if( dest.type == DST_REG && (dest.reg == curr_arch()->ip() || dest.reg == curr_arch()->sp()) ){
        return nullptr;
    }
    
    if( env->lmax() < 3 ){
        env->fail_record()->set_max_len(true);
        return nullptr;
    }
    
    /* Setting env */
    env->add_call(strategy);
    
    /* Chaining... */
    /* 1. Get possible gadgets */
    /* Set constraint to JMP and CALL only */
    tmp_constraint = prev_constraint->copy();
    tmp_constraint->update(new ConstrReturn(false, true, true));
    tmp_constraint->add(new ConstrMaxSpInc(env->lmax()*curr_arch()->octets()), true);
    env->set_constraint(tmp_constraint);
    /* Find possible gadgets */
    possible_gadgets = _gadget_db_lookup(dest, assign, env, ADJUST_RET_MAX_POSSIBLE_GADGETS);
    /* Restore normal constraint to search for other gadgets/chains */
    env->set_constraint(prev_constraint);
    delete tmp_constraint;
    tmp_constraint = nullptr;
    
     if( possible_gadgets.empty() ){
        local_fail_record.merge_with(env->fail_record());
    }
    
    if( possible_gadgets.empty() ){
        local_fail_record.merge_with(env->fail_record());
    }
    
    /* For each possible gadget, try to adjust */ 
    for( it = possible_gadgets.begin(); (it != possible_gadgets.end()) && !found; it++ ){
        gadget = gadget_db()->get(*it);
        ret_reg = gadget->ret_reg();
        /* Check return reg */
        if( env->adjust_ret_record()->is_impossible(ret_reg) || 
        gadget->modified_reg(ret_reg) || 
        !gadget->known_sp_inc() ||
        env->constraint()->keep_reg(ret_reg, &local_fail_record)){
            continue;
        }
        /* Find the number of bytes to pop to adjust */
        if( gadget->sp_inc() < 0 ){
            offset = -1*gadget->sp_inc();
            padding_len = 0;
        }else{
            padding_len = gadget->sp_inc() / curr_arch()->octets();
            if( gadget->ret_type() == RET_JMP ){ 
                // JMP
                offset = 0;
            }else{ 
                // CALL
                offset = curr_arch()->octets();
            }
        }
        
        /* 2. Find gadget that do the adjustment (ret, pop-pop-ret, etc) */
        /* Set constraint to ensure that the adjustment doesn't destroy the 
         * effects wanted by the gadget */ 
        if( dest.type == DST_REG ){
            tmp_constraint = prev_constraint->copy();
            tmp_constraint->add(new ConstrKeepRegs(dest.reg), true);
            env->set_constraint(tmp_constraint);
        }
        adjust_gadgets = _gadget_db_lookup(DestArg(DST_REG, curr_arch()->ip()), AssignArg(ASSIGN_MEM_BINOP_CST, curr_arch()->sp(), OP_ADD, offset,0) , env, ADJUST_RET_MAX_ADJUST_GADGETS);
        /* Restore normal constraint */
        if( tmp_constraint != nullptr ){
            delete tmp_constraint;
            tmp_constraint = nullptr;
            env->set_constraint(prev_constraint);
        }
        /* Check if we found something */ 
        if( adjust_gadgets.empty()){
            local_fail_record.merge_with(env->fail_record());
            continue;
        }
        
        /* Check if we still have enough length */
        if( padding_len+1 >= prev_lmax )
            continue;
        
        /* For each adjust gadget, see if we can put its address in the ret_reg */
        for( it2 = adjust_gadgets.begin(); (it2 != adjust_gadgets.end()) && !found; it2++){
            addr_count = 0; // Limit number of addresses checked
            addr_list = gadget_db()->get(*it2)->addresses();
            for( ait = addr_list->begin(); (ait != addr_list->end()) && !found; ait++ ){
                /* Check number of addresses */ 
                if( ++addr_count > ADJUST_RET_MAX_ADDRESS_TRY)
                    break;
                /* 3. Find ROPChain that puts the address of the adjust gadget 
                 * in the ret_reg */ 
                /* Set constraint to ensure that setting adjustment doesn't clobber 
                 * the value that we want to assign */ 
                if( assign.type == ASSIGN_REG_BINOP_CST ){
                    tmp_constraint = prev_constraint->copy();
                    tmp_constraint->add(new ConstrKeepRegs(assign.reg), true);
                    env->set_constraint(tmp_constraint);
                }else if(assign.type == ASSIGN_MEM_BINOP_CST){
                    tmp_constraint = prev_constraint->copy();
                    tmp_constraint->add(new ConstrKeepRegs(assign.addr_reg), true);
                    env->set_constraint(tmp_constraint);
                }
                
                /* Adapt lmax */
                env->set_lmax(prev_lmax - padding_len - 1);
                /* Set comment */ 
                env->push_comment(STRATEGY_POP_CONSTANT, string("Address of ") + str_bold(gadget_db()->get(*it2)->asm_str()));
                /* Search */ 
                set_ret_reg_chain = search(DestArg(DST_REG, ret_reg), AssignArg(ASSIGN_CST, *ait), env);
                /* Restore env */ 
                env->set_lmax(prev_lmax);
                env->pop_comment(STRATEGY_POP_CONSTANT);
                if( tmp_constraint != nullptr ){
                    delete tmp_constraint;
                    tmp_constraint = nullptr;
                    env->set_constraint(prev_constraint);
                }
                /* If didn't find result, continue. The adjust_ret record will 
                 * be updated only if we fail for all addresses and all adjust 
                 * gadgets */  
                if( set_ret_reg_chain == nullptr ){
                    local_fail_record.merge_with(env->fail_record());
                    continue;
                }
                /* 4. If we found result, padd everything and return */ 
                else{
                    found = true;
                    /* Find padding */ 
                    std::tie(success_padding,padding) = env->constraint()->valid_padding();
                    if( !success_padding ){
                        env->fail_record()->set_no_valid_padding(true);
                        delete set_ret_reg_chain;
                    }else{
                        /* Create ropchain */
                        res = set_ret_reg_chain;
                        res->add_gadget(*it);
                        res->add_padding(padding, padding_len);
                        break;
                    }
                }
            }
        }
        /* If could not set ret_reg, put it in the record */ 
        if( !found && !adjust_gadgets.empty() && !env->fail_record()->max_len()){
            env->adjust_ret_record()->add_fail(ret_reg);
        }
    }
    
    /* Restore env */
    env->remove_last_call();
    /* Merge fail record with global */
    if( res == nullptr ){
        env->fail_record()->merge_with(&local_fail_record); 
        g_fail_record.merge_with(env->fail_record());
    }else{
        env->fail_record()->reset();
    }
    
    // DEBUG Keep old adjust ? maybe not --> makes it very slow 
    //env->set_adjust_ret_record(&prev_adjust_ret);
    
    /* Return result */
    return res;
}


pair<bool,cst_t> _invert_operation(cst_t adjust_cst, Binop op, cst_t cst){
    switch(op){
        case OP_ADD:
            return make_pair(true, adjust_cst-cst);
        case OP_SUB:
            return make_pair(true, adjust_cst+cst);
        case OP_MUL:
            if( adjust_cst % cst == 0 )
                return make_pair(true, adjust_cst/cst);
            break;
        case OP_DIV:
            if( ((1<<curr_arch()->bits())-1)/cst > adjust_cst )
                return make_pair(true, adjust_cst*cst);
            break;
        default:
            break;
    }
    return make_pair(false, 0);
}

/* We want to to mem(requested) <- ... 
 * we only have mem(available) <- ...
 *  - requested is reg_binop_cst or cst
 *  - available is reg2_binop2_cst2
 * Find the AssignArg 'res' such that we can emulate 'requested'
 * by putting 'res' into reg2 (in available) 
 *
 * Example:
 *  - requested= mem(rax+8)
 *  - available= mem(rdx+16)
 *  - res is what we want to put in rdx = rax-8
 */
pair<bool,AssignArg> _adjust_store_adapt_dest_arg(DestArg requested, DestArg available){
    bool success;
    cst_t res_cst;
    AssignArg res;
    
    if( available.type != DST_MEM )
        return make_pair(false, res); 
    switch(requested.type){
        case DST_CSTMEM:
            /* Find the right cst to put in the register */
            std::tie(success,res_cst) = _invert_operation(requested.addr_cst, available.addr_op, available.addr_cst);
            if( success )
                return make_pair(true,AssignArg(ASSIGN_CST, res_cst));
            break;
        case DST_MEM:
            /* Find the cst to put in the register */
            std::tie(success, res_cst)= _invert_operation(requested.addr_cst, available.addr_op, available.addr_cst);
            if( success )
                return make_pair(true, AssignArg(ASSIGN_REG_BINOP_CST, requested.addr_reg, requested.addr_op, res_cst));
            break;
        default:
            break;
    }
    return make_pair(false, res);
}

/* We want to to ... <- requested
 * we only have ... <- available (reg op cst)
 *  - requested is anything
 *  - available is reg op cst 
 * Find the AssignArg 'res' such that we can emulate 'requested'
 * by putting 'res' into reg (in available) 
 *
 * Example:
 *  - requested= mem(rax+8) + 8
 *  - available= rbx+4
 *  - res is what we want to put in rbx = mem(rax+8) + 4 
 */  
pair<bool,AssignArg> _adjust_store_adapt_assign_arg(AssignArg requested, AssignArg available){
    bool success;
    cst_t res_cst; 
    AssignArg res = requested;
    if( available.type != ASSIGN_REG_BINOP_CST ){
        return make_pair(false, res);
    }
    std::tie(success, res_cst) = _invert_operation(requested.cst, available.op, available.cst);
    if( success ){
        res.cst = res_cst;
    }else{
        return make_pair(false, res);
    }
    return make_pair(true, res);
}

/* Adjust registers to do complex stores
 * eg:  mem(X) <- Y 
 * becomes: 
 *      reg1 <- Y+cst1
 *      reg2 <- X+cst2
 *      mem(reg2-cst2) <- reg1-cst1
 * 
 * !! Expects dest to be DST_CSTMEM
 */ 
 
/* Maximum gadgets to try for each storing register 
* i.e mem(REG+...) <- ... */ 
#define ADJUST_STORE_MAX_PER_STORE_REG 4
/* Given reg1, reg2, cst, op, max gadgets to get
 * for mem(reg1 op cst ) <- reg2 ... */
#define ADJUST_STORE_MAX_POSSIBLE_PER_STORE 1
ROPChain* chain_adjust_store(DestArg dest, AssignArg assign, SearchEnvironment* env){
    SearchStrategyType strategy = STRATEGY_ADJUST_STORE;
    ROPChain *res=nullptr, *set_dest_reg=nullptr, *set_assign_reg=nullptr, *chain1=nullptr, *chain2=nullptr;
    unsigned int saved_lmax = env->lmax();
    vector<tuple<DestArg, AssignArg, vector<int>>>* possible = nullptr;
    vector<tuple<DestArg, AssignArg, vector<int>>>::iterator it;
    FailRecord local_fail_record;
    AssignArg assign_to_dest_reg;
    AssignArg assign_to_store_reg;
    ExprObjectPtr tmp_dest_expr;
    bool success;
    bool already_right_assign;
    bool already_right_dest;
    Constraint *tmp_constraint = nullptr, *saved_constraint = env->constraint();
    addr_t padding;
    int gadget_sp_inc; 
    int dest_used_reg=-1; // The reg that is used in dest
    int assign_used_reg=-1; // The reg that is used in assign

    /* Reset env fail record */ 
    env->fail_record()->reset();

    /* Check for special cases */
    /* Don't call this strategy consecutively, transitivity is handled
     * via other chaining functions so no need to do it within this function 
     * too */
    if( !env->calls_history().empty() && env->calls_history().back() == strategy){
        return nullptr;
    }
    /* Accept only one recursive calls */ 
    if( env->calls_count(strategy) > 0 ){
        return nullptr;
    }
    /* If lmax is < 3, impossible to use this strat
     * At least 1 for store, 2 for setting regs */
    if( env->lmax() < 3 ){
        env->fail_record()->set_max_len(true);
        return nullptr;
    }
    
    /* Set env */ 
    env->add_call(strategy);
    
    /* Set env */
    /* Get only valid RET gadgets, and not too big sp inc*/ 
    tmp_constraint = env->constraint()->copy();
    tmp_constraint->update(new ConstrReturn(true, false, false));
    tmp_constraint->add(new ConstrMaxSpInc(env->lmax()*curr_arch()->octets()), true);
    /* 0. Find all possible memory writes */
    possible = gadget_db()->get_possible_stores_reg(tmp_constraint, env->assertion(), 1 , &local_fail_record, -1, -1);
    /* Restore env */ 
    delete tmp_constraint;
    tmp_constraint = nullptr;
    
    /* Loop through all possibilities */
    for( it = possible->begin(); it != possible->end(); it++ ){
        /* Get sp increment for the gadget (will determine the max
         * length allowed for adjustement ROPChains) */ 
        gadget_sp_inc = gadget_db()->get(std::get<2>(*it).at(0))->sp_inc()/curr_arch()->octets();
        /* Build new arguments for dest and assign */ 
        /* Dest */
        if( dest == std::get<0>(*it) ){
            already_right_dest = true;
        }else{
            std::tie(success, assign_to_dest_reg) = _adjust_store_adapt_dest_arg(dest, std::get<0>(*it));
            if( !success ){
                continue;
            }
            already_right_dest = false;
        }
        /* Store */ 
        if( assign == std::get<1>(*it) ){
			already_right_assign = true;
		}else{
			std::tie(success, assign_to_store_reg ) = _adjust_store_adapt_assign_arg(assign, std::get<1>(*it));
			if( !success){
				continue;
            }
			already_right_assign = false;
		}
        /* Get regs that are used in dest and assign (for the keep_regs 
         * constraints */ 
        /* Get the regs that must be kept, depends on the DestType */ 
        dest_used_reg = std::get<0>(*it).addr_reg;
        assign_used_reg = std::get<1>(*it).reg;
        
        /* --------------------------------------------------------------------------------------------
         * (A.) Try to adjust the reg that references memory first then the
         * one that is stored */
        /* 1. Set dest reg */ 
        if( already_right_dest){
            set_dest_reg = new ROPChain();
        }else{
			/* Set env */ 
			tmp_constraint = saved_constraint->copy();
            env->set_lmax(saved_lmax-gadget_sp_inc);
			/* If assign is already the good one, we should not modify it*/ 
			if( already_right_assign ){
				tmp_constraint->add(new ConstrKeepRegs(assign.reg), true);
			}
			/* In any case, don't modify the register that goes in assign */
			tmp_constraint->add(new ConstrKeepRegs(assign_used_reg), true);
			env->set_constraint(tmp_constraint);
			/* Search */
			set_dest_reg = search(DestArg(DST_REG, std::get<0>(*it).addr_reg), assign_to_dest_reg, env);
            /* Restore env */ 
			delete tmp_constraint;
			tmp_constraint = nullptr;
			env->set_constraint(saved_constraint);
            env->set_lmax(saved_lmax);
		}
		/* 2. Set assign reg */ 
        if( already_right_assign ){
            set_assign_reg = new ROPChain();
        }else if( (set_dest_reg != nullptr )){
			/* Set env */ 
			if( set_dest_reg != nullptr && set_dest_reg->len()+1+gadget_sp_inc-1 >= saved_lmax ){
				delete set_dest_reg;
				set_dest_reg = nullptr;
                local_fail_record.set_max_len(true);
				continue;
			}else if( set_dest_reg != nullptr){
				env->set_lmax(saved_lmax-set_dest_reg->len()-gadget_sp_inc);
			}
			tmp_constraint = saved_constraint->copy();
			tmp_constraint->add(new ConstrKeepRegs(dest_used_reg), true);
			env->set_constraint(tmp_constraint);
			/* Search */
			set_assign_reg = search(DestArg(DST_REG, std::get<1>(*it).reg), assign_to_store_reg, env);
			/* Restore env */
			env->set_lmax(saved_lmax);
			env->set_constraint(saved_constraint);
			delete tmp_constraint;
			tmp_constraint = nullptr;
		}else{
			local_fail_record.merge_with(env->fail_record());
		}
		/* Check result */ 
		if( set_assign_reg == nullptr || set_dest_reg == nullptr){
			delete set_dest_reg; set_dest_reg = nullptr;
            delete set_assign_reg; set_assign_reg = nullptr;
			local_fail_record.merge_with(env->fail_record());
            /* Check fail record */
			if( env->fail_record()->modified_reg(std::get<0>(*it).addr_reg)){
				// If we fail because of previous reg modified, just 
				// try the other order :)
				goto try_reversed_order;
            }else{
				// Otherwise, continue :) 
				continue;
			}
		}else{
			/* Found both, build res and exit the search loop */
			chain1 = set_dest_reg;
			chain2 = set_assign_reg;
			break;
		}
		
try_reversed_order:
        /* --------------------------------------------------------------------------------------------
         * (B.) Try to adjust the reg that is stored first, then the
         * one that is dereferenced */
        /* 1. Set assign reg */ 
        if( already_right_assign ){
            set_assign_reg = new ROPChain();
        }else{
            /* Set env */
			tmp_constraint = saved_constraint->copy();
			/* If dest is already the good one, we should not modify it*/ 
			if( already_right_dest ){
				tmp_constraint->add(new ConstrKeepRegs(dest.addr_reg), true);
			}
			/* In any case, don't modify the reg that is put in dest */ 
			tmp_constraint->add(new ConstrKeepRegs(dest_used_reg), true);
			env->set_constraint(tmp_constraint);
            env->set_lmax(saved_lmax - gadget_sp_inc);
			/* Search */
			set_assign_reg = search(DestArg(DST_REG, std::get<1>(*it).reg), assign_to_store_reg, env);
			/* Restore env */
			delete tmp_constraint;
			tmp_constraint = nullptr;
			env->set_constraint(saved_constraint);
            env->set_lmax(saved_lmax);
        }
        /* 2. Set dest reg */ 
        if( already_right_dest ){
            set_dest_reg = new ROPChain();
        }else if( (set_assign_reg != nullptr )){
			/* Set env */ 
			if( set_assign_reg != nullptr && set_assign_reg->len()+1+gadget_sp_inc-1 >= saved_lmax ){
				delete set_assign_reg;
				set_assign_reg = nullptr;
                local_fail_record.set_max_len(true);
				continue;
			}else if( set_assign_reg != nullptr){
				env->set_lmax(saved_lmax-set_assign_reg->len()-gadget_sp_inc);
			}
			tmp_constraint = saved_constraint->copy();
			tmp_constraint->add(new ConstrKeepRegs(assign_used_reg), true);
			env->set_constraint(tmp_constraint);
			/* Search */
			set_assign_reg = search(DestArg(DST_REG, std::get<0>(*it).addr_reg), assign_to_dest_reg, env);
			/* Restore env */
			env->set_lmax(saved_lmax);
			env->set_constraint(saved_constraint);
			delete tmp_constraint;
			tmp_constraint = nullptr;
		}else{
			local_fail_record.merge_with(env->fail_record());
		}
        /* Check result */ 
		if( set_assign_reg == nullptr || set_dest_reg == nullptr){
			delete set_dest_reg; set_dest_reg = nullptr;
            delete set_assign_reg; set_assign_reg = nullptr;
			local_fail_record.merge_with(env->fail_record());
		}else{
			/* Found both, build res and exit the search loop */
			chain1 = set_assign_reg;
			chain2 = set_dest_reg;
			break;
		}
	}
    
    /* --------------------------------------------------------------------------------------------
     * Build result ropchain if any */
    if( chain1 != nullptr && chain2 != nullptr ){
		res = chain1;
		res->add_chain(chain2);
		delete chain2; chain2 = nullptr;
		res->add_gadget(std::get<2>(*it).at(0));
		/* Add padding */ 
		std::tie(success, padding) = env->constraint()->valid_padding();
		if( success ){
                res->add_padding(padding, ((gadget_db()->get(std::get<2>(*it).at(0))->sp_inc()/curr_arch()->octets()) -1));
		}else{
			local_fail_record.set_no_valid_padding(true);
			delete res;
			res = nullptr;
		}
	}
    
    /* Delete the possible gadgets vector */ 
    delete possible;
    possible = nullptr;
    
    /* Restore env */ 
    env->remove_last_call();
    /* Merge local fail record with global one */
    if( res == nullptr ){
		env->fail_record()->merge_with(&local_fail_record);
        g_fail_record.merge_with(env->fail_record());
    }else{
        env->fail_record()->reset();
    }
    
    /* Return result */
    return res;
}

/* Similar to adjust_store_adapt_dest_arg
 * 
 * We want to to mem(requested) <- ... 
 * we only have mem(available) <- ...
 *  - requested is reg_binop_cst or cst
 *  - available is reg2_binop2_cst2
 *  !!! We assume that assign.op is ADD and assign.cst is 0 !!! 
 * Find the AssignArg 'res' such that we can emulate 'requested'
 * by putting 'res' into reg2 (in available) 
 *
 * Example:
 *  - requested= mem(rax+8)
 *  - available= mem(rdx+16)
 *  - res is what we want to put in rdx = rax-8
 */
pair<bool,AssignArg> _adjust_load_adapt_assign_arg(AssignArg requested, AssignArg available){
    bool success;
    cst_t res_cst;
    AssignArg res;
    
    if( available.type != ASSIGN_CSTMEM_BINOP_CST && available.type != ASSIGN_MEM_BINOP_CST )
        return make_pair(false, res); 
    switch(requested.type){
        case ASSIGN_CSTMEM_BINOP_CST:
            /* Find the right cst to put in the register */
            std::tie(success,res_cst) = _invert_operation(requested.addr_cst, available.addr_op, available.addr_cst);
            if( success )
                return make_pair(true,AssignArg(ASSIGN_CST, res_cst));
            break;
        case ASSIGN_MEM_BINOP_CST:
            /* Find the cst to put in the register */
            std::tie(success, res_cst)= _invert_operation(requested.addr_cst, available.addr_op, available.addr_cst);
            if( success )
                return make_pair(true, AssignArg(ASSIGN_REG_BINOP_CST, requested.addr_reg, requested.addr_op, res_cst));
            break;
        default:
            break;
    }
    return make_pair(false, res);
}

/* Read memory into a register 
 * reg1 <- mem(X) becomes:
 *     reg2 <- X op2 cst2
 * 	   reg1 <- mem(reg2 op cst)
 * */
ROPChain* chain_adjust_load(DestArg dest, AssignArg assign, SearchEnvironment* env){
	vector<tuple<int, AssignArg, vector<int>>> * possible; 
	vector<tuple<int, AssignArg, vector<int>>>::iterator it;
	FailRecord local_fail_record; 
	unsigned int saved_lmax = env->lmax();
	SearchStrategyType strategy = STRATEGY_ADJUST_LOAD;
	ROPChain * res = nullptr, *set_addr_reg=nullptr; 
	Constraint *tmp_constraint = nullptr, *saved_constraint = env->constraint()->copy();
	int gadget_sp_inc;
	AssignArg assign_to_addr_reg;
    bool already_right_addr; 
    bool success; 
    int addr_used_reg;
    addr_t padding;
	
	/* Reset env fail record */ 
    env->fail_record()->reset();

    /* Check for special cases */
    /* Don't call this strategy consecutively, transitivity is handled
     * via other chaining functions so no need to do it within this function 
     * too */
    if( !env->calls_history().empty() && env->calls_history().back() == strategy){
        return nullptr;
    }
    /* Accept only one recursive call */ 
    if( env->calls_count(strategy) > 0 ){
        return nullptr;
    }
    /* If lmax is < 3, impossible to use this strat
     * At least 1 for store, 2 for setting regs */
    if( env->lmax() < 2 ){
        env->fail_record()->set_max_len(true);
        return nullptr;
    }
    /* This strategy only supports mem expressions without constants 
     * added (e.g mem(rbx+8)+1 not supported, but mem(rbx+2) is ok */
     if( assign.cst != 0){
		 return nullptr;
	 }
    
    /* Set env */ 
    env->add_call(strategy);
    
    /* Set env */
    /* Get only valid RET gadgets, and not too big sp inc*/ 
    tmp_constraint = env->constraint()->copy();
    tmp_constraint->update(new ConstrReturn(true, false, false));
    tmp_constraint->add(new ConstrMaxSpInc(env->lmax()*curr_arch()->octets()), true);  
	/* 0. Get possible memory reads to this register */
	possible = gadget_db()->get_possible_loads_reg(env->constraint(), env->assertion(), 1, &local_fail_record, dest.reg, -1 );
	/* Restore env */ 
    delete tmp_constraint;
    tmp_constraint = nullptr;
	/* Loop through all possibilities */
    for( it = possible->begin(); it != possible->end(); it++ ){
		/* Get sp increment for the gadget (will determine the max
         * length allowed for adjustement ROPChains) */ 
        gadget_sp_inc = gadget_db()->get(std::get<2>(*it).at(0))->sp_inc()/curr_arch()->octets();
        /* Build new arguments for assign */ 
		if( assign == std::get<1>(*it)){
			already_right_addr = true;
		}else{
			already_right_addr = false;
			std::tie(success, assign_to_addr_reg) = _adjust_load_adapt_assign_arg(assign, std::get<1>(*it));
			if( !success ){
				continue;
			}
		}
		/* Get regs that are used in dest and assign (for the keep_regs 
         * constraints */ 
        addr_used_reg = std::get<1>(*it).addr_reg;
				
		/* 2. Set the address reg */
		if( already_right_addr ){
			set_addr_reg = new ROPChain();
		}else{
			/* Test length */ 
			if( gadget_sp_inc-1+1 >= saved_lmax ){
                local_fail_record.set_max_len(true);
				continue;
			}else{
				env->set_lmax(saved_lmax-gadget_sp_inc);
				set_addr_reg = search(DestArg(DST_REG, addr_used_reg), assign_to_addr_reg, env);
				env->set_lmax(saved_lmax);
			}
		}
		/* Check result */ 
		if( set_addr_reg == nullptr ){
			local_fail_record.merge_with(env->fail_record());
            continue;
		}else{
			/* Found it, exit the search loop */
			break;
		}
	}
	/* --------------------------------------------------------------------------------------------
     * Build result ropchain if any */
    if( set_addr_reg != nullptr ){
		res = set_addr_reg;
		res->add_gadget(std::get<2>(*it).at(0));
		/* Add padding */ 
		std::tie(success, padding) = env->constraint()->valid_padding();
		if( success ){
                res->add_padding(padding, ((gadget_db()->get(std::get<2>(*it).at(0))->sp_inc()/curr_arch()->octets()) -1));
		}else{
			local_fail_record.set_no_valid_padding(true);
			delete set_addr_reg;
			res = nullptr;
		}
	}
 
    /* Delete the possible gadgets vector */ 
    delete possible;
    possible = nullptr;
   
    /* Restore env */ 
    env->remove_last_call();
    env->set_lmax(saved_lmax);
    /* Merge local fail record with global one */
    if( res == nullptr ){
        g_fail_record.merge_with(&local_fail_record);
        env->fail_record()->merge_with(&local_fail_record);
    }else{
        env->fail_record()->reset();
    }
    
    /* Return result */
    return res;
}


/* Init functions */
void init_chaining_engine(){
    g_reg_transitivity_record = RegTransitivityRecord();
    g_search_verbose = false;
}
