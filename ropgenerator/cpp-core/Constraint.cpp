#include "Constraint.hpp"
#include "Architecture.hpp"
#include "Expression.hpp"
#include "Condition.hpp"
#include "Exception.hpp"
#include "ChainingEngine.hpp"
#include <algorithm>
#include <cstring>


/* ---------------------------------------------------------------------
 *                          Constraints 
 * --------------------------------------------------------------------*/

// SubConstraint
SubConstraint::SubConstraint(SubConstraintType t): _type(t){}
SubConstraintType SubConstraint::type(){return _type;}

// ConstrReturn
ConstrReturn::ConstrReturn(bool r=false, bool j=false, bool c=false): SubConstraint(CONSTR_RETURN), _ret(r), _jmp(j), _call(c){}
bool ConstrReturn::ret(){return _ret;}
bool ConstrReturn::jmp(){return _jmp;}
bool ConstrReturn::call(){return _call;}
SubConstraint* ConstrReturn::copy(){
    return new ConstrReturn(_ret, _jmp, _call);
}

pair<ConstrEval,CondObjectPtr> ConstrReturn::verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr){
    if  (( _ret && (g->ret_type() == RET_RET))  || 
        ( _jmp && (g->ret_type() == RET_JMP))  ||
        ( _call && (g->ret_type() == RET_CALL)))
        return g->ret_pre_cond()->cond_ptr()->type() == COND_TRUE ? make_pair(EVAL_VALID, g->ret_pre_cond()):
                                                        make_pair(EVAL_MAYBE, g->ret_pre_cond());
    else
        return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
}

void ConstrReturn::merge(SubConstraint* c, bool del=false){
    if( c->type() != CONSTR_RETURN )
        throw_exception("ConstrReturn : Invalid sub constraint type when merging");
    _ret = ((ConstrReturn*)c)->ret() || _ret; 
    _jmp = ((ConstrReturn*)c)->jmp() || _jmp; 
    _call = ((ConstrReturn*)c)->call() || _call; 
    if( del )
        delete c; 
}

// ConstrBadBytes
ConstrBadBytes::ConstrBadBytes(vector<unsigned char> bb): SubConstraint(CONSTR_BAD_BYTES){
    _bad_bytes = bb;
}

vector<unsigned char>* ConstrBadBytes::bad_bytes(){return &_bad_bytes;} 

bool ConstrBadBytes::verify_address(addr_t a, FailRecord* fail_record=nullptr){
    // Check if each byte of the address is not in bad bytes list
    int i; 
    for( i = 0; i < curr_arch()->octets(); i++ ){
        if( std::find(_bad_bytes.begin(), _bad_bytes.end(), (unsigned char)((a >> i)&0xFF)) != _bad_bytes.end()){
            if( fail_record != nullptr){
                fail_record->add_bad_byte((unsigned char)((a >> i)&0xFF));
            }
            return false;
        }
    }
    return true;
}

pair<ConstrEval,CondObjectPtr> ConstrBadBytes::verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr){
    vector<addr_t>::iterator it; 
    vector<addr_t>* addr_list = g->addresses();
    for( it = addr_list->begin(); it != addr_list->end(); it++){
        if( ! verify_address(*it, fail_record)){
            return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
        }
    }
    return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
}

SubConstraint* ConstrBadBytes::copy(){
    return new ConstrBadBytes(_bad_bytes);
}

void ConstrBadBytes::merge(SubConstraint* c, bool del=false){
    if( c->type() != CONSTR_BAD_BYTES )
        throw_exception("ConstrBadBytes : Invalid sub constraint type when merging");
    _bad_bytes.insert(_bad_bytes.end(), c->bad_bytes()->begin(), c->bad_bytes()->end()); 
    if( del )
        delete c; 
}

// ConstrKeepRegs 
ConstrKeepRegs::ConstrKeepRegs(): SubConstraint(CONSTR_KEEP_REGS){
    memset(_regs, false, sizeof(_regs));
}

ConstrKeepRegs::ConstrKeepRegs(int num): SubConstraint(CONSTR_KEEP_REGS){
    memset(_regs, false, sizeof(_regs));
    _regs[num] = true;
}

ConstrKeepRegs::ConstrKeepRegs(vector<int>& k): SubConstraint(CONSTR_KEEP_REGS){
    vector<int>::iterator it; 
    memset(_regs, false, sizeof(_regs));
    for( it = k.begin(); it != k.end(); it++){
        if( *it < 0 || *it >= curr_arch()->nb_regs() )
            throw_exception("In Constraint Keep Regs: invalid reg when init");
        _regs[*it] = true; 
    }
}

bool ConstrKeepRegs::get(int num){
    return ( num >= NB_REGS_MAX || num < 0)? false : _regs[num];
}
void ConstrKeepRegs::add_reg(int num){ 
    if( num < NB_REGS_MAX && num >= 0 ){
        _regs[num] = true;
    }else{
        throw_exception("Adding invalid reg in add_reg");
    }
}

void ConstrKeepRegs::remove_reg(int num){
    if( num < NB_REGS_MAX && num >= 0 )
        _regs[num] = false; 
}
pair<ConstrEval,CondObjectPtr> ConstrKeepRegs::verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr){
    bool * modified = g->modified_regs();

    for( int i = 0; i < NB_REGS_MAX; i++){
        if( _regs[i] && modified[i] ){
            if( fail_record != nullptr ){
                fail_record->add_modified_reg(i);
            }
            return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
        }
    }
    return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
}

SubConstraint* ConstrKeepRegs::copy(){
    int i;
    ConstrKeepRegs* res = new ConstrKeepRegs();
    for( i = 0; i < NB_REGS_MAX; i++)
        if( _regs[i] )
            res->add_reg(i);
    return res; 
}

void ConstrKeepRegs::merge(SubConstraint* c, bool del=false){
    int i;
    if( c->type() != CONSTR_KEEP_REGS )
        throw_exception("ConstrKeepRegs : Invalid sub constraint type when merging");
    for( i = 0; i < NB_REGS_MAX; i++){
        _regs[i] |= ((ConstrKeepRegs*)c)->get(i); 
    }
    if( del )
        delete c; 
}

// ConstrValidRead
ConstrValidRead::ConstrValidRead(): SubConstraint(CONSTR_VALID_READ){}
void ConstrValidRead::add_addr( ExprObjectPtr a){
    _addresses.push_back(a);
}

vector<ExprObjectPtr>* ConstrValidRead::addresses(){return &_addresses;}

pair<ConstrEval,CondObjectPtr> ConstrValidRead::verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr){
    vector<ExprObjectPtr>::iterator it;
    CondObjectPtr tmp; 
    if( _addresses.size() == 0 )
        return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
    tmp = NewCondTrue();
    for( it = _addresses.begin(); it != _addresses.end(); it++ )
        tmp = tmp && NewCondPointer(COND_VALID_READ, (*it));
    return make_pair(EVAL_MAYBE, tmp);
}

SubConstraint* ConstrValidRead::copy(){
    ConstrValidRead * res = new ConstrValidRead();
    vector<ExprObjectPtr>::iterator it;
    for( it = _addresses.begin(); it != _addresses.end(); it++ )
        res->add_addr(*it);
    return res; 
}

void ConstrValidRead::merge(SubConstraint* c, bool del=false){
    if( c->type() != CONSTR_VALID_READ )
       throw_exception("ConstrValidRead : Invalid sub constraint type when merging");
    _addresses.insert(_addresses.end(), c->addresses()->begin(), c->addresses()->end());
    if( del )
        delete c; 
}

// ConstrValidWrite
ConstrValidWrite::ConstrValidWrite(): SubConstraint(CONSTR_VALID_WRITE){}
void ConstrValidWrite::add_addr( ExprObjectPtr a){
    _addresses.push_back(a);
}

vector<ExprObjectPtr>* ConstrValidWrite::addresses(){return &_addresses;}

pair<ConstrEval,CondObjectPtr> ConstrValidWrite::verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr){
    vector<ExprObjectPtr>::iterator it;
    CondObjectPtr tmp; 
    if( _addresses.size() == 0 )
        return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
    tmp = NewCondTrue();
    for( it = _addresses.begin(); it != _addresses.end(); it++ )
        tmp = tmp && NewCondPointer(COND_VALID_WRITE, (*it));
    return make_pair(EVAL_MAYBE, tmp);
}

SubConstraint* ConstrValidWrite::copy(){
    ConstrValidWrite * res = new ConstrValidWrite();
    vector<ExprObjectPtr>::iterator it;
    for( it = _addresses.begin(); it != _addresses.end(); it++ )
        res->add_addr(*it);
    return res; 
}

void ConstrValidWrite::merge(SubConstraint* c, bool del=false){
    if( c->type() != CONSTR_VALID_WRITE )
       throw_exception("ConstrValidWrite : Invalid sub constraint type when merging");
    _addresses.insert(_addresses.end(), c->addresses()->begin(), c->addresses()->end());
    if( del )
        delete c; 
}

// ConstrMaxSpInc
ConstrMaxSpInc::ConstrMaxSpInc(cst_t i): SubConstraint(CONSTR_MAX_SP_INC), _inc(i){}
cst_t ConstrMaxSpInc::inc(){return _inc;}

pair<ConstrEval,CondObjectPtr> ConstrMaxSpInc::verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr){
    if( !g->known_sp_inc() || g->sp_inc() > _inc ){
        if( fail_record != nullptr ){
            fail_record->set_max_len(true);
        }
        return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
    }
    return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
}

SubConstraint* ConstrMaxSpInc::copy(){
    return new ConstrMaxSpInc(_inc); 
}

// ConstrMinSpInc
ConstrMinSpInc::ConstrMinSpInc(cst_t i): SubConstraint(CONSTR_MIN_SP_INC), _inc(i){}
cst_t ConstrMinSpInc::inc(){return _inc;}

pair<ConstrEval,CondObjectPtr> ConstrMinSpInc::verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr){
    if( !g->known_sp_inc() || g->sp_inc() < _inc ){
        return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
    }
    return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
}

SubConstraint* ConstrMinSpInc::copy(){
    return new ConstrMinSpInc(_inc); 
}


// Constraint class (collection of subconstraints)
Constraint::Constraint(){
    std::memset(_constr, 0, sizeof(SubConstraint*)*COUNT_NB_CONSTR);
}
// Accessors 
SubConstraint* Constraint::get(SubConstraintType t){
    return _constr[t];
}
// Modifiers
void Constraint::add(SubConstraint* c, bool del=false){
    if( _constr[c->type()] != nullptr )
        _constr[c->type()]->merge(c, del);
    else
        _constr[c->type()] = c;
}

void Constraint::update(SubConstraint* c){
    delete _constr[c->type()];
    _constr[c->type()] = c; 
}

void Constraint::remove(SubConstraintType t){
    delete _constr[t];
    _constr[t] = nullptr; 
}

// Copy 
Constraint* Constraint::copy(){
    Constraint * res = new Constraint();
    for( int i = 0; i < COUNT_NB_CONSTR; i++)
        if( _constr[i] != nullptr )
            res->add(_constr[i]->copy());
    return res; 
}

pair<ConstrEval,CondObjectPtr> Constraint::verify(shared_ptr<Gadget> g, FailRecord* fail_record){
    ConstrEval eval; 
    CondObjectPtr cond; 
    CondObjectPtr res_cond = NewCondTrue(); 
    bool maybe = false;
    if( g->type() == INT80 or g->type() == SYSCALL )
        return make_pair(EVAL_VALID, NewCondTrue());
        
    for( int i = 0; i < COUNT_NB_CONSTR; i++){
        if( _constr[i] != nullptr ){
            std::tie(eval, cond) = _constr[i]->verify(g, fail_record);
            if( eval == EVAL_INVALID ){
                return make_pair(EVAL_INVALID, NewCondFalse());
            }else if( eval == EVAL_MAYBE){
                res_cond = res_cond && cond;
                maybe = true;
            }
        }
    }
    if( maybe )
        return make_pair(EVAL_MAYBE, res_cond);
    else
        return make_pair(EVAL_VALID, res_cond);
}

bool Constraint::verify_address(addr_t a, FailRecord* fail_record){
    if( _constr[CONSTR_BAD_BYTES] == nullptr ){
        return true;
    }
    return _constr[CONSTR_BAD_BYTES]->verify_address(a, fail_record);
}

bool Constraint::keep_reg(int num, FailRecord* fail_record){
    bool res;
    if( _constr[CONSTR_KEEP_REGS] == nullptr ){
        return false;
    }
    res= _constr[CONSTR_KEEP_REGS]->get(num);
    if( !res && (fail_record!=nullptr))
        fail_record->add_modified_reg(num);
    return res;
}

pair<bool, addr_t> Constraint::valid_padding(){
    vector<unsigned char>* bad;
    unsigned char byte;
    addr_t padding = 0;
    unsigned char tmp=0xff;
    bool found = false;
    
    if( _constr[CONSTR_BAD_BYTES] == nullptr ){
        found = true;
        byte = 0xff;
    }else{
        bad = _constr[CONSTR_BAD_BYTES]->bad_bytes();
        for( tmp = 0xff; tmp >= 0; tmp--){
            if( std::find(bad->begin(), bad->end(), (unsigned char)(tmp)) == bad->end()){
                byte = tmp;
                found = true;
                break;
            }
        }
    }
    if( ! found ){
        return make_pair(false, 0);
    }/* Compute full padding value */
    padding = (addr_t)byte;
    for( int i = 0; i < curr_arch()->octets()-1; i++){
        padding = (padding*256) + (addr_t)byte;
    }
    return make_pair(true, padding);
}

// Destructor 
Constraint::~Constraint(){
    for( int i = 0; i < COUNT_NB_CONSTR; i++)
        delete _constr[i];
}

/* -------------------------------------------------------------------
 *        Constraint Signature
 * 
 * The modified regs are stored as the lower bits 
 * 0 to NB_REGS_MAX-1. It always applicable and missing as default of 
 * 0 (no regs are set). 
 * 
 * The return type is stored on 3 bits after modified
 * regs. From left to right (CALL,JMP,RET). It is always applicable and
 * missing has default 0b000 (all types allowed). Forbidden type is
 * set to 1 
 *  
 * The depth is stored on 8 bits after the return type. We assume that 
 * the depth will never be bigger than 8. A depth of 1 gives the signature
 * 0b00000001n a depth of 5 gives 0b00011111. I.E set as many bits to 1 as
 * the depth value. This is to keep the requirement of inclusion between 
 * weaker and stronger constraints/signatures. 
 * 
 * Requirement: sig1 included in sig2 <=> constr1 is weaker than constr2
 * 
 * ------------------------------------------------------------------*/
 
cstr_sig_t Constraint::signature(SearchEnvironment* env){
    vector<int>::iterator it;
    cstr_sig_t curr_bit = 0x1;
    cstr_sig_t res = 0x0;
    unsigned int i;
    
    // keep regs
    // 1. env reg transitivity unusable regs
    for( it = env->reg_transitivity_unusable()->begin(); it != env->reg_transitivity_unusable()->end(); it++ ){
        res |= (cstr_sig_t)(1ULL << (MODIFIED_REGS_BIT+(*it)));
    }
    // 2. from constraint
    curr_bit = 1ULL << MODIFIED_REGS_BIT;
    if( _constr[CONSTR_KEEP_REGS] != nullptr ){
        for( i = 0; i < NB_REGS_MAX; i++ ){
            if( _constr[CONSTR_KEEP_REGS]->get(i) )
                res |= curr_bit;
            curr_bit = curr_bit << 1;
        }
    }    
    // return type
    curr_bit = 1ULL << RET_TYPE_BIT;
    if( _constr[CONSTR_RETURN] != nullptr ){
        if( ! _constr[CONSTR_RETURN]->ret() )
            res |= curr_bit; 
        curr_bit = curr_bit << 1;
        if( ! _constr[CONSTR_RETURN]->jmp() )
            res |= curr_bit; 
        curr_bit = curr_bit << 1; 
        if( ! _constr[CONSTR_RETURN]->call() )
            res |= curr_bit; 
        curr_bit = curr_bit << 1;  
    }
    
    // Dept
    for( i = 0; (i < env->depth()) && (i < DEPTH_SIG_SIZE); i++ ){
        res |= 1ULL << (DEPTH_BIT + i);
    }
    
    return res;
}

/*
 * ASSERTIONS 
 */ 

SubAssertion::SubAssertion(SubAssertionType t): _type(t){}
SubAssertionType SubAssertion::type(){return _type;}

// AssertRegsEqual
AssertRegsEqual::AssertRegsEqual(): SubAssertion(ASSERT_REGS_EQUAL){
    for( int i =0; i < NB_REGS_MAX; i++){
        _regs[i][i] = true;
        for( int j=i+1; j < NB_REGS_MAX; j++){
            _regs[i][j] = false;
            _regs[j][i] = false; 
        }
    }
}       
AssertRegsEqual::AssertRegsEqual( bool array[NB_REGS_MAX][NB_REGS_MAX]): SubAssertion(ASSERT_REGS_EQUAL){
    for( int i =0; i < NB_REGS_MAX; i++){
        for( int j=i+1; j < NB_REGS_MAX; j++){
            _regs[i][j] = array[i][j];
        }
    }
}       

bool AssertRegsEqual::get(int reg1, int reg2){
    return _regs[reg1][reg2];
}

void AssertRegsEqual::add(int reg1, int reg2){
    _regs[reg1][reg2] = true; 
    _regs[reg2][reg1] = true; 
}

/* Precondition: c is an equal comparison */ 
bool AssertRegsEqual::validate( CondObjectPtr c){
    int l_reg, r_reg, l_inc, r_inc; 
    bool l_is_inc, r_is_inc; 
    std::tie(l_is_inc, l_reg, l_inc) = c->cond_ptr()->left_expr_ptr()->is_reg_increment(); 
    std::tie(r_is_inc, r_reg, r_inc) = c->cond_ptr()->right_expr_ptr()->is_reg_increment(); 
    if( (!l_is_inc) || (!r_is_inc) || (l_inc != r_inc) )
        return false; 
    else
        return _regs[l_reg][r_reg] || (l_reg==r_reg); 
}

SubAssertion* AssertRegsEqual::copy(){
    return new AssertRegsEqual(_regs);
}

void AssertRegsEqual::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw_exception("RegsEsqul: Merging wrong assertion !!");
    for( int i=0; i<NB_REGS_MAX; i++)
        for( int j=0; j<NB_REGS_MAX; j++)
            _regs[i][j] |= a->get(i,j);
    if( del )
        delete a; 
}

// AssertRegsNoOverlap
AssertRegsNoOverlap::AssertRegsNoOverlap(): SubAssertion(ASSERT_REGS_NO_OVERLAP){
    for( int i =0; i < NB_REGS_MAX; i++){
        _regs[i][i] = true;
        for( int j=i+1; j < NB_REGS_MAX; j++){
            _regs[i][j] = false;
            _regs[j][i] = false; 
        }
    }
}

AssertRegsNoOverlap::AssertRegsNoOverlap(int reg1, int reg2): SubAssertion(ASSERT_REGS_NO_OVERLAP){
	for( int i =0; i < NB_REGS_MAX; i++){
        _regs[i][i] = true;
        for( int j=i+1; j < NB_REGS_MAX; j++){
            _regs[i][j] = false;
            _regs[j][i] = false; 
        }
    }
    _regs[reg1][reg2] = true;
	_regs[reg2][reg1] = true;
}

AssertRegsNoOverlap::AssertRegsNoOverlap(bool array[NB_REGS_MAX][NB_REGS_MAX]): SubAssertion(ASSERT_REGS_NO_OVERLAP){
    for( int i =0; i < NB_REGS_MAX; i++){
        for( int j=i+1; j < NB_REGS_MAX; j++){
            _regs[i][j] = array[i][j];
        }
    }
}

bool AssertRegsNoOverlap::get(int reg1, int reg2){
    return _regs[reg1][reg2];
}
void AssertRegsNoOverlap::add(int reg1, int reg2){
    _regs[reg1][reg2] = true; 
    _regs[reg2][reg1] = true; 
}

/* Pre-condition: condition is !=, <= , or < */ 
bool AssertRegsNoOverlap::validate( CondObjectPtr c){
    int l_reg, r_reg, l_inc, r_inc; 
    bool l_is_inc, r_is_inc; 
    std::tie(l_is_inc, l_reg, l_inc) = c->cond_ptr()->left_expr_ptr()->is_reg_increment(); 
    std::tie(r_is_inc, r_reg, r_inc) = c->cond_ptr()->right_expr_ptr()->is_reg_increment(); 
    if( !l_is_inc || !r_is_inc ){
        return false; 
    }else{
        return _regs[l_reg][r_reg]; 
	}
}

SubAssertion* AssertRegsNoOverlap::copy(){
    return new AssertRegsNoOverlap(_regs);
}

void AssertRegsNoOverlap::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw_exception("NoOverlap: Merging wrong assertion !!");
    for( int i=0; i<NB_REGS_MAX; i++)
        for( int j=0; j<NB_REGS_MAX; j++)
            _regs[i][j] |= a->get(i,j);
    if( del )
        delete a; 
}

// AssertValidRead
AssertValidRead::AssertValidRead(): SubAssertion(ASSERT_VALID_READ){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
}
AssertValidRead::AssertValidRead(int num):SubAssertion(ASSERT_VALID_WRITE){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
    _regs[num] = true;
}
AssertValidRead::AssertValidRead(bool* array): SubAssertion(ASSERT_VALID_READ){
    std::memcpy(_regs, array, sizeof(bool)*NB_REGS_MAX);
}

bool* AssertValidRead::reg(){return _regs;}

void AssertValidRead::add(int reg){
    _regs[reg] = true; 
} 

// 4092 IS ARBITRARY HERE 
/* if ebp is valid then ebp +- MAX_VALID... is also valid */ 
#define MAX_VALID_READ_OFFSET 4092 

/* Pre-condition: condition is CondValidRead */ 
bool AssertValidRead::validate( CondObjectPtr c){
    int reg, inc; 
    bool is_inc; 
    std::tie(is_inc, reg, inc) = c->cond_ptr()->arg_expr_ptr()->is_reg_increment(); 
    if( is_inc && inc < MAX_VALID_READ_OFFSET && inc > -MAX_VALID_READ_OFFSET){
        return _regs[reg];
    }else
        return false; 
}

SubAssertion* AssertValidRead::copy(){
    return new AssertValidRead(_regs);
}

void AssertValidRead::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw_exception("AssertValidRead: Merging wrong assertion !!");
    for( int i=0; i<NB_REGS_MAX; i++)
        _regs[i] |= a->reg()[i];
    if( del )
        delete a; 
}

// AssertValidWrite
AssertValidWrite::AssertValidWrite(): SubAssertion(ASSERT_VALID_WRITE){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
}
AssertValidWrite::AssertValidWrite(int num):SubAssertion(ASSERT_VALID_WRITE){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
    _regs[num] = true;
}

AssertValidWrite::AssertValidWrite(bool* array): SubAssertion(ASSERT_VALID_WRITE){
    std::memcpy(_regs, array, sizeof(bool)*NB_REGS_MAX);
}

bool* AssertValidWrite::reg(){return _regs;}

void AssertValidWrite::add(int reg){
    _regs[reg] = true; 
} 

#define MAX_VALID_WRITE_OFFSET 4092
/* Pre-condition: condition is CondValidWrite */ 
bool AssertValidWrite::validate( CondObjectPtr c){
    int reg, inc; 
    bool is_inc; 
    std::tie(is_inc, reg, inc) = c->cond_ptr()->arg_expr_ptr()->is_reg_increment(); 
    if( is_inc && inc < MAX_VALID_WRITE_OFFSET && inc > -MAX_VALID_WRITE_OFFSET ){
        return _regs[reg];
    }else
        return false; 
}
SubAssertion* AssertValidWrite::copy(){
    return new AssertValidWrite(_regs);
}

void AssertValidWrite::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw_exception("AssertValidWrite: Merging wrong assertion !!");
    for( int i=0; i<NB_REGS_MAX; i++)
        _regs[i] |= a->reg()[i];
    if( del )
        delete a; 
}

// AssertRegSupTo
AssertRegSupTo::AssertRegSupTo(): SubAssertion(ASSERT_REG_SUP_TO){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
}
AssertRegSupTo::AssertRegSupTo(bool regs[NB_REGS_MAX], cst_t limit[NB_REGS_MAX]):SubAssertion(ASSERT_REG_SUP_TO){
    int i; 
    for ( i = 0; i < NB_REGS_MAX; i++){
        _regs[i] = regs[i];
        _limit[i] = limit[i];
    }
}
bool* AssertRegSupTo::reg(){return _regs;}
cst_t* AssertRegSupTo::limit(){return _limit;}

void AssertRegSupTo::add(int reg, cst_t cst ){
    _regs[reg] = true; 
    _limit[reg] = cst; 
}

/* Pre-condition: condition is < or <= */ 
bool AssertRegSupTo::validate( CondObjectPtr c){
    if( c->cond_ptr()->left_expr_ptr()->type() == EXPR_CST && 
        c->cond_ptr()->right_expr_ptr()->type() == EXPR_REG){
        if( c->cond_ptr()->type() == COND_LT )
            return  _regs[c->cond_ptr()->right_expr_ptr()->num()] &&
                    _limit[c->cond_ptr()->right_expr_ptr()->num()] < c->cond_ptr()->left_expr_ptr()->value(); 
        else if( c->cond_ptr()->type() == COND_LE )
            return _regs[c->cond_ptr()->right_expr_ptr()->num()] &&
                    _limit[c->cond_ptr()->right_expr_ptr()->num()] <= c->cond_ptr()->left_expr_ptr()->value()+1; 
        else
            throw_exception("RegSupTo: Error, unexpected cond type !!!");
    }else
        return false; 
}

SubAssertion* AssertRegSupTo::copy(){
    return new AssertRegSupTo(_regs, _limit); 
}

void AssertRegSupTo::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw_exception("RegSupTo: Merging wrong assertion !!");
    for( int i=0; i<NB_REGS_MAX; i++){
        _regs[i] |= a->reg()[i];
        if( a->limit()[i] > _limit[i] )
            _limit[i] = a->limit()[i]; 
    }
    if( del )
        delete a; 
}

// AssertRegInfTo
AssertRegInfTo::AssertRegInfTo(): SubAssertion(ASSERT_REG_INF_TO){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
}
AssertRegInfTo::AssertRegInfTo(bool regs[NB_REGS_MAX], cst_t limit[NB_REGS_MAX]): SubAssertion(ASSERT_REG_INF_TO){
    int i; 
    for ( i = 0; i < NB_REGS_MAX; i++){
        _regs[i] = regs[i];
        _limit[i] = limit[i];
    }
}
bool* AssertRegInfTo::reg(){return _regs;}
cst_t* AssertRegInfTo::limit(){return _limit;}

void AssertRegInfTo::add(int reg, cst_t cst ){
    _regs[reg] = true; 
    _limit[reg] = cst; 
}

/* Pre-condition: condition is < or <= or != */ 
bool AssertRegInfTo::validate( CondObjectPtr c){
    if( c->cond_ptr()->left_expr_ptr()->type() == EXPR_REG && 
        c->cond_ptr()->right_expr_ptr()->type() == EXPR_CST){
        if( c->cond_ptr()->type() == COND_LT )
            return  _regs[c->cond_ptr()->right_expr_ptr()->num()] &&
                    _limit[c->cond_ptr()->right_expr_ptr()->num()] < c->cond_ptr()->left_expr_ptr()->value(); 
        else if( c->cond_ptr()->type() == COND_LE )
            return _regs[c->cond_ptr()->right_expr_ptr()->num()] &&
                    _limit[c->cond_ptr()->right_expr_ptr()->num()] <= c->cond_ptr()->left_expr_ptr()->value()-1; 
        else
            throw_exception("RegInfTo: Error, unexpected cond type !!!");
    }else
        return false; 
}
SubAssertion* AssertRegInfTo::copy(){
    return new AssertRegInfTo(_regs, _limit); 
}

void AssertRegInfTo::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw_exception("RegInfTo: Merging wrong assertion !!");
    for( int i=0; i<NB_REGS_MAX; i++){
        _regs[i] |= a->reg()[i];
        if( a->limit()[i] < _limit[i] )
            _limit[i] = a->limit()[i]; 
    }
    if( del )
        delete a; 
}

// Assertion class (collection of subassertions)
Assertion::Assertion(){
    std::memset(_assert, 0, COUNT_NB_ASSERT*sizeof(SubAssertion*)); 
}

/* Add constraint to previous constraint */ 
void Assertion::add(SubAssertion* c, bool del=false){
    if( _assert[c->type()] != nullptr )
        _assert[c->type()]->merge(c, del);
    else
        _assert[c->type()] = c; 
}

/* Replace previous constraint */ 
void Assertion::update(SubAssertion* c){
    delete _assert[c->type()]; 
    _assert[c->type()] = c; 
}

void Assertion::remove(SubAssertionType t){
    delete _assert[t]; 
    _assert[t] = nullptr; 
}

bool Assertion::validate(CondObjectPtr c){
    switch(c->cond_ptr()->type()){
        case COND_TRUE:
            return true; 
        case COND_EQ:
            return (_assert[ASSERT_REGS_EQUAL] != nullptr) && _assert[ASSERT_REGS_EQUAL]->validate(c);
        case COND_NEQ:
        case COND_LT:
        case COND_LE:
            return (_assert[ASSERT_REGS_NO_OVERLAP] != nullptr) && _assert[ASSERT_REGS_NO_OVERLAP]->validate(c);
        case COND_VALID_READ:
            return (_assert[ASSERT_VALID_WRITE] != nullptr && _assert[ASSERT_VALID_WRITE]->validate(c))
                || (_assert[ASSERT_VALID_READ] != nullptr && _assert[ASSERT_VALID_READ]->validate(c));
        case COND_VALID_WRITE:
            return _assert[ASSERT_VALID_WRITE] != nullptr && _assert[ASSERT_VALID_WRITE]->validate(c);
        case COND_AND:
            return  validate(c->cond_ptr()->left_condobject_ptr()) && 
                    validate(c->cond_ptr()->right_condobject_ptr());
        case COND_OR:
            return  validate(c->cond_ptr()->left_condobject_ptr()) && 
                    validate(c->cond_ptr()->right_condobject_ptr());
        default:
            return false; 
    }
}

Assertion* Assertion::copy(){
    Assertion * res = new Assertion();
    for( int i = 0; i < COUNT_NB_ASSERT; i++)
		if( _assert[i] != nullptr )
			res->update(_assert[i]->copy());
    return res; 
}

Assertion::~Assertion(){
    for( int i = 0; i < COUNT_NB_ASSERT; i++)
        delete _assert[i]; 
}

