#include "Constraint.hpp"
#include "Architecture.hpp"
#include "Expression.hpp"
#include "Condition.hpp"
#include <algorithm>
#include <cstring>

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

pair<ConstrEval,CondObjectPtr> ConstrReturn::verify(Gadget* g){
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
        throw "Invalid sub constraint type when merging";
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

bool ConstrBadBytes::verify_address(addr_t a){
    // Check if each byte of the address is not in bad bytes list
    int i; 
    for( i = 0; i < curr_arch()->octets(); i++ ){
        if( std::find(_bad_bytes.begin(), _bad_bytes.end(), (unsigned char)((a >> i)&0xFF)) != _bad_bytes.end())
            return false;
    }
    return true;
}

pair<ConstrEval,CondObjectPtr> ConstrBadBytes::verify(Gadget* g){
    vector<addr_t>::iterator it; 
    for( it = g->addresses()->begin(); it != g->addresses()->end(); it++){
        if( ! verify_address(*it))
            return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
    }
    return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
}

SubConstraint* ConstrBadBytes::copy(){
    return new ConstrBadBytes(_bad_bytes);
}

void ConstrBadBytes::merge(SubConstraint* c, bool del=false){
    if( c->type() != CONSTR_BAD_BYTES )
        throw "Invalid sub constraint type when merging";
    _bad_bytes.insert(_bad_bytes.end(), c->bad_bytes()->begin(), c->bad_bytes()->end()); 
    if( del )
        delete c; 
}

// ConstrKeepRegs 
ConstrKeepRegs::ConstrKeepRegs(): SubConstraint(CONSTR_KEEP_REGS){}
bool ConstrKeepRegs::get(int num){
    return ( num >= NB_REGS_MAX || num < 0)? false : _regs[num];
}
void ConstrKeepRegs::add_reg(int num){ 
    if( num < NB_REGS_MAX && num >= 0 )
        _regs[num] = true; 
}
void ConstrKeepRegs::remove_reg(int num){
    if( num < NB_REGS_MAX && num >= 0 )
        _regs[num] = false; 
}
pair<ConstrEval,CondObjectPtr> ConstrKeepRegs::verify(Gadget* g){
    bool * modified = g->modified_regs();
    for( int i = 0; i < NB_REGS_MAX; i++)
        if( _regs[i] && modified[i] )
            return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
    return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
}

SubConstraint* ConstrKeepRegs::copy(){
    int i;
    ConstrKeepRegs* res = new ConstrKeepRegs();
    for( i = 0; i > NB_REGS_MAX; i++)
        res->_regs[i] = _regs[i];
    return res; 
}

void ConstrKeepRegs::merge(SubConstraint* c, bool del=false){
    int i;
    if( c->type() != CONSTR_KEEP_REGS )
        throw "Invalid sub constraint type when merging";
    for( i = 0; i < NB_REGS_MAX; i++)
        _regs[i] = _regs[i] || ((ConstrKeepRegs*)c)->get(i); 
    if( del )
        delete c; 
}

// ConstrValidRead
ConstrValidRead::ConstrValidRead(): SubConstraint(CONSTR_VALID_READ){}
void ConstrValidRead::add_addr( ExprObjectPtr a){
    _addresses.push_back(a);
}

vector<ExprObjectPtr>* ConstrValidRead::addresses(){return &_addresses;}

pair<ConstrEval,CondObjectPtr> ConstrValidRead::verify(Gadget* g){
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
        throw "Invalid sub constraint type when merging";
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

pair<ConstrEval,CondObjectPtr> ConstrValidWrite::verify(Gadget* g){
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
        throw "Invalid sub constraint type when merging";
    _addresses.insert(_addresses.end(), c->addresses()->begin(), c->addresses()->end());
    if( del )
        delete c; 
}

// ConstrSpInc
ConstrSpInc::ConstrSpInc(cst_t i): SubConstraint(CONSTR_SP_INC), _inc(i){}
pair<ConstrEval,CondObjectPtr> ConstrSpInc::verify(Gadget* g){
    if( !g->known_sp_inc() || g->sp_inc() != _inc )
        return make_pair(EVAL_INVALID, make_shared<CondObject>(nullptr));
    return make_pair(EVAL_VALID, make_shared<CondObject>(nullptr));
}

SubConstraint* ConstrSpInc::copy(){
    return new ConstrSpInc(_inc); 
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
        res->add(_constr[i]->copy());
    return res; 
}

// Destructor 
Constraint::~Constraint(){
    for( int i = 0; i < COUNT_NB_CONSTR; i++)
        delete _constr[i];
}

/*
 * ASSERTIONS 
 */ 

SubAssertion::SubAssertion(SubAssertionType t): _type(t){}
SubAssertionType SubAssertion::type(){return _type;}

// AssertRegsEqual
AssertRegsEqual::AssertRegsEqual(): SubAssertion(ASSERT_REGS_EQUAL){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX*NB_REGS_MAX);
}       
AssertRegsEqual::AssertRegsEqual( bool array[NB_REGS_MAX][NB_REGS_MAX]): SubAssertion(ASSERT_REGS_EQUAL){
    std::memcpy(_regs, array, sizeof(bool)*NB_REGS_MAX*NB_REGS_MAX);
}       

bool ** AssertRegsEqual::regs(){return (bool**)_regs;}

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
        return _regs[l_reg][r_reg]; 
}

SubAssertion* AssertRegsEqual::copy(){
    return new AssertRegsEqual(_regs);
}

void AssertRegsEqual::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw "Merging wrong assertion !!";
    for( int i=0; i<NB_REGS_MAX; i++)
        for( int j=0; j<NB_REGS_MAX; j++)
            _regs[i][j] |= a->regs()[i][j];
    if( del )
        delete a; 
}

// AssertRegsNoOverlap
AssertRegsNoOverlap::AssertRegsNoOverlap(): SubAssertion(ASSERT_REGS_NO_OVERLAP){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX*NB_REGS_MAX);
}

AssertRegsNoOverlap::AssertRegsNoOverlap(bool array[NB_REGS_MAX][NB_REGS_MAX]): SubAssertion(ASSERT_REGS_NO_OVERLAP){
    std::memcpy(_regs, array, sizeof(bool)*NB_REGS_MAX*NB_REGS_MAX);
}

bool ** AssertRegsNoOverlap::regs(){return (bool**)_regs;}

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
    if( !l_is_inc || !r_is_inc )
        return false; 
    else
        return _regs[l_reg][r_reg]; 
}

SubAssertion* AssertRegsNoOverlap::copy(){
    return new AssertRegsNoOverlap(_regs);
}

void AssertRegsNoOverlap::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw "Merging wrong assertion !!";
    for( int i=0; i<NB_REGS_MAX; i++)
        for( int j=0; j<NB_REGS_MAX; j++)
            _regs[i][j] |= a->regs()[i][j];
    if( del )
        delete a; 
}

// AssertValidRead
AssertValidRead::AssertValidRead(): SubAssertion(ASSERT_VALID_READ){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
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
        throw "Merging wrong assertion !!";
    for( int i=0; i<NB_REGS_MAX; i++)
        _regs[i] |= a->reg()[i];
    if( del )
        delete a; 
}

// AssertValidWrite
AssertValidWrite::AssertValidWrite(): SubAssertion(ASSERT_VALID_WRITE){
    std::memset(_regs, false, sizeof(bool)*NB_REGS_MAX);
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
    if( is_inc && inc < MAX_VALID_WRITE_OFFSET && inc > MAX_VALID_WRITE_OFFSET ){
        return _regs[reg];
    }else
        return false; 
}
SubAssertion* AssertValidWrite::copy(){
    return new AssertValidWrite(_regs);
}

void AssertValidWrite::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw "Merging wrong assertion !!";
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
            throw "Error, unexpected cond type !!!";
    }else
        return false; 
}

SubAssertion* AssertRegSupTo::copy(){
    return new AssertRegSupTo(_regs, _limit); 
}

void AssertRegSupTo::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw "Merging wrong assertion !!";
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

/* Pre-condition: condition is < or <= */ 
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
            throw "Error, unexpected cond type !!!";
    }else
        return false; 
}
SubAssertion* AssertRegInfTo::copy(){
    return new AssertRegInfTo(_regs, _limit); 
}

void AssertRegInfTo::merge(SubAssertion* a, bool del){
    if( a->type() != _type )
        throw "Merging wrong assertion !!";
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

void Assertion::add(SubAssertion* c, bool del=false){
    if( _assert[c->type()] != nullptr )
        _assert[c->type()]->merge(c, del);
    else
        _assert[c->type()] = c; 
}

void Assertion::update(SubAssertion* c){
    delete _assert[c->type()]; 
    _assert[c->type()] = c; 
}

void Assertion::remove(SubAssertionType t){
    delete _assert[t]; 
    _assert[t] = nullptr; 
}

bool Assertion::validate(CondObjectPtr c){
    // TODO 
}

Assertion* Assertion::copy(){
    Assertion * res = new Assertion();
    for( int i = 0; i < COUNT_NB_ASSERT; i++)
        res->add(_assert[i]->copy());
    return res; 
}

Assertion::~Assertion(){
    for( int i = 0; i < COUNT_NB_ASSERT; i++)
        delete _assert[i]; 
}

