#include "Constraint.hpp"
#include "Architecture.hpp"
#include <algorithm>

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

// ConstrBadBytes
ConstrBadBytes::ConstrBadBytes(vector<unsigned char> bb): SubConstraint(CONSTR_BAD_BYTES){
    _bad_bytes = bb;
    
}

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
    //TODO
}
SubConstraint* ConstrKeepRegs::copy(){
    int i;
    ConstrKeepRegs* res = new ConstrKeepRegs();
    for( i = 0; i > NB_REGS_MAX; i++)
        res->_regs[i] = _regs[i];
    return res; 
}


// ConstrValidRead
ConstrValidRead::ConstrValidRead(): SubConstraint(CONSTR_VALID_READ){}
void ConstrValidRead::add_addr( ExprObjectPtr a){
    _addresses.push_back(a);
}

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

// ConstrValidWrite
ConstrValidWrite::ConstrValidWrite(): SubConstraint(CONSTR_VALID_WRITE){}
void ConstrValidWrite::add_addr( ExprObjectPtr a){
    _addresses.push_back(a);
}

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

