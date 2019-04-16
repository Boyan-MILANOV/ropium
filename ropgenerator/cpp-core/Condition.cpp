#include "Condition.hpp"
#include "Simplification.hpp"
#include "Exception.hpp"

// Condition types 
CondType invert_cond_type(CondType c){
    switch(c){
        case COND_EQ:
            return COND_NEQ;
            break;
        case COND_NEQ:
            return COND_EQ;
            break;
        case COND_AND:
            return COND_OR;
            break;
        case COND_OR:
            return COND_AND;
            break;
        case COND_TRUE:
            return COND_FALSE;
            break;
        case COND_FALSE:
            return COND_TRUE;
            break;
        case COND_UNKNOWN:
            return COND_UNKNOWN;
            break;
        default:
            throw_exception("CondType not supported by invert_cond()");
    }
}

// Usefull functions 
bool is_compare_cond(CondType c){
    return (c == COND_EQ || c == COND_NEQ || c == COND_LE || c == COND_LT ); 
}
bool is_binlogic_cond(CondType c){
    return c == COND_AND || c == COND_OR;
}
bool is_unlogic_cond(CondType c){
    return c == COND_NOT;
}
bool is_pointer_cond(CondType c){
    return c == COND_VALID_READ || c == COND_VALID_WRITE;
}
bool is_const_cond(CondType c){
    return c == COND_TRUE || c == COND_FALSE;
}
////////////////////////////////////////////////////////////////////////
// Cond class
// Has to match the enum in Condition.hpp 
const char *condtype_to_str[] = {"true", "false", "==", "!=", "<", "<=", 
              "&&", "||", "!", "valid_read", "valid_write", "thumb_mode"}; 
Cond::Cond(CondType t): _type(t){}
CondType Cond::type(){return _type;}
CondEval Cond::eval(){
    if( _type == COND_TRUE)
        return EVAL_TRUE;
    else if( _type == COND_FALSE )
        return EVAL_FALSE; 
    else
        return EVAL_UNKNOWN;
}
bool Cond::is_true(){return _type == COND_TRUE;}
void Cond::print(ostream& os){os << "???";}
ostream& operator<< (ostream& os, Cond c){
    c.print(os);
    return os;
}
////////////////////////////////////////////////////////////////////////
//CondConst
CondConst::CondConst(CondType t): Cond(t){}
CondPtr CondConst::invert(){
    return make_shared<CondConst>(invert_cond_type(_type));
}
void CondConst::print(ostream& os){  
    os << condtype_to_str[_type];  
}
////////////////////////////////////////////////////////////////////////
//CondCompare 
CondCompare::CondCompare(CondType t, ExprObjectPtr l, ExprObjectPtr r): Cond(t), _left(l), _right(r){}
ExprObjectPtr CondCompare::left_exprobject_ptr(){return _left;}
ExprObjectPtr CondCompare::right_exprobject_ptr(){return _right;}
ExprPtr CondCompare::left_expr_ptr(){return _left->expr_ptr();}
ExprPtr CondCompare::right_expr_ptr(){return _right->expr_ptr();}

CondPtr CondCompare::invert(){
    if( _type == COND_LT || _type == COND_LE )
        return make_shared<CondCompare>(_type, _right, _left);
    else
        return make_shared<CondCompare>(invert_cond_type(_type), _left, _right);
}
void CondCompare::print(ostream& os){  
    os << "(" << _left << " " << condtype_to_str[_type] << " " << _right << ")";  
}

////////////////////////////////////////////////////////////////////////
//CondBinLogic 
CondBinLogic::CondBinLogic(CondType t, CondObjectPtr l, CondObjectPtr r): Cond(t), _left(l), _right(r){}
CondObjectPtr CondBinLogic::left_condobject_ptr(){return _left;}
CondObjectPtr CondBinLogic::right_condobject_ptr(){return _right;}
CondPtr CondBinLogic::left_cond_ptr(){return _left->cond_ptr();}
CondPtr CondBinLogic::right_cond_ptr(){return _right->cond_ptr();}

CondPtr CondBinLogic::invert(){
    return make_shared<CondBinLogic>(invert_cond_type(_type),
                make_shared<CondObject>(_left->cond_ptr()->invert()),
                make_shared<CondObject>(_right->cond_ptr()->invert()));
}
void CondBinLogic::print(ostream& os){  
    os << "(" << _left << " " << condtype_to_str[_type] << " " << _right << ")";   
}


////////////////////////////////////////////////////////////////////////
//CondUnLogic 
CondUnLogic::CondUnLogic(CondType t, CondObjectPtr a): Cond(t), _arg(a){}
CondObjectPtr CondUnLogic::arg_condobject_ptr(){return _arg;}
CondPtr CondUnLogic::arg_cond_ptr(){return _arg->cond_ptr();}

CondPtr CondUnLogic::invert(){
    if( _type == COND_NOT )
        return _arg->cond_ptr();
    else
        return make_shared<CondUnLogic>(invert_cond_type(_type),
                make_shared<CondObject>(_arg->cond_ptr()->invert()));
}
void CondUnLogic::print(ostream& os){  
    os << "(" << condtype_to_str[_type] << " " << _arg << ")";  
}

////////////////////////////////////////////////////////////////////////
//CondPointer 
CondPointer::CondPointer(CondType t, ExprObjectPtr a): Cond(t), _arg(a){}
ExprObjectPtr CondPointer::arg_exprobject_ptr(){return _arg;}
ExprPtr CondPointer::arg_expr_ptr(){return _arg->expr_ptr();}

CondPtr CondPointer::invert(){
    return make_shared<CondConst>(COND_TRUE);
}
void CondPointer::print(ostream& os){  
    os << condtype_to_str[_type] << "(" << _arg << ")";  
}

////////////////////////////////////////////////////////////////////////
//CondCPUMode
CondCPUMode::CondCPUMode(CondType t):Cond(t){}
void CondCPUMode::print(ostream& os){
    os << condtype_to_str[_type];
}

////////////////////////////////////////////////////////////////////////
//CondUnknown

CondUnknown::CondUnknown(): Cond(COND_UNKNOWN){}
void CondUnknown::print(ostream& os){
    os << "unkwown";
}

////////////////////////////////////////////////////////////////////////
// CondObject (wrapper around Cond)
// Constructors 
CondObject::CondObject(CondPtr p):_cond_ptr(p), _simplified(false), _filtered(false){}
// Accessors, modifiers
CondPtr CondObject::cond_ptr(){return _cond_ptr;}
Cond CondObject::cond(){return *_cond_ptr;}
// Misc
void CondObject::simplify(){
    if( _simplified )
        return;
    // TODO IN SIMPLIFY R1 + 4 < 8 --> R1 < 4 
    if( is_compare_cond(_cond_ptr->type()) ){
        _cond_ptr->left_exprobject_ptr()->simplify();
        _cond_ptr->right_exprobject_ptr()->simplify();
        _cond_ptr = simplify_constant_folding(_cond_ptr);
        _cond_ptr = simplify_compare_polynom(_cond_ptr);
    }else if( is_binlogic_cond(_cond_ptr->type()) ){
        _cond_ptr->left_condobject_ptr()->simplify();
        _cond_ptr->right_condobject_ptr()->simplify();
        _cond_ptr = simplify_neutral_element(_cond_ptr);
    }else if( is_unlogic_cond(_cond_ptr->type())){
        _cond_ptr->arg_condobject_ptr()->simplify();
        _cond_ptr = simplify_neutral_element(_cond_ptr);
    }
    
    _simplified = true;
}

pair<CondObjectPtr, CondObjectPtr> CondObject::tweak(){
    return tweak_condition(_cond_ptr);
}

/* Return true if unknown */ 
bool CondObject::filter(){
    bool unknown = false; 
    if( _filtered )
        return (_cond_ptr->type() == COND_UNKNOWN); 
    _filtered = true; 
    
    if( is_compare_cond(_cond_ptr->type()) ){
        unknown = !supported_compared_expr(_cond_ptr->left_expr_ptr()) || 
                  !supported_compared_expr(_cond_ptr->right_expr_ptr()); 
    }else if( is_binlogic_cond(_cond_ptr->type()) ){
        unknown = ( _cond_ptr->left_condobject_ptr()->filter() ||
                    _cond_ptr->right_condobject_ptr()->filter() );
    }else if( is_pointer_cond(_cond_ptr->type())){
        unknown = !supported_valid_pointer_expr(_cond_ptr->arg_expr_ptr()); 
    }
     
    if( unknown ){
        _cond_ptr = special_NewCondPtrUnknown();
        return true; 
    }else
        return false; 
    
}

// ExprObjectPtr level manipulation 
// IO
ostream& operator<< (ostream& os, CondObjectPtr p){
    p->cond_ptr()->print(os);
    return os; 
}
// Operators 
CondObjectPtr operator== (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<CondObject>(make_shared<CondCompare>(COND_EQ, p1, p2));
}
CondObjectPtr operator!= (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<CondObject>(make_shared<CondCompare>(COND_NEQ, p1, p2));
}
CondObjectPtr operator< (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<CondObject>(make_shared<CondCompare>(COND_LT, p1, p2));
}
CondObjectPtr operator<= (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<CondObject>(make_shared<CondCompare>(COND_LE, p1, p2));
}
CondObjectPtr Valid_read (ExprObjectPtr p1){
    return make_shared<CondObject>(make_shared<CondPointer>(COND_VALID_READ, p1));
}
CondObjectPtr Valid_write (ExprObjectPtr p1){
    return make_shared<CondObject>(make_shared<CondPointer>(COND_VALID_WRITE, p1));
} 
CondObjectPtr operator&& (CondObjectPtr p1, CondObjectPtr p2){
    return make_shared<CondObject>(make_shared<CondBinLogic>(COND_AND, p1, p2));
}
CondObjectPtr operator|| (CondObjectPtr p1, CondObjectPtr p2){
    return make_shared<CondObject>(make_shared<CondBinLogic>(COND_OR, p1, p2));
}
CondObjectPtr operator! (CondObjectPtr p1){
    return make_shared<CondObject>(make_shared<CondUnLogic>(COND_NOT, p1));
}


CondObjectPtr g_cond_true = make_shared<CondObject>(make_shared<CondConst>(COND_TRUE));
CondObjectPtr NewCondTrue(){
    return g_cond_true; 
}
CondObjectPtr g_cond_false = make_shared<CondObject>(make_shared<CondConst>(COND_FALSE));
CondObjectPtr NewCondFalse(){
    return g_cond_false; 
}
CondObjectPtr NewCondPointer(CondType t, ExprObjectPtr a){
    return make_shared<CondObject>(make_shared<CondPointer>(t, a));
}
CondObjectPtr NewCondCompare(CondType t, ExprObjectPtr l, ExprObjectPtr r){
    return make_shared<CondObject>(make_shared<CondCompare>(t, l, r));
}
CondObjectPtr NewCondBinLogic(CondType t, CondObjectPtr l, CondObjectPtr r){
    return make_shared<CondObject>(make_shared<CondBinLogic>(t,l,r));
}
CondObjectPtr NewCondUnLogic(CondType t, CondObjectPtr a){
    return make_shared<CondObject>(make_shared<CondUnLogic>(t,a));
}

CondObjectPtr NewCondCPUMode(CondType t){
    return make_shared<CondObject>(make_shared<CondCPUMode>(t));
}

CondObjectPtr g_cond_unknown = make_shared<CondObject>(make_shared<CondUnknown>());
CondObjectPtr NewCondUnknown(){
    return g_cond_unknown;
}
CondPtr g_condptr_unknown = make_shared<CondUnknown>(); 
CondPtr special_NewCondPtrUnknown(){
    return g_condptr_unknown; 
}
