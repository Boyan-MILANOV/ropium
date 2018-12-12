#include "Expression.hpp" 
#include "Simplification.hpp"

using namespace std; 

////////////////////////////////////////////////////////////////////////
//// Expr
// Constructors
Expr::Expr(ExprType t): _type(t),_size(-1), _polynom(nullptr), _computed_polynom(false){}
Expr::Expr(ExprType t, int s): _type(t),_size(s), _polynom(nullptr), _computed_polynom(false){}
// Accessors and modifiers
int Expr::size(){return _size;}
int Expr::set_size(int s){return (_size=s); }
ExprType Expr::type(){return _type;}
// IO
void Expr::print(ostream& os){os << "???";}
ostream& operator<< (ostream& os, Expr e){
    e.print(os);
    return os;
}
// Polynom
void Expr::set_polynom(ExprAsPolynom* p){
    if( _polynom )
        delete _polynom;
    _polynom = p;
    _computed_polynom = true;
}
ExprAsPolynom * Expr::polynom(){
    if( !_computed_polynom)
        compute_polynom();
    return _polynom; 
}
void Expr::compute_polynom(){
    _computed_polynom = true;
    _polynom = nullptr;
}

// Destructor
Expr::~Expr(){
    if( _polynom )
        delete _polynom; 
}


////////////////////////////////////////////////////////////////////////
//// ExprCst
// Constructor 
ExprCst::ExprCst(cst_t v, int s):Expr(EXPR_CST, s),_value(v) {}
// Accessors and modifiers 
cst_t ExprCst::value(){return _value;}
// Operators
void ExprCst::print(ostream& os){ 
    os << _value; 
}
// POlynom
void ExprCst::compute_polynom(){
    if( !_computed_polynom){
        _polynom = new ExprAsPolynom(NB_REGS_MAX+1);
        _polynom->set(NB_REGS_MAX, _value);
        _computed_polynom = true;
    }
}
// Misc
bool ExprCst::equal(shared_ptr<Expr> other){
    return ( other.get() == this ) || 
            ( (other->type() == EXPR_CST) &&
            (other->value() ==  _value) );
}
bool ExprCst::lthan(ExprPtr other){
    if( _type == other->type())
        return _value < other->value();
    else
        return _type < other->type();
}

////////////////////////////////////////////////////////////////////////
//// ExprReg
// Constructor 
ExprReg::ExprReg(int n, int s): Expr(EXPR_REG, s),_num(n){}
// Operators
void ExprReg::print(ostream& os){  
    os << "r" << _num;  
}
// Polynom
void ExprReg::compute_polynom(){
    if( !_computed_polynom){
        _polynom = new ExprAsPolynom(NB_REGS_MAX+1);
        _polynom->set(_num, 1);
        _computed_polynom = true;
    }
}
// Misc
bool ExprReg::equal(shared_ptr<Expr> other){
    return ( other.get() == this ) || 
            ( (other->type() == EXPR_REG) &&
            (other->num() ==  _num) );
}
bool ExprReg::lthan(ExprPtr other){
    if( _type == other->type())
        return _num < other->num();
    else
        return _type < other->type();
}

int ExprReg::num(){return _num;}

////////////////////////////////////////////////////////////////////////
//// ExprMem
// Constructor 
ExprMem::ExprMem( ExprObjectPtr a, int s): Expr(EXPR_MEM, s), _addr(a){}
// Operators
void ExprMem::print(ostream& os){  
    os << "mem[" << _addr << "]";
}
// Accessors
ExprObjectPtr ExprMem::addr_object_ptr(){ return _addr;}
ExprPtr ExprMem::addr_expr_ptr(){ return _addr->expr_ptr();}

// Misc
bool ExprMem::equal(shared_ptr<Expr> other){
    return ( other.get() == this ) || 
            ( (other->type() == EXPR_MEM) &&
            (_addr->expr_ptr()->equal(other->addr_expr_ptr())) );
}
bool ExprMem::lthan(ExprPtr other){
    if( _type == other->type())
        return _addr->expr_ptr()->lthan(other->addr_expr_ptr());
    else
        return _type < other->type();
}

////////////////////////////////////////////////////////////////////////
//// ExprBinop
// To string, needs to match the enum in Expression.hpp !!
const char* binop_to_str[] = {"+","-","*","/","&","|","^","%", "<>"}; 
// Constructor 
ExprBinop::ExprBinop( Binop o, ExprObjectPtr l, ExprObjectPtr r): Expr(EXPR_BINOP), _op(o), _left(l), _right(r){
    if( l->expr_ptr()->size() != r->expr_ptr()->size() )
        throw "Different sizes when initializing ExprBinop"; 
    set_size(l->expr_ptr()->size()); 
}
// Accessor
ExprObjectPtr ExprBinop::left_object_ptr(){return _left;}
ExprObjectPtr ExprBinop::right_object_ptr(){return _right;}
ExprPtr ExprBinop::left_expr_ptr(){return _left->expr_ptr();}
ExprPtr ExprBinop::right_expr_ptr(){return _right->expr_ptr();}
void ExprBinop::exchange_args(){
        ExprObjectPtr tmp = _left;
        _left = _right; 
        _right = tmp;  
}
    
Binop ExprBinop::binop(){return _op;}
// Operators 
void ExprBinop::print(ostream& os){  
    os << "(" << _left << binop_to_str[_op] << _right <<")";
}
void ExprBinop::compute_polynom(){
    ExprPtr res; 
    ExprAsPolynom *left_p, *right_p;
    
    if( _computed_polynom )
        return; 
        
    // Supported operators for polynoms 
    if( _op != OP_ADD && _op != OP_SUB && 
        !((_op == OP_MUL && _left->expr_ptr()->type() == EXPR_CST)))
        return; 
    
    _computed_polynom = true; 
    left_p = _left->expr_ptr()->polynom();
    right_p = _right->expr_ptr()->polynom();
    if( _polynom != nullptr){
        delete _polynom; 
        _polynom = nullptr; 
    }
        
    if( !left_p || !right_p )
        _polynom = nullptr; 
    else if( _op == OP_ADD || _op == OP_SUB)
        _polynom = left_p->merge_op(right_p, _op);
    else if(_op == OP_MUL && _left->expr_ptr()->type() == EXPR_CST)
        _polynom = right_p->mul_all(_left->expr_ptr()->value());
}
// Misc
bool ExprBinop::equal(shared_ptr<Expr> other){
    if( other.get() == this )
        return true; 
    else if( polynom() == nullptr || other->polynom() == nullptr)
        return ( (other->type() == EXPR_BINOP) &&
            (other->binop() ==  _op) &&
            (_left->expr_ptr()->equal(other->left_expr_ptr())) && 
            (_right->expr_ptr()->equal(other->right_expr_ptr())));
    else
        return polynom()->equal(other->polynom());
}
bool ExprBinop::lthan(ExprPtr other){
    if( _type == other->type())
        if( _left->expr_ptr()->lthan(other->left_expr_ptr()))
            return true;
        else
            return ( _right->expr_ptr()->lthan(other->right_expr_ptr()));
    else
        return _type < other->type();
}

////////////////////////////////////////////////////////////////////////
//// ExprUnop
// To string, needs to match the enum in Expression.hpp !!
const char* unop_to_str[] = {"~"}; 
// Constructor 
ExprUnop::ExprUnop( Unop o, ExprObjectPtr a): Expr(EXPR_UNOP), _op(o), _arg(a){
    set_size(a->expr_ptr()->size()); 
}
// Accessors 
ExprObjectPtr ExprUnop::arg_object_ptr(){return _arg;}
ExprPtr ExprUnop::arg_expr_ptr(){return _arg->expr_ptr();}
Unop ExprUnop::unop(){return _op;}
// Operators 
void ExprUnop::print(ostream& os){  
    os << unop_to_str[_op] << _arg;
}
// Misc
bool ExprUnop::equal(shared_ptr<Expr> other){
    return ( other.get() == this ) || 
            ( (other->type() == EXPR_UNOP) &&
            (other->unop() == _op) && 
            (_arg->expr_ptr()->equal(other->arg_expr_ptr())) );
}
bool ExprUnop::lthan(ExprPtr other){
    if( _type == other->type())
        return _arg->expr_ptr()->lthan(other->arg_expr_ptr());
    else
        return _type < other->type();
}


////////////////////////////////////////////////////////////////////////
// ExprExtract
// Constructor 
ExprExtract::ExprExtract( ExprObjectPtr a, int h, int l): Expr(EXPR_EXTRACT), _arg(a), _low(l), _high(h){
    set_size(h-l+1);
}
// Operators  
void ExprExtract::print(ostream& os){  
    os << _arg << "[" << _high << ":" << _low << "]" ;
}
// Accessors 
int ExprExtract::low(){ return _low;}
int ExprExtract::high(){ return _high;}
ExprPtr ExprExtract::arg_expr_ptr(){return _arg->expr_ptr();}
ExprObjectPtr ExprExtract::arg_object_ptr(){ return _arg;}
// Misc
bool ExprExtract::equal(shared_ptr<Expr> other){
    return ( other.get() == this ) || 
            ( (other->type() == EXPR_EXTRACT) &&
            (other->high() == _high) && (other->low() == _low) && 
            (_arg->expr_ptr()->equal(other->arg_expr_ptr())) );
}
bool ExprExtract::lthan(ExprPtr other){
    if( _type == other->type())
        return _arg->expr_ptr()->lthan(other->arg_expr_ptr());
    else
        return _type < other->type();
}

/////////////////////////////////////////////////////////////////////////
// ExprConcat
// Constructor
ExprConcat::ExprConcat( ExprObjectPtr u, ExprObjectPtr l ): Expr(EXPR_CONCAT), _upper(u), _lower(l){
    set_size(l->expr_ptr()->size() + u->expr_ptr()->size());
}
// Accessors and modifiers 
ExprObjectPtr ExprConcat::upper_object_ptr(){ return _upper;}
ExprObjectPtr ExprConcat::lower_object_ptr(){ return _lower;}
ExprPtr ExprConcat::upper_expr_ptr(){ return _upper->expr_ptr();}
ExprPtr ExprConcat::lower_expr_ptr(){ return _lower->expr_ptr();}
// Misc 
void ExprConcat::print(ostream& os){
    os << "(" << _upper << "." << _lower << ")";
}
bool ExprConcat::equal(shared_ptr<Expr> other){
    return ( other.get() == this ) || 
            ( (other->type() == EXPR_CONCAT) &&
            (_upper->expr_ptr()->equal(other->upper_expr_ptr())) && 
            (_lower->expr_ptr()->equal(other->lower_expr_ptr())));
}
bool ExprConcat::lthan(ExprPtr other){
    if( _type == other->type())
        if( _upper->expr_ptr()->lthan(other->upper_expr_ptr()))
            return true;
        else
            return ( _lower->expr_ptr()->lthan(other->lower_expr_ptr()));
    else
        return _type < other->type();
}

////////////////////////////////////////////////////////////////////////
// ExprUnknown
ExprUnknown::ExprUnknown(): Expr(EXPR_UNKNOWN){};

////////////////////////////////////////////////////////////////////////
// ExprObject
ExprObject::ExprObject(ExprPtr p): _expr_ptr(p), _simplified(false){}
ExprPtr ExprObject::expr_ptr(){return _expr_ptr;}
Expr ExprObject::expr(){return *_expr_ptr;}
bool ExprObject::equal(ExprObjectPtr other){
    return _expr_ptr->equal(other->expr_ptr());
}
void ExprObject::simplify(){
    if( _simplified )
        return; 
        
    switch( _expr_ptr->type() ){
        case EXPR_UNOP:
            _expr_ptr->arg_object_ptr()->simplify();
            _expr_ptr = simplify_unknown(_expr_ptr);
            _expr_ptr = simplify_constant_folding(_expr_ptr);
            break;
        case EXPR_BINOP:
            _expr_ptr->left_object_ptr()->simplify(); 
            _expr_ptr->right_object_ptr()->simplify(); 
            canonize(_expr_ptr);
            _expr_ptr = simplify_unknown(_expr_ptr);
            _expr_ptr = simplify_constant_folding(_expr_ptr);
            _expr_ptr = simplify_neutral_element(_expr_ptr);
            _expr_ptr = simplify_polynom_factorization(_expr_ptr);
            break;
        case EXPR_EXTRACT:
            _expr_ptr->arg_object_ptr()->simplify();
            _expr_ptr = simplify_unknown(_expr_ptr);
            _expr_ptr = simplify_constant_folding(_expr_ptr);
            _expr_ptr = simplify_pattern(_expr_ptr);
            _expr_ptr = simplify_neutral_element(_expr_ptr);
            break;
        case EXPR_CONCAT:
            _expr_ptr->lower_object_ptr()->simplify();
            _expr_ptr->upper_object_ptr()->simplify();
            _expr_ptr = simplify_unknown(_expr_ptr);
            _expr_ptr = simplify_constant_folding(_expr_ptr);
            break;
        case EXPR_MEM:
            _expr_ptr->addr_object_ptr()->simplify(); 
            _expr_ptr = simplify_unknown(_expr_ptr);
            break;
        default:
            break;
    }
    _expr_ptr->compute_polynom(); 
    _simplified = true;
}

////////////////////////////////////////////////////////////////////////
//// Support to use operators at ExprObjectPtr  level :) 
// IO
ostream& operator<< (ostream& os, ExprObjectPtr p){
    p->expr_ptr()->print(os);
    return os; 
} 
// Operators: + - * / & | ^ ~ Extract 
ExprObjectPtr operator+ (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_ADD, p1, p2)); 
}
ExprObjectPtr operator- (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_SUB, p1, p2)); 
}
ExprObjectPtr operator* (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_MUL, p1, p2)); 
}
ExprObjectPtr operator/ (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_DIV, p1, p2)); 
}
ExprObjectPtr operator& (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_AND, p1, p2)); 
}
ExprObjectPtr operator| (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_OR, p1, p2));
}
ExprObjectPtr operator^ (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_XOR, p1, p2)); 
}
ExprObjectPtr operator% (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_MOD, p1, p2)); 
}
ExprObjectPtr Bsh(ExprObjectPtr p1,  ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprBinop>(OP_BSH, p1, p2)); 
}
ExprObjectPtr Extract(ExprObjectPtr p1, int high, int low){
    return make_shared<ExprObject>(make_shared<ExprExtract>(p1, high, low)); 
}
ExprObjectPtr Concat (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprConcat>(p1,p2));
}
ExprObjectPtr operator~ (ExprObjectPtr p1){
    return make_shared<ExprObject>(make_shared<ExprUnop>(OP_NEG, p1)); 
}

// Wrappers
ExprObjectPtr NewExprCst(cst_t value, int size){
    return make_shared<ExprObject>(make_shared<ExprCst>(value, size));
}
ExprObjectPtr NewExprMem(ExprObjectPtr addr, int s){
    return make_shared<ExprObject>(make_shared<ExprMem>(addr, s));
}



