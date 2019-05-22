#include "Expression.hpp" 
#include "Simplification.hpp"
#include "Exception.hpp"
#include "Architecture.hpp"

#include <cmath>

using namespace std; 

////////////////////////////////////////////////////////////////////////
//// Expr
// Constructors
Expr::Expr(ExprType t, bool i=false): _type(t),_size(-1), _polynom(nullptr), _computed_polynom(false), _is_polynom(i){}
Expr::Expr(ExprType t, int s, bool i=false): _type(t),_size(s), _polynom(nullptr), _computed_polynom(false), _is_polynom(i){}
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

bool Expr::computed_polynom(){
    return _computed_polynom; 
}

bool Expr::is_polynom(){
    return _is_polynom; 
}

void Expr::compute_polynom(){
    _computed_polynom = true;
    _polynom = nullptr;
}

tuple<bool, int, cst_t> Expr::is_reg_increment(){
    return make_tuple(false,-1,0); 
}

tuple<bool, cst_t> Expr::is_reg_increment(int num){
    return make_tuple(false,0);
}

// Destructor
Expr::~Expr(){
    if( _polynom )
        delete _polynom; 
}


////////////////////////////////////////////////////////////////////////
//// ExprCst
// Constructor 
ExprCst::ExprCst(cst_t v, int s):Expr(EXPR_CST, s, true),_value(v) {}
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
// Convert the expression size
ExprObjectPtr ExprCst::convert(int size){
    return NewExprCst(_value, size);
}


////////////////////////////////////////////////////////////////////////
//// ExprReg
// Constructor 
ExprReg::ExprReg(int n, int s): Expr(EXPR_REG, s, true),_num(n){}
// Operators
void ExprReg::print(ostream& os){  
    //os << "r" << _num;  
    os << curr_arch()->reg_name(_num);
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

tuple<bool, int, cst_t> ExprReg::is_reg_increment(){
    return make_tuple(true, _num, 0); 
}

tuple<bool, cst_t> ExprReg::is_reg_increment(int num){
    return make_tuple((num == _num), 0);
}

// Convert the expression size
ExprObjectPtr ExprReg::convert(int size){
    if( size < _size )
        return Extract(NewExprReg(_num, size), size-1, 0);
    else if( size > _size )
        return Concat(NewExprCst(0,size-_size), NewExprReg(_num, _size));
    else
        return NewExprReg(_num, _size);
}

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


// Convert the expression size
ExprObjectPtr ExprMem::convert(int size){
    return NewExprMem(_addr, size);
}

////////////////////////////////////////////////////////////////////////
//// ExprBinop
// To string, needs to match the enum in Expression.hpp !!
const char* binop_to_str[] = {"+","-","*","/","&","|","^","%", "<>"}; 
// Constructor 
ExprBinop::ExprBinop( Binop o, ExprObjectPtr l, ExprObjectPtr r): Expr(EXPR_BINOP), _op(o), _left(l), _right(r){
    if( o != OP_BSH && l->expr_ptr()->size() != r->expr_ptr()->size() ){
        throw_exception(ExceptionFormatter() << "Different sizes when initializing ExprBinop: " << l << 
        " and " << r << "(sizes: " << l->expr_ptr()->size() << " and " << r->expr_ptr()->size() << ") " >> ExceptionFormatter::to_str); 
    }
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
    else
        _computed_polynom = true; 
        
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

tuple<bool, int, cst_t> ExprBinop::is_reg_increment(){
    cst_t factor; 
    if( _op != OP_ADD && _op != OP_SUB)
        return make_tuple(false, -1, 0);
    factor = (_op == OP_ADD) ? 1 : -1 ;
    if( _left->expr_ptr()->type() == EXPR_CST &&
        _right->expr_ptr()->type() == EXPR_REG)
        return make_tuple(true, _right->expr_ptr()->num(), factor * _left->expr_ptr()->value());
    else if(    _right->expr_ptr()->type() == EXPR_CST &&
                _left->expr_ptr()->type() == EXPR_REG)
        return make_tuple(true, _left->expr_ptr()->num(), factor * _right->expr_ptr()->value());
    else
        return make_tuple(false, -1, 0);
}

tuple<bool, cst_t> ExprBinop::is_reg_increment(int num){
    cst_t factor; 
    if( _op != OP_ADD && _op != OP_SUB)
        return make_tuple(false, 0);
    factor = (_op == OP_ADD) ? 1 : -1 ;
    if( _left->expr_ptr()->type() == EXPR_CST &&
        _right->expr_ptr()->type() == EXPR_REG)
        return make_tuple((_right->expr_ptr()->num() == num), factor * _left->expr_ptr()->value());
    else if(    _right->expr_ptr()->type() == EXPR_CST &&
                _left->expr_ptr()->type() == EXPR_REG)
        return make_tuple((_left->expr_ptr()->num() == num), factor * _right->expr_ptr()->value());
    else
        return make_tuple(false, 0);    
}
// Convert the expression size
ExprObjectPtr ExprBinop::convert(int size){
    if( _op == OP_BSH )
        return NewExprBinop(_op, _left->convert(size), _right);
    else
        return NewExprBinop(_op, _left->convert(size), _right->convert(size));
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

// Convert the expression size
ExprObjectPtr ExprUnop::convert(int size){
    return NewExprUnop(_op, _arg->convert(size));
}

////////////////////////////////////////////////////////////////////////
// ExprExtract
// Constructor 
ExprExtract::ExprExtract( ExprObjectPtr a, int h, int l): Expr(EXPR_EXTRACT), _arg(a), _high(h), _low(l){
    if( h < l )
        throw_exception("Invalid Extract() expression: high < low !");
    else if( h >= a->expr_ptr()->size()){ 
        throw_exception(ExceptionFormatter() << "Invalid Extract() expression: high >= size ! in "
            << a << "(high:" << h << ", low:" << l << ")\n" >> ExceptionFormatter::to_str);
    }else if( l < 0)
        throw_exception("Invalid Extract() expression: low < 0 !");
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

// Convert the expression size
ExprObjectPtr ExprExtract::convert(int size){
    if( _low + size <= _arg->expr_ptr()->size())
        return NewExprExtract(_arg, _low+size-1, _low );
    else
        return Concat(NewExprCst(0,size- (_arg->expr_ptr()->size()- _low)), 
                      NewExprExtract(_arg, _arg->expr_ptr()->size()-1, _low));
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

// Convert the expression size
ExprObjectPtr ExprConcat::convert(int size){
    if( size <= _lower->expr_ptr()->size() )
        return _lower->convert(size);
    else if( size <= _size )
        return NewExprConcat(_upper->convert(size - _lower->expr_ptr()->size()), _lower);
    else
        return NewExprConcat(NewExprCst(0, size-_size), NewExprConcat(_upper, _lower));
}

////////////////////////////////////////////////////////////////////////
// ExprUnknown
ExprUnknown::ExprUnknown(int size): Expr(EXPR_UNKNOWN){
    set_size(size);
};
void ExprUnknown::print(ostream& os){  
    os << "unknown";  
}
bool ExprUnknown::equal(shared_ptr<Expr> other){
    return false;
}
bool ExprUnknown::lthan(ExprPtr other){
    return _type < other->type();
}

ExprObjectPtr ExprUnknown::convert(int size){
    return NewExprUnknown(size);
}

////////////////////////////////////////////////////////////////////////
// ExprObject
ExprObject::ExprObject(ExprPtr p): _expr_ptr(p), _simplified(false), _filtered(false){}
int ExprObject::size(){return _expr_ptr->size();}
ExprPtr ExprObject::expr_ptr(){return _expr_ptr;}
Expr ExprObject::expr(){return *_expr_ptr;}
bool ExprObject::equal(ExprObjectPtr other){
    return _expr_ptr->equal(other->expr_ptr());
}

pair<ExprObjectPtr, CondObjectPtr> ExprObject::tweak(){
    return tweak_expression(_expr_ptr);
}

void ExprObject::simplify(){
    ExprPtr saved = nullptr; 
    if( _simplified )
        return; 
        
    while( saved != _expr_ptr ){
        saved = _expr_ptr;
        switch( _expr_ptr->type() ){
            case EXPR_UNOP:
                _expr_ptr->arg_object_ptr()->simplify();
                _expr_ptr = simplify_unknown(_expr_ptr);
                _expr_ptr = simplify_constant_folding(_expr_ptr);
                break;
            case EXPR_BINOP:
                // Check if _expr_ptr comes from a polynom, is yes it is the best 
                // simplification we can do 
                if( _expr_ptr->is_polynom() )
                    break;
                _expr_ptr->left_object_ptr()->simplify(); 
                _expr_ptr->right_object_ptr()->simplify(); 
                canonize(_expr_ptr);
                _expr_ptr = simplify_unknown(_expr_ptr);
                _expr_ptr = simplify_constant_folding(_expr_ptr);
                _expr_ptr = simplify_pattern(_expr_ptr);
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
                _expr_ptr = simplify_pattern(_expr_ptr); 
                _expr_ptr = simplify_constant_folding(_expr_ptr);
                break;
            case EXPR_MEM:
                _expr_ptr->addr_object_ptr()->simplify(); 
                _expr_ptr = simplify_unknown(_expr_ptr);
                break;
            default:
                break;
        }
    }
    _expr_ptr->compute_polynom(); 
    _simplified = true;
}

bool ExprObject::filter(){
    bool unknown = false; 
    if( _filtered )
        return _expr_ptr->type() == EXPR_UNKNOWN; 
    _filtered = true;   
     
    switch(_expr_ptr->type()){
        case EXPR_CST:
        case EXPR_REG:
            break;
        case EXPR_MEM:
            if( _expr_ptr->addr_object_ptr()->filter())
                unknown = true; 
            else
                unknown = ( ! supported_address(_expr_ptr->addr_expr_ptr()) );
            break; 
        case EXPR_BINOP:
            if( _expr_ptr->left_object_ptr()->filter() ||
                _expr_ptr->right_object_ptr()->filter() )
                unknown = true; 
            else
                unknown = ( ! supported_binop(_expr_ptr));
          break;
        default:
            unknown = true; 
    }
    if( unknown ){
        _expr_ptr = special_NewExprPtrUnknown();
        return true; 
    }else
        return false; 
}

ExprObjectPtr ExprObject::convert(int size){
    return _expr_ptr->convert(size);
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
ExprObjectPtr NewExprReg(int n, int size){
    return make_shared<ExprObject>(make_shared<ExprReg>(n, size));
}
ExprObjectPtr NewExprMem(ExprObjectPtr addr, int s){
    return make_shared<ExprObject>(make_shared<ExprMem>(addr, s));
}
ExprObjectPtr NewExprBinop(Binop op, ExprObjectPtr left, ExprObjectPtr right){
    return make_shared<ExprObject>(make_shared<ExprBinop>(op, left, right));
}
ExprObjectPtr NewExprUnop(Unop op, ExprObjectPtr arg){
    return make_shared<ExprObject>(make_shared<ExprUnop>(op, arg));
}
ExprObjectPtr NewExprExtract(ExprObjectPtr arg, int high, int low){
    return make_shared<ExprObject>(make_shared<ExprExtract>(arg, high, low));
}
ExprObjectPtr NewExprConcat(ExprObjectPtr upper, ExprObjectPtr lower){
    return make_shared<ExprObject>(make_shared<ExprConcat>(upper, lower));
}
ExprObjectPtr g_expr_unknown = make_shared<ExprObject>(make_shared<ExprUnknown>(-1));
ExprObjectPtr NewExprUnknown(int size=-1){
    if( size == -1 )
        return g_expr_unknown;
    else
        return make_shared<ExprObject>(make_shared<ExprUnknown>(size));
}
// Create new ExprPtr for ExprUnknown, ONLY INTERNAL USAGE
ExprPtr g_expr_ptr_unknown = make_shared<ExprUnknown>(-1);
ExprPtr special_NewExprPtrUnknown(){
    return g_expr_ptr_unknown; 
}


