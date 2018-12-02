#include "Expression.hpp" 
#include "Simplification.hpp"

using namespace std; 

////////////////////////////////////////////////////////////////////////
//// Expr
// Constructors
Expr::Expr(ExprType t): _type(t),_size(-1), _polynom(nullptr), _computed_polynom(false){}
Expr::Expr(ExprType t, int s): _type(t),_size(s), _polynom(nullptr), _computed_polynom(false){}
Expr::Expr(ExprType t, int s, bool simp): _type(t),_size(s), _polynom(nullptr), _computed_polynom(false){}
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

////////////////////////////////////////////////////////////////////////
//// ExprMem
// Constructor 
ExprMem::ExprMem( ExprObjectPtr a, int s): Expr(EXPR_MEM, s), addr(a){}
// Operators
void ExprMem::print(ostream& os){  
    os << "mem[" << addr << "]";
}

////////////////////////////////////////////////////////////////////////
//// ExprBinop
// To string, needs to match the enum in Expression.hpp !!
const char* binop_to_str[] = {"+","-","*","/","&","|","^"}; 
// Constructor 
ExprBinop::ExprBinop( Binop o, ExprObjectPtr l, ExprObjectPtr r): Expr(EXPR_BINOP), op(o), left(l), right(r){
    if( l->expr_ptr()->size() != r->expr_ptr()->size() )
        throw "Different sizes when initializing ExprBinop"; 
    set_size(l->expr_ptr()->size()); 
}
// Accessor
ExprObjectPtr ExprBinop::left_object_ptr(){return left;}
ExprObjectPtr ExprBinop::right_object_ptr(){return right;}
ExprPtr ExprBinop::left_expr_ptr(){return left->expr_ptr();}
ExprPtr ExprBinop::right_expr_ptr(){return right->expr_ptr();}
void ExprBinop::exchange_args(){
        ExprObjectPtr tmp = left;
        left = right; 
        right = tmp;  
}
    
Binop ExprBinop::binop(){return op;}
// Operators 
void ExprBinop::print(ostream& os){  
    os << "(" << left << binop_to_str[op] << right <<")";
}
void ExprBinop::compute_polynom(){
    ExprPtr res; 
    ExprAsPolynom *left_p, *right_p;
    
    if( _computed_polynom )
        return; 
        
    // Supported operators for polynoms 
    if( op != OP_ADD && op != OP_SUB && 
        !((op == OP_MUL && right->expr_ptr()->type() == EXPR_CST)))
        return; 
    
    _computed_polynom = true; 
    left_p = left->expr_ptr()->polynom();
    right_p = right->expr_ptr()->polynom();
    if( _polynom != nullptr){
        delete _polynom; 
        _polynom = nullptr; 
    }
        
    if( !left_p || !right_p )
        _polynom = nullptr; 
    else if( op == OP_ADD || op == OP_SUB)
        _polynom = left_p->merge_op(right_p, op);
    else if(op == OP_MUL && right->expr_ptr()->type() == EXPR_CST)
        _polynom = left_p->mul_all(right->expr_ptr()->value());
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

////////////////////////////////////////////////////////////////////////
// ExprObject
ExprObject::ExprObject(ExprPtr p): _expr_ptr(p), _simplified(false){}
ExprPtr ExprObject::expr_ptr(){return _expr_ptr;}
Expr ExprObject::expr(){return *_expr_ptr;}
void ExprObject::set_expr_ptr(ExprPtr p){_expr_ptr = p;}
void ExprObject::simplify(){
    ExprPtr tmp;
    if( _simplified )
        return; 
        
    switch( _expr_ptr->type() ){
        case EXPR_UNOP:
            _expr_ptr->arg_object_ptr()->simplify();
            _expr_ptr = simplify_constant_folding(_expr_ptr);
        case EXPR_BINOP:
            _expr_ptr->left_object_ptr()->simplify(); 
            _expr_ptr->right_object_ptr()->simplify(); 
            _expr_ptr = simplify_constant_folding(_expr_ptr);
            _expr_ptr = simplify_neutral_element(_expr_ptr);
            _expr_ptr = simplify_polynom_factorization(_expr_ptr);
            break;
        case EXPR_EXTRACT:
            _expr_ptr->arg_object_ptr()->simplify();
            _expr_ptr = simplify_constant_folding(_expr_ptr);
            _expr_ptr = simplify_neutral_element(_expr_ptr);
            break;
        case EXPR_CONCAT:
            _expr_ptr->lower_object_ptr()->simplify();
            _expr_ptr->upper_object_ptr()->simplify();
            _expr_ptr = simplify_constant_folding(_expr_ptr);
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
ExprObjectPtr Extract(ExprObjectPtr p1, int high, int low){
    return make_shared<ExprObject>(make_shared<ExprExtract>(p1, high, low)); 
}
ExprObjectPtr Concat (ExprObjectPtr p1, ExprObjectPtr p2){
    return make_shared<ExprObject>(make_shared<ExprConcat>(p1,p2));
}
ExprObjectPtr operator~ (ExprObjectPtr p1){
    return make_shared<ExprObject>(make_shared<ExprUnop>(OP_NEG, p1)); 
}





