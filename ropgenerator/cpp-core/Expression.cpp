#include "Expression.hpp" 

using namespace std; 

////////////////////////////////////////////////////////////////////////
//// Expr 
// Constructors
Expr::Expr(ExprType t): _type(t),_size(-1), _simplified(false), _polynom(nullptr), _no_polynom(false){}
Expr::Expr(ExprType t, int s): _type(t),_size(s), _simplified(false), _polynom(nullptr), _no_polynom(false){}
Expr::Expr(ExprType t, int s, bool simp): _type(t),_size(s), _simplified(simp), _polynom(nullptr), _no_polynom(false){}
// Accessors and modifiers 
int Expr::size(){return _size;}
int Expr::set_size(int s){return (_size=s); }
ExprType Expr::type(){return _type;}
ExprAsPolynom * Expr::polynom(){
    return _polynom; 
}
void Expr::set_polynom(ExprAsPolynom* p){
    free(_polynom);
    _polynom = p;
}
void Expr::set_simplified(bool v){_simplified = v;}
// IO
void Expr::print(ostream& os){os << "???";}
ostream& operator<< (ostream& os, Expr e){
    e.print(os);
    return os; 
}
// !!! This function must ALWAYS be overloaded by child classes 
ExprPtr Expr::get_shared_ptr(){
    return nullptr;
}
// Destructor
Expr::~Expr(){
    if( _polynom != nullptr)
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
// Shared ptr management
ExprPtr ExprCst::get_shared_ptr(){
    return shared_from_this(); 
}
// POlynom
ExprAsPolynom* compute_polynom(int size){
    ExprAsPolynom* res = new ExprAsPolynom(size);
    res.set(size-1, _value);
    return res; 
}

////////////////////////////////////////////////////////////////////////
//// ExprReg
// Constructor 
ExprReg::ExprReg(int n, int s): Expr(EXPR_REG, s),_num(n){}
// Operators
void ExprReg::print(ostream& os){  
    os << "r" << _num;  
}
// Shared ptr management
ExprPtr ExprReg::get_shared_ptr(){
    return shared_from_this(); 
}
// Polynom
ExprAsPolynom* compute_polynom(int size){
    ExprAsPolynom* res = new ExprAsPolynom(size);
    res.set(_num, 1);
    return res; 
}

////////////////////////////////////////////////////////////////////////
//// ExprMem
// Constructor 
ExprMem::ExprMem( ExprObjectPtr a, int s): Expr(EXPR_MEM, s), addr(a){}
// Operators
void ExprMem::print(ostream& os){  
    os << "mem[" << addr << "]";
}
// Shared ptr management
ExprPtr ExprMem::get_shared_ptr(){
    return shared_from_this(); 
}
// Polynom
ExprAsPolynom* compute_polynom(int size){
    return nullptr;
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
// Shared ptr management
ExprPtr ExprBinop::get_shared_ptr(){
    return shared_from_this(); 
}


////////////////////////////////////////////////////////////////////////
//// ExprUnop
// To string, needs to match the enum in Expression.hpp !!
const char* unop_to_str[] = {"~"}; 
// Constructor 
ExprUnop::ExprUnop( Unop o, ExprObjectPtr a): Expr(EXPR_UNOP), op(o), arg(a){
    set_size(a->expr_ptr()->size()); 
}
// Operators 
void ExprUnop::print(ostream& os){  
    os << unop_to_str[op] << arg;
}
// Shared ptr management
ExprPtr ExprUnop::get_shared_ptr(){
    return shared_from_this(); 
}


////////////////////////////////////////////////////////////////////////
// ExprExtract
// Constructor 
ExprExtract::ExprExtract( ExprObjectPtr a, int h, int l): Expr(EXPR_EXTRACT), arg(a), low(l), high(h){
    set_size(h-l+1);
}
// Operators  
void ExprExtract::print(ostream& os){  
    os << arg << "[" << high << ":" << low << "]" ;
}
// Shared ptr management
ExprPtr ExprExtract::get_shared_ptr(){
    return shared_from_this(); 
}

////////////////////////////////////////////////////////////////////////
// ExprObject
ExprObject::ExprObject(ExprPtr p): _expr_ptr(p){}
ExprPtr ExprObject::expr_ptr(){return _expr_ptr;}
Expr ExprObject::expr(){return *_expr_ptr;}
void ExprObject::set_expr_ptr(ExprPtr p){_expr_ptr = p;}


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
ExprObjectPtr operator~ (ExprObjectPtr p1){
    return make_shared<ExprObject>(make_shared<ExprUnop>(OP_NEG, p1)); 
}

////////////////////////////////////////////////////////////////////////
// ExprAsPolynom
// Constructor 
ExprAsPolynom::ExprAsPolynom(int l){
    if( l > POLYNOM_MAXLEN || l <= 0)
        throw "Invalid polynop size!";
    _polynom = (int*)calloc(l,sizeof(int)); // calloc initializes bits to zero 
    _len = l; 
}
// Accessors 
int ExprAsPolynom::len(){ return _len;}
int * ExprAsPolynom::polynom(){return _polynom;}
// Operations 
void ExprAsPolynom::set(int index, int value){
    _polynom[index] = value; 
}

ExprAsPolynom* ExprAsPolynom::merge_op(ExprAsPolynom *other, Binop op){
    int i; 
    ExprAsPolynom *res = new ExprAsPolynom(_len);
    int (*func)(int,int);
    switch(op){
        case OP_ADD:
            func = [](int a, int b)->int{return a+b;};
            break;
        case OP_SUB:
            func = [](int a, int b)->int{return a+b;};
            break;
        case OP_MUL:
            func = [](int a, int b)->int{return a+b;};
            break;
        default:
            throw "Invalid ExprType in merge_op!";
    }
    if( other->len() != _len )
        throw "Merging polynoms of different length!";
    for( i = 0; i < _len; i++)
        res->polynom()[i] = func(_polynom[i], other->polynom()[i]); 
    return res; 
}

ExprPtr ExprAsPolynom::to_expr(int expr_size){
    int i; 
    ExprObjectPtr tmp; 
    // Const 
    tmp = make_shared<ExprObject>(make_shared<ExprCst>(_polynom[_len-1], expr_size));
    // Regs
    for(i = 0; i < _len-1; i++){
        if( _polynom[i] == 1 )
            tmp = make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)) + tmp; 
        else if( _polynom[i] > 1  )
            tmp = (make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)) * 
                  make_shared<ExprObject>(make_shared<ExprCst>(_polynom[i], expr_size))) 
                  + tmp;
        else if( _polynom[i] < 0  )
            tmp = tmp - (make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)) * 
                  make_shared<ExprObject>(make_shared<ExprCst>(_polynom[i], expr_size))) ;
    }
    tmp->expr_ptr()->set_polynom(this);
    return tmp->expr_ptr(); 
}
// Destructor 
ExprAsPolynom::~ExprAsPolynom(){
    free(_polynom);
}

