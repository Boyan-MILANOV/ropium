#include "Expression.hpp"
#include "Simplification.hpp"
#include "Expression.hpp"


////////////////////////////////////////////////////////////////////////
// Simplification functions 
/* Simplification functions take an ExprPtr as input
   They return 
   - The argument if no simplifaction was found 
   - Another ExprPtr to the new expression if they simplified the argument  
*/

void canonize(ExprPtr p){
    /* Canonize for binop
     * Lowest priority goes on the left
     * Priorities are the values of the enum ExprType ;) 
    */
    if( p ->type() != EXPR_BINOP || p->binop() == OP_SUB)
        return;
    else if( p->right_expr_ptr()->lthan( p->left_expr_ptr()))
        p->exchange_args();
}


// Constant folding 
ExprPtr simplify_constant_folding(ExprPtr p){
    cst_t left_val, right_val; 
    // Neutral for binary operations 
    if( p->type() == EXPR_BINOP ){
        // Neutral elements for BINOP are only constants 
        if( p->right_expr_ptr()->type() != EXPR_CST ||
            p->left_expr_ptr()->type() != EXPR_CST)
            return p; 
        left_val = p->left_expr_ptr()->value();
        right_val = p->right_expr_ptr()->value();
        switch(p->binop()){
            case OP_ADD:
                return make_shared<ExprCst>(left_val+right_val, p->size());
            case OP_SUB:
                return make_shared<ExprCst>(left_val-right_val, p->size()); 
            case OP_MUL:
                return make_shared<ExprCst>(left_val*right_val, p->size());
            case OP_DIV:
                return make_shared<ExprCst>(left_val/right_val, p->size());
            case OP_AND:
                return make_shared<ExprCst>(left_val&right_val, p->size());
            case OP_OR:
                return make_shared<ExprCst>(left_val|right_val, p->size());
            case OP_XOR:
                return make_shared<ExprCst>(left_val^right_val, p->size()); 
            default:
                return p;
        }
    }else if( p->type() == EXPR_UNOP ){
        if( p->arg_expr_ptr()->type() != EXPR_CST )
            return p;
        switch(p->unop()){
            case OP_NEG:
                return make_shared<ExprCst>(~p->arg_expr_ptr()->value(), p->size());
            default:
                return p;
        }
    }else if( p->type() == EXPR_EXTRACT ){
        if( p->arg_expr_ptr()->type() != EXPR_CST ){
            return p;
        }
        if( (p->low() == 0) && (p->high() == p->arg_expr_ptr()->size()-1)){
            return p->arg_object_ptr()->expr_ptr();
        }else{
            left_val = p->arg_expr_ptr()->value() >> p->low();
            left_val &= ((1<<(p->high() - p->low() + 1))-1); 
            return make_shared<ExprCst>(left_val, p->size());
        }
    }else if( p->type() == EXPR_CONCAT ){
        if( p->lower_expr_ptr()->type() != EXPR_CST ||
            p->upper_expr_ptr()->type() != EXPR_CST)
            return p; 
        left_val = p->upper_expr_ptr()->value();
        right_val = p->lower_expr_ptr()->value();
        return make_shared<ExprCst>((left_val << p->lower_expr_ptr()->size()) + right_val ,
                                    p->lower_expr_ptr()->size() + p->upper_expr_ptr()->size()); 
    }
    return p; 
}

// Polynom simplifications 
ExprPtr simplify_polynom_factorization(ExprPtr p){
    ExprAsPolynom* polynom; 

    if( p->type() != EXPR_BINOP )
        return p; 
    
    polynom = p->polynom();
    if( polynom)
        return polynom->to_expr(p->size());
    else
        return p;
}

ExprPtr simplify_neutral_element(ExprPtr p){
    cst_t val; 
    // Neutral for binary operations 
    if( p->type() == EXPR_BINOP ){
        // Neutral elements for BINOP are only constants 
        if( p->left_expr_ptr()->type() != EXPR_CST )
            return p; 
        val = p->left_expr_ptr()->value();
        switch(p->binop()){
            case OP_ADD:
            case OP_SUB:
                return ( val == 0 )? p->right_expr_ptr() : p; 
            case OP_MUL:
            case OP_DIV:
                return ( val == 1 )? p->right_expr_ptr() : p; 
            case OP_AND:
                if( val == (1 << (p->size()-1) ))
                    return p->right_expr_ptr();
                return p;
                break;
            case OP_OR:
            case OP_XOR:
                if( val == (1 << (p->size()-1) ))
                    return p->right_expr_ptr();
                else if( val == (1 << (p->size()-1) ))
                    return make_shared<ExprUnop>(OP_NEG, p->right_object_ptr());
                return ( val == 0 )? p->right_expr_ptr() : p; 
            default:
                return p;
        }
    }else if( p->type() == EXPR_UNOP ){
        return p; // TODO
    }else if( p->type() == EXPR_EXTRACT ){
        if( p->low() == 0 && p->high() == p->size()-1)
            return p->arg_object_ptr()->expr_ptr();
        else
            return p; 
    }
    return p; 
}


////////////////////////////////////////////////////////////////////////
// ExprAsPolynom
// Constructor 
ExprAsPolynom::ExprAsPolynom(int l){
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

ExprAsPolynom* ExprAsPolynom::copy(){
    ExprAsPolynom* res = new ExprAsPolynom(_len);
    int i;
    for (i=0; i<_len; i++)
        res->_polynom[i] = _polynom[i];
    return res; 
}

bool ExprAsPolynom::equal(ExprAsPolynom* other){
    int i;
    if( _len != other->len() )
        return false;
    for( i = 0; i < _len; i++)
        if( _polynom[i] != other->polynom()[i])
            return false;
    return true;
}

ExprAsPolynom* ExprAsPolynom::merge_op(ExprAsPolynom* other, Binop op){
    int i; 
    ExprAsPolynom *res = new ExprAsPolynom(_len);
    int (*func)(int,int);
    switch(op){
        case OP_ADD:
            func = [](int a, int b)->int{return a+b;};
            break;
        case OP_SUB:
            func = [](int a, int b)->int{return a-b;};
            break;
        case OP_MUL:
            func = [](int a, int b)->int{return a*b;};
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

ExprAsPolynom* ExprAsPolynom::mul_all(int factor){
    ExprAsPolynom* res = new ExprAsPolynom(_len);
    int i;
    for(i = 0; i < _len; i++)
        res->set(i, _polynom[i]*factor);
    return res; 
}

ExprPtr ExprAsPolynom::to_expr(int expr_size){
    int i; 
    ExprObjectPtr tmp;
    bool not_null = false;
    // Regs
    for(i = 0; i < _len-1; i++){
        if( _polynom[i] == 1 )
            if( not_null )
                tmp = tmp + make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)); 
            else{
                tmp = make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size));
                not_null = true;
            }
        else if( _polynom[i] == -1){
            if( not_null )
                tmp = tmp - make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)); 
            else{
                tmp = make_shared<ExprObject>(make_shared<ExprCst>(-1, expr_size))
                      * make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size));
                not_null = true;
            }
        } 
        
        else if( _polynom[i] > 1  )
            if( not_null )
                tmp = tmp + (make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)) * 
                  make_shared<ExprObject>(make_shared<ExprCst>(_polynom[i], expr_size)));
            else{
                tmp = (make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)) * 
                  make_shared<ExprObject>(make_shared<ExprCst>(_polynom[i], expr_size)));
                not_null = true;
            }
        else if( _polynom[i] < -1  ){
            if( not_null )
                tmp = tmp - (make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size)) * 
                  make_shared<ExprObject>(make_shared<ExprCst>(_polynom[i], expr_size))) ;
            else{
                tmp = make_shared<ExprObject>(make_shared<ExprCst>(-1*_polynom[i], expr_size))
                      * make_shared<ExprObject>(make_shared<ExprReg>(i, expr_size));
                not_null = true;
            }
        }
    }
    // Const
    if( not_null )
        tmp = make_shared<ExprObject>(make_shared<ExprCst>(_polynom[_len-1], expr_size)) + tmp;
    else
        tmp = make_shared<ExprObject>(make_shared<ExprCst>(_polynom[_len-1], expr_size));
    tmp->expr_ptr()->set_polynom(copy());
    return tmp->expr_ptr(); 
}
// Destructor 
ExprAsPolynom::~ExprAsPolynom(){
    free(_polynom);
}


