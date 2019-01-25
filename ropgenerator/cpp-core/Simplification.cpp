#include "Expression.hpp"
#include "Simplification.hpp"
#include "Exception.hpp"
#include "Architecture.hpp"

#include <cmath>

/*---------------------------------------------------------------
 *              Simplifications on Expressions 
 *---------------------------------------------------------------*/ 


////////////////////////////////////////////////////////////////////////
// Simplification functions 
/* Simplification functions take an ExprPtr as input
   They return 
   - The argument if no simplifaction was found 
   - Another ExprPtr to the new expression if they simplified the argument  
*/

void canonize(ExprPtr p){
    /* Canonize for symetrical binops
     * Lowest priority goes on the right
     * Priorities are the values of the enum ExprType ;) 
     * 
     * Transform BSH into MUL and DIV when possible
    */
    if( p->type() != EXPR_BINOP || p->binop() == OP_SUB || p->binop() == OP_DIV ||
        p->binop() == OP_MOD || p->binop() == OP_BSH)
        return;
    else if( p->left_expr_ptr()->lthan( p->right_expr_ptr()))
        p->exchange_args();
}

// Propagate unknown expressions 
ExprPtr simplify_unknown(ExprPtr p){
    if( p->type() == EXPR_UNOP && p->arg_expr_ptr()->type() == EXPR_UNKNOWN)
        return p->arg_expr_ptr(); 
    else if( p->type() == EXPR_BINOP )
        if( p->left_expr_ptr()->type() == EXPR_UNKNOWN)
            return p->left_expr_ptr();
        else if( p->right_expr_ptr()->type() == EXPR_UNKNOWN)
            return p->right_expr_ptr(); 
    else if( p->type() == EXPR_EXTRACT && p->arg_expr_ptr()->type() == EXPR_UNKNOWN)
        return p->arg_expr_ptr(); 
    else if( p->type() == EXPR_CONCAT ) 
        if( p->upper_expr_ptr()->type() == EXPR_UNKNOWN)
            return p->upper_expr_ptr();
        else if( p->lower_expr_ptr()->type() == EXPR_UNKNOWN)
            return p->lower_expr_ptr();
    else if( p->type() == EXPR_MEM && p->addr_expr_ptr()->type() == EXPR_UNKNOWN)
        return p->addr_expr_ptr();
        
    return p; 
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
            case OP_MOD:
                return make_shared<ExprCst>(left_val%right_val, p->size());
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
        }else if( (p->low() == 0) && (p->high() == p->arg_expr_ptr()->size()-1)){
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
    // Check if we already have computed the polynom
    if( p->is_polynom() )
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
        if( p->right_expr_ptr()->type() != EXPR_CST )
            return p; 
        val = p->right_expr_ptr()->value();
        switch(p->binop()){
            case OP_ADD:
            case OP_SUB:
                return ( val == 0 )? p->left_expr_ptr() : p; 
            case OP_MUL:
                if( val == 0 )
                    return p->right_expr_ptr();
                else
                    return ( val == 1 )? p->left_expr_ptr() : p; 
            case OP_DIV:
                return ( val == 1 )? p->left_expr_ptr() : p; 
            case OP_AND:
                if( val == (1 << (p->size()-1) ))
                    return p->left_expr_ptr();
                else if( val == 0 )
                    return p->right_expr_ptr(); 
                else
                    return p;
                break;
            case OP_OR:
                if( val == (1 << (p->size()-1) )) // 0xfffff... 
                    return p->right_expr_ptr();
                return ( val == 0 )? p->left_expr_ptr() : p; 
            case OP_XOR:
                if( val == (1 << (p->size()-1) ))
                    return make_shared<ExprUnop>(OP_NEG, p->left_object_ptr());
                return ( val == 0 )? p->left_expr_ptr() : p; 
            case OP_MOD:
                return ( val == 1 )? make_shared<ExprCst>(0,p->left_expr_ptr()->size()) : p;
            default:
                return p;
        }
    }else if( p->type() == EXPR_EXTRACT ){
        if( (p->low() == 0) && (p->high() == p->arg_expr_ptr()->size()-1))
            return p->arg_object_ptr()->expr_ptr();
        else
            return p; 
    }
    return p; 
}

ExprPtr simplify_pattern(ExprPtr p){
    int bound; 
    
    if( p->type() == EXPR_CONCAT ){
        // Concat(X[a:b], X[b-1:c]) = X[a:c]         
        if( p->upper_expr_ptr()->type() == EXPR_EXTRACT && 
            p->lower_expr_ptr()->type() == EXPR_EXTRACT &&
            p->lower_expr_ptr()->arg_expr_ptr()->equal(p->upper_expr_ptr()->arg_expr_ptr()) && 
            p->upper_expr_ptr()->low() == p->lower_expr_ptr()->high() + 1)
            
            return make_shared<ExprExtract>(p->lower_expr_ptr()->arg_object_ptr(), 
                                            p->upper_expr_ptr()->high(),
                                            p->lower_expr_ptr()->low());
    }else if( p->type() == EXPR_EXTRACT ){
        if( p->arg_expr_ptr()->type() == EXPR_CONCAT ){
            // Extract( Concat(X,Y), a, b ) where a,b in Y only 
            bound = p->arg_expr_ptr()->lower_expr_ptr()->size(); 
            if( p->high() == bound-1 && p->low() == 0 )
                return p->arg_expr_ptr()->lower_expr_ptr(); 
            else if( p->high() < bound-1 )
                return make_shared<ExprExtract>(p->arg_expr_ptr()->lower_object_ptr(), p->high(), p->low());
            // Extract( Concat(X,Y), a, b ) where a,b in X only
            if( p->low() == bound && p->high() == p->arg_expr_ptr()->size()-1)
                return p->arg_expr_ptr()->upper_expr_ptr(); 
            else if( p->low() > bound ){
                return make_shared<ExprExtract>(p->arg_expr_ptr()->upper_object_ptr(), p->high()-bound, p->low()-bound);
                
            }
        // Extract(Extract(X,a,b), c, d) with a > c > d > b
        }else if( p->arg_expr_ptr()->type() == EXPR_EXTRACT ){
            if( p->arg_expr_ptr()->high() >= p->high() && 
                p->arg_expr_ptr()->low() <= p->low() )
                return make_shared<ExprExtract>(p->arg_expr_ptr()->arg_object_ptr(),
                                p->arg_expr_ptr()->low()+p->high(),
                                p->arg_expr_ptr()->low()+p->low());
        // Extract(X op CST, a, 0) where CST can be out of the extract 
        }else if( p->arg_expr_ptr()->type() == EXPR_BINOP && 
                 p->arg_expr_ptr()->right_expr_ptr()->type() == EXPR_CST &&
                 p->low() == 0 ){
            return make_shared<ExprBinop>(p->arg_expr_ptr()->binop(),
                     NewExprExtract(p->arg_expr_ptr()->left_object_ptr(), p->high(), p->low()),   
                     NewExprCst( p->arg_expr_ptr()->right_expr_ptr()->value() & (cst_t)(std::pow(2,p->high()+1)-1) ,p->high()+1)
                        );
        }
    }else if( p->type() == EXPR_BINOP ){
        switch(p->binop()){
            case OP_DIV:
                // (X*Y)/Y
                if( p->right_expr_ptr()->type() == EXPR_CST && 
                    p->left_expr_ptr()->type() == EXPR_BINOP &&
                    p->left_expr_ptr()->binop() == OP_MUL && 
                    p->left_expr_ptr()->right_expr_ptr()->type() == EXPR_CST &&
                    p->left_expr_ptr()->right_expr_ptr()->value() % p->right_expr_ptr()->value() == 0 ){
                        
                    if( p->left_expr_ptr()->right_expr_ptr()->value() >= p->right_expr_ptr()->value() )
                        return make_shared<ExprBinop>(OP_MUL, p->left_expr_ptr()->left_object_ptr(), NewExprCst( p->left_expr_ptr()->right_expr_ptr()->value()/p->right_expr_ptr()->value(), 
                                                                                  p->left_expr_ptr()->left_expr_ptr()->size()));
                }
                break;
            case OP_XOR:
                // X XOR X
                if( p->left_object_ptr()->equal(p->right_object_ptr()) ){
                    return make_shared<ExprCst>(0, p->size());
                }
                break;
            default:
                break;
        }
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

CondEval ExprAsPolynom::compare(ExprAsPolynom* other, CondType comp){
    int i;
    if( other->len() != _len )
        throw_exception("Comparing polynoms of different length!");
    for( i = 0; i < _len; i++)
        if( _polynom[i] != other->polynom()[i])
            break;
    if( i == _len )
        return (comp == COND_EQ || comp == COND_LE) ? EVAL_TRUE : EVAL_FALSE;
    else if( i == _len-1)
        if( _polynom[i] < other->polynom()[i] )
            return (comp == COND_NEQ || comp == COND_LT) ? EVAL_TRUE : EVAL_FALSE;
        else
            return (comp == COND_NEQ) ? EVAL_TRUE : EVAL_FALSE;
    else
        return EVAL_UNKNOWN;
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
            throw_exception("Invalid ExprType in merge_op!");
    }
    if( other->len() != _len )
        throw_exception("Merging polynoms of different length!");
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
    if( not_null && _polynom[_len-1] > 0)
        tmp = tmp + NewExprCst(_polynom[_len-1], expr_size);
    else if( not_null && _polynom[_len-1] < 0)
        tmp = tmp - NewExprCst(_polynom[_len-1]*-1, expr_size);
    else
        tmp = make_shared<ExprObject>(make_shared<ExprCst>(_polynom[_len-1], expr_size));
    tmp->expr_ptr()->set_polynom(copy());
    tmp->expr_ptr()->_is_polynom = true; 
    return tmp->expr_ptr(); 
}
// Destructor 
ExprAsPolynom::~ExprAsPolynom(){
    free(_polynom);
}



/*---------------------------------------------------------------
 *              Simplifications on Conditions 
 *---------------------------------------------------------------*/ 
// Simplifications
CondPtr simplify_constant_folding(CondPtr p){
    cst_t left_val, right_val; 
    if( !is_compare_cond(p->type()) )
        return p;
    if( p->left_expr_ptr()->type() == EXPR_CST && 
        p->right_expr_ptr()->type() == EXPR_CST ){
        left_val = p->left_expr_ptr()->value(); 
        right_val = p->right_expr_ptr()->value(); 
    }else
        return p; 
        
    switch(p->type()){
        case COND_EQ:
            return make_shared<CondConst>((left_val==right_val)?COND_TRUE:COND_FALSE);
        case COND_NEQ:
            return make_shared<CondConst>((left_val!=right_val)?COND_TRUE:COND_FALSE);
        case COND_LT:
            return make_shared<CondConst>((left_val<right_val)?COND_TRUE:COND_FALSE);
        case COND_LE:
            return make_shared<CondConst>((left_val<=right_val)?COND_TRUE:COND_FALSE);
        default:
            return p; 
    }
}


CondPtr simplify_neutral_element(CondPtr p){
    switch(p->type()){
        case COND_NOT:
            if( is_const_cond(p->arg_cond_ptr()->type()))
                return make_shared<CondConst>(invert_cond_type(p->arg_cond_ptr()->type()));
            else
                return p; 
        case COND_AND:
            if( p->left_cond_ptr()->type() == COND_TRUE)
                return p->right_cond_ptr();
            else if( p->left_cond_ptr()->type() == COND_FALSE)
                return p->left_cond_ptr();
            else if( p->right_cond_ptr()->type() == COND_TRUE)
                return p->left_cond_ptr();
            else if(  p->right_cond_ptr()->type() == COND_FALSE)
                return p->right_cond_ptr();
            else
                return p;
        case COND_OR:
            if( p->left_cond_ptr()->type() == COND_TRUE)
                return p->left_cond_ptr();
            else if( p->left_cond_ptr()->type() == COND_FALSE)
                return p->right_cond_ptr();
            else if( p->right_cond_ptr()->type() == COND_TRUE)
                return p->right_cond_ptr();
            else if(  p->right_cond_ptr()->type() == COND_FALSE)
                return p->left_cond_ptr();
            else
                return p;
        default:
            return p;
        
    }
}

CondPtr simplify_compare_polynom(CondPtr p){
    ExprAsPolynom *left_p, *right_p;
    if( ! is_compare_cond(p->type()) )
        return p;
    left_p = p->left_expr_ptr()->polynom();
    right_p = p->right_expr_ptr()->polynom();
    if( left_p==nullptr || right_p==nullptr )
        return p;
        
    switch(left_p->compare(right_p, p->type())){
        case EVAL_TRUE:
            return make_shared<CondConst>(COND_TRUE);
        case EVAL_FALSE:
            return make_shared<CondConst>(COND_FALSE);
        default:
            return p;
    }
}

CondPtr simplify_redundancy(CondPtr p);



/*----------------------------------------------------------------
 *                  Expressions tweaking
 * --------------------------------------------------------------*/
 
pair<ExprObjectPtr, CondObjectPtr> tweak_expression(ExprPtr p){
    pair<ExprObjectPtr, CondObjectPtr> arg1, arg2; 
    ExprObjectPtr expr1, expr2;
    CondObjectPtr cond1, cond2; 
    
    switch(p->type()){
        case EXPR_MEM:
            arg1 = p->addr_object_ptr()->tweak();
            if( (arg1.first) != nullptr )
                return make_pair(NewExprMem(arg1.first, p->size()), arg1.second);
            break;
        
        case EXPR_BINOP:
            arg1 = p->left_object_ptr()->tweak();
            arg2 = p->right_object_ptr()->tweak();
            if( (arg1.first) != nullptr &&  (arg2.first) != nullptr )
                return make_pair(NewExprBinop(p->binop(), arg1.first, arg2.first), 
                                arg1.second && arg2.second);
            else if( (arg1.first) != nullptr && (arg2.first) == nullptr )
                return make_pair(NewExprBinop(p->binop(), arg1.first, p->right_object_ptr()), 
                                arg1.second);
            else if( (arg1.first) == nullptr && (arg2.first) != nullptr )
                return make_pair(NewExprBinop(p->binop(), p->left_object_ptr(), arg2.first ), 
                                arg2.second);
            break;
        
        case EXPR_UNOP:
            arg1 = p->arg_object_ptr()->tweak();
            if( (arg1.first) != nullptr )
                return make_pair(NewExprUnop(p->unop(), arg1.first), arg1.second);
            break;
        
        case EXPR_EXTRACT:
            arg1 = p->arg_object_ptr()->tweak();
            if( (arg1.first) != nullptr )
                return make_pair(NewExprExtract(arg1.first, p->high(), p->low()), arg1.second);
            break;
            
        case EXPR_CONCAT:
            // First tweak arguments 
            arg1 = p->upper_object_ptr()->tweak();
            arg2 = p->lower_object_ptr()->tweak();
            if( (arg1.first) == nullptr ){
                expr1 = p->upper_object_ptr();
                cond1 = NewCondTrue();
            }else{
                std::tie(expr1, cond1) = arg1; 
            }
            if( (arg2.first) == nullptr ){
                expr2 = p->lower_object_ptr();
                cond2 = NewCondTrue();
            }else{
                std::tie(expr2, cond2) = arg2; 
            }
            // Concat(0, Extract(reg, x, 0)) -> reg if reg < 2^x
            if( expr1->expr_ptr()->type() == EXPR_CST &&
                expr1->expr_ptr()->value() == 0 &&
                expr2->expr_ptr()->type() == EXPR_EXTRACT &&
                expr2->expr_ptr()->low() == 0 && 
                expr2->expr_ptr()->arg_expr_ptr()->type() == EXPR_REG 
                ){
                return make_pair(NewExprReg(expr2->expr_ptr()->arg_expr_ptr()->num(), curr_arch()->bits()), 
                                 cond1 && cond2 && NewCondCompare(COND_LT, NewExprReg(expr2->expr_ptr()->arg_expr_ptr()->num(),
                                                                                      curr_arch()->bits()),
                                                                        NewExprCst(std::pow(2, expr2->expr_ptr()->high()+1),
                                                                                   curr_arch()->bits())
                                                                  )
                                );
            }
            // Concat(X, Y op CST ) -> Concat(X,Y) op CST 
            else if( 
                    expr2->expr_ptr()->type() == EXPR_BINOP && 
                    expr2->expr_ptr()->right_expr_ptr()->type() == EXPR_CST && 
                    (expr2->expr_ptr()->binop() == OP_ADD || expr2->expr_ptr()->binop() == OP_SUB ||
                    expr2->expr_ptr()->binop() == OP_XOR || expr2->expr_ptr()->binop() == OP_OR || 
                    expr2->expr_ptr()->binop() == OP_AND)
                    
                ){
                if( expr2->expr_ptr()->binop() == OP_ADD ){
                    return make_pair( Concat(expr1, expr2->expr_ptr()->left_object_ptr()) + NewExprCst(expr2->expr_ptr()->right_expr_ptr()->value() ,p->size()),
                                      NewCondCompare(COND_LT, expr2->expr_ptr()->left_object_ptr(),
                                                     NewExprCst(std::pow(2,expr2->expr_ptr()->size())-expr2->expr_ptr()->right_expr_ptr()->value(),
                                                                expr2->expr_ptr()->left_object_ptr()->size())
                                                    )
                                    );
                }else if( expr2->expr_ptr()->binop() == OP_SUB ){
                    return make_pair( Concat(expr1, expr2->expr_ptr()->left_object_ptr()) - NewExprCst(expr2->expr_ptr()->right_expr_ptr()->value() ,p->size()),
                                      NewCondCompare(COND_LT, NewExprCst(expr2->expr_ptr()->right_expr_ptr()->value(),
                                                                expr2->expr_ptr()->left_object_ptr()->size()),
                                                              expr2->expr_ptr()->left_object_ptr()
                                                    )
                                    );
                }else if( (expr2->expr_ptr()->binop() == OP_AND && expr2->expr_ptr()->right_expr_ptr()->value() < std::pow(2,expr2->expr_ptr()->left_expr_ptr()->size())) 
                        || expr2->expr_ptr()->binop() == OP_XOR 
                        || expr2->expr_ptr()->binop() == OP_OR){
                    return make_pair( NewExprBinop( expr2->expr_ptr()->binop(), Concat(expr1, expr2->expr_ptr()->left_object_ptr()),
                                                    NewExprCst(expr2->expr_ptr()->right_expr_ptr()->value() ,p->size())
                                                   ),
                                      NewCondTrue()
                                    );
                    
                }
            }
            // Otherwise normal return 
            else if( (arg1.first) != nullptr &&  (arg2.first) != nullptr )
                return make_pair(Concat(arg1.first, arg2.first), 
                                arg1.second && arg2.second);
            else if( (arg1.first) != nullptr && (arg2.first) == nullptr )
                return make_pair(Concat(arg1.first, p->lower_object_ptr()), 
                                arg1.second);
            else if( (arg1.first) == nullptr && (arg2.first) != nullptr )
                return make_pair(Concat( p->upper_object_ptr(), arg2.first ), 
                                arg2.second );
            break;
        default:
            break;
    }
    //return make_pair(make_shared<ExprObject>(nullptr), make_shared<CondObject>(nullptr));
    return make_pair(nullptr, nullptr);
}


/*----------------------------------------------------------------
 *                  Conditions tweaking
 * --------------------------------------------------------------*/
pair<CondObjectPtr,CondObjectPtr> tweak_condition(CondPtr p){
    pair<ExprObjectPtr, CondObjectPtr> arg1, arg2; 
    pair<CondObjectPtr, CondObjectPtr> c1;
    ExprObjectPtr expr1, expr2; 
    CondObjectPtr cond1,cond2, tcond1, tcond2; 
    // Comapre condition 
    if( is_compare_cond( p->type() )){
        // Get arguments 
        arg1 = p->left_exprobject_ptr()->tweak();
        arg2 = p->right_exprobject_ptr()->tweak(); 
        if( arg1.first == nullptr ){
            expr1 = p->left_exprobject_ptr();
            cond1 = NewCondTrue();
        }else
            std::tie(expr1,cond1) = arg1;
            
        if( arg2.first == nullptr ){
            expr2 = p->right_exprobject_ptr();
            cond2 = NewCondTrue();
        }else
            std::tie(expr2,cond2) = arg2;

        // X[a:0] < Y --> X < Y 
        if( (p->type() == COND_LT || p->type() == COND_LE) &&
            expr1->expr_ptr()->type() == EXPR_EXTRACT &&
            expr1->expr_ptr()->low() == 0 ){
            return make_pair(NewCondCompare(p->type(), expr1->expr_ptr()->arg_object_ptr(), expr2), cond1 && cond2);
        } // Y < X[a:0] --> Y < X && X < 2^size(Y)
        else if((p->type() == COND_LT || p->type() == COND_LE) &&
            expr2->expr_ptr()->type() == EXPR_EXTRACT &&
            expr2->expr_ptr()->low() == 0 ){
            return make_pair(NewCondCompare(p->type(), expr1, expr2->expr_ptr()->arg_object_ptr()), 
                             cond1 && cond2 && (expr2->expr_ptr()->arg_object_ptr() < NewExprCst(std::pow(2,expr1->size()), 
                                                                                     expr2->expr_ptr()->arg_object_ptr()->size() )
                                                )
                            );
        }
        
        // Normal return 
        if( arg1.first != nullptr && arg2.first != nullptr ){
            return make_pair(NewCondCompare(p->type(), arg1.first, arg2.first), arg1.second && arg2.second);
        }else if( arg1.first != nullptr && arg2.first == nullptr ){
            return make_pair(NewCondCompare(p->type(), arg1.first, p->right_exprobject_ptr()), arg1.second);
        }else if( arg1.first == nullptr && arg2.first != nullptr ){
            return make_pair(NewCondCompare(p->type(), p->left_exprobject_ptr(), arg2.first), arg2.second);
        }
    }// Pointer condition
    else if(is_pointer_cond( p->type())){
        arg1 = p->arg_exprobject_ptr()->tweak();
        if( arg1.first != nullptr )
            return make_pair(NewCondPointer(p->type(), arg1.first), arg2.second);
    }// Bin Logic Condition
    else if( is_binlogic_cond( p->type() )){
        std::tie(cond1,tcond1) = p->left_condobject_ptr()->tweak();
        std::tie(cond2,tcond2) = p->right_condobject_ptr()->tweak();
        if( cond1 != nullptr && cond2 != nullptr )
            return make_pair(NewCondBinLogic(p->type(), cond1, cond2), tcond1 && tcond2);
        else if( cond1 != nullptr )
            return make_pair(NewCondBinLogic(p->type(), cond1, p->right_condobject_ptr()), tcond1);
        else if( cond2 != nullptr )
            return make_pair(NewCondBinLogic(p->type(), p->left_condobject_ptr(), cond2), tcond2);
    }// Un Logic Condition
    else if( is_unlogic_cond( p->type() )){
        std::tie(cond1,tcond1) = p->arg_condobject_ptr()->tweak();
        if( cond1 != nullptr )
            return make_pair(NewCondUnLogic(p->type(), cond1), tcond1);
    } 
    return make_pair(nullptr, nullptr);
}

/*---------------------------------------------------------------
 *              Filtering expressions  
 *---------------------------------------------------------------*/ 
bool supported_address(ExprPtr addr){
    return  
            // Reg 
            ( addr->type() == EXPR_REG ) || 
            // Reg +/- cst 
            (addr->type() == EXPR_BINOP && (addr->binop() == OP_ADD || addr->binop() == OP_SUB)  
                    && (addr->right_expr_ptr()->type() == EXPR_CST) 
                    && (addr->left_expr_ptr()->type() == EXPR_REG)
            );
}

bool supported_binop(ExprPtr expr){
    // reg|mem OP cst 
    if ( expr->right_expr_ptr()->type() == EXPR_CST ){
            if( expr->left_expr_ptr()->type() == EXPR_REG )
                return true; 
            else if(expr->left_expr_ptr()->type() == EXPR_MEM )
                return supported_address(expr->left_expr_ptr()->addr_expr_ptr());
    }
    return false; 
}

/*---------------------------------------------------------------
 *              Filtering conditions 
 *---------------------------------------------------------------*/  
bool supported_compared_expr(ExprPtr expr){
    // cst or reg 
    if( expr->type() == EXPR_CST || expr->type() == EXPR_REG)
        return true; 
    // reg +- cst
    else if(    expr->type() == EXPR_BINOP && 
                (expr->binop() == OP_ADD || expr->binop() == OP_SUB ) &&
                (expr->left_expr_ptr()->type() == EXPR_CST || expr->right_expr_ptr()->type() == EXPR_CST)
            )
        return true; 
    return false; 
}

bool supported_valid_pointer_expr(ExprPtr expr){
    // reg 
    if( expr->type() == EXPR_REG )
        return true; 
    // reg +- cst 
    else if(    expr->type() == EXPR_BINOP && 
                (expr->binop() == OP_ADD || expr->binop() == OP_SUB ) &&
                (expr->left_expr_ptr()->type() == EXPR_CST || expr->right_expr_ptr()->type() == EXPR_CST)
            )
        return true; 
    return false; 
}

