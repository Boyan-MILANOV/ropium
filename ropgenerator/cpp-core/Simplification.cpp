#include "Expression.hpp"
#include "Simplification.hpp"

/* Simplification functions take an ExprPtr as input
   They return 
   - The argument if no simplifaction was found 
   - Another ExprPtr to the new expression if they simplified the argument  
*/


ExprPtr simplify_arithmetic_const_folding(Binop op, ExprPtr left, ExprPtr right){
        ExprObjectPtr tmp, new_object_ptr; 
        ExprPtr new_expr_ptr;
        int factor;
        
        if( op == OP_ADD )
            factor = 1; 
        else
            factor = -1; 
            
        // If right is a constant 
        if( right->type() == EXPR_CST ){
            // Check if left is a constant 
            if( left->type() == EXPR_CST )
                return make_shared<ExprCst>(left->value() + factor*right->value(), left->size());
            // Check if left is a OP_ADD with a constant (X + 1)+ 2 = X + 3  
            // Or if left is a OP_SUB with a constant (X - 1)+ 2 = X + 1
            else if( left->type() == EXPR_BINOP 
                     && left->right_expr_ptr()->type() == EXPR_CST){
                if( left->binop() == OP_ADD ){
                    new_expr_ptr = make_shared<ExprCst>(left->right_expr_ptr()->value() + factor*right->value(),
                                                        left->size());
                    new_object_ptr = make_shared<ExprObject>(new_expr_ptr);
                    return make_shared<ExprBinop>(OP_ADD, 
                                                 left->left_object_ptr(), 
                                                 new_object_ptr);
                }else if( left->binop() == OP_SUB ){
                    return left; // TODO 
                }   
            }
        }
        // If no simplifications, return a null shared_pointer
        return left; 
}

// Polynom simplifications 
ExprPtr simplify_arithmetic_const_folding(ExprPtr p){
    ExprPtr res; 
    ExprAsPolynom *left, *right; 

    if( p->type() != EXPR_BINOP )
        return p; 
        
    left = p->left_expr_ptr()->polynom();
    right = p->right_expr_ptr()->polynom();
    if( !left || !right )
        return p; 
        
    if( p->binop() == OP_ADD || p->binop() == OP_SUB)
        return (left->merge_op(right, p->binop()))->to_expr(p->size());
    else if(p->binop() == OP_MUL && p->right_expr_ptr()->type() == EXPR_CST)
        return (left->mul_all(p->right_expr_ptr()->value()))->to_expr(p->size());
    else
        return p; 
}


