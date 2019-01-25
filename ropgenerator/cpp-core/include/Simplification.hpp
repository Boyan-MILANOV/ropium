#ifndef SIMPLIFICATION_H
#define SIMPLIFICATION_H

#include "Expression.hpp"
#include "Condition.hpp"
/*---------------------------------------------------------------
 *              Simplifications on Expressions 
 *---------------------------------------------------------------*/ 
 
////////////////////////////////////////////////////////////////////////
// Polynom representation for simplifications :)
class ExprAsPolynom{
    int* _polynom; //polynom[i] = reg i , last element is the constant
    int _len; 
    public: 
        // Constructor 
        ExprAsPolynom(int l);
        // Accessors 
        int len();
        int * polynom();
        // Operations
        void set(int index, int value);
        ExprAsPolynom* copy();
        bool equal( ExprAsPolynom* other);
        CondEval compare(ExprAsPolynom* other, CondType comp);
        ExprAsPolynom* merge_op(ExprAsPolynom *other, Binop op);
        ExprAsPolynom* mul_all(int factor);
        ExprPtr to_expr(int expr_size);
        // Destructor 
        ~ExprAsPolynom();
};

////////////////////////////////////////////////////////////////////////
//Simplifications
void canonize(ExprPtr p);
ExprPtr simplify_unknown(ExprPtr p);
ExprPtr simplify_constant_folding(ExprPtr p);
ExprPtr simplify_polynom_factorization(ExprPtr p);
ExprPtr simplify_neutral_element(ExprPtr p);
ExprPtr simplify_pattern(ExprPtr p);

/*---------------------------------------------------------------
 *              Simplifications on Conditions 
 *---------------------------------------------------------------*/ 
// Simplifications
CondPtr simplify_constant_folding(CondPtr p);
CondPtr simplify_neutral_element(CondPtr p);
CondPtr simplify_compare_polynom(CondPtr p);
CondPtr simplify_redundancy(CondPtr p);
 
/*---------------------------------------------------------------
 *              Tweaking Expressions & Conditions
 *---------------------------------------------------------------*/ 
pair<ExprObjectPtr, CondObjectPtr> tweak_expression(ExprPtr p);
pair<CondObjectPtr,CondObjectPtr> tweak_condition(CondPtr p);

/*---------------------------------------------------------------
 *              Filtering expressions  
 *---------------------------------------------------------------*/ 
bool supported_address(ExprPtr addr);
bool supported_binop(ExprPtr expr);

/*---------------------------------------------------------------
 *              Filtering conditions 
 *---------------------------------------------------------------*/  
bool supported_compared_expr(ExprPtr expr);
bool supported_valid_pointer_expr(ExprPtr expr); 

#endif 
