#ifndef SIMPLIFICATION_H
#define SIMPLIFICATION_H

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
        ExprAsPolynom* merge_op(ExprAsPolynom *other, Binop op);
        ExprAsPolynom* mul_all(int factor);
        ExprPtr to_expr(int expr_size);
        // Destructor 
        ~ExprAsPolynom();
};

////////////////////////////////////////////////////////////////////////
//Simplifications
void canonize(ExprPtr p);
ExprPtr simplify_constant_folding(ExprPtr p);
ExprPtr simplify_polynom_factorization(ExprPtr p);
ExprPtr simplify_neutral_element(ExprPtr p);
#endif 
