#include "Expression.hpp"
#include "Simplification.hpp"

////////////////////////////////////////////////////////////////////////
int main(){
    // Test function 
    ExprObjectPtr e1,e2,e3,e4, e5; 
    ExprObjectPtr res; 
    
    e1 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprCst(23, 64))));
    e2 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprReg(0,64))));
    e5 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprReg(3,64))));
    e4 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprCst(6, 64))));
    e3 = e1 + e4;
    res = make_shared<ExprObject>(simplify_arithmetic_const_folding(e3->expr_ptr()));
    cout << res; 
    return 0;  
}
