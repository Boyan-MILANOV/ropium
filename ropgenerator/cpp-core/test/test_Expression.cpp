#include "../Expression.hpp"

////////////////////////////////////////////////////////////////////////
int main(){
    // Test function 
    ExprObjectPtr e1,e2,e3,e4, e5; 
    
    
    e1 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprCst(23, 64))));
    e2 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprReg(0,64))));
    e5 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprReg(3,64))));
    e4 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprMem(e5^e1, 64))));
    e3 = (e1 + e2)*e4;
    e3 = Extract(e2, 31,0);
    e3->simplify();  
    cout << e3 << endl;  
    e3 = Concat(Extract(e2,31,0), Extract(e5,31,0));
    e3->simplify();
    cout << e3 << endl;
    return 0;  
}
