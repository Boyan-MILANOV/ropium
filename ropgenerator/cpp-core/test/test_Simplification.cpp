#include "Expression.hpp"
#include "Architecture.hpp"

////////////////////////////////////////////////////////////////////////
int main(){
    // Test function 
    ExprObjectPtr e1,e2,e3,e4, e5; 
    ExprObjectPtr res; 
    
    set_arch(ARCH_X64);
    
    e1 = NewExprReg(0,64);
    e2 = NewExprCst(8,64);
    e3 = e1 - e2 + e2;
    
    cout << e3 << endl;
    e3->simplify();
    cout << e3 << endl; 
    return 0;  
}
