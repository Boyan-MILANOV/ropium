#include "Expression.hpp"
#include "Architecture.hpp"

////////////////////////////////////////////////////////////////////////
int main(){
    // Test function 
    ExprObjectPtr e1,e2,e3,e4, e5; 
    ExprObjectPtr res; 
    
    set_arch(ARCH_X64);
    
    e1 = NewExprCst(0,64);
    e2 = NewExprCst(776876587,64);
    e3 = Extract(Concat(Extract(e1,63,32), e2),31,0);
    e3 = Extract(e2,31,0);
    
    cout << e3 << endl;
    e3->simplify();
    cout << e3 << endl; 
    return 0;  
}
