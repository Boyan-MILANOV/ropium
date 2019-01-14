#include "Expression.hpp"
#include "Condition.hpp"

int main(){
    // Test function 
    ExprObjectPtr e1,e2,e3,e4, e5; 
    CondObjectPtr c1,c2,c3; 
    int i;
    
    e1 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprCst(23, 64))));
    e2 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprReg(0,64))));
    e5 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprReg(3,64))));
    e4 = ExprObjectPtr(new ExprObject (ExprPtr(new ExprCst(6, 64))));
    e3 = e1 + (e2+e4) - e5*e4;
    e3->simplify();
    cout << e3 << endl;
    
    for( i = 0; i < 1000000; i++){
        c1 = (e1 == e4);
        //cout << c1 << endl; 
        c2 = !(e2 < e3);
        //cout << c2 << endl; 
        //c3 = c1 && c2; 
        c3 = (Concat(Extract(e2,31,0), Extract(e5,31,0)) < e4) && c1 && c2; 
        //cout << c3 << endl; 
        c3->simplify(); 
        //cout << c3 << endl; 
        c1 = (e1 == e4) || (e4*e1+e4*e5 == e4*(e1+e1+e5-e1));
        c1->simplify();
        //cout << c1 << endl; 
    }
    return 0;  
}
