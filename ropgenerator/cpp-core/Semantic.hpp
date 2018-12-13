#ifndef SEMANTIC_H
#define SEMANTIC_H

#include <vector>
#include "Expression.hpp"
#include "Condition.hpp"

using std::vector; 

class SPair{
    ExprObjectPtr _expr;
    CondObjectPtr _cond; 
    public: 
        SPair(ExprObjectPtr e, CondObjectPtr c);
        ExprObjectPtr expr();
        CondObjectPtr cond();
        void set_cond(CondObjectPtr cond); 
        // IO
        void print(ostream& os); 
};

using reg_pair=pair<int, vector<SPair>*>;
using mem_pair=pair<ExprObjectPtr, vector<SPair>*>;

class Semantics{
    vector<reg_pair> _regs;
    vector<mem_pair> _mem; 
    public: 
        Semantics();
        void add_reg(int num, vector<SPair>* pairs);
        void add_mem(ExprObjectPtr addr, vector<SPair>* pairs);
        vector<reg_pair> regs();
        vector<mem_pair> mem();
        vector<SPair>* get_reg(int num);
        void print(ostream& os);
        ~Semantics(); 
        // Simplification functions
        void simplify_expressions();
        void simplify_conditions();  
};

ostream& operator<< (ostream& os, Semantics *s);

#endif
