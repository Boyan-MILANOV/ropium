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
};

using reg_pair=pair<int, vector<class SPair>>;
using mem_pair=pair<ExprObjectPtr, vector<class SPair>>;

class Semantics{
    vector<reg_pair> _regs;
    vector<mem_pair> _mem; 
    public: 
        Semantics();
        void add_reg(int num, vector<class SPair>pairs);
        void add_mem(ExprObjectPtr addr, vector<class SPair>pairs);
        vector<reg_pair> regs();
        vector<mem_pair> mem(); 
};

#endif
