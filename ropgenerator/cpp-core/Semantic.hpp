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

using reg_tuple=tuple<int, vector<class SPair>>;
using mem_tuple=tuple<ExprObjectPtr, vector<class SPair>>;

class Semantics{
    vector<reg_tuple> _regs;
    vector<mem_tuple> _mem; 
    public: 
        Semantics();
        void add_reg(int num, vector<class SPair>pairs);
        void add_mem(ExprObjectPtr addr, vector<class SPair>pairs);
        vector<reg_tuple> regs();
        vector<mem_tuple> mem(); 
};

#endif
