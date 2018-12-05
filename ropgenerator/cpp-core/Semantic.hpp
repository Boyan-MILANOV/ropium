#ifndef SEMANTIC_H
#define SEMANTIC_H

#include <list>
#include "Expression.hpp"
#include "Condition.hpp"

using namespace std; 

class SPair{
    ExprObjectPtr _expr;
    CondObjectPtr _cond; 
    public: 
        SPair(ExprObjectPtr e, CondObjectPtr c);
        ExprObjectPtr expr();
        CondObjectPtr cond(); 
};

using reg_tuple=tuple<int, std::list<class SPair>>;
using mem_tuple=tuple<ExprObjectPtr, list<class SPair>>;

class Semantics{
    list<reg_tuple> _regs;
    list<mem_tuple> _mem; 
    public: 
        Semantics();
        void add_reg(int num, list<class SPair>pairs);
        void add_mem(ExprObjectPtr addr, list<class SPair>pairs);
        list<reg_tuple> regs();
        list<mem_tuple> mem(); 
};

#endif
