#include "Semantic.hpp"

// SPair
SPair::SPair(ExprObjectPtr e, CondObjectPtr c): _expr(e), _cond(c){};
ExprObjectPtr SPair::expr(){return _expr;}
CondObjectPtr SPair::cond(){return _cond;}

// Semantics 
Semantics::Semantics(){
        _regs = list<reg_tuple>();
        _mem = list<mem_tuple>();
}
void Semantics::add_reg(int num, list<class SPair>pairs){
    _regs.push_front(make_tuple(num, pairs));
}
void Semantics::add_mem(ExprObjectPtr addr, list<class SPair>pairs){
    _mem.push_front(make_tuple(addr, pairs));
}
list<reg_tuple> Semantics::regs(){return _regs;}
list<mem_tuple> Semantics::mem(){return _mem;}

 

