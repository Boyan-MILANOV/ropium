#include "Semantic.hpp"

// SPair
SPair::SPair(ExprObjectPtr e, CondObjectPtr c): _expr(e), _cond(c){};
ExprObjectPtr SPair::expr(){return _expr;}
CondObjectPtr SPair::cond(){return _cond;}

// Semantics 
Semantics::Semantics(){
        _regs = vector<reg_pair>();
        _mem = vector<mem_pair>();
}
void Semantics::add_reg(int num, vector<class SPair>pairs){
    _regs.push_back(make_pair(num, pairs));
}
void Semantics::add_mem(ExprObjectPtr addr, vector<class SPair>pairs){
    _mem.push_back(make_pair(addr, pairs));
}
vector<reg_pair> Semantics::regs(){return _regs;}
vector<mem_pair> Semantics::mem(){return _mem;}

 

