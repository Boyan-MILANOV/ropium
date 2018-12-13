#include "Semantic.hpp"

// SPair
SPair::SPair(ExprObjectPtr e, CondObjectPtr c): _expr(e), _cond(c){};
ExprObjectPtr SPair::expr(){return _expr;}
CondObjectPtr SPair::cond(){return _cond;}
void SPair::set_cond(CondObjectPtr cond){ _cond = cond; }
void SPair::print(ostream& os){
    os << "\n\tExpr: " << _expr; 
    os << "\n\tCond: " << _cond << endl; 
}

// Semantics 
Semantics::Semantics(){
        _regs = vector<reg_pair>();
        _mem = vector<mem_pair>();
}
void Semantics::add_reg(int num, vector<SPair> *pairs){
    _regs.push_back(make_pair(num, pairs));
}
void Semantics::add_mem(ExprObjectPtr addr, vector<SPair> *pairs){
    _mem.push_back(make_pair(addr, pairs));
}
vector<reg_pair> Semantics::regs(){return _regs;}
vector<mem_pair> Semantics::mem(){return _mem;}

void Semantics::print(ostream& os){
    vector<reg_pair>::iterator it; 
    vector<SPair>::iterator pit; 
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        os << "Register r" << (*it).first; 
        for( pit = (*it).second->begin(); pit != (*it).second->end(); pit++ )
            (*pit).print(os);
    }
    os << "Memory:";
    os << "\nNOT IMPLEMENTED\n"; // TODO 
 }

ostream& operator<< (ostream& os, Semantics s){
    s.print(os); 
    return os; 
}
