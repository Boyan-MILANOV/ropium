#include "Semantic.hpp"

// SPair
SPair::SPair(ExprObjectPtr e, CondObjectPtr c): _expr(e), _cond(c){};
ExprObjectPtr SPair::expr(){return _expr;}
CondObjectPtr SPair::cond(){return _cond;}
ExprPtr SPair::expr_ptr(){return _expr->expr_ptr();}
CondPtr SPair::cond_ptr(){return _cond->cond_ptr();}

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
vector<SPair>* Semantics::get_reg(int num){
    vector<reg_pair>::iterator it;
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        if( (*it).first == num )
            return (*it).second; 
    } 
    return nullptr; 
}

void Semantics::print(ostream& os){
    vector<reg_pair>::iterator it;
    vector<mem_pair>::iterator mit; 
    vector<SPair>::iterator pit; 
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        os << "\n-- Register r" << (*it).first << endl; 
        for( pit = (*it).second->begin(); pit != (*it).second->end(); pit++ )
            (*pit).print(os);
    }
    
    for(mit = _mem.begin(); mit != _mem.end(); mit++ ){
        os << "\n-- Memory [ " << (*mit).first << " ]" << endl; 
        for( pit = (*mit).second->begin(); pit != (*mit).second->end(); pit++ )
            (*pit).print(os);
    }
}

ostream& operator<< (ostream& os, Semantics* s){
    s->print(os); 
    return os; 
}

Semantics::~Semantics(){
    vector<reg_pair>::iterator it;
    vector<mem_pair>::iterator mit;
    
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        delete (*it).second; 
        (*it).second = nullptr; 
    }
    
    for(mit = _mem.begin(); mit != _mem.end(); mit++ ){
        delete (*mit).second;
        (*mit).second = nullptr; 
    }
}

// Simplifications 
void Semantics::simplify(){
    vector<reg_pair>::iterator it;
    vector<mem_pair>::iterator mit;
    vector<SPair>::iterator pit; 
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        for( pit = (*it).second->begin(); pit != (*it).second->end(); pit++ ){
            (*pit).expr()->simplify(); 
            (*pit).cond()->simplify(); 
        }
    }
    
    for(mit = _mem.begin(); mit != _mem.end(); mit++ ){
        for( pit = (*mit).second->begin(); pit != (*mit).second->end(); pit++ ){
            (*pit).expr()->simplify(); 
            (*pit).cond()->simplify();
        }
    }
}

// Filtering
void Semantics::filter(){
    vector<reg_pair>::iterator it;
    vector<mem_pair>::iterator mit;
    vector<SPair>::iterator pit; 
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        for( pit = (*it).second->begin(); pit != (*it).second->end(); pit++ ){
            (*pit).expr()->filter(); 
            (*pit).cond()->filter();
        }
    }
    
    for(mit = _mem.begin(); mit != _mem.end(); mit++ ){
        for( pit = (*mit).second->begin(); pit != (*mit).second->end(); pit++ ){
            (*pit).expr()->filter(); 
            (*pit).cond()->filter(); 
        }
    }
}
