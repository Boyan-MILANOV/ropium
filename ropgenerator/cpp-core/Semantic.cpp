#include "Semantic.hpp"
#include "Architecture.hpp"

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
vector<reg_pair>& Semantics::regs(){return _regs;}
vector<mem_pair>& Semantics::mem(){return _mem;}
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
        os << "\n-- Register " << curr_arch()->reg_name((*it).first) << endl; 
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
    vector<SPair>* new_pairs;
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        new_pairs = new vector<SPair>(); 
        for( pit = (*it).second->begin(); pit != (*it).second->end(); pit++ ){
            cout << "DEBUG, simplifying spair epxpr " << (*pit).expr() << endl;
            (*pit).cond()->simplify();
            // If the condition is false, ignore it ;) 
            if( (*pit).cond()->cond_ptr()->type() == COND_FALSE )
                continue;
            (*pit).expr()->simplify();
            new_pairs->push_back(*pit);
        }
        delete (*it).second;
        (*it).second = new_pairs;
    }
    
    for(mit = _mem.begin(); mit != _mem.end(); mit++ ){
        (*mit).first->simplify();
        new_pairs = new vector<SPair>(); 
        for( pit = (*mit).second->begin(); pit != (*mit).second->end(); pit++ ){
            (*pit).cond()->simplify();
            // If the condition is false, ignore it ;) 
            if( (*pit).cond()->cond_ptr()->type() == COND_FALSE )
                continue;
            (*pit).expr()->simplify();
            new_pairs->push_back(*pit);
        }
        delete (*mit).second;
        (*mit).second = new_pairs;
    }
}

// Tweaking 
void Semantics::tweak(bool simplify=true){
    vector<reg_pair>::iterator it;
    vector<mem_pair>::iterator mit;
    vector<SPair>::iterator pit; 
    pair<ExprObjectPtr,CondObjectPtr> epair;
    pair<CondObjectPtr,CondObjectPtr> cpair;
    CondObjectPtr tmp;
    vector<SPair> add, last;
    bool found_new;
    
    // Regs, expressions
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        last = *(it->second);
        do{
            add = vector<SPair>();
            found_new = false;
            for( pit = last.begin(); pit != last.end(); pit++ ){
                epair = (*pit).expr()->tweak();
                if( epair.first != nullptr ){
                    found_new = true;
                    if( simplify ){
                        epair.first->simplify();
                        epair.second->simplify();
                    }
                    add.push_back(SPair(epair.first, epair.second && pit->cond()));
                }
            }
            it->second->insert(it->second->end(), add.begin(), add.end());
            last = std::move(add);
        }while( found_new && simplify );
    }
    
    // Regs, conditions
    for(it = _regs.begin(); it != _regs.end(); it++ ){
        last = *(it->second);
        do{
            add = vector<SPair>();
            found_new = false;
            for( pit = last.begin(); pit != last.end(); pit++ ){
                cpair = (*pit).cond()->tweak();
                if( cpair.first != nullptr ){
                    found_new = true;
                    tmp  = cpair.first && cpair.second;
                    if( simplify ){
                        tmp->simplify();
                    }
                    add.push_back(SPair(pit->expr(), tmp ));
                }
            }
            it->second->insert(it->second->end(), add.begin(), add.end());
            last = std::move(add);
        }while( found_new && simplify );
    }
    
    // Memory, expressions
    for(mit = _mem.begin(); mit != _mem.end(); mit++ ){
        last = *(mit->second);
        do{
            add = vector<SPair>();
            found_new = false;
            for( pit = last.begin(); pit != last.end(); pit++ ){
                epair = (*pit).expr()->tweak(); 
                if( epair.first != nullptr ){
                    found_new = true;
                    if( simplify ){
                        epair.first->simplify();
                        epair.second->simplify();
                    }
                    add.push_back(SPair(epair.first, epair.second && pit->cond()));
                }
            }
            mit->second->insert(mit->second->end(), add.begin(), add.end());
            last = std::move(add);
        }while( found_new && simplify);
    }
    
    // Memory, conditions
    for(mit = _mem.begin(); mit != _mem.end(); mit++ ){
        last = *(mit->second);
        do{
            add = vector<SPair>();
            found_new = false;
            for( pit = last.begin(); pit != last.end(); pit++ ){
                cpair = (*pit).cond()->tweak(); 
                if( cpair.first != nullptr ){
                    found_new = true;
                    tmp = cpair.second && cpair.first;
                    if( simplify ){
                        tmp->simplify();
                    }
                    add.push_back(SPair(pit->expr(), tmp));
                }
            }
            mit->second->insert(mit->second->end(), add.begin(), add.end());
            last = std::move(add);
        }while( found_new && simplify);
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
        (*mit).first->filter();
        for( pit = (*mit).second->begin(); pit != (*mit).second->end(); pit++ ){
            (*pit).expr()->filter(); 
            (*pit).cond()->filter(); 
        }
    }
}
