#include "Database.hpp"
#include "ChainingEngine.hpp"
#include <cstring>
#include <memory>
#include <utility>

int find_insert_index(vector<int>& gadget_list, int gadget_num, vector<shared_ptr<Gadget>>& gadgets){
    int count= gadget_list.size(); 
    int first = 0; 
    int curr;
    while(count > 0){
        curr = first;
        curr += count/2;
        if( gadgets.at(gadget_list.at(curr))->lthan(gadgets.at(gadget_num))){
            first = curr+1;
            count -= count/2 + 1;
        }else{
            count = count/2;
        }
    }
    return first; 
}

void SimpleGadgetList::add(int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets){
	int insert_idx = find_insert_index(_gadgets, gadget_num, gadgets);
    _gadgets.insert(_gadgets.begin()+insert_idx, gadget_num);
    _pre_conds.insert(_pre_conds.begin()+insert_idx, pre_cond);
}
vector<int> SimpleGadgetList::find(Constraint* constr, Assertion *assert, int n, FailRecord *fail_record){
	vector<int> res; 
    shared_ptr<Gadget> g; 
    CondObjectPtr constr_cond, all_conds;
    ConstrEval eval;
    
    
    for( unsigned int i = 0; i < _gadgets.size() &&  res.size() < n; i++){
        
        
        g = gadget_db()->get(_gadgets.at(i));        
        // Verify constraint 
        std::tie(eval, constr_cond) = constr->verify(g, fail_record);
        if( eval == EVAL_VALID || eval == EVAL_MAYBE){
            /* Check with assertion to verify
                - remaining constraint
                - semantic pre_conditions
                - memory accesses pre-conditions
            */
            all_conds = constr_cond && _pre_conds.at(i) && g->mem_pre_cond();
            if( assert->validate(all_conds) ){
                res.push_back(_gadgets.at(i));
            }
        }
    }
    return res;
}



/* CSTList */
CSTList::CSTList(){} 
void CSTList::add(cst_t val, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets){
    int insert_idx = find_insert_index(_values[val], gadget_num, gadgets);
    _values[val].insert(_values[val].begin()+insert_idx, gadget_num);
    _pre_conds[val].insert(_pre_conds[val].begin()+insert_idx, pre_cond);
}
vector<int> CSTList::find(cst_t val, Constraint* constr, Assertion* assert, int n=1, FailRecord* fail_record=nullptr){
    vector<int> res; 
    shared_ptr<Gadget> g; 
    CondObjectPtr constr_cond, all_conds;
    ConstrEval eval;
    
    if( _values.count(val) == 0)
        return res; 
    for( unsigned int i = 0; i < _values.at(val).size() &&  res.size() < n; i++){
        g = gadget_db()->get(_values[val].at(i));        
        // Verify constraint 
        std::tie(eval, constr_cond) = constr->verify(g, fail_record);
        if( eval == EVAL_VALID || eval == EVAL_MAYBE){
            /* Check with assertion to verify
                - remaining constraint
                - semantic pre_conditions
                - memory accesses pre-conditions
            */
            all_conds = constr_cond && _pre_conds[val].at(i) && g->mem_pre_cond();
            if( assert->validate(all_conds) ){
                res.push_back(_values[val].at(i));
            }
        }
    }
    return res;
}


/* REGList */ 
REGList::REGList(){
    std::memset(_values, 0, sizeof(CSTList*)*NB_REGS_MAX*COUNT_NB_BINOP);
}

void REGList::add(Binop op, int reg_num, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets){
    if( _values[op][reg_num] == nullptr )
        _values[op][reg_num] = new CSTList();
    _values[op][reg_num]->add(cst, gadget_num, pre_cond, gadgets);
}
vector<int> REGList::find(Binop op, int reg_num, cst_t cst, Constraint* constr, Assertion* assert, int n=1, FailRecord* fail_record=nullptr){
    if( _values[op][reg_num] == nullptr )
        return vector<int>();
    return _values[op][reg_num]->find(cst, constr, assert, n, fail_record);
}
vector<pair<AssignArg, vector<int>>>* REGList::get_possible(Constraint* constr, Assertion* assert, int n, FailRecord* fail_record, int assign_reg){
    int tmp_reg;
    int tmp_op;
    vector<int> tmp_gadgets;
    vector<int>::iterator git;
    unordered_map<cst_t, vector<int>>::iterator it;
    vector<pair<AssignArg, vector<int>>>* res = new vector<pair<AssignArg, vector<int>>>();
    
    for( tmp_op = 0; tmp_op < COUNT_NB_BINOP; tmp_op++){
        /* For each register */ 
        for( tmp_reg = 0; tmp_reg < NB_REGS_MAX; tmp_reg++){
            /* Check if one register requested in particular */ 
            if( assign_reg != -1 && assign_reg != tmp_reg )
                continue;
            /* Check if there are gadgets */
            if( _values[tmp_op][tmp_reg] == nullptr )
                continue;
            /* Get gadgets for each constant */
            for( it = _values[tmp_op][tmp_reg]->_values.begin(); it != _values[tmp_op][tmp_reg]->_values.end(); it++ ){
                tmp_gadgets = _values[tmp_op][tmp_reg]->find(it->first, constr, assert, n, fail_record);
                if( !tmp_gadgets.empty() ){
                    res->push_back(make_pair(AssignArg(ASSIGN_REG_BINOP_CST, tmp_reg, (Binop)tmp_op, it->first), tmp_gadgets));
                }
            }
        }
    }
    return res;
}

REGList::~REGList(){
    for (int j = 0; j < COUNT_NB_BINOP; j++ )
        for( int i = 0; i < NB_REGS_MAX; i++)
            if( _values[i] != nullptr )
                delete _values[j][i];
}

/* MEMList */ 
MEMList::MEMList(){
    std::memset(_addresses, 0, sizeof(unordered_map<cst_t, shared_ptr<CSTList>>*)*NB_REGS_MAX*COUNT_NB_BINOP);
}

/* For expressions of type mem + cst */ 
void MEMList::add(Binop op, int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets ){
    CSTList *t;    
    if( _addresses[op][addr_reg] == nullptr )
        _addresses[op][addr_reg] = new unordered_map<cst_t, shared_ptr<CSTList>>; 
    if( _addresses[op][addr_reg]->count(addr_cst) == 0){
        t = new CSTList(); 
        _addresses[op][addr_reg]->insert(make_pair(addr_cst, shared_ptr<CSTList>(t)));
    }
    _addresses[op][addr_reg]->at(addr_cst)->add(cst, gadget_num, pre_cond, gadgets);
}

vector<int> MEMList::find(Binop op, int addr_reg, cst_t addr_cst, cst_t cst, Constraint* constr, Assertion* assert, int n=1, FailRecord* fail_record=nullptr){
    if( _addresses[op][addr_reg] == nullptr )
        return vector<int>();
    else if( _addresses[op][addr_reg]->count(addr_cst) == 0 )
        return vector<int>();
    else
        return _addresses[op][addr_reg]->at(addr_cst)->find(cst, constr, assert, n, fail_record);
}

vector<pair<AssignArg, vector<int>>>* MEMList::get_possible(Constraint*c, Assertion *a, int n, FailRecord* fail_record, int addr_reg){
	int tmp_addr_reg;
	int tmp_op;
	vector<pair<AssignArg, vector<int>>> * res = new vector<pair<AssignArg, vector<int>>>();
	Assertion* tmp_assertion;
	unordered_map<cst_t, shared_ptr<CSTList>>::iterator it;
	vector<int> tmp_gadgets; 
	cst_t cst_fixed = 0; // This the cst2 in mem(reg op cst) + cst2
	
	for( tmp_addr_reg =  0; tmp_addr_reg < curr_arch()->nb_regs(); tmp_addr_reg++ ){
		/* Test if requested reg */
		if( addr_reg != -1 && addr_reg != tmp_addr_reg )
			continue;
		/* Add assertion to say that read is valid */
		tmp_assertion = a->copy();
		tmp_assertion->add(new AssertValidRead(tmp_addr_reg), true);
		/* Search */ 
		for( tmp_op = 0; tmp_op < COUNT_NB_BINOP; tmp_op++){
			/* Test if no gadgets */ 
			if( _addresses[tmp_op][tmp_addr_reg] == nullptr )
				continue;
			for( it = _addresses[tmp_op][tmp_addr_reg]->begin(); it != _addresses[tmp_op][tmp_addr_reg]->end(); it++ ){
				tmp_gadgets = _addresses[tmp_op][tmp_addr_reg]->at(it->first)->find(cst_fixed, c, tmp_assertion, n, fail_record);
				if( !tmp_gadgets.empty()){
					res->push_back(make_pair(AssignArg(ASSIGN_MEM_BINOP_CST, tmp_addr_reg, (Binop)tmp_op, it->first, cst_fixed), tmp_gadgets));
				}
			}
		}
		delete tmp_assertion; 
	}
	
	/* Return res */ 
	return res;
}

MEMList::~MEMList(){
    for( int j= 0; j < COUNT_NB_BINOP; j++) 
        for( int i = 0; i < NB_REGS_MAX; i++)
            if( _addresses[j][i] != nullptr )
                delete _addresses[j][i];
}

/* MEMDict */ 
template <class T> MEMDict<T>::MEMDict(){
    std::memset(_addresses, 0, sizeof(unordered_map<cst_t, unique_ptr<T>>*)*NB_REGS_MAX*COUNT_NB_BINOP);
}

/* For expressions of type mem + cst */ 
template <class T> void MEMDict<T>::add_cst(Binop addr_op, int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets ){
    T* t;
    if( _addresses[addr_op][addr_reg] == nullptr )
        _addresses[addr_op][addr_reg] = new unordered_map<cst_t, unique_ptr<T>>; 
    if( _addresses[addr_op][addr_reg]->count(addr_cst) == 0 ){
        t = new T(); 
        _addresses[addr_op][addr_reg]->insert(std::make_pair(addr_cst, std::unique_ptr<T>(t)));
    }
   _addresses[addr_op][addr_reg]->at(addr_cst)->add(cst, gadget_num, pre_cond, gadgets);
}

/* To store mem <- reg */ 
template <class T> void MEMDict<T>::add_reg(Binop addr_op, int addr_reg, cst_t addr_cst, int reg, cst_t cst, Binop op, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets ){
    T* t;
    if( _addresses[addr_op][addr_reg] == nullptr )
        _addresses[addr_op][addr_reg] = new unordered_map<cst_t, unique_ptr<T>>; 
    if( _addresses[addr_op][addr_reg]->count(addr_cst) == 0 ){
        t = new T(); 
        _addresses[addr_op][addr_reg]->insert(std::make_pair(addr_cst, std::unique_ptr<T>(t)));
    }
    _addresses[addr_op][addr_reg]->at(addr_cst)->add(op, reg, cst, gadget_num, pre_cond, gadgets);
}

/* To store mem <- mem */ 
template <class T> void MEMDict<T>::add_mem(Binop addr_op, int addr_reg, cst_t addr_cst, int mem_reg, cst_t mem_cst, cst_t cst, 
                                            Binop op, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets ){
    T* t;
    if( _addresses[addr_op][addr_reg] == nullptr )
        _addresses[addr_op][addr_reg] = new unordered_map<cst_t, unique_ptr<T>>; 
    if( _addresses[addr_op][addr_reg]->count(addr_cst) == 0 ){
        t = new T(); 
        _addresses[addr_op][addr_reg]->insert(std::make_pair(addr_cst, std::unique_ptr<T>(t)));
    }
    _addresses[addr_op][addr_reg]->at(addr_cst)->add(op, mem_reg, mem_cst, cst, gadget_num, pre_cond, gadgets);
}

template <class T> vector<int> MEMDict<T>::find_cst(Binop addr_op, int addr_reg, cst_t addr_cst, cst_t cst, 
                                            Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    if( _addresses[addr_op][addr_reg] == nullptr || _addresses[addr_op][addr_reg]->count(addr_cst) == 0 )
        return vector<int>();
    else
        return _addresses[addr_op][addr_reg]->at(addr_cst)->find(cst, c, a, n, fail_record);
}

template <class T> vector<int> MEMDict<T>::find_reg(Binop addr_op, int addr_reg, cst_t addr_cst, int reg, cst_t cst, 
                                            Binop op, Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    if( _addresses[addr_op][addr_reg] == nullptr || _addresses[addr_op][addr_reg]->count(addr_cst) == 0 )
        return vector<int>();
    else
        return _addresses[addr_op][addr_reg]->at(addr_cst)->find(op, reg, cst, c, a, n, fail_record);
}

template <class T> vector<int> MEMDict<T>::find_mem(Binop addr_op, int addr_reg, cst_t addr_cst, int src_reg, 
                                            cst_t src_cst, cst_t cst, Binop op, Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    if( _addresses[addr_op][addr_reg] == nullptr || _addresses[addr_op][addr_reg]->count(addr_cst) == 0 )
        return vector<int>();
    else
        return _addresses[addr_op][addr_reg]->at(addr_cst)->find(op, src_reg, src_cst, cst, c, a, n, fail_record);
}

/* Find possible gadgets of the form mem(reg op cst) <- reg op cst 
 * for each case, take at max 'n' gadgets
 * If dest_addr_reg or assign_reg is set then return only gadgets using those registers 
 * 
 * !! To be used only for mem <- reg binop cst, because explicit instanciation of template param T */ 
template <class T> vector<tuple<DestArg, AssignArg, vector<int>>>* MEMDict<T>::get_possible_stores_reg(Constraint*c, Assertion*a, int n, FailRecord* fail_record, int dest_addr_reg, int assign_reg){
    unordered_map<cst_t, unique_ptr<REGList>>::iterator it;
    int tmp_addr_reg;
    int tmp_op;
    vector<tuple<DestArg, AssignArg, vector<int>>>* res = new vector<tuple<DestArg, AssignArg, vector<int>>>();
    vector<pair<AssignArg, vector<int>>>* reglist_res = nullptr;
    vector<pair<AssignArg, vector<int>>>::iterator it2;
    Assertion* tmp_assertion = nullptr;
    
    for( tmp_op = 0; tmp_op < COUNT_NB_BINOP; tmp_op++){
        for( tmp_addr_reg = 0; tmp_addr_reg < curr_arch()->nb_regs(); tmp_addr_reg++ ){
            /* If no gadgets here, continue */ 
            if( _addresses[tmp_op][tmp_addr_reg] == nullptr )
                continue;
            /* If dest_addr_reg is specified check if it is the right one */
            if( dest_addr_reg != -1 && dest_addr_reg != tmp_addr_reg)
                continue;
            /* Don't use sp nor ip if not specified */
            if( dest_addr_reg != curr_arch()->sp() && tmp_addr_reg == curr_arch()->sp())
				continue;
			if( dest_addr_reg != curr_arch()->ip() && tmp_addr_reg == curr_arch()->ip())
				continue;
            /* Add an assertion to say that this memory write is correct */ 
            tmp_assertion = a->copy();
            tmp_assertion->add(new AssertValidWrite(tmp_addr_reg), true);
            tmp_assertion->add(new AssertRegsNoOverlap(tmp_addr_reg, curr_arch()->sp()), true);
            /* Search suitable gadgets */
            for( it = _addresses[tmp_op][tmp_addr_reg]->begin(); it != _addresses[tmp_op][tmp_addr_reg]->end(); it++ ){
                /* Iterator through the REGList corresponding to this memory store */ 
                reglist_res = _addresses[tmp_op][tmp_addr_reg]->at(it->first)->get_possible(c, tmp_assertion, n, fail_record, assign_reg);
                if( !reglist_res->empty() ){
                    for( it2 = reglist_res->begin(); it2 != reglist_res->end(); it2++){
                        res->push_back(make_tuple(DestArg(DST_MEM, tmp_addr_reg, (Binop)tmp_op, it->first), it2->first, it2->second));
                    }
                }
                delete reglist_res;
            }
            delete tmp_assertion;
        }
    }
    return res;
}

template <class T> MEMDict<T>::~MEMDict(){
    for( int j=0; j < COUNT_NB_BINOP; j++)
        for( int i = 0; i < NB_REGS_MAX; i++)
            delete _addresses[j][i];
}

/* Database */ 
Database::Database():_entries_count(0){
    std::memset( _cst_to_reg, 0, sizeof(CSTList*)*NB_REGS_MAX);
    std::memset( _reg_binop_cst_to_reg, 0, sizeof(REGList*)*NB_REGS_MAX);
    std::memset( _mem_binop_cst_to_reg, 0, sizeof(MEMList*)*NB_REGS_MAX);
}
 
int Database::entries_count(){
    return _entries_count;
} 
 
int Database::add(shared_ptr<Gadget> g){
    ExprPtr tmp; 
    vector<reg_pair>::iterator rit; 
    vector<mem_pair>::iterator mit; 
    vector<SPair>::iterator sit; 
    int reg, addr_reg;
    cst_t addr_cst;  
    Binop addr_op; 
    int num = _gadgets.size(); 
    /* Add gadget to the list */ 
    _gadgets.push_back(g);
    
    
    /* Check for special gadgets */ 
    if( g->type() == INT80 ){
		_int80.add(num, NewCondTrue(), _gadgets);
		_entries_count++;
		return num;
	}else if( g->type() == SYSCALL ){
		_syscall.add(num, NewCondTrue(), _gadgets);
		_entries_count++;
		return num;
	}
    
    /* Get semantics for ... -> reg */ 
    for( rit = g->semantics()->regs().begin(); rit != g->semantics()->regs().end(); rit++){
        reg = (*rit).first;
        /* Get possible values */ 
        for( sit = (*rit).second->begin(); sit != (*rit).second->end(); sit++ ){
            // cst -> reg ? 
            if( sit->expr_ptr()->type() == EXPR_CST ){
                if( _cst_to_reg[reg] == nullptr )
                    _cst_to_reg[reg] = new CSTList(); 
                _cst_to_reg[reg]->add(sit->expr_ptr()->value(), num, sit->cond(), _gadgets);
                _entries_count++;
            } // reg -> reg ? 
            else if( sit->expr_ptr()->type() == EXPR_REG ){
                if( _reg_binop_cst_to_reg[reg] == nullptr )
                    _reg_binop_cst_to_reg[reg] = new REGList();
                _reg_binop_cst_to_reg[reg]->add(OP_ADD,sit->expr_ptr()->num(), 0, num, sit->cond(), _gadgets);
                _entries_count++;
            } // X binop cst to reg 
            else if( sit->expr_ptr()->type() == EXPR_BINOP ){
                // reg binop cst -> reg
                /* We don't check if left is the constant because expressions should be 
                 * canonized */ 
                if( sit->expr_ptr()->right_expr_ptr()->type() == EXPR_CST &&
                    sit->expr_ptr()->left_expr_ptr()->type() == EXPR_REG){
                    if( _reg_binop_cst_to_reg[reg] == nullptr )
                        _reg_binop_cst_to_reg[reg] = new REGList();
                    _reg_binop_cst_to_reg[reg]->add(
                        sit->expr_ptr()->binop(), 
                        sit->expr_ptr()->left_expr_ptr()->num(),
                        sit->expr_ptr()->right_expr_ptr()->value(),
                        num, sit->cond(), _gadgets
                        );
                    _entries_count++;
                } // mem binop cst -> reg 
                else if( sit->expr_ptr()->left_expr_ptr()->type() == EXPR_MEM &&
                         sit->expr_ptr()->right_expr_ptr()->type() == EXPR_CST &&
                         sit->expr_ptr()->binop() == OP_ADD){
                    // Check if mem is a binop itself ;)
                    tmp =  sit->expr_ptr()->left_expr_ptr()->addr_expr_ptr();
                    if( tmp->type() == EXPR_REG){
                        // only reg
                        if( _mem_binop_cst_to_reg[reg] == nullptr){
                            _mem_binop_cst_to_reg[reg] = new MEMList(); 
                        }
                        _mem_binop_cst_to_reg[reg]->add(
                            OP_ADD,
                            tmp->num(),
                            0,
                            sit->expr_ptr()->right_expr_ptr()->value(),
                            num, sit->cond(), _gadgets
                            );
                        _entries_count++;
                    }else if( tmp->type() == EXPR_BINOP &&
                        tmp->right_expr_ptr()->type() == EXPR_CST &&
                        tmp->left_expr_ptr()->type() == EXPR_REG){
                        // reg binop cst
                        if( _mem_binop_cst_to_reg[reg] == nullptr){
                            _mem_binop_cst_to_reg[reg] = new MEMList(); 
                        }
                        _mem_binop_cst_to_reg[reg]->add(
                            tmp->binop(),
                            tmp->left_expr_ptr()->num(),
                            tmp->right_expr_ptr()->value(),
                            sit->expr_ptr()->right_expr_ptr()->value(),
                            num, sit->cond(), _gadgets
                            );
                        _entries_count++;
                    }
                }
                // mem -> reg ? 
            }else if( sit->expr_ptr()->type() == EXPR_MEM ){
                // Check if mem is a binop itself ;)
                tmp =  sit->expr_ptr()->addr_expr_ptr();
                if( tmp->type() == EXPR_REG){
                    // only reg
                    if( _mem_binop_cst_to_reg[reg] == nullptr){
                        _mem_binop_cst_to_reg[reg] = new MEMList(); 
                    }
                    _mem_binop_cst_to_reg[reg]->add(
                        OP_ADD,
                        tmp->num(),
                        0,
                        0,
                        num, sit->cond(), _gadgets
                        );
                    _entries_count++;
                }else if( tmp->type() == EXPR_BINOP &&
                    tmp->right_expr_ptr()->type() == EXPR_CST &&
                    tmp->left_expr_ptr()->type() == EXPR_REG){
                    // reg binop cst
                    if( _mem_binop_cst_to_reg[reg] == nullptr){
                        _mem_binop_cst_to_reg[reg] = new MEMList(); 
                    }
                    _mem_binop_cst_to_reg[reg]->add(
                        tmp->binop(),
                        tmp->left_expr_ptr()->num(),
                        tmp->right_expr_ptr()->value(),
                        0,
                        num, sit->cond(), _gadgets
                        );
                    _entries_count++;
                }
            } 
        }
    }
    
    /* Get semantics for ... -> mem */ 
    /* Note : This is very similar to the code above for registers, but I keep it 
     * duplicated because the two cases might differ in the future */ 
    for( mit = g->semantics()->mem().begin(); mit != g->semantics()->mem().end(); mit++){
        /* Get address where we write */
        tmp = (*mit).first->expr_ptr();
        if( tmp->type() == EXPR_REG ){
            addr_reg = tmp->num(); 
            addr_cst = 0; 
            addr_op = OP_ADD; 
        }else if(   tmp->type() == EXPR_BINOP &&
                    tmp->right_expr_ptr()->type() == EXPR_CST &&
                    tmp->left_expr_ptr()->type() == EXPR_REG){
            addr_reg = tmp->left_expr_ptr()->num(); 
            addr_cst = tmp->right_expr_ptr()->value();
            addr_op = tmp->binop(); 
        }else // Not supported for memory addresses 
            continue;
            
        /* Get possible values */ 
        for( sit = (*mit).second->begin(); sit != (*mit).second->end(); sit++ ){
            // cst -> mem ? 
            if( sit->expr_ptr()->type() == EXPR_CST ){
                _cst_to_mem.add_cst(addr_op, addr_reg, addr_cst, sit->expr_ptr()->value(), num, sit->cond(), _gadgets);
                _entries_count++;
            } // reg -> mem ? 
            else if( sit->expr_ptr()->type() == EXPR_REG ){
                _reg_binop_cst_to_mem.add_reg(addr_op, addr_reg, addr_cst,sit->expr_ptr()->num(), 0, OP_ADD, num, sit->cond(), _gadgets);
                _entries_count++;
            } 
            else if( sit->expr_ptr()->type() == EXPR_BINOP ){
                // reg binop cst -> mem
                /* We don't check if left is the constant because expressions should be 
                 * canonized */ 
                if( sit->expr_ptr()->left_expr_ptr()->type() == EXPR_REG &&
                    sit->expr_ptr()->right_expr_ptr()->type() == EXPR_CST){
                    _reg_binop_cst_to_mem.add_reg( addr_op, addr_reg, addr_cst,  
                        sit->expr_ptr()->left_expr_ptr()->num(),
                        sit->expr_ptr()->right_expr_ptr()->value(),
                        sit->expr_ptr()->binop(),
                        num, sit->cond(), _gadgets
                        );
                    _entries_count++;
                } // mem binop cst -> mem
                else if( sit->expr_ptr()->left_expr_ptr()->type() == EXPR_MEM &&
                         sit->expr_ptr()->right_expr_ptr()->type() == EXPR_CST &&
                         sit->expr_ptr()->binop() == OP_ADD){
                    // Check if mem is a binop itself ;)
                    tmp =  sit->expr_ptr()->left_expr_ptr()->addr_expr_ptr();
                    if( tmp->type() == EXPR_REG ){
                        _mem_binop_cst_to_mem.add_mem(OP_ADD, addr_reg, addr_cst, 
                            tmp->num(),
                            0,
                            sit->expr_ptr()->right_expr_ptr()->value(),
                            OP_ADD,
                            num, sit->cond(), _gadgets
                            );
                        _entries_count++;
                    }else if( tmp->type() == EXPR_BINOP &&
                        tmp->left_expr_ptr()->type() == EXPR_REG &&
                        tmp->right_expr_ptr()->type() == EXPR_CST){

                        _mem_binop_cst_to_mem.add_mem(addr_op, addr_reg, addr_cst, 
                            tmp->left_expr_ptr()->num(),
                            tmp->right_expr_ptr()->value(),
                            sit->expr_ptr()->right_expr_ptr()->value(),
                            tmp->binop(),
                            num, sit->cond(), _gadgets
                            );
                        _entries_count++;
                    }
                }
            }else if( sit->expr_ptr()->type() == EXPR_MEM ){
                // Check if mem is a binop itself ;)
                tmp =  sit->expr_ptr()->addr_expr_ptr();
                if( tmp->type() == EXPR_REG ){
                    _mem_binop_cst_to_mem.add_mem(OP_ADD, addr_reg, addr_cst, 
                        tmp->num(),
                        0,
                        0,
                        OP_ADD,
                        num, sit->cond(), _gadgets
                        );
                    _entries_count++;
                }else if( tmp->type() == EXPR_BINOP &&
                    tmp->left_expr_ptr()->type() == EXPR_REG &&
                    tmp->right_expr_ptr()->type() == EXPR_CST){

                    _mem_binop_cst_to_mem.add_mem(addr_op, addr_reg, addr_cst, 
                        tmp->left_expr_ptr()->num(),
                        tmp->right_expr_ptr()->value(),
                        0,
                        tmp->binop(),
                        num, sit->cond(), _gadgets
                        );
                    _entries_count++;
                }
                
            }
        }
    }
    return _gadgets.size()-1;
} 

shared_ptr<Gadget> Database::get(int num){
    return _gadgets.at(num); 
}

vector<int> Database::find_cst_to_reg(int reg_dest, cst_t cst, Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    if( _cst_to_reg[reg_dest] != nullptr )
        return _cst_to_reg[reg_dest]->find(cst, c, a, n, fail_record);
    else
        return vector<int>();
}

vector<int> Database::find_reg_binop_cst_to_reg(int reg_dest, Binop op, int reg, cst_t cst, Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    if( _reg_binop_cst_to_reg[reg_dest] != nullptr )
        return _reg_binop_cst_to_reg[reg_dest]->find(op, reg, cst, c, a, n, fail_record);
    else
        return vector<int>();
}

vector<int> Database::find_mem_binop_cst_to_reg(int reg_dest, Binop op, int addr_reg, cst_t addr_cst, cst_t cst, Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    if( _mem_binop_cst_to_reg[reg_dest] != nullptr )
        return _mem_binop_cst_to_reg[reg_dest]->find(op, addr_reg, addr_cst, cst, c, a, n, fail_record);
    else
        return vector<int>();
}

vector<int> Database::find_cst_to_mem(  Binop op_dest, int reg_dest, cst_t cst_dest, cst_t cst, 
                                        Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    return _cst_to_mem.find_cst(op_dest, reg_dest, cst_dest, cst, c, a, n, fail_record);

}
vector<int> Database::find_reg_binop_cst_to_mem(Binop op_dest, int reg_dest, cst_t cst_dest, Binop op, int reg,
                                    cst_t cst, Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    return _reg_binop_cst_to_mem.find_reg(op_dest, reg_dest, cst_dest, reg, cst, op, c, a, n, fail_record);
}

vector<int> Database::find_mem_binop_cst_to_mem(Binop op_dest, int reg_dest, cst_t cst_dest, Binop op, int addr_reg,
                                    cst_t addr_cst, cst_t cst, Constraint* c, Assertion* a, int n, FailRecord* fail_record){
    return _mem_binop_cst_to_mem.find_mem( op_dest, reg_dest, cst_dest, addr_reg, addr_cst, cst, op, c, a, n, fail_record);
}

vector<int> Database::find_syscall(Constraint *c, Assertion *a, int n, FailRecord* fail_record){
	return _syscall.find(c, a, n, fail_record);
}

vector<int> Database::find_int80(Constraint *c, Assertion *a, int n, FailRecord* fail_record){
	return _int80.find(c, a, n, fail_record);
}

/* More advanced functions */ 
vector<tuple<DestArg, AssignArg, vector<int>>>* Database::get_possible_stores_reg(Constraint*c, Assertion*a, int n, FailRecord* fail_record, int dest_addr_reg, int assign_reg){
    return _reg_binop_cst_to_mem.get_possible_stores_reg(c, a, n, fail_record, dest_addr_reg, assign_reg);
}

/* Find gadgets of the form reg <- mem(reg2 op cst)
 * n is the number of gadgets to return per case
 * 
 * If dest_reg and/or assign_addr_reg are set, return gadgets using 
 * only them 
 * */
vector<tuple<int, AssignArg, vector<int>>>* Database::get_possible_loads_reg(Constraint*c, Assertion *a, int n, FailRecord* fail_record, int dest_reg, int assign_addr_reg){
	int tmp_dest_reg;
	vector<tuple<int, AssignArg, vector<int>>>* res = new vector<tuple<int, AssignArg, vector<int>>>();
	vector<pair<AssignArg, vector<int>>>* tmp_possible; 
	vector<pair<AssignArg, vector<int>>>::iterator it;
	/* Go through all possible dest_reg */ 
	for( tmp_dest_reg = 0; tmp_dest_reg <= curr_arch()->nb_regs(); tmp_dest_reg++ ){
		/* If no gadgets here, continue */ 
		if( _mem_binop_cst_to_reg[tmp_dest_reg] == nullptr )
			continue;
		/* If dest_addr_reg is specified check if it is the right one */
		if( dest_reg != -1 && dest_reg != tmp_dest_reg)
			continue;
		/* Don't use sp nor ip if not specified */
		if( dest_reg != curr_arch()->sp() && tmp_dest_reg == curr_arch()->sp())
			continue;
		if( dest_reg != curr_arch()->ip() && tmp_dest_reg == curr_arch()->ip())
			continue;
		/* Get possible gadgets */ 
		tmp_possible = _mem_binop_cst_to_reg[tmp_dest_reg]->get_possible(c, a, n, fail_record, assign_addr_reg);
		for( it = tmp_possible->begin(); it != tmp_possible->end(); it++){
			res->push_back(make_tuple(tmp_dest_reg, it->first, it->second));
		}
		delete tmp_possible; tmp_possible = nullptr;
	}
	return res; 
}

/* Destructor */ 
Database::~Database(){
    for( int i = 0; i < NB_REGS_MAX; i++){
        delete _cst_to_reg[i]; 
        delete _reg_binop_cst_to_reg[i]; 
        delete _mem_binop_cst_to_reg[i]; 
    }
}



/* Global database variable to be used by ROPGenerator */ 
Database * g_gadget_db = nullptr; 
Database * gadget_db(){return g_gadget_db;}
bool init_gadget_db(){
    if( g_gadget_db != nullptr )
        delete g_gadget_db;
    return (g_gadget_db = new Database()) != nullptr;
}
