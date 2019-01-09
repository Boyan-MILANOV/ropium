#include "Database.hpp"
#include <cstring>
#include <memory>
#include <utility>

int find_insert_index(vector<int> gadget_list, int gadget_num, vector<Gadget*> gadgets){
    int count= gadget_list.size(); 
    int first = 0; 
    int curr; 
    while(count > 0){
        curr = first;
        curr += count/2; 
        if( gadgets.at(gadget_list.at(curr))->lthan(gadgets.at(gadget_num))){
            first = ++curr; 
            count -= count/2 + 1;
        }else
            count = count/2; 
    }
    return first; 
}

/* CSTList */ 
CSTList::CSTList(){} 
void CSTList::add(cst_t val, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets){
    int insert_idx = find_insert_index(_values[val], gadget_num, gadgets);
    _values[val].insert(_values.at(val).begin()+insert_idx, gadget_num);
    _pre_conds[val].insert(_pre_conds.at(val).begin()+insert_idx, pre_cond);
    
}

/* REGList */ 
REGList::REGList(){
    std::memset(_values, 0, sizeof(CSTList*)*NB_REGS_MAX*COUNT_NB_BINOP);
}

void REGList::add(Binop op, int reg_num, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets){
    if( _values[op][reg_num] == nullptr )
        _values[op][reg_num] = new CSTList();
    _values[op][reg_num]->add(cst, gadget_num, pre_cond, gadgets);
}
 
REGList::~REGList(){
    for (int j = 0; j < COUNT_NB_BINOP; j++ )
        for( int i = 0; i < NB_REGS_MAX; i++)
            if( _values[i] != nullptr )
                delete _values[j][i];
}

/* MEMList */ 
MEMList::MEMList(){
    std::memset(_addresses, 0, sizeof(unordered_map<cst_t, unique_ptr<CSTList>>*)*NB_REGS_MAX);
}

/* For expressions of type mem + cst */ 
void MEMList::add(Binop op, int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets ){
    CSTList *t; 
    if( _addresses[op][addr_reg] == nullptr )
        _addresses[op][addr_reg] = new unordered_map<cst_t, unique_ptr<CSTList>>; 
    if( _addresses[op][addr_reg]->count(addr_cst) == 0 ){
        t = new CSTList(); 
        _addresses[op][addr_reg]->insert(std::make_pair(addr_cst, std::unique_ptr<CSTList>(t)));
    }
    _addresses[op][addr_reg]->at(addr_cst)->add(cst, gadget_num, pre_cond, gadgets);
}

MEMList::~MEMList(){
    for( int j= 0; j < COUNT_NB_BINOP; j++) 
        for( int i = 0; i < NB_REGS_MAX; i++)
            if( _addresses[j][i] != nullptr )
                delete _addresses[j][i];
}


/* MEMDict */ 
template <class T> MEMDict<T>::MEMDict(){
    std::memset(_addresses, 0, sizeof(unordered_map<cst_t, unique_ptr<T>>*)*NB_REGS_MAX);
}

/* For expressions of type mem + cst */ 
template <class T> void MEMDict<T>::add_cst(int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets ){
    T* t;
    if( _addresses[addr_reg] == nullptr )
        _addresses[addr_reg] = new unordered_map<cst_t, unique_ptr<T>>; 
    if( _addresses[addr_reg]->count(addr_cst) == 0 ){
        t = new T(); 
        _addresses[addr_reg]->insert(std::make_pair(addr_cst, std::unique_ptr<T>(t)));
    }
    t->add(cst, gadget_num, pre_cond, gadgets);
}

/* To store mem <- reg */ 
template <class T> void MEMDict<T>::add_reg(int addr_reg, cst_t addr_cst, int reg, cst_t cst, Binop op, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets ){
    T* t;
    if( _addresses[addr_reg] == nullptr )
        _addresses[addr_reg] = new unordered_map<cst_t, unique_ptr<T>>; 
    if( _addresses[addr_reg].count(addr_cst) == 0 ){
        t = new T(); 
        _addresses[addr_reg]->insert(std::make_pair(addr_cst, std::unique_ptr<T>(t)));
    }
    t->add(op, reg, cst, gadget_num, pre_cond, gadgets);
}

/* To store mem <- mem */ 
template <class T> void MEMDict<T>::add_mem(int addr_reg, cst_t addr_cst, int mem_reg, cst_t mem_cst, cst_t cst, Binop op, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets ){
    T* t;
    if( _addresses[addr_reg] == nullptr )
        _addresses[addr_reg] = new unordered_map<cst_t, unique_ptr<T>>; 
    if( _addresses[addr_reg].count(addr_cst) == 0 ){
        t = new T(); 
        _addresses[addr_reg]->insert(std::make_pair(addr_cst, std::unique_ptr<T>(t)));
    }
    t->add(op, mem_reg, mem_cst, cst, gadget_num, pre_cond, gadgets);
}

template <class T> MEMDict<T>::~MEMDict(){
    for( int i = 0; i < NB_REGS_MAX; i++)
        if( _addresses[i] != nullptr )
            delete _addresses[i];
}

// TODO Implement Database class 
