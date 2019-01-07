#include "Database.hpp"
#include <cstring>

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
void CSTList::add(cst_t val, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets){
    int insert_idx = find_insert_index(_values[val], gadget_num, gadgets);
    _values[val].insert(_values.at(val).begin()+insert_idx, gadget_num);
    _pre_conds[val].insert(_pre_conds.at(val).begin()+insert_idx, pre_cond);
    
}

/* REGList */ 
REGList::REGList(){
    std::memset(_regs, 0, sizeof(CSTList*)*NB_REGS_MAX);
}

void REGList::add(int reg_num, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets){
    if( _regs[reg_num] == nullptr )
        _regs[reg_num] = new CSTList();
    _regs[reg_num]->add(cst, gadget_num, pre_cond, gadgets);
}
 
REGList::~REGList(){
    for( int i = 0; i < NB_REGS_MAX; i++)
        if( _regs[i] != nullptr )
            delete _regs[i];
}

/* MEMList */ 
template <class T> MEMList<T>::MEMList(){
    std::memset(_addresses, 0, sizeof(unordered_map<cst_t, T*>*)*NB_REGS_MAX);
}

template <class T> void MEMList<T>::add(int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets ){
    T* t;
    if( _addresses[addr_reg] == nullptr )
        _addresses[addr_reg] = new unordered_map<cst_t, T*>; 
    if( _addresses[addr_reg].count(addr_cst) == 0 ){
        t = new T(); 
        _addresses[addr_reg].insert(std::make_pair<addr_cst, t>());
    }
    // TODO 
}

template <class T> MEMList<T>::~MEMList(){
    for( int i = 0; i < NB_REGS_MAX; i++)
        if( _addresses[i] != nullptr )
            delete _addresses[i];
}

