#ifndef DATABASE_H
#define DATABASE_H

#include <unordered_map>
using std::unordered_map; 
#include <vector>
using std::vector; 

#include "Expression.hpp"
#include "Condition.hpp"
#include "Gadget.hpp"


enum QueryType {
    CST,            /* constant */
    REG_MUL_CST,    /* reg*cst */
    REG_DIV_CST,    /* reg/cst */
    REG_ADD_CST,    /* reg+cst */
    MEM_ADD_CST,    /* mem[reg+cst]+cst*/
    Q_SYSCALL,        /* syscall */ 
    Q_INT80           /* int80 */
};

class CSTList{
    unordered_map<cst_t, vector<int>> _values;
    unordered_map<cst_t, vector<CondObjectPtr>> _pre_conds; 
    public:
        CSTList(); 
        void add(cst_t val, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets);
};

class REGList{
    CSTList* _regs[NB_REGS_MAX]; 
    public: 
        REGList(); 
        void add(int reg_num, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets); 
        ~REGList();
};

/* T should be CSTList ou REGList ou un autre MEMList */ 
template <typename T> class MEMList{
    unordered_map<cst_t, T*>* _addresses[NB_REGS_MAX]; 
    public: 
        MEMList(); 
        void add(int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets );
        ~MEMList();
};



class Database{
    vector<Gadget*> _gadgets; 
    /* reg <- expr */ 
    CSTList* cst_to_reg[NB_REGS_MAX];
    REGList* reg_mul_cst_to_reg[NB_REGS_MAX];
    REGList* reg_div_cst_to_reg[NB_REGS_MAX];
    REGList* reg_add_cst_to_reg[NB_REGS_MAX];
    MEMList<CSTList>* mem_add_cst_to_reg[NB_REGS_MAX]; 
    /* mem <- expr */ 
    MEMList<CSTList> cst_to_mem; 
    MEMList<REGList> reg_mul_cst_to_mem; 
    MEMList<REGList> reg_div_cst_to_mem; 
    MEMList<REGList> reg_add_cst_to_mem; 
    MEMList<MEMList<CSTList>> mem_add_cst_to_mem; 
    // TODO Syscalls and INT80 

    public: 
        Database(); 
        void add_gadget(Gadget* g); 
        Gadget* get_gadget(int num);
        ~Database(); 
};




#endif 
