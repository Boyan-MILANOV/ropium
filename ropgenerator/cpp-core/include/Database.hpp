#ifndef DATABASE_H
#define DATABASE_H

#include <unordered_map>
using std::unordered_map; 
#include <vector>
using std::vector; 

#include "Expression.hpp"
#include "Condition.hpp"
#include "Gadget.hpp"

using std::unique_ptr; 

enum QueryType {
    Q_CST,            /* constant */
    Q_REG_BINOP_CST,    /* reg op cst */
    Q_MEM_BINOP_CST,    /* mem op cst */
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
    CSTList* _values[COUNT_NB_BINOP][NB_REGS_MAX];
    public: 
        REGList(); 
        void add(Binop op, int reg_num, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets); 
        ~REGList();
};

class MEMList{
    unordered_map<cst_t, unique_ptr<CSTList>>* _addresses[COUNT_NB_BINOP][NB_REGS_MAX]; 
    public: 
        MEMList(); 
        void add(Binop op, int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets );
        ~MEMList();
};

template<class T>
class MEMDict{
    unordered_map<cst_t, unique_ptr<T>>* _addresses[NB_REGS_MAX]; 
    public:  
        MEMDict();
        void add_cst(int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets );
        void add_reg(   int addr_reg, cst_t addr_cst, int reg, cst_t cst, Binop op, int gadget_num, \
                        CondObjectPtr pre_cond, vector<Gadget*> gadgets );
        void add_mem(   int addr_reg, cst_t addr_cst, int mem_reg, cst_t mem_cst, cst_t cst, \
                        Binop op, int gadget_num, CondObjectPtr pre_cond, vector<Gadget*> gadgets );
        ~MEMDict();
};

class Database{
    vector<Gadget*> _gadgets; 
    /* reg <- expr */ 
    CSTList* cst_to_reg[NB_REGS_MAX];
    REGList* reg_binop_cst_to_reg[NB_REGS_MAX];
    MEMList* mem_binop_cst_to_reg[NB_REGS_MAX]; 
    /* mem <- expr */ 
    MEMDict<CSTList> cst_to_mem; 
    MEMDict<REGList> reg_binop_cst_to_mem; 
    MEMDict<MEMList> mem_binop_cst_to_mem; 
    // TODO Syscalls and INT80 

    public: 
        Database(); 
        void add_gadget(Gadget* g); 
        Gadget* get_gadget(int num);
        ~Database(); 
};

Database* gadget_db();
void set_gadget_db();  

#endif 
