#ifndef DATABASE_H
#define DATABASE_H

#include <unordered_map>
using std::unordered_map; 
#include <vector>
using std::vector; 
#include <memory>
using std::shared_ptr;

#include "Expression.hpp"
#include "Condition.hpp"
#include "Gadget.hpp"
#include "Constraint.hpp"

using std::unique_ptr; 

enum AssignType {
    Q_CST,                  /* constant */
    Q_REG_BINOP_CST,    /* reg op cst */
    Q_MEM_BINOP_CST,    /* mem op cst */
    Q_CSTMEM,      /* mem(cst) */ 
    Q_SYSCALL,                  /* syscall */ 
    Q_INT80                     /* int80 */
};

enum DestType {
    DST_REG,
    DST_MEM,
    DST_CSTMEM,
};

class CSTList{
    unordered_map<cst_t, vector<int>> _values;
    unordered_map<cst_t, vector<CondObjectPtr>> _pre_conds; 
    public:
        CSTList(); 
        void add(cst_t val, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets);
        vector<int> find(cst_t val, Constraint* constr, Assertion* assert, int n);
        
};

class REGList{
    CSTList* _values[COUNT_NB_BINOP][NB_REGS_MAX];
    public: 
        REGList(); 
        void add(Binop op, int reg_num, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets); 
        vector<int> find(Binop op, int reg_num, cst_t cst, Constraint* constr, Assertion* assert, int n);
        ~REGList();
};

class MEMList{
    unordered_map<cst_t, unique_ptr<CSTList>>* _addresses[COUNT_NB_BINOP][NB_REGS_MAX]; 
    public: 
        MEMList(); 
        void add(Binop op, int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets );
        vector<int> find(Binop op, int addr_reg, cst_t addr_cst, cst_t cst, Constraint* constr, Assertion* assert, int n);
        ~MEMList();
};

template<class T>
class MEMDict{
    unordered_map<cst_t, unique_ptr<T>>* _addresses[COUNT_NB_BINOP][NB_REGS_MAX]; 
    public:  
        MEMDict();
        void add_cst(Binop addr_op, int addr_reg, cst_t addr_cst, cst_t cst, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets );
        void add_reg(Binop addr_op, int addr_reg, cst_t addr_cst, int reg, cst_t cst, Binop op, int gadget_num, \
                        CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets );
        void add_mem(Binop addr_op, int addr_reg, cst_t addr_cst, int mem_reg, cst_t mem_cst, cst_t cst, \
                        Binop op, int gadget_num, CondObjectPtr pre_cond, vector<shared_ptr<Gadget>>& gadgets );
        vector<int> find_cst(Binop addr_op, int addr_reg, cst_t addr_cst, cst_t cst, 
                                            Constraint* c, Assertion* a, int n);
        vector<int> find_reg(Binop addr_op, int addr_reg, cst_t addr_cst, int reg, cst_t cst, 
                                            Binop op, Constraint* c, Assertion* a, int n);
        vector<int> find_mem(Binop addr_op, int addr_reg, cst_t addr_cst, int src_reg, 
                                            cst_t src_cst, cst_t cst, Binop op, Constraint* c, Assertion* a, int n);
        ~MEMDict();
};

class Database{
    vector<shared_ptr<Gadget>> _gadgets; 
    /* reg <- expr */ 
    CSTList* _cst_to_reg[NB_REGS_MAX];
    REGList* _reg_binop_cst_to_reg[NB_REGS_MAX];
    MEMList* _mem_binop_cst_to_reg[NB_REGS_MAX]; 
    /* mem <- expr */ 
    MEMDict<CSTList> _cst_to_mem; 
    MEMDict<REGList> _reg_binop_cst_to_mem; 
    MEMDict<MEMList> _mem_binop_cst_to_mem; 
    // TODO Syscalls and INT80 

    public: 
        Database(); 
        int add(shared_ptr<Gadget> g); 
        shared_ptr<Gadget> get(int num);
        vector<int> find_cst_to_reg(int reg_dest, cst_t cst, Constraint* c, Assertion* a, int n); 
        vector<int> find_reg_binop_cst_to_reg(int reg_dest, Binop op, int reg, cst_t cst, Constraint* c, Assertion* a, int n);
        vector<int> find_mem_binop_cst_to_reg(int reg_dest, Binop op, int addr_reg, cst_t addr_cst, cst_t cst, Constraint* c, Assertion* a, int n);
        vector<int> find_cst_to_mem(Binop op_dest, int reg_dest, cst_t cst_dest, cst_t cst, Constraint* c, Assertion* a, int n); 
        vector<int> find_reg_binop_cst_to_mem(Binop op_dest, int reg_dest, cst_t cst_dest, Binop op, int reg, cst_t cst, Constraint* c, Assertion* a, int n);
        vector<int> find_mem_binop_cst_to_mem(Binop op_dest, int reg_dest, cst_t cst_dest, Binop op, int addr_reg, cst_t addr_cst, cst_t cst, Constraint* c, Assertion* a, int n);
        
        ~Database(); 
};

Database* gadget_db(); 
bool init_gadget_db();

#endif 
