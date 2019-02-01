#ifndef ENGINE_H
#define ENGINE_H

#include "Database.hpp"
#include "Expression.hpp"

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */

enum AssignType {
    ASSIGN_CST,                  /* constant */
    ASSIGN_REG_BINOP_CST,    /* reg op cst */
    ASSIGN_MEM_BINOP_CST,    /* mem op cst */
    ASSIGN_CSTMEM,          /* mem(cst) */ 
    ASSIGN_SYSCALL,          /* syscall */ 
    ASSIGN_INT80             /* int80 */
};

enum DestType {
    DST_REG,
    DST_MEM,
    DST_CSTMEM,
};

class DestArg {
    public: 
    DestType type;
    int addr_reg;
    cst_t addr_cst; 
    int reg; 
    cst_t cst; 
    
    DestArg(DestType t, int r, cst_t c);   /* For DEST_REG */ 
    DestArg(DestType t, int addr_r, cst_t addr_c, cst_t c ); /* For DEST_MEM */
    DestArg(DestType t, cst_t addr_c, cst_t c); /* For DEST_CSTMEM */
};

class AssignArg {
    public:
    AssignType type;
    int addr_reg;
    cst_t addr_cst;
    IROperation addr_op;
    int reg;
    IROperation op;
    cst_t cst;
    
    AssignArg(AssignType t, cst_t c); /* For ASSIGN_CST */
    AssignArg(AssignType t, int r, IROperation o, cst_t c); /* For ASSIGN_REG_BINOP_CST */
    AssignArg(AssignType t, int ar, IROperation o, cst_t ac, cst_t c); /* For ASSIGN_MEM_BINOP_CST */
    AssignArg(AssignType t, cst_t ac, cst_t c); /* For ASSIGN_CST_MEM */
    AssignArg(AssignType t); /* For ASSIGN_SYSCALL and INT80 */ 
};

/* ***************************************************
 *                    FailRecord
 * ************************************************* */ 
 
class FailRecord{
    bool _max_len;                          /* Reached length limit */ 
    bool _modified_reg[NB_REGS_MAX];        /* Modified reg that should be kept */ 
    vector<unsigned char> _bad_bytes;       /* Gadget could be used but bad bytes in addresses */
    
    public:
        FailRecord();
        FailRecord(bool max_len);
        // Accessors
        bool max_len(); 
        bool modified_reg(int reg_num);
        vector<unsigned char>& bad_bytes(); 
        // Modifiers
        void set_max_len(bool val);
        void add_modified_reg(int reg_num);
        void add_bad_byte(unsigned char bad_byte);
};

/* ***************************************************
 *                RegTransitivityRecord
 * ************************************************* */ 
#define NB_OP_RECORD 4
#define NB_REG_RECORD 10
#define NB_CST_RECORD 13
#define MAX_SIGNATURES_PER_QUERY 30

Binop record_op_list[NB_OP_RECORD] = {OP_ADD, OP_SUB, OP_MUL, OP_DIV};
/* !! If constants are changed, don't forget to chage the *_index() functions implementation
 * in the .c */ 
cst_t record_cst_list_addsub[NB_CST_RECORD] = {-32,-16, -8, -4, -2, -1, 0,1,2,4,8,16,32};
int record_cst_list_addsub_index(cst_t c); // Inverts record_cst_list_addsub
cst_t record_cst_list_muldiv[NB_CST_RECORD] = {2, 3, 4,8,16,32,64, 128, 256, 512, 1024, 2048, 4092};
int record_cst_list_muldiv_index(cst_t c); // Inverts record_cst_list_muldiv

class RegTransitivityRecord{
    // reg <- reg op cst 
    vector<cstr_sig_t> _query[NB_REG_RECORD][NB_REG_RECORD][NB_OP_RECORD][NB_CST_RECORD];
    int (*_cst_list_index)(cst_t);
    public:
        void add_fail(int dest_reg, int src_reg, Binop op, cst_t src_cst, Constraint* constr);
        bool is_impossible(int dest_reg, int src_reg, Binop op, cst_t src_cst, Constraint* constr);
};


#endif
