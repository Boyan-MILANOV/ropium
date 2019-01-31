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




#endif
