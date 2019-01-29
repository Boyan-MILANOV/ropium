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
    cst_t cst; 
    int reg; 
    int addr_reg;
    cst_t addr_cst; 
    
    DestArg();
};

class AssignArg {
    public:
    AssignType type;
    cst_t cst;
    int reg; 
    IROperation op; 
    int addr_reg;
    cst_t addr_cst;
    IROperation addr_op;   
    
    AssignArg();
};

/* ***************************************************
 * 
 * ************************************************* */ 


#endif
