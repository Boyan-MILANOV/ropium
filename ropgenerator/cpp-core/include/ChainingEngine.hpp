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
    bool _bad_bytes[256];                   /* Gadget could be used but bad bytes in addresses */
    
    public:
        FailRecord();
        FailRecord(bool max_len);
        // Accessors
        bool max_len(); 
        bool modified_reg(int reg_num);
        bool* bad_bytes(); 
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

class RegTransitivityRecord{
    // reg <- reg op cst 
    vector<cstr_sig_t> _query[NB_REG_RECORD][NB_REG_RECORD][NB_OP_RECORD][NB_CST_RECORD];
    int (*_cst_list_index)(cst_t);
    public:
        void add_fail(int dest_reg, int src_reg, Binop op, cst_t src_cst, Constraint* constr);
        bool is_impossible(int dest_reg, int src_reg, Binop op, cst_t src_cst, Constraint* constr);
};


/* *********************************************************************
 *                         SearchEnvironment 
 * ******************************************************************* */

enum SearchStrategyType{NB_STRATEGY_TYPES};
 
class SearchEnvironment{
    /* Constraints and contextual infos */ 
    Constraint* _constraint;
    Assertion* _assertion;
    unsigned int _depth;
    unsigned int _max_depth;
    int _calls_count[NB_STRATEGY_TYPES];
    vector<SearchStrategyType> _calls_history;
    unsigned int _lmax;
    /* ROPChain options */ 
    bool _no_padding;
    /* Records for optimisations and infos */ 
    RegTransitivityRecord* _reg_transitivity_record;
    FailRecord _fail_record;
    
    /* Methods */ 
    public: 
        /* Constructor */ 
        SearchEnvironment(RegTransitivityRecord* reg_trans_record);
    
        /* copy */ 
        SearchEnvironment* copy();
        
        /* Contextual infos getters/setters */ 
        Constraint* constraint();
        void set_constraint(Constraint* c);
        Assertion* assertion();
        void set_assertion(Assertion* a);
        unsigned int lmax();
        void set_lmax(unsigned int val);
        unsigned int depth();
        void set_depth(unsigned int val);
        bool no_padding();
        void set_no_padding(bool val);
        void add_call(SearchStrategyType type);
        void remove_last_call();
        int calls_count(SearchStrategyType type);
        bool reached_max_depth();
        
        /* Record functions */ 
        RegTransitivityRecord* reg_transitivity_record();
        FailRecord* fail_record();
};

#endif
