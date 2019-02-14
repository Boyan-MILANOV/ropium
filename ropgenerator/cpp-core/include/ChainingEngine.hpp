#ifndef ENGINE_H
#define ENGINE_H

#include "Database.hpp"
#include "Expression.hpp"
#include "ROPChain.hpp"

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */

enum AssignType {
    ASSIGN_CST,                  /* constant */
    ASSIGN_REG_BINOP_CST,    /* reg op cst */
    ASSIGN_MEM_BINOP_CST,    /* mem op cst */
    ASSIGN_CSTMEM_BINOP_CST, /* mem(cst) */ 
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
    Binop addr_op;
    int reg; 
    
    DestArg(DestType t, int r);   /* For DEST_REG */ 
    DestArg(DestType t, int addr_r, Binop op, cst_t addr_c); /* For DEST_MEM */
    DestArg(DestType t, cst_t addr_c); /* For DEST_CSTMEM */
};

class AssignArg {
    public:
    AssignType type;
    int addr_reg;
    cst_t addr_cst;
    Binop addr_op;
    int reg;
    Binop op;
    cst_t cst;
    
    AssignArg(AssignType t, cst_t c); /* For ASSIGN_CST */
    AssignArg(AssignType t, int r, Binop o, cst_t c); /* For ASSIGN_REG_BINOP_CST */
    AssignArg(AssignType t, int ar, Binop o, cst_t ac, cst_t c); /* For ASSIGN_MEM_BINOP_CST */
    AssignArg(AssignType t, cst_t ac, cst_t c); /* For ASSIGN_CSTMEM_BINOP_CST */
    AssignArg(AssignType t); /* For ASSIGN_SYSCALL and INT80 */ 
};

/* ***************************************************
 *                    FailRecord
 * ************************************************* */ 

enum FailType{FAIL_LMAX, FAIL_MODIFIED_REG, FAIL_BAD_BYTES, FAIL_NO_VALID_PADDING};
 
class FailRecord{
    bool _max_len;                          /* Reached length limit */ 
    bool _no_valid_padding;                 /* Couldn't find a valid padding for gadgets */ 
    bool _modified_reg[NB_REGS_MAX];        /* Modified reg that should be kept */ 
    bool _bad_bytes[256];                   /* Gadget could be used but bad bytes in addresses */
    
    public:
        FailRecord();
        FailRecord(bool max_len);
        // Accessors
        bool max_len(); 
        bool no_valid_padding();
        bool modified_reg(int reg_num);
        bool* bad_bytes(); 
        // Modifiers
        void set_max_len(bool val);
        void set_no_valid_padding(bool val);
        void add_modified_reg(int reg_num);
        void add_bad_byte(unsigned char bad_byte);
        // Assign
        void copy_from(FailRecord* other);
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
 *                         Search Parameters Bindings
 * ******************************************************************* */
class SearchParametersBinding{
    public: 
    vector<int> keep_regs; 
    vector<unsigned char> bad_bytes;
    unsigned int lmax; 
    bool shortest;
    SearchParametersBinding(vector<int> k, vector<unsigned char> b, unsigned int l, bool s );
};

class SearchResultsBinding{
    public:
    ROPChain chain;
    FailRecord fail_record; 
    bool found;
    SearchResultsBinding();
    SearchResultsBinding(ROPChain* chain);
    SearchResultsBinding(FailRecord* record);
    void operator=(SearchResultsBinding other);
};

/* *********************************************************************
 *                         SearchEnvironment 
 * ******************************************************************* */
#define DEFAULT_LMAX 100
#define DEFAULT_MAX_DEPTH 8

enum SearchStrategyType{STRATEGY_REG_TRANSITIVITY, STRATEGY_POP_CONSTANT, STRATEGY_ANY_REG_TRANSITIVITY , 
                        STRATEGY_ADJUST_RET, NB_STRATEGY_TYPES};

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
    /* Comments about gadgets */ 
    string _comment[NB_STRATEGY_TYPES];
    /* Records for optimisations and infos */ 
    RegTransitivityRecord* _reg_transitivity_record;
    FailRecord _fail_record;
    FailType _last_fail;
    /* Strategy-specific information */ 
    vector<int>* _reg_transitivity_unusable; // Use a pointer because will be saved and restored often
    
    /* Methods */ 
    public: 
        /* Constructor */ 
        SearchEnvironment(Constraint* c, Assertion* a, unsigned int lm, 
                             unsigned int max_depth, bool no_padd, 
                             RegTransitivityRecord* reg_trans_record);
        /* Destructor  */ 
        ~SearchEnvironment();
    
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
        vector<SearchStrategyType>& calls_history();
        int calls_count(SearchStrategyType type);
        bool reached_max_depth();
        vector<int>* reg_transitivity_unusable();
        void set_reg_transitivity_unusable(vector<int>* vec);
        bool is_reg_transitivity_unusable(int reg);
        
        /* Comments about gadgets */ 
        bool has_comment(SearchStrategyType t);
        void push_comment(SearchStrategyType t, string& comment);
        string pop_comment(SearchStrategyType t);
        
        /* Record functions */ 
        RegTransitivityRecord* reg_transitivity_record();
        FailRecord* fail_record();
        FailType last_fail();
        void set_last_fail(FailType t);
        
};


/* **********************************************************************
 *                      Search & Chaining Functions ! 
 * ******************************************************************** */
SearchResultsBinding search(DestArg dest, AssignArg assign,SearchParametersBinding params);
ROPChain* search(DestArg dest, AssignArg assign, SearchEnvironment* env, bool shortest=false);

#endif
