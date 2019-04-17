#ifndef ENGINE_H
#define ENGINE_H

#include "Database.hpp"
#include "Expression.hpp"
#include "ROPChain.hpp"
#include <string>

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */

enum AssignType {
    ASSIGN_CST,                  /* constant */
    ASSIGN_REG_BINOP_CST,    /* reg op cst */
    ASSIGN_MEM_BINOP_CST,    /* mem op cst */
    ASSIGN_CSTMEM_BINOP_CST, /* mem(cst) */ 
    ASSIGN_SYSCALL,          /* syscall */ 
    ASSIGN_INT80,             /* int80 */
    ASSIGN_INVALID
};

enum DestType {
    DST_REG,
    DST_MEM,
    DST_CSTMEM,
    DST_INVALID
};

class DestArg {
    public: 
    DestType type;
    int addr_reg;
    cst_t addr_cst;
    Binop addr_op;
    int reg; 
    bool addr_cst_has_offset; // If the dest is a cst_mem, indicate if needs to be adjusted with offset (for add_padding() method )
    
    DestArg();
    //DestArg(DestType t, cst_t r);   /* For DEST_REG */ 
    DestArg(DestType t, int addr_r, Binop op, cst_t addr_c); /* For DEST_MEM */
    DestArg(DestType t, cst_t val, bool offset=false); /* For DEST_CSTMEM */
    bool operator==(DestArg& other);
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
    bool cst_has_offset; // If the arg is a constant, indicate if it has been modified with 
                 // an offset (for add_padding, to pretty print with offset)
    
    AssignArg();
    AssignArg(AssignType t, cst_t c, bool offset=false); /* For ASSIGN_CST */
    AssignArg(AssignType t, int r, Binop o, cst_t c); /* For ASSIGN_REG_BINOP_CST */
    AssignArg(AssignType t, int ar, Binop o, cst_t ac, cst_t c); /* For ASSIGN_MEM_BINOP_CST */
    AssignArg(AssignType t, cst_t ac, cst_t c); /* For ASSIGN_CSTMEM_BINOP_CST */
    AssignArg(AssignType t); /* For ASSIGN_SYSCALL and INT80 */
    bool operator==(AssignArg& other);
};

/* ***************************************************
 *                    FailRecord
 * ************************************************* */ 

enum FailType{FAIL_NO_CHAIN, FAIL_LMAX, FAIL_MODIFIED_REG, FAIL_BAD_BYTES, FAIL_NO_VALID_PADDING, FAIL_OTHER};

class FailRecord{
    bool _max_len;                          /* Reached length limit */ 
    bool _no_valid_padding;                 /* Couldn't find a valid padding for gadgets */ 
    bool _modified_reg[NB_REGS_MAX];        /* Modified reg that should be kept */ 
    bool _bad_bytes[256];                   /* Gadget could be used but bad bytes in addresses */
    int _bad_bytes_index[256];				/* Index of the byte that was bad */ 
    bool _bad_byte;                         /* At least one bad_byte fail occured */ 
    
    public:
        FailRecord();
        FailRecord(bool max_len);
        // Accessors
        bool max_len(); 
        bool no_valid_padding();
        bool modified_reg(int reg_num);
        bool get_bad_byte(unsigned char bad_byte);
        int bad_byte_index(unsigned char bad_byte);
        bool* bad_bytes(); 
        bool bad_byte();
        // Modifiers
        void set_max_len(bool val);
        void set_no_valid_padding(bool val);
        void add_modified_reg(int reg_num);
        void add_bad_byte(unsigned char bad_byte, int index=-1);
        // Assign
        void copy_from(FailRecord* other);
        void merge_with(FailRecord* other);
        void reset();
};

/* ***************************************************
 *                RegTransitivityRecord
 * ************************************************* */ 
#define NB_OP_RECORD 4
#define NB_REG_RECORD 10
#define NB_CST_RECORD 13
#define MAX_SIGNATURES_PER_QUERY 40

class RegTransitivityRecord{
    // reg <- reg op cst 
    vector<cstr_sig_t> _query[NB_REG_RECORD][NB_REG_RECORD][NB_OP_RECORD][NB_CST_RECORD];
    int (*_cst_list_index)(cst_t);
    public:
        void add_fail(int dest_reg, int src_reg, Binop op, cst_t src_cst, SearchEnvironment* env);
        bool is_impossible(int dest_reg, int src_reg, Binop op, cst_t src_cst, SearchEnvironment* env);
};

/* *********************************************************************
 *                          Adjust Ret Record 
 * ******************************************************************* */ 

class AdjustRetRecord{
    bool _regs[NB_REGS_MAX];
    public:
        AdjustRetRecord();
        void add_fail(int reg_num);
        bool is_impossible(int reg_num);
        void reset();
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
    bool no_padding;
    bool single_gadget;
    bool chainable;
    addr_t lower_valid_write_addr;
    addr_t higher_valid_write_addr; // invalid values are 0 
    std::string initial_pop_constant_comment; 
    SearchParametersBinding(vector<int> k, vector<unsigned char> b, unsigned int l, bool s , bool np, bool sg , addr_t la, addr_t ha, string ic, bool chnbl);
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
#define DEFAULT_MAX_DEPTH 5

enum SearchStrategyType{STRATEGY_REG_TRANSITIVITY, STRATEGY_POP_CONSTANT, STRATEGY_ANY_REG_TRANSITIVITY , 
                        STRATEGY_ADJUST_RET, STRATEGY_ADJUST_STORE, STRATEGY_ADJUST_LOAD, NB_STRATEGY_TYPES};

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
    bool _single_gadget;
    /* Comments about gadgets */ 
    string _comment[NB_STRATEGY_TYPES];
    string _initial_comment[NB_STRATEGY_TYPES]; // This is only for pretty printing when using high level strategies from python
    /* Records for optimisations and infos */ 
    RegTransitivityRecord* _reg_transitivity_record; // Use a pointer in case we use a global record
    AdjustRetRecord _adjust_ret_record;
    FailRecord _fail_record;
    /* Strategy-specific information */ 
    vector<int>* _reg_transitivity_unusable; // Use a pointer because will be saved and restored often
    
    /* Methods */ 
    public: 
        /* Constructor */ 
        SearchEnvironment(Constraint* c, Assertion* a, unsigned int lm, 
                             unsigned int max_depth, bool no_padd, bool single_gadget,
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
        bool single_gadget();
        void set_single_gadget(bool val);
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
        void push_comment(SearchStrategyType t, string comment);
        string pop_comment(SearchStrategyType t);
        bool has_initial_comment(SearchStrategyType t);
        void set_initial_comment(SearchStrategyType t, string comment);
        string pop_initial_comment(SearchStrategyType t);
        
        /* Record functions */ 
        RegTransitivityRecord* reg_transitivity_record();
        AdjustRetRecord* adjust_ret_record();
        void set_adjust_ret_record(AdjustRetRecord* rec);
        FailRecord* fail_record();
};


/* **********************************************************************
 *                      Search & Chaining Functions ! 
 * ******************************************************************** */
void set_search_verbose(bool val);
SearchResultsBinding search(DestArg dest, AssignArg assign,SearchParametersBinding params);
ROPChain* search(DestArg dest, AssignArg assign, SearchEnvironment* env, bool shortest=false);

/* Init function */ 
void init_chaining_engine();
#endif
