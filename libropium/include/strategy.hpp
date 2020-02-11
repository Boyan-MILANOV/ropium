#ifndef STRATEGY_H
#define STRATEGY_H

#include "database.hpp"
#include "expression.hpp"
#include "constraint.hpp"
#include "assertion.hpp"
#include <vector>
#include <string>
#include <array>

using std::stringstream;
using std::vector;
using std::array;

/* Forward declaration */
typedef int node_t;
typedef int param_t;

enum class ParamType{
    CST,
    REG,
    OP,
    NONE
};

struct ParamDep{
    node_t node;
    param_t param_type;
};

class Param{
public:
    ParamType type; 
    string name; // Name for the param (used for 'free' constants only)
    // Value
    cst_t value; // Used to put constant OR regnum
    // Dependencies
    vector<ParamDep> deps;
    Expr expr; // For constants only
    bool is_fixed;
    bool is_data_link; 

    Param():type(ParamType::NONE), name(""), value(-1), expr(nullptr), is_fixed(true), is_data_link(false){};

    void add_dep(node_t n, param_t p){
        // Check if already present
        for( ParamDep& dep : deps )
            if( dep.node == n && dep.param_type == p )
                return;
        // If not present, add the dependency
        deps.push_back(ParamDep{n, p});
    };
    
    bool depends_on(node_t n){
        for( ParamDep& dep : deps ){
            if( dep.node == n )
                return true;
        }
        return false;
    };
    
    // Fixed or free register
    void make_reg(int reg, bool fixed=true){
        type = ParamType::REG;
        value = reg;
        is_fixed = fixed;
        deps.clear();
        expr = nullptr;
        is_data_link = false;
    };
    
    // Dependent register
    void make_reg(node_t dn, int dpt){
        type = ParamType::REG;
        value = -1;
        is_fixed = false;
        deps.clear();
        add_dep(dn, dpt);
        expr = nullptr;
        is_data_link = false;
    };
    
    // Fixed or free constant
    void make_cst(cst_t val, string n, bool fixed=true){
        type = ParamType::CST;
        name = n;
        value = val;
        is_fixed = fixed;
        deps.clear();
        expr = nullptr;
        is_data_link = false;
    };
    
    // Dependent constant
    void make_cst(node_t dn, int dpt, Expr e, string n){
        type = ParamType::CST;
        name = n;
        value = 0;
        is_fixed = false;
        deps.clear();
        add_dep(dn, dpt);
        expr = e;
        is_data_link = false;
    };

    // Operator
    void make_op(Op op){
        type = ParamType::OP;
        value = (int)op;
        is_fixed = true;
        deps.clear();
        expr = nullptr;
        is_data_link = false;
    };

    bool is_dependent(){return !is_fixed && !deps.empty();};
    bool is_free(){return !is_dependent() && !is_fixed;};
    bool is_cst(){return type == ParamType::CST;};
    bool is_reg(){return type == ParamType::REG;};
};

ostream& operator<<(ostream& os, Param& param);


struct EdgeSet{
    vector<node_t> in;
    vector<node_t> out;
};

class UniqueNameGenerator{
private:
    int n;
public:
    UniqueNameGenerator():n(0){};
    string new_name(string& name){
        stringstream ss;
        ss << name << "_" << std::dec << n;
        n++;
        return ss.str();
    };
};

/* Different kinds parameters for nodes/IL instructions
   ====================================================
   WARNING: their values have to match the place they have in the tuple
   when the gadgets are addded in the database !
*/
#define MAX_PARAMS 9

#define PARAM_MOVREG_DST_REG 0
#define PARAM_MOVREG_SRC_REG 1
#define PARAM_MOVREG_GADGET_ADDR 2
#define PARAM_MOVREG_GADGET_SP_INC 3
#define PARAM_MOVREG_GADGET_JMP_REG 4
#define PARAM_MOVREG_GADGET_SP_DELTA 5
#define PARAM_MOVREG_DATA_LINK 6
#define NB_PARAM_MOVREG 7

#define PARAM_MOVCST_DST_REG 0
#define PARAM_MOVCST_SRC_CST 1
#define PARAM_MOVCST_GADGET_ADDR 2
#define PARAM_MOVCST_GADGET_SP_INC 3
#define PARAM_MOVCST_GADGET_JMP_REG 4
#define PARAM_MOVCST_GADGET_SP_DELTA 5
#define PARAM_MOVCST_DATA_LINK 6
#define NB_PARAM_MOVCST 7

#define PARAM_AMOVCST_DST_REG 0
#define PARAM_AMOVCST_SRC_REG 1
#define PARAM_AMOVCST_SRC_OP 2
#define PARAM_AMOVCST_SRC_CST 3
#define PARAM_AMOVCST_GADGET_ADDR 4
#define PARAM_AMOVCST_GADGET_SP_INC 5
#define PARAM_AMOVCST_GADGET_JMP_REG 6
#define PARAM_AMOVCST_GADGET_SP_DELTA 7
#define PARAM_AMOVCST_DATA_LINK 8
#define NB_PARAM_AMOVCST 9

#define PARAM_AMOVREG_DST_REG 0
#define PARAM_AMOVREG_SRC_REG1 1
#define PARAM_AMOVREG_SRC_OP 2
#define PARAM_AMOVREG_SRC_REG2 3
#define PARAM_AMOVREG_GADGET_ADDR 4
#define PARAM_AMOVREG_GADGET_SP_INC 5
#define PARAM_AMOVREG_GADGET_JMP_REG 6
#define PARAM_AMOVREG_GADGET_SP_DELTA 7
#define PARAM_AMOVREG_DATA_LINK 8
#define NB_PARAM_AMOVREG 9

#define PARAM_LOAD_DST_REG 0
#define PARAM_LOAD_SRC_ADDR_REG 1
#define PARAM_LOAD_SRC_ADDR_OFFSET 2
#define PARAM_LOAD_GADGET_ADDR 3
#define PARAM_LOAD_GADGET_SP_INC 4
#define PARAM_LOAD_GADGET_JMP_REG 5
#define PARAM_LOAD_GADGET_SP_DELTA 6
#define PARAM_LOAD_DATA_LINK 7
#define NB_PARAM_LOAD 8

#define PARAM_ALOAD_DST_REG 0
#define PARAM_ALOAD_OP 1
#define PARAM_ALOAD_SRC_ADDR_REG 2
#define PARAM_ALOAD_SRC_ADDR_OFFSET 3
#define PARAM_ALOAD_GADGET_ADDR 4
#define PARAM_ALOAD_GADGET_SP_INC 5
#define PARAM_ALOAD_GADGET_JMP_REG 6
#define PARAM_ALOAD_GADGET_SP_DELTA 7
#define PARAM_ALOAD_DATA_LINK 8
#define NB_PARAM_ALOAD 9

#define PARAM_LOADCST_DST_REG 0
#define PARAM_LOADCST_SRC_ADDR_OFFSET 1
#define PARAM_LOADCST_GADGET_ADDR 2
#define PARAM_LOADCST_GADGET_SP_INC 3
#define PARAM_LOADCST_GADGET_JMP_REG 4
#define PARAM_LOADCST_GADGET_SP_DELTA 5
#define NB_PARAM_LOADCST 6

#define PARAM_ALOADCST_DST_REG 0
#define PARAM_ALOADCST_OP 1
#define PARAM_ALOADCST_SRC_ADDR_OFFSET 2
#define PARAM_ALOADCST_GADGET_ADDR 3
#define PARAM_ALOADCST_GADGET_SP_INC 4
#define PARAM_ALOADCST_GADGET_JMP_REG 5
#define PARAM_ALOADCST_GADGET_SP_DELTA 6
#define NB_PARAM_ALOADCST 7

#define PARAM_STORE_DST_ADDR_REG 0
#define PARAM_STORE_DST_ADDR_OFFSET 1
#define PARAM_STORE_SRC_REG 2
#define PARAM_STORE_GADGET_ADDR 3
#define PARAM_STORE_GADGET_SP_INC 4
#define PARAM_STORE_GADGET_JMP_REG 5
#define PARAM_STORE_GADGET_SP_DELTA 6
#define PARAM_STORE_DATA_LINK 7
#define NB_PARAM_STORE 8

#define PARAM_CSTSTORE_DST_ADDR_OFFSET 0
#define PARAM_CSTSTORE_SRC_REG 1
#define PARAM_CSTSTORE_GADGET_ADDR 2
#define PARAM_CSTSTORE_GADGET_SP_INC 3
#define PARAM_CSTSTORE_GADGET_JMP_REG 4
#define PARAM_CSTSTORE_GADGET_SP_DELTA 5
#define NB_PARAM_CSTSTORE 6

#define PARAM_ASTORE_DST_ADDR_REG 0
#define PARAM_ASTORE_DST_ADDR_OFFSET 1
#define PARAM_ASTORE_OP 2
#define PARAM_ASTORE_SRC_REG 3
#define PARAM_ASTORE_GADGET_ADDR 4
#define PARAM_ASTORE_GADGET_SP_INC 5
#define PARAM_ASTORE_GADGET_JMP_REG 6
#define PARAM_ASTORE_GADGET_SP_DELTA 7
#define PARAM_ASTORE_DATA_LINK 8
#define NB_PARAM_ASTORE 9

#define PARAM_CSTASTORE_DST_ADDR_OFFSET 0
#define PARAM_CSTASTORE_OP 1
#define PARAM_CSTASTORE_SRC_REG 2
#define PARAM_CSTASTORE_GADGET_ADDR 3
#define PARAM_CSTASTORE_GADGET_SP_INC 4
#define PARAM_CSTASTORE_GADGET_JMP_REG 5
#define PARAM_CSTASTORE_GADGET_SP_DELTA 6
#define NB_PARAM_CSTASTORE 7


#define PARAM_STORECST_DST_ADDR_REG 0
#define PARAM_STORECST_DST_ADDR_OFFSET 1
#define PARAM_STORECST_SRC_CST 2
#define PARAM_STORECST_GADGET_ADDR 3
#define PARAM_STORECST_GADGET_SP_INC 4
#define PARAM_STORECST_GADGET_JMP_REG 5
#define PARAM_STORECST_GADGET_SP_DELTA 6
#define NB_PARAM_STORECST 7

#define PARAM_CSTSTORECST_DST_ADDR_OFFSET 0
#define PARAM_CSTSTORECST_SRC_CST 1
#define PARAM_CSTSTORECST_GADGET_ADDR 2
#define PARAM_CSTSTORECST_GADGET_SP_INC 3
#define PARAM_CSTSTORECST_GADGET_JMP_REG 4
#define PARAM_CSTSTORECST_GADGET_SP_DELTA 5
#define NB_PARAM_CSTSTORECST 6

#define PARAM_ASTORECST_DST_ADDR_REG 0
#define PARAM_ASTORECST_DST_ADDR_OFFSET 1
#define PARAM_ASTORECST_OP 2
#define PARAM_ASTORECST_SRC_CST 3
#define PARAM_ASTORECST_GADGET_ADDR 4
#define PARAM_ASTORECST_GADGET_SP_INC 5
#define PARAM_ASTORECST_GADGET_JMP_REG 6
#define PARAM_ASTORECST_GADGET_SP_DELTA 7
#define NB_PARAM_ASTORECST 8

#define PARAM_CSTASTORECST_DST_ADDR_OFFSET 0
#define PARAM_CSTASTORECST_OP 1
#define PARAM_CSTASTORECST_SRC_CST 2
#define PARAM_CSTASTORECST_GADGET_ADDR 3
#define PARAM_CSTASTORECST_GADGET_SP_INC 4
#define PARAM_CSTASTORECST_GADGET_JMP_REG 5
#define PARAM_CSTASTORECST_GADGET_SP_DELTA 6
#define NB_PARAM_CSTASTORECST 7

#define PARAM_FUNCTION_ADDR 0
#define PARAM_FUNCTION_ARGS 1

#define PARAM_SYSCALL_ARGS 0 // For IL
#define PARAM_SYSCALL_GADGET_ADDR 0 // For gadget
#define PARAM_SYSCALL_GADGET_SP_INC 1
#define PARAM_SYSCALL_GADGET_JMP_REG 2
#define PARAM_SYSCALL_GADGET_SP_DELTA 3
#define PARAM_SYSCALL_DATA_LINK 4
#define NB_PARAM_SYSCALL 5

#define PARAM_INT80_ARGS 0 // For IL
#define PARAM_INT80_GADGET_ADDR 0 // For gadget
#define PARAM_INT80_GADGET_SP_INC 1
#define PARAM_INT80_GADGET_JMP_REG 2
#define PARAM_INT80_GADGET_SP_DELTA 3
#define PARAM_INT80_DATA_LINK 4
#define NB_PARAM_INT80 5


typedef struct {
    Param offset;
    Param value;
} ROPPadding;

class Node;

class NodeValidPointers{
    vector<param_t> _params;
public:
    void add_valid_pointer(param_t param);
    void to_assertion(Node& node, Assertion* assertion);
    void clear();
};

class NodeAssertion{
public:
    NodeValidPointers valid_pointers;
    void to_assertion(Node& node, Assertion* a);
    void clear();
};


// Callback for custom constraints called to filter gadgets on each node
class Node;
class StrategyGraph;
typedef bool (*constraint_callback_t)(Node* node, StrategyGraph* graph, Arch* arch);

// Commonly used node constraints
bool constraint_branch_type(Node* node, StrategyGraph* graph, Arch* arch);

class Node{
public:
    int id;
    bool is_indirect;
    bool is_disabled;
    GadgetType type;
    // Edges
    EdgeSet strategy_edges; 
    EdgeSet param_edges;
    EdgeSet interference_edges;
    // Parameters
    Param params[MAX_PARAMS];
    // Affected gadget
    Gadget* affected_gadget;
    // Constraint
    vector<constraint_callback_t> strategy_constraints;
    vector<constraint_callback_t> assigned_gadget_constraints;
    // Branch type (RET, JMP, ANY, ...)
    BranchType branch_type;
    // Gadget paddings
    vector<ROPPadding> special_paddings;
    // Assertions
    NodeAssertion node_assertion;
    Assertion assertion;
    // Mandatory Following node
    node_t mandatory_following_node;

    Node(int i, GadgetType t);
    int nb_params();
    bool has_free_param();
    bool has_mandatory_following_node();
    // Manage edges
    void add_incoming_strategy_edge(node_t src_node);
    void add_incoming_param_edge(node_t src_node);
    void add_outgoing_strategy_edge(node_t dst_node);
    void add_outgoing_param_edge(node_t dst_node);
    void remove_incoming_strategy_edge(node_t src_node);
    void remove_incoming_param_edge(node_t src_node);
    void remove_outgoing_strategy_edge(node_t dst_node);
    void remove_outgoing_param_edge(node_t dst_node);

    bool is_initial_param(param_t param);
    bool is_final_param(param_t param);
    bool is_src_param(param_t param);
    bool is_generic_param(param_t param);

    int get_param_num_gadget_sp_inc();
    int get_param_num_gadget_addr();
    int get_param_num_gadget_jmp_reg();
    int get_param_num_gadget_sp_delta();
    int get_param_num_src_reg();
    int get_param_num_dst_reg();
    int get_param_num_src_addr_offset();
    int get_param_num_src_addr_reg();
    int get_param_num_dst_addr_offset();
    int get_param_num_dst_addr_reg();
    int get_param_num_data_link();
    bool has_dst_reg_param();
    bool has_dst_addr_reg_param();

    bool assign_gadget(Gadget* gadget, Arch* arch=nullptr, Constraint* constraint=nullptr);
    void apply_assertion();
    bool modifies_reg(int reg_num);
};

ostream& operator<<(ostream& os, Node& node);

class InterferencePoint {
public:
    node_t interfering_node;
    node_t start_node;
    node_t end_node;
    InterferencePoint(node_t i, node_t s, node_t e):interfering_node(i), start_node(s), end_node(e){};
};

/* Strategy graph */
class StrategyGraph{
private:
    UniqueNameGenerator name_generator;
    void _dfs_strategy_explore(vector<node_t>& marked, node_t n);
    void _dfs_params_explore(vector<node_t>& marked, node_t n);
    bool _dfs_scheduling_explore(vector<node_t>& marked, node_t n);
    void _resolve_param(Param& param);
    void _resolve_all_params(node_t n);
    const vector<Gadget*>& _get_matching_gadgets(GadgetDB& db, node_t node);
    PossibleGadgets* _get_possible_gadgets(GadgetDB& db, node_t n);
    bool _check_strategy_constraints(Node& node, Arch* arch);
    bool _check_assigned_gadget_constraints(Node& node, Arch* arch);
    bool _check_special_padding_constraints(Node& node, Arch* arch, Constraint* constraint=nullptr);
    bool _do_scheduling(int interference_idx=0);
    
    bool has_gadget_selection;
    VarContext params_ctx;
    int _depth;
    vector<InterferencePoint> interference_points;
public:
    int size;
    vector<Node> nodes;
    vector<node_t> dfs_strategy;
    vector<node_t> dfs_params;
    vector<node_t> dfs_scheduling;

    StrategyGraph();
    // Create new nodes/edges
    node_t new_node(GadgetType t);
    string new_name(string base);
    void disable_node(node_t node);
    void redirect_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type);
    void redirect_incoming_strategy_edges(node_t curr_node, node_t new_node);
    void redirect_outgoing_strategy_edges(node_t curr_node, node_t new_node);
    void redirect_generic_param_edges(node_t curr_node, node_t new_node);
    void add_strategy_edge(node_t from, node_t to);
    void add_param_edge(node_t from, node_t to);
    void add_interference_edge(node_t from, node_t to);
    void update_param_edges();
    void update_size();
    void clear_interference_edges(node_t n);
    bool modifies_reg(node_t n, int reg_num, bool check_following_node=false);
    // Strategy rules
    bool rule_mov_cst_pop(node_t n, Arch* arch);
    bool rule_generic_transitivity(node_t n);
    bool rule_generic_src_transitivity(node_t n);
    bool rule_generic_adjust_jmp(node_t n, Arch* arch);
    bool rule_adjust_load(node_t n, Arch* arch);
    bool rule_adjust_store(node_t n, Arch* arch);
    // Ordering
    void compute_dfs_strategy();
    void compute_dfs_params();
    bool compute_dfs_scheduling();

    // Gadget selection
    bool select_gadgets(GadgetDB& db, Constraint* constraint=nullptr, Arch* arch=nullptr, node_t dfs_idx=-1);
    ROPChain* get_ropchain(Arch* arch, Constraint* constraint=nullptr);

    // Scheduling
    void compute_interference_points();
    bool schedule_gadgets();
    bool has_dependent_param(node_t node, param_t param);

    // Copy
    StrategyGraph* copy();
};

ostream& operator<<(ostream& os, StrategyGraph& graph);

#endif
