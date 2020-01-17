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

class Param{
public:
    ParamType type;
    string name; // Name for the param (used for 'free' constants only)
    // Value
    cst_t value; // Used to put constant OR regnum
    // Dependencies
    int dep_param_type;
    node_t dep_node;
    Expr expr; // For constants only
    bool is_fixed;

    Param():type(ParamType::NONE), name(""), value(-1), dep_param_type(-1), dep_node(-1), expr(nullptr), is_fixed(true){};
    
    // Fixed or free register
    void make_reg(int reg, bool fixed=true){
        type = ParamType::REG;
        value = reg;
        is_fixed = fixed;
        dep_node = -1;
        expr = nullptr;
    };
    
    // Dependent register
    void make_reg(node_t dn, int dpt){
        type = ParamType::REG;
        value = -1;
        is_fixed = false;
        dep_node = dn;
        dep_param_type = dpt;
        expr = nullptr;
    };
    
    // Fixed or free constant
    void make_cst(cst_t val, string n, bool fixed=true){
        type = ParamType::CST;
        name = n;
        value = val;
        is_fixed = fixed;
        dep_node = -1;
        expr = nullptr;
    };
    
    // Dependent constant
    void make_cst(node_t dn, int dpt, Expr e, string n){
        type = ParamType::CST;
        name = n;
        value = 0;
        is_fixed = false;
        dep_node = dn;
        dep_param_type = dpt;
        expr = e;
    };

    // Operator
    void make_op(Op op){
        type = ParamType::OP;
        value = (int)op;
        is_fixed = true;
        dep_node = -1;
        expr = nullptr;
    };

    bool is_dependent(){return !is_fixed && dep_node != -1;};
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
        return ss.str();
    };
};

/* Different kinds parameters for nodes/IL instructions
   ====================================================
   WARNING: their values have to match the place they have in the tuple
   when the gadgets are addded in the database !
*/
#define MAX_PARAMS 8

#define PARAM_MOVREG_DST_REG 0
#define PARAM_MOVREG_SRC_REG 1
#define PARAM_MOVREG_GADGET_ADDR 2
#define PARAM_MOVREG_GADGET_SP_INC 3
#define PARAM_MOVREG_GADGET_JMP_REG 4
#define PARAM_MOVREG_GADGET_SP_DELTA 5
#define NB_PARAM_MOVREG 6

#define PARAM_MOVCST_DST_REG 0
#define PARAM_MOVCST_SRC_CST 1
#define PARAM_MOVCST_GADGET_ADDR 2
#define PARAM_MOVCST_GADGET_SP_INC 3
#define PARAM_MOVCST_GADGET_JMP_REG 4
#define PARAM_MOVCST_GADGET_SP_DELTA 5
#define NB_PARAM_MOVCST 6

#define PARAM_AMOVCST_DST_REG 0
#define PARAM_AMOVCST_SRC_REG 1
#define PARAM_AMOVCST_SRC_OP 2
#define PARAM_AMOVCST_SRC_CST 3
#define PARAM_AMOVCST_GADGET_ADDR 4
#define PARAM_AMOVCST_GADGET_SP_INC 5
#define PARAM_AMOVCST_GADGET_JMP_REG 6
#define PARAM_AMOVCST_GADGET_SP_DELTA 7
#define NB_PARAM_AMOVCST 8

#define PARAM_AMOVREG_DST_REG 0
#define PARAM_AMOVREG_SRC_REG1 1
#define PARAM_AMOVREG_SRC_OP 2
#define PARAM_AMOVREG_SRC_REG2 3
#define PARAM_AMOVREG_GADGET_ADDR 4
#define PARAM_AMOVREG_GADGET_SP_INC 5
#define PARAM_AMOVREG_GADGET_JMP_REG 6
#define PARAM_AMOVREG_GADGET_SP_DELTA 7
#define NB_PARAM_AMOVREG 8

#define PARAM_LOAD_DST_REG 0
#define PARAM_LOAD_SRC_ADDR_REG 1
#define PARAM_LOAD_SRC_ADDR_OFFSET 2
#define PARAM_LOAD_GADGET_ADDR 3
#define PARAM_LOAD_GADGET_SP_INC 4
#define PARAM_LOAD_GADGET_JMP_REG 5
#define PARAM_LOAD_GADGET_SP_DELTA 6
#define NB_PARAM_LOAD 7

#define PARAM_ALOAD_DST_REG 0
#define PARAM_ALOAD_OP 1
#define PARAM_ALOAD_SRC_ADDR_REG 2
#define PARAM_ALOAD_SRC_ADDR_OFFSET 3
#define PARAM_ALOAD_GADGET_ADDR 4
#define PARAM_ALOAD_GADGET_SP_INC 5
#define PARAM_ALOAD_GADGET_JMP_REG 6
#define PARAM_ALOAD_GADGET_SP_DELTA 7
#define NB_PARAM_ALOAD 8

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
#define NB_PARAM_STORE 7

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
#define NB_PARAM_ASTORE 8

#define PARAM_CSTASTORE_DST_ADDR_OFFSET 0
#define PARAM_CSTASTORE_OP 1
#define PARAM_CSTASTORE_SRC_REG 2
#define PARAM_CSTASTORE_GADGET_ADDR 3
#define PARAM_CSTASTORE_GADGET_SP_INC 4
#define PARAM_CSTASTORE_GADGET_JMP_REG 5
#define PARAM_CSTASTORE_GADGET_SP_DELTA 6
#define NB_PARAM_CSTASTORE 7


typedef struct {
    Param offset;
    Param value;
} ROPPadding;

class RegDataLink {
public:
    param_t src_param;
    node_t dst_node;
    param_t dst_param;
    RegDataLink( param_t srcp, node_t dstn, param_t dstp): src_param(srcp),
        dst_node(dstn), dst_param(dstp){};
};


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
typedef bool (*constraint_callback_t)(Node* node, StrategyGraph* graph);

// Commonly used node constraints
bool constraint_branch_type(Node* node, StrategyGraph* graph);

// Node class
class Node{
public:
    int depth;
    // Fixed
    int id;
    bool indirect; // Means that the node must have a gadget assigned
                   // but the gaget is not added explicitely in the ROPChain
                   // (it is used for adjust_reg strategy for example)
    GadgetType type;
    EdgeSet strategy_edges;
    EdgeSet param_edges;
    EdgeSet interference_edges;
    // Dynamic
    Param params[MAX_PARAMS];
    Gadget* affected_gadget;
    // Constraint
    vector<constraint_callback_t> strategy_constraints;
    vector<constraint_callback_t> assigned_gadget_constraints;
    BranchType branch_type;
    // Gadget paddings
    vector<ROPPadding> special_paddings;
    // Assertions
    NodeAssertion node_assertion;
    Assertion assertion;
    // Data links 
    vector<RegDataLink> reg_data_links;

    Node(int i, GadgetType t);
    int nb_params();
    bool has_free_param();
    bool is_disabled();
    bool is_indirect();
    int get_param_num_gadget_sp_inc();
    int get_param_num_gadget_addr();
    int get_param_num_gadget_jmp_reg();
    int get_param_num_gadget_sp_delta();
    int get_param_num_dst_reg();
    void assign_gadget(Gadget* gadget, Arch* arch=nullptr, Constraint* constraint=nullptr);
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
    bool _check_strategy_constraints(Node& node);
    bool _check_assigned_gadget_constraints(Node& node);
    bool _do_scheduling(int interference_idx=0);
    
    bool has_gadget_selection;
    VarContext params_ctx;
    int _depth;
    vector<InterferencePoint> interference_points;
public:
    vector<Node> nodes;
    vector<node_t> dfs_strategy;
    vector<node_t> dfs_params;
    vector<node_t> dfs_scheduling;

    StrategyGraph();
    // Create new nodes/edges
    node_t new_node(GadgetType t);
    string new_name(string base);
    void disable_node(node_t node);
    void redirect_incoming_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type);
    void redirect_incoming_strategy_edges(node_t curr_node, node_t new_node);
    void redirect_outgoing_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type);
    void redirect_outgoing_strategy_edges(node_t curr_node, node_t new_node);
    void add_strategy_edge(node_t from, node_t to);
    void add_param_edge(node_t from, node_t to);
    void add_interference_edge(node_t from, node_t to);
    void clear_interference_edges(node_t n);
    // Strategy rules
    bool rule_mov_cst_pop(node_t n, Arch* arch);
    bool rule_generic_transitivity(node_t n);
    bool rule_generic_adjust_jmp(node_t n, Arch* arch);
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

    // Copy
    StrategyGraph* copy();
};

ostream& operator<<(ostream& os, StrategyGraph& graph);

#endif
