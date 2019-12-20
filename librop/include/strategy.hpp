#ifndef STRATEGY_H
#define STRATEGY_H

#include "database.hpp"
#include "expression.hpp"
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
    REG
};

class Param{
public:
    ParamType type;
    string name; // Name for the param (used for patchable constants only)
    // Value
    cst_t value; // Used to put constant OR regnum
    // Dependencies
    int dep_param_type;
    node_t dep_node;
    Expr expr; // For constants only
    bool is_fixed;

    Param():name(""), value(-1), dep_param_type(-1), dep_node(-1), expr(nullptr), is_fixed(true){};
    
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

// TODO PUT THIS IN DATABASE ? 
#define MAX_PARAMS 7
// Different kinds parameters for nodes
// WARNING: their values have to match the place they have in the tuple
// when the gadgets are addded in the database !
#define PARAM_MOVREG_DST_REG 0
#define PARAM_MOVREG_SRC_REG 1
#define PARAM_MOVREG_GADGET_ADDR 2
#define PARAM_MOVREG_GADGET_SP_INC 3
#define NB_PARAM_MOVREG 4

#define PARAM_MOVCST_DST_REG 0
#define PARAM_MOVCST_SRC_CST 1
#define PARAM_MOVCST_GADGET_ADDR 2
#define PARAM_MOVCST_GADGET_SP_INC 3
#define NB_PARAM_MOVCST 4

#define PARAM_AMOVCST_DST_REG 0
#define PARAM_AMOVCST_SRC_REG 1
#define PARAM_AMOVCST_SRC_OP 2
#define PARAM_AMOVCST_SRC_CST 3
#define PARAM_AMOVCST_GADGET_ADDR 4
#define PARAM_AMOVCST_GADGET_SP_INC 5
#define NB_PARAM_AMOVCST 6

#define PARAM_AMOVREG_DST_REG 0
#define PARAM_AMOVREG_SRC_REG1 1
#define PARAM_AMOVREG_SRC_OP 2
#define PARAM_AMOVREG_SRC_REG2 3
#define PARAM_AMOVREG_GADGET_ADDR 4
#define PARAM_AMOVREG_GADGET_SP_INC 5
#define NB_PARAM_AMOVREG 6

#define PARAM_LOAD_DST_REG 0
#define PARAM_LOAD_SRC_ADDR_REG 1
#define PARAM_LOAD_SRC_ADDR_OFFSET 2
#define PARAM_LOAD_GADGET_ADDR 3
#define PARAM_LOAD_GADGET_SP_INC 4
#define NB_PARAM_LOAD 5

#define PARAM_LOADCST_DST_REG 0
#define PARAM_LOADCST_SRC_ADDR_OFFSET 1
#define PARAM_LOADCST_GADGET_ADDR 2
#define PARAM_LOADCST_GADGET_SP_INC 3
#define NB_PARAM_LOADCST 4

#define PARAM_STORE_DST_ADDR_REG 0
#define PARAM_STORE_DST_ADDR_OFFSET 1
#define PARAM_STORE_SRC_REG 2
#define PARAM_STORE_GADGET_ADDR 3
#define PARAM_STORE_GADGET_SP_INC 4
#define NB_PARAM_STORE 5

#define PARAM_CSTSTORE_DST_ADDR_OFFSET 0
#define PARAM_CSTSTORE_SRC_REG 1
#define PARAM_CSTSTORE_GADGET_ADDR 2
#define PARAM_CSTSTORE_GADGET_SP_INC 3
#define NB_PARAM_CSTSTORE 4

class Node{
public:
    // Fixed
    int id;
    GadgetType type;
    EdgeSet strategy_edges;
    EdgeSet param_edges;
    // Dynamic
    Param params[MAX_PARAMS];
    Gadget* affected_gadget;

    Node(int i, GadgetType t):id(i), type(t){};
    int nb_params(){
        switch( type ){
            case GadgetType::MOV_REG: return NB_PARAM_MOVREG;
            case GadgetType::MOV_CST: return NB_PARAM_MOVCST;
            default: throw runtime_exception("Unsupported gadget type in Node::nb_params()");
        }
    }

    bool has_free_param(){
        for( int p = 0; p < nb_params(); p++){
            if( params[p].is_free() )
                return true;
        }
        return false;
    }
};
ostream& operator<<(ostream& os, Node& node);


/* Strategy graph */
class StrategyGraph{
private:
    UniqueNameGenerator name_generator;
    void _dfs_strategy_explore(vector<node_t>& marked, node_t n);
    void _dfs_params_explore(vector<node_t>& marked, node_t n);
    void _resolve_param(Param& param);
    const vector<Gadget*>& _get_matching_gadgets(GadgetDB& db, node_t node);
    PossibleGadgets* _get_possible_gadgets(GadgetDB& db, node_t n);
    bool has_gadget_selection;
    VarContext params_ctx;
public:
    vector<Node> nodes;
    vector<node_t> dfs_strategy;
    vector<node_t> dfs_params;

    StrategyGraph();
    // Create new nodes/edges
    node_t new_node(GadgetType t);
    string new_name(string base);
    void remove_node(node_t node);
    void redirect_incoming_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type);
    void redirect_incoming_strategy_edges(node_t curr_node, node_t new_node);
    void redirect_outgoing_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type);
    void redirect_outgoing_strategy_edges(node_t curr_node, node_t new_node);
    void add_strategy_edge(node_t from, node_t to);
    void add_param_edge(node_t from, node_t to);
    // Strategy rules
    void rule_mov_reg_transitivity(node_t n);
    // Ordering
    void compute_dfs_strategy();
    void compute_dfs_params();
    
    // Gadget selection
    bool select_gadgets(GadgetDB& db, node_t dfs_idx=-1);
    ROPChain* get_ropchain(Arch* arch);
};
ostream& operator<<(ostream& os, StrategyGraph& graph);


#endif
