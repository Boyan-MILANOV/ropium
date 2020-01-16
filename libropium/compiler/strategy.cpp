#include "strategy.hpp"
#include "expression.hpp"
#include "exception.hpp"
#include <algorithm>

/* ===============  Node Assertions ============== */

void NodeValidPointers::add_valid_pointer(param_t p){
    _params.push_back(p);
}

void NodeValidPointers::to_assertion(Node& node, Assertion* assertion){
    for( auto p : _params ){
        assertion->valid_pointers.add_valid_pointer(node.params[p].value);
    }
}

void NodeValidPointers::clear(){
    _params.clear();
}


void NodeAssertion::clear(){
    valid_pointers.clear();
}

void NodeAssertion::to_assertion(Node& node, Assertion * a){
    valid_pointers.to_assertion(node, a);
}

/* ===============  Nodes ============== */

bool constraint_branch_type(Node* node, StrategyGraph* graph){
    return (node->affected_gadget->branch_type == node->branch_type) ||
           (node->branch_type == BranchType::ANY);
}

Node::Node(int i, GadgetType t):id(i), type(t), depth(-1), branch_type(BranchType::ANY), indirect(false){
    // Add constraints that must always be verified
    assigned_gadget_constraints.push_back(constraint_branch_type); // Matching branch type
};

int Node::nb_params(){
    switch( type ){
        case GadgetType::MOV_REG: return NB_PARAM_MOVREG;
        case GadgetType::MOV_CST: return NB_PARAM_MOVCST;
        case GadgetType::AMOV_CST: return NB_PARAM_AMOVCST;
        case GadgetType::AMOV_REG: return NB_PARAM_AMOVREG;
        case GadgetType::LOAD: return NB_PARAM_LOAD;
        case GadgetType::ALOAD: return NB_PARAM_ALOAD;
        case GadgetType::STORE: return NB_PARAM_STORE;
        case GadgetType::ASTORE: return NB_PARAM_ASTORE;
        default: throw runtime_exception("Unsupported gadget type in Node::nb_params()");
    }
}

bool Node::has_free_param(){
    for( int p = 0; p < nb_params(); p++){
        if( params[p].is_free() )
            return true;
    }
    return false;
}

bool Node::is_disabled(){
    return id == -1;
}

bool Node::is_indirect(){
    return indirect;
}

int Node::get_param_num_gadget_sp_inc(){
    switch( type ){
        case GadgetType::MOV_REG: return PARAM_MOVREG_GADGET_SP_INC;
        case GadgetType::AMOV_REG: return PARAM_AMOVREG_GADGET_SP_INC;
        case GadgetType::MOV_CST: return PARAM_MOVCST_GADGET_SP_INC;
        case GadgetType::AMOV_CST: return PARAM_AMOVCST_GADGET_SP_INC;
        case GadgetType::LOAD: return PARAM_LOAD_GADGET_SP_INC;
        case GadgetType::ALOAD: return PARAM_ALOAD_GADGET_SP_INC;
        case GadgetType::STORE: return PARAM_STORE_GADGET_SP_INC;
        case GadgetType::ASTORE: return PARAM_ASTORE_GADGET_SP_INC;
        default:
            throw runtime_exception("Node::get_param_num_gadget_sp_inc(): got unsupported gadget type");
    }
}

int Node::get_param_num_gadget_sp_delta(){
    switch( type ){
        case GadgetType::MOV_REG: return PARAM_MOVREG_GADGET_SP_DELTA;
        case GadgetType::AMOV_REG: return PARAM_AMOVREG_GADGET_SP_DELTA;
        case GadgetType::MOV_CST: return PARAM_MOVCST_GADGET_SP_DELTA;
        case GadgetType::AMOV_CST: return PARAM_AMOVCST_GADGET_SP_DELTA;
        case GadgetType::LOAD: return PARAM_LOAD_GADGET_SP_DELTA;
        case GadgetType::ALOAD: return PARAM_ALOAD_GADGET_SP_DELTA;
        case GadgetType::STORE: return PARAM_STORE_GADGET_SP_DELTA;
        case GadgetType::ASTORE: return PARAM_ASTORE_GADGET_SP_DELTA;
        default:
            throw runtime_exception("Node::get_param_num_gadget_sp_inc(): got unsupported gadget type");
    }
}

int Node::get_param_num_gadget_addr(){
    switch( type ){
        case GadgetType::MOV_REG: return PARAM_MOVREG_GADGET_ADDR;
        case GadgetType::AMOV_REG: return PARAM_AMOVREG_GADGET_ADDR;
        case GadgetType::MOV_CST: return PARAM_MOVCST_GADGET_ADDR;
        case GadgetType::AMOV_CST: return PARAM_AMOVCST_GADGET_ADDR;
        case GadgetType::LOAD: return PARAM_LOAD_GADGET_ADDR;
        case GadgetType::ALOAD: return PARAM_ALOAD_GADGET_ADDR;
        case GadgetType::STORE: return PARAM_STORE_GADGET_ADDR;
        case GadgetType::ASTORE: return PARAM_ASTORE_GADGET_ADDR;
        default:
            throw runtime_exception("Node::get_param_num_gadget_addr(): got unsupported gadget type");
    }
}

int Node::get_param_num_gadget_jmp_reg(){
    switch( type ){
        case GadgetType::MOV_REG: return PARAM_MOVREG_GADGET_JMP_REG;
        case GadgetType::AMOV_REG: return PARAM_AMOVREG_GADGET_JMP_REG;
        case GadgetType::MOV_CST: return PARAM_MOVCST_GADGET_JMP_REG;
        case GadgetType::AMOV_CST: return PARAM_AMOVCST_GADGET_JMP_REG;
        case GadgetType::LOAD: return PARAM_LOAD_GADGET_JMP_REG;
        case GadgetType::ALOAD: return PARAM_ALOAD_GADGET_JMP_REG;
        case GadgetType::STORE: return PARAM_STORE_GADGET_JMP_REG;
        case GadgetType::ASTORE: return PARAM_ASTORE_GADGET_JMP_REG;
        default:
            throw runtime_exception("Node::get_param_num_gadget_jmp_reg(): got unsupported gadget type");
    }
}

int Node::get_param_num_dst_reg(){
    switch( type ){
        case GadgetType::MOV_REG: return PARAM_MOVREG_DST_REG;
        case GadgetType::AMOV_REG: return PARAM_AMOVREG_DST_REG;
        case GadgetType::MOV_CST: return PARAM_MOVCST_DST_REG;
        case GadgetType::AMOV_CST: return PARAM_AMOVCST_DST_REG;
        case GadgetType::LOAD: return PARAM_LOAD_DST_REG;
        case GadgetType::ALOAD: return PARAM_ALOAD_DST_REG;
        default:
            throw runtime_exception("Node::get_param_num_dst_reg(): got unsupported gadget type");
    }
}

addr_t _get_valid_gadget_address(Gadget* gadget, Arch* arch, Constraint* constraint){
    for( addr_t addr : gadget->addresses){
        if( !constraint || constraint->bad_bytes.is_valid_address(addr, arch->octets))
            return addr;
    }
    throw runtime_exception("Fatal error: couldn't get valid gadget address. This should not happen ! ");
}

void Node::assign_gadget(Gadget* gadget, Arch* arch, Constraint* constraint){
    addr_t addr = _get_valid_gadget_address(gadget, arch, constraint);
    affected_gadget = gadget;
    // Set gadget parameters depending on type
    params[get_param_num_gadget_addr()].value = addr;
    params[get_param_num_gadget_sp_inc()].value = gadget->sp_inc;
    params[get_param_num_gadget_jmp_reg()].value = gadget->jmp_reg;
    params[get_param_num_gadget_sp_delta()].value = gadget->max_sp_inc - gadget->sp_inc;
}

void Node::apply_assertion(){
    assertion.clear();
    node_assertion.to_assertion(*this, &assertion);
}

/* ===============  Strategy Graphs ============== */
/* =============================================== */

StrategyGraph::StrategyGraph(): has_gadget_selection(false), _depth(-1){};

/* =========== Basic manips on edges/nodes =========== */
node_t StrategyGraph::new_node(GadgetType t){
    nodes.push_back(Node(nodes.size(), t));
    return nodes.size()-1;
}

void StrategyGraph::disable_node(node_t node){
    nodes[node].id = -1;
}

string StrategyGraph::new_name(string base){
    return name_generator.new_name(base);
}

// Make the edges that point to the parameter 'curr_param_type' on 'curr_node' point to 'new_node'
// and 'new_param_type'. The edges to 'curr_node' are removed and the new edges are also added as
// 'in' edges in the new node.
void StrategyGraph::redirect_incoming_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type){
    Node& curr = nodes[curr_node];
    Node& newn = nodes[new_node];
    bool changed = false;
    for( node_t p : curr.param_edges.in ){
        Node& prev = nodes[p];
        // Redirect parameters
        for( int p = 0; p < prev.nb_params(); p++ ){
            Param& param = prev.params[p];
            if( param.is_dependent() && param.dep_node == curr_node && param.dep_param_type == curr_param_type ){
                // Change param dep node and type
                param.dep_node = new_node;
                param.dep_param_type = new_param_type;
                changed = true;
            }
        }
        if( changed ){
            // Remove previous outgoing edge
            prev.param_edges.out.erase(std::remove(prev.param_edges.out.begin(), prev.param_edges.out.end(), curr_node), prev.param_edges.out.end());
            // Add new outgoing edge
            prev.param_edges.out.push_back(new_node);
            // Add new incoming edge to new node
            newn.param_edges.in.push_back(prev.id);
        }
    }
}

void StrategyGraph::redirect_incoming_strategy_edges(node_t curr_node, node_t new_node){
    Node& curr = nodes[curr_node];
    Node& newn = nodes[new_node];
    
    for( node_t p : curr.strategy_edges.in ){
        Node& prev = nodes[p];
        if( std::count(prev.strategy_edges.out.begin(), prev.strategy_edges.out.end(), curr_node) > 0 ){
            // Erase previous outgoing edges to curr
            prev.strategy_edges.out.erase(std::remove(prev.strategy_edges.out.begin(), prev.strategy_edges.out.end(), curr_node), prev.strategy_edges.out.end());
            if( new_node != prev.id ){ // If new node depends on curr_node, don't redirect it to itself
                // Add new outgoing to new_node
                prev.strategy_edges.out.push_back(new_node);
                // Add new incoming in new_node
                newn.strategy_edges.in.push_back(prev.id);
            }
        }
    }
}

// Redirect edges that come from parameter 'curr_param_type' in 'curr_node' to make them come from
// parameter 'new_param_type' from 'new_node'
void StrategyGraph::redirect_outgoing_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type){
    Node& curr = nodes[curr_node];
    Node& newn = nodes[new_node];
    Param& param = curr.params[curr_param_type];
    if( param.is_dependent() ){
        // Add outgoing edge in new node
        if( std::count(newn.param_edges.out.begin(), newn.param_edges.out.end(), param.dep_node) == 0 ){
            newn.param_edges.out.push_back(param.dep_node);
        }
        // Remove incoming edge from curr in next node
        Node& next = nodes[param.dep_node];
        next.param_edges.in.erase(std::remove(next.param_edges.in.begin(),next.param_edges.in.end(), curr_node), next.param_edges.in.end());
        // And replace it
        next.param_edges.in.push_back(new_node);
    }
}

void StrategyGraph::redirect_outgoing_strategy_edges(node_t curr_node, node_t new_node){
    Node& curr = nodes[curr_node];
    Node& newn = nodes[new_node];
    
    for( node_t n : curr.strategy_edges.out ){
        Node& next = nodes[n];
        if( std::count(next.strategy_edges.in.begin(), next.strategy_edges.in.end(), curr_node) > 0 ){
            // Erase next incoming edges from curr
            next.strategy_edges.in.erase(std::remove(next.strategy_edges.in.begin(), next.strategy_edges.in.end(), curr_node), next.strategy_edges.in.end());
            if( new_node != next.id ){ // If new node depends on curr_node, don't redirect it to itself
                // Add new incoming from new_node
                next.strategy_edges.in.push_back(new_node);
                // Add new outgoing in new_node
                newn.strategy_edges.out.push_back(next.id);
            }
        }
    }
}

void StrategyGraph::add_strategy_edge(node_t from, node_t to){
    nodes[from].strategy_edges.out.push_back(to);
    nodes[to].strategy_edges.in.push_back(from);
}

void StrategyGraph::add_param_edge(node_t from, node_t to){
    nodes[from].param_edges.out.push_back(to);
    nodes[to].param_edges.in.push_back(from);
}

/* =============== Strategy Rules ============== */

/* MovReg dst_reg, src_reg
 * =======================
 * MovReg R1, src_reg
 * MovReg dst_reg, R1 
 * ======================= */
bool StrategyGraph::rule_mov_reg_transitivity(node_t n){
    
    if( nodes[n].type != GadgetType::MOV_REG ){
        return false;
    }
    
    // Get/Create nodes
    node_t n1 = new_node(GadgetType::MOV_REG);
    node_t n2 = new_node(GadgetType::MOV_REG);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];

    // Modify parameters
    node1.params[PARAM_MOVREG_SRC_REG] = node.params[PARAM_MOVREG_SRC_REG];
    node1.params[PARAM_MOVREG_DST_REG].make_reg(node2.id, PARAM_MOVREG_SRC_REG); // node1 dst is R1, depends on R1 in node2
    node2.params[PARAM_MOVREG_SRC_REG].make_reg(0, false); // node2 src is R1
    node2.params[PARAM_MOVREG_DST_REG] = node.params[PARAM_MOVREG_DST_REG];
    
    // Node1 must end with a ret
    node1.branch_type = BranchType::RET;
    
    // Add new edges
    add_strategy_edge(node1.id, node2.id);
    add_param_edge(node1.id, node2.id);

    // Redirect the different params and edges
    // Any arc incoming to node:src_reg goes to node1:src_reg
    redirect_incoming_param_edges(node.id, PARAM_MOVREG_SRC_REG, node1.id, PARAM_MOVREG_SRC_REG);

    // Any arc outgoing from node:dst_reg now goes out from node2:dst_reg
    redirect_outgoing_param_edges(node.id, PARAM_MOVREG_DST_REG, node2.id, PARAM_MOVREG_DST_REG);
    
    // Redirect strategy edges
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node2.id);
    
    // Disable node
    disable_node(node.id);
    
    return true;
}


/* MovCst dst_reg, src_cst
 * =======================
 * MovReg R1, src_cst
 * MovReg dst_reg, R1 
 * ======================= */
bool StrategyGraph::rule_mov_cst_transitivity(node_t n){
    
    if( nodes[n].type != GadgetType::MOV_CST ){
        return false;
    }
    
    // Get/Create nodes
    node_t n1 = new_node(GadgetType::MOV_CST);
    node_t n2 = new_node(GadgetType::MOV_REG);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];

    // Modify parameters
    node1.params[PARAM_MOVCST_SRC_CST] = node.params[PARAM_MOVCST_SRC_CST];
    node1.params[PARAM_MOVCST_SRC_CST].name = new_name("cst"); // copy the constant but change the name 
    node1.params[PARAM_MOVCST_DST_REG].make_reg(node2.id, PARAM_MOVREG_SRC_REG); // node1 dst is R1, depends on R1 in node2
    node2.params[PARAM_MOVREG_SRC_REG].make_reg(0, false); // node2 src is R1
    node2.params[PARAM_MOVREG_DST_REG] = node.params[PARAM_MOVREG_DST_REG];
    
    // Node1 must end with a ret
    node1.branch_type = BranchType::RET;
    
    // Add new edges
    add_strategy_edge(node1.id, node2.id);
    add_param_edge(node1.id, node2.id);

    // Redirect the different params and edges
    // Any arc incoming to node:src_cst goes to node1:src_cst
    redirect_incoming_param_edges(node.id, PARAM_MOVCST_SRC_CST, node1.id, PARAM_MOVCST_SRC_CST);

    // Any arc outgoing from node:dst_reg now goes out from node2:dst_reg
    redirect_outgoing_param_edges(node.id, PARAM_MOVCST_DST_REG, node2.id, PARAM_MOVCST_DST_REG);
    
    // Redirect strategy edges
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node2.id);
    
    // Disable node
    disable_node(node.id);
    
    return true;
}

/* MovCst dst_reg, src_cst
 * =======================
 * MovReg R1, src_cst
 * MovReg dst_reg, R1 
 * ======================= */
bool StrategyGraph::rule_generic_transitivity(node_t n){
    
    int i = 0;

    if( nodes[n].type != GadgetType::MOV_CST &&
        nodes[n].type != GadgetType::MOV_REG && 
        nodes[n].type != GadgetType::AMOV_CST && 
        nodes[n].type != GadgetType::AMOV_REG &&
        nodes[n].type != GadgetType::LOAD &&
        nodes[n].type != GadgetType::ALOAD ){
        return false;
    }
    
    // Get/Create nodes
    node_t n1 = new_node(nodes[n].type);
    node_t n2 = new_node(GadgetType::MOV_REG);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];
    
    
    node1 = node; // Copy node to node1
    node1.id = n1; // But keep id
    // Modify dst_reg
    node1.params[node1.get_param_num_dst_reg()].make_reg(node2.id, PARAM_MOVREG_SRC_REG);
    
    // Set node2 with the reg transitivity gadget
    node2.params[PARAM_MOVREG_SRC_REG].make_reg(-1, false); // free reg
    node2.params[PARAM_MOVREG_DST_REG] = node.params[node.get_param_num_dst_reg()]; // Same dst reg as initial query in node
    
    // Node1 must end with a ret
    node1.branch_type = BranchType::RET;
    // Node2 same as node
    node2.branch_type = node.branch_type;

    // Add new edges
    add_strategy_edge(node1.id, node2.id);
    add_param_edge(node1.id, node2.id);

    // Redirect input params arcs from node to node1
    for( i = 0; i < MAX_PARAMS; i++){
        redirect_incoming_param_edges(node.id, i, node1.id, i);
    }

    // Redirect outgoing dst_reg arcs
    redirect_outgoing_param_edges(node.id, node.get_param_num_dst_reg(), node2.id, node.get_param_num_dst_reg());

    // Redirect strategy edges
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node2.id);
    
    // Disable previous node
    disable_node(node.id);
    
    return true;
}

/* MovCst dst_reg, src_cst
+ * =======================
+ * Load dst_reg, mem(SP + off)
+ * padding(off, src_cst) 
+ * ======================= */
bool StrategyGraph::rule_mov_cst_pop(node_t n, Arch* arch){
    
    if( nodes[n].type != GadgetType::MOV_CST ){
        return false;
    }
    
    // Get/Create nodes
    node_t n1 = new_node(GadgetType::LOAD);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];

    // Modify parameters
    node1.params[PARAM_LOAD_DST_REG] = node.params[PARAM_MOVCST_DST_REG];
    node1.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(arch->sp());
    node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(-1, new_name("stack_offset"), false); // Free offset

    // Set special padding at SP  offset to put the constant
    node1.special_paddings.push_back(ROPPadding());
    // Offset is the offset at which we pop the constant
    node1.special_paddings.back().offset.make_cst(n1, PARAM_LOAD_SRC_ADDR_OFFSET, exprvar(arch->bits, node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].name), new_name("padding_offset"));
    // Padding value is just the constant
    node1.special_paddings.back().value = node.params[PARAM_MOVCST_SRC_CST];
    node1.special_paddings.back().value.name = new_name("padding_value"); // Get a new name for the value parameter

    // Add a constraint: the offset of the pop must not be too big (max 160)
    node1.strategy_constraints.push_back(
        [](Node* node, StrategyGraph* graph){
            return node->params[PARAM_LOAD_SRC_ADDR_OFFSET].value < 160 &&
                   node->params[PARAM_LOAD_SRC_ADDR_OFFSET].value >= 0;
        }
    );
    
    // Add a constraint: the offset of the pop must not be bigger than the sp inc
    node1.assigned_gadget_constraints.push_back(
        [](Node* node, StrategyGraph* graph){
            return node->params[PARAM_LOAD_SRC_ADDR_OFFSET].value < node->affected_gadget->sp_inc;
        }
    );

    // Redirect the different params and edges
    // Leave incoming args to the constant (do nothing)
    // Any arc outgoing from node:dst_reg now goes out from node1:dst_reg
    redirect_outgoing_param_edges(node.id, PARAM_MOVCST_DST_REG, node1.id, PARAM_LOAD_DST_REG);

    // Redirect strategy edges
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node1.id);

    // Disable node
    disable_node(node.id);
    
    return true;
}

/* <Any type>; ret
 * ====================
 * R1 <- @(next gadget)
 * <Any type>; jmp R1; 
 */
bool StrategyGraph::rule_generic_adjust_jmp(node_t n, Arch* arch){
    // Only apply on "RET" nodes (and "ANY" by extension)
    if( nodes[n].branch_type != BranchType::RET &&
        nodes[n].branch_type != BranchType::ANY ){
        return false;
    }
    
    // Get/Create nodes
    node_t n1 = new_node(GadgetType::MOV_CST); // Node to adjust the jmp reg
    node_t n_ret = new_node(GadgetType::LOAD); // Node of the 'adjust gadget' (ret N basically)
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node_ret = nodes[n_ret];
        
    // Change return type to JMP in node
    node.branch_type = BranchType::JMP;
    
    // Set the 'adjust gadget' node. It must make the PC that the next value one the
    // stack after the 'jmp' gadget is executed
    node_ret.params[PARAM_LOAD_DST_REG].make_reg(arch->pc()); // Dest reg is PC
    node_ret.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(arch->sp()); // addr reg is SP (pop from the stack)
    node_ret.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst( n, node.get_param_num_gadget_sp_delta(), nullptr, new_name("adjust_jmp_offset"));
    add_param_edge(node_ret.id, node.id);
    node_ret.indirect = true; // This node is 'indirect' (gadget not added explicitely on the stack)

    // Set the 'pre-jmp' gadget. It sets the jmp reg to the address of the 'adjust gadget'.
    // Dest reg of node1 is the jmp reg of node
    node1.params[PARAM_MOVCST_DST_REG].make_reg(n, node.get_param_num_gadget_jmp_reg());
    // Src cst of node1 is the address of the adjust gadget
    node1.params[PARAM_MOVCST_SRC_CST].make_cst(node_ret.id, node_ret.get_param_num_gadget_addr(), nullptr, new_name("adjust_jmp_addr"));
    add_param_edge(node1.id, node.id);
    add_param_edge(node1.id, node_ret.id);

    // Redirect strategy edges
    redirect_incoming_strategy_edges(node.id, node1.id);
    add_strategy_edge(node1.id, node.id); // Add after so it's not redirected ;)
    
    // Add callback that checks that the jmp reg is not implied in the operation
    // for example if the gadget is mov eax,ebx; jmp ebx; and we adjust ebx then
    // the semantics are corrupted because ebx's value will be overwritten with 
    // the address of the 'adjust-gadget'
    node.assigned_gadget_constraints.push_back(
        [](Node* node, StrategyGraph* graph){
            switch( node->type ){
                case GadgetType::MOV_CST:
                    return node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_MOVCST_DST_REG].value;
                case GadgetType::MOV_REG:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_MOVREG_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_MOVREG_SRC_REG].value;
                case GadgetType::AMOV_CST:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVCST_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVCST_SRC_REG].value;
                case GadgetType::AMOV_REG:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVREG_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVREG_SRC_REG1].value &&
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVREG_SRC_REG2].value;
                case GadgetType::LOAD:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_LOAD_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_LOAD_SRC_ADDR_REG].value;
                case GadgetType::ALOAD:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ALOAD_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ALOAD_SRC_ADDR_REG].value;
                case GadgetType::STORE:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_STORE_SRC_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_STORE_DST_ADDR_REG].value;
                case GadgetType::ASTORE:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ASTORE_SRC_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ASTORE_DST_ADDR_REG].value;
                default:
                    throw runtime_exception("rule_generic_adjust_jmp(): constraint callback got unsupported GadgetType! ");
            }
        }
    );
    
    return true;
}


/* ===============  Ordering ============== */
void StrategyGraph::_dfs_strategy_explore(vector<node_t>& marked, node_t n){
    if( nodes[n].is_disabled() || nodes[n].is_indirect() || std::count(dfs_strategy.begin(), dfs_strategy.end(), n))
        return; // Ignore disabled or indirect nodes
    if( std::count(marked.begin(), marked.end(), n) != 0 ){
        throw runtime_exception("StrategyGraph: strategy DFS: unexpected cycle detected!");
    }else{
        marked.push_back(n);
    }
    nodes[n].depth = 0;
    for( node_t n2 : nodes[n].strategy_edges.out ){
        _dfs_strategy_explore(marked, n2);
        // Adjust depth
        if( nodes[n2].depth +1 < nodes[n].depth)
            nodes[n].depth = nodes[n2].depth +1;
    }
    dfs_strategy.push_back(n);
}

void StrategyGraph::compute_dfs_strategy(){
    vector<node_t> marked;
    dfs_strategy.clear();
    for( Node& node : nodes ){
        if( node.is_disabled() || (std::count(marked.begin(), marked.end(), node.id) != 0))
            continue;
        else
            _dfs_strategy_explore(marked, node.id);
    }
}

void StrategyGraph::_dfs_params_explore(vector<node_t>& marked, node_t n){
    if( std::count(dfs_params.begin(), dfs_params.end(), n))
        return; // Ignore already visited nodes
    // Note: we don't ignore disabled nodes because they can hold constants parameters
    // from which other nodes depend
    if( std::count(marked.begin(), marked.end(), n) != 0 ){
        throw runtime_exception("StrategyGraph: params DFS: unexpected cycle detected!");
    }else{
        marked.push_back(n);
    }
    for( node_t n2 : nodes[n].param_edges.out ){
        _dfs_params_explore(marked, n2);
    }
    marked.pop_back(); // Unmark the node for the current exploration
    dfs_params.push_back(n);
}

void StrategyGraph::compute_dfs_params(){
    vector<node_t> marked;
    dfs_params.clear();
    for( Node& node : nodes ){
        if( node.is_disabled() || (std::count(marked.begin(), marked.end(), node.id) != 0))
            continue;
        else
            _dfs_params_explore(marked, node.id);
    }
}

/* =============== Gadget Selection ============== */
// Get the concrete value for parameters depending on other 
// gadgets. This functions expects all the parameters in nodes that
// are used by the 'param' argument to have been resolved already
void StrategyGraph::_resolve_param(Param& param){
    if( param.is_dependent()){
        if( param.type == ParamType::REG ){
            param.value = nodes[param.dep_node].params[param.dep_param_type].value;
        }else if( param.type == ParamType::CST){
            if( param.expr == nullptr ){
                // If not expr, just take the value of the other param
                param.value = nodes[param.dep_node].params[param.dep_param_type].value;
            }else{
                param.value = param.expr->concretize(&params_ctx);
            }
        }else{
            throw runtime_exception("_resolve_param(): got unsupported param type");
        }
    }
    // If constant, update the context
    if( param.type == ParamType::CST){
        params_ctx.set(param.name, param.value);
    }
}

void StrategyGraph::_resolve_all_params(node_t n){
    Node& node = nodes[n];
    // Resolve normal parameters
    for( int p = 0; p < node.nb_params(); p++){
        _resolve_param(node.params[p]);
    }
    // Resolve special paddings
    for( ROPPadding& padd : node.special_paddings ){
        _resolve_param(padd.offset);
        _resolve_param(padd.value);   
    }
}


// Wrapper that queries the database to find the list of gadgets that match
// a strategy node
const vector<Gadget*>& StrategyGraph::_get_matching_gadgets(GadgetDB& db, node_t n){
    Node& node = nodes[n];
    reg_t src_reg, src_reg2, dst_reg, dst_addr_reg, src_addr_reg;
    cst_t src_cst, src_addr_cst, dst_addr_cst;
    Op src_op, op;

    // resolve parameters for node 'n'
    _resolve_all_params(n);

    switch( node.type ){
        // make query
        case GadgetType::MOV_REG:
            src_reg = node.params[PARAM_MOVREG_SRC_REG].value;
            dst_reg = node.params[PARAM_MOVREG_DST_REG].value;
            return db.get_mov_reg(dst_reg, src_reg);
        case GadgetType::MOV_CST:
            dst_reg = node.params[PARAM_MOVCST_DST_REG].value;
            src_cst = node.params[PARAM_MOVCST_SRC_CST].value;
            return db.get_mov_cst(dst_reg, src_cst);
        case GadgetType::AMOV_CST:
            dst_reg = node.params[PARAM_AMOVCST_DST_REG].value;
            src_reg = node.params[PARAM_AMOVCST_SRC_REG].value;
            src_op = (Op)node.params[PARAM_AMOVCST_SRC_OP].value;
            src_cst = node.params[PARAM_AMOVCST_SRC_CST].value;
            return db.get_amov_cst(dst_reg, src_reg, src_op, src_cst);
        case GadgetType::AMOV_REG:
            dst_reg = node.params[PARAM_AMOVREG_DST_REG].value;
            src_reg = node.params[PARAM_AMOVREG_SRC_REG1].value;
            src_op = (Op)node.params[PARAM_AMOVREG_SRC_OP].value;
            src_reg2 = node.params[PARAM_AMOVREG_SRC_REG2].value;
            return db.get_amov_reg(dst_reg, src_reg, src_op, src_reg2);
        case GadgetType::LOAD:
            dst_reg = node.params[PARAM_LOAD_DST_REG].value;
            src_addr_reg = node.params[PARAM_LOAD_SRC_ADDR_REG].value;
            src_addr_cst = node.params[PARAM_LOAD_SRC_ADDR_OFFSET].value;
            return db.get_load(dst_reg, src_addr_reg, src_addr_cst);
        case GadgetType::ALOAD:
            dst_reg = node.params[PARAM_ALOAD_DST_REG].value;
            op = (Op)node.params[PARAM_ALOAD_OP].value;
            src_addr_reg = node.params[PARAM_ALOAD_SRC_ADDR_REG].value;
            src_addr_cst = node.params[PARAM_ALOAD_SRC_ADDR_OFFSET].value;
            return db.get_aload(dst_reg, op, src_addr_reg, src_addr_cst);
        case GadgetType::STORE:
            dst_addr_reg = node.params[PARAM_STORE_DST_ADDR_REG].value;
            dst_addr_cst = node.params[PARAM_STORE_DST_ADDR_OFFSET].value;
            src_reg = node.params[PARAM_STORE_SRC_REG].value;
            return db.get_store(dst_addr_reg, dst_addr_cst, src_reg);
        case GadgetType::ASTORE:
            dst_addr_reg = node.params[PARAM_ASTORE_DST_ADDR_REG].value;
            dst_addr_cst = node.params[PARAM_ASTORE_DST_ADDR_OFFSET].value;
            op = (Op)node.params[PARAM_ASTORE_OP].value;
            src_reg = node.params[PARAM_ASTORE_SRC_REG].value;
            return db.get_astore(dst_addr_reg, dst_addr_cst, op, src_reg);
        default:
            throw runtime_exception(QuickFmt() << "_get_matching_gadgets(): got unsupported node type " << (int)node.type >> QuickFmt::to_str);
    }
}

// Wrapper to the database to get a list of gadgets that match a strategy node
// that still has non-resolved (also called 'free') parameters. 
// 
// For example it can find all gadgets that match a node: X = ecx + Y
// and return :
//   - mov edx, ecx
//   - add ecx, esi
//   ... 

PossibleGadgets* StrategyGraph::_get_possible_gadgets(GadgetDB& db, node_t n){
    Node& node = nodes[n];
    bool params_status[MAX_PARAMS];
    int p;

    // resolve parameters for node 'n'
    _resolve_all_params(n);

    // Fill a table with parameters status (free or not)
    for( p = 0; p < node.nb_params(); p++){
        params_status[p] = node.params[p].is_free();
    }
    // Make the query to the db
    switch( node.type ){
        case GadgetType::MOV_REG:
            return db.get_possible_mov_reg(node.params[PARAM_MOVREG_DST_REG].value,
                                           node.params[PARAM_MOVREG_SRC_REG].value,
                                           params_status); 
        case GadgetType::AMOV_REG:
            return db.get_possible_amov_reg(node.params[PARAM_AMOVREG_DST_REG].value,
                                           node.params[PARAM_AMOVREG_SRC_REG1].value,
                                           (Op)node.params[PARAM_AMOVREG_SRC_OP].value,
                                           node.params[PARAM_AMOVREG_SRC_REG2].value,
                                           params_status); 
        case GadgetType::MOV_CST:
            return db.get_possible_mov_cst(node.params[PARAM_MOVCST_DST_REG].value,
                                           node.params[PARAM_MOVCST_SRC_CST].value,
                                           params_status);
        case GadgetType::AMOV_CST:
            return db.get_possible_amov_cst(node.params[PARAM_AMOVCST_DST_REG].value,
                                           node.params[PARAM_AMOVCST_SRC_REG].value,
                                           (Op)node.params[PARAM_AMOVCST_SRC_OP].value,
                                           node.params[PARAM_AMOVCST_SRC_CST].value,
                                           params_status); 
        case GadgetType::LOAD:
            return db.get_possible_load(node.params[PARAM_LOAD_DST_REG].value,
                                        node.params[PARAM_LOAD_SRC_ADDR_REG].value,
                                        node.params[PARAM_LOAD_SRC_ADDR_OFFSET].value,
                                        params_status);
        case GadgetType::ALOAD:
            return db.get_possible_aload(node.params[PARAM_ALOAD_DST_REG].value,
                                        (Op)node.params[PARAM_ALOAD_OP].value,
                                        node.params[PARAM_ALOAD_SRC_ADDR_REG].value,
                                        node.params[PARAM_ALOAD_SRC_ADDR_OFFSET].value,
                                        params_status);
        case GadgetType::STORE:
            return db.get_possible_store(node.params[PARAM_STORE_DST_ADDR_REG].value,
                                        node.params[PARAM_STORE_DST_ADDR_OFFSET].value,
                                        node.params[PARAM_STORE_SRC_REG].value,
                                        params_status);
        case GadgetType::ASTORE:
            return db.get_possible_astore(node.params[PARAM_ASTORE_DST_ADDR_REG].value,
                                        node.params[PARAM_ASTORE_DST_ADDR_OFFSET].value,
                                        (Op)node.params[PARAM_ASTORE_OP].value,
                                        node.params[PARAM_ASTORE_SRC_REG].value,
                                        params_status);
        default:
            throw runtime_exception("_get_possible_gadgets(): got unsupported gadget type!");
    }
}

// Must be checked after parameter resolution
bool StrategyGraph::_check_strategy_constraints(Node& node){
    for( constraint_callback_t constr : node.strategy_constraints ){
        if( ! constr(&node, this))
            return false;
    }
    return true;
}

// Must be checked after gadget assignment
bool StrategyGraph::_check_assigned_gadget_constraints(Node& node){
    for( constraint_callback_t constr : node.assigned_gadget_constraints ){
        if( ! constr(&node, this))
            return false;
    }
    return true;
}

/* This function tries to find a gadget selection for a strategy graph.
 It iteratively (the order is the one of the DFS on parameter dependencies) resolves
 parameters and queries the database to find a matching gadget on each node of the
 strategy graph.  
*/
bool StrategyGraph::select_gadgets(GadgetDB& db, Constraint* constraint, Arch* arch, int dfs_idx){
    // Check if constraint is specified with an architecture
    if( constraint && !arch){
        throw runtime_exception("StrategyGraph::select_gadget(): should NEVER be called with a non-NULL constraint and a NULL arch");
    }

    // Otherwise do proper gadget selection : 

    // If root call
    if( dfs_idx == -1 ){
        compute_dfs_params();
        compute_dfs_strategy();
        params_ctx = VarContext(); // New context for params
        has_gadget_selection = select_gadgets(db, constraint, arch, 0);
        return has_gadget_selection;
    }
    
    if( dfs_idx >= dfs_params.size()){
        // DEBUG TODO 4. If last node, try to schedule gadgets :)
        return true;
    }
    
    node_t n = dfs_params[dfs_idx];
    Node& node = nodes[n];
    
    // If the node is a disabled node, juste resolve the parameters
    // and continue the selection 
    if( node.is_disabled()){
        _resolve_all_params(n);
        // Continue to select from next node
        if( select_gadgets(db, constraint, arch, dfs_idx+1) )
                return true;
        else
                return false;
    }
    
    // 1. Try all possibilities for parameters
    if( node.has_free_param() ){
        // Get possible gadgets
        PossibleGadgets* possible = _get_possible_gadgets(db, node.id);
        // 2.a. Try all possible params
        for( auto pos: possible->gadgets ){
            // Update free params
            for( int p = 0; p < node.nb_params(); p++){
                if( node.params[p].is_free())
                    node.params[p].value = pos.first[p];
                if( node.params[p].is_cst())
                    params_ctx.set(node.params[p].name, node.params[p].value);
            }
            // Resolve params again (useful for special paddings that depend
            // on regular parameters such as offsets, etc)
            _resolve_all_params(node.id);

            // Check strategy constraints 
            if( !_check_strategy_constraints(node)){
                continue;
            }

            // Prepare assertion for current parameter choice
            node.apply_assertion();

            // 2.b Try all possible gadgets
            for( Gadget* gadget : *(pos.second) ){
                node.assign_gadget(gadget, arch, constraint);

                // Check assigned gadget constraints and global constraint
                if( !_check_assigned_gadget_constraints(node) || (constraint && !constraint->check(gadget, arch, &node.assertion))){
                    continue;
                }
                // 3. Recursive call on next node 
                if( select_gadgets(db, constraint, arch, dfs_idx+1)){
                    delete possible; possible = nullptr;
                    return true;
                }
            }
        }
        delete possible; possible = nullptr;
    }else{

        // Check strategy constraints 
        if( _check_strategy_constraints(node)){
            
            // Get matching gadgets
            const vector<Gadget*>& gadgets = _get_matching_gadgets(db, node.id);
            
            // 2. Try all possible gadgets (or a subset)
            for( Gadget* gadget : gadgets ){
                node.assign_gadget(gadget, arch, constraint);
                // Prepare assertion for current parameter choice
                node.apply_assertion();
                
                // Check assigned gadget constraints and global constraint
                if( !_check_assigned_gadget_constraints(node) || (constraint && !constraint->check(gadget, arch, &node.assertion))){
                    continue;
                }
                // 3. Recursive call on next node
                if( select_gadgets(db, constraint, arch, dfs_idx+1) ){
                    return true;
                }
            }
        }
    }
    return false;
}

/* Function that builds a ROPChain from a valid gadget selection
   ==> If no valid selection has been computed for the graph, it 
       returns a NULL pointer
*/
ROPChain* StrategyGraph::get_ropchain(Arch* arch, Constraint* constraint){
    vector<node_t>::reverse_iterator rit;
    cst_t default_padding;
    ROPPadding padding;
    int padding_num = -1;

    // Check if there is a selection in the nodes
    if( !has_gadget_selection ){
        return nullptr;
    }

    // Get default padding (validate against bad_bytes if constraint specified)
    default_padding = constraint ? constraint->bad_bytes.get_valid_padding(arch->octets) : cst_sign_trunc(arch->bits, -1);

    ROPChain* ropchain = new ROPChain(arch);
    for( rit = dfs_strategy.rbegin(); rit != dfs_strategy.rend(); rit++ ){
        // Add gadget
        ropchain->add_gadget(nodes[*rit].params[nodes[*rit].get_param_num_gadget_addr()].value, nodes[*rit].affected_gadget);
        // Add padding after gadget
        if( !nodes[*rit].special_paddings.empty()){
            padding = nodes[*rit].special_paddings[0];
            padding_num = 0;
        }

        for( int offset = 0; offset < nodes[*rit].affected_gadget->sp_inc - arch->octets; offset += arch->octets){
            // If special padding
            if( padding_num != -1 && padding.offset.value == offset ){
                ropchain->add_padding(cst_sign_trunc(arch->bits, padding.value.value));
                // Step to next special padding (if any)
                if( padding_num == nodes[*rit].special_paddings.size()-1 ){
                    // No more special paddings
                    padding_num = -1;
                }else{
                    // Next special padding
                    padding = nodes[*rit].special_paddings[++padding_num];
                }                
            }
            // Else default padding
            else{
                ropchain->add_padding(default_padding);
            }
        }
    }
    return ropchain;
}

StrategyGraph* StrategyGraph::copy(){
    StrategyGraph* new_graph = new StrategyGraph();
    // Copy nodes
    new_graph->nodes = nodes;
    // Copy name generator (to avoid create new names for 0 that colision with previous ones)
    new_graph->name_generator = name_generator;
    return new_graph;
}

/* ================ Printing =================== */
ostream& operator<<(ostream& os, Param& param){
    string tab = "\t";
    os << tab << "Param:" << std::endl;
    os << tab << "\t Value: " << param.value << std::endl;
    os << tab << "\t Fixed?: " << param.is_fixed << std::endl;
    os << tab << "\t Dep on node: " << param.dep_node << std::endl;
    os << tab << "\t Dep on param type: " << param.dep_param_type << std::endl;
    if( param.expr != nullptr )
        os << tab << "\t Expr: " << param.expr << std::endl;
    return os;
}

ostream& operator<<(ostream& os, Node& node){
    os << "Node " << std::dec << node.id << ":";
    os << "\n\tGadget type:  " << (int)node.type;
    os << "\n\tBranch type:  " << (int)node.branch_type;
    os << "\n\tIncoming strategy edges: ";
    for( node_t n : node.strategy_edges.in )
        os << n << "  ";
    os << "\n\tOutgoing strategy edges: ";
    for( node_t n : node.strategy_edges.out )
        os << n << "  ";
    os << "\n\tIncoming param edges: ";
    for( node_t n : node.param_edges.in )
        os << n << "  ";
    os << "\n\tOutgoing param edges: ";
    for( node_t n : node.param_edges.out )
        os << n << "  ";
    
    os << "\n\tParams: \n";
    for( int p = 0; p < node.nb_params(); p++){
        os << node.params[p] << std::endl;
    }
    
    os << "\n\tSpecial paddings: \n";
    for( ROPPadding& padding : node.special_paddings){
        os << "offset: " << padding.offset << ", value: " << padding.value << std::endl;
    }

    os << std::endl;
    return os;
}

ostream& operator<<(ostream& os, StrategyGraph& graph){
    os << "STRATEGY GRAPH\n==============";
    
    os << "\n\tDFS strategy: "; 
    for( node_t n : graph.dfs_strategy ){
        os << n << " ";
    }
    
    os << "\n\tDFS params: "; 
    for( node_t n : graph.dfs_params ){
        os << n << " ";
    }
    
    os << std::endl;
    for( Node& n : graph.nodes ){
        os << n;
    }

    return os;
}
