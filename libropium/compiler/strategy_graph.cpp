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

Node::Node(int i, GadgetType t):id(i), type(t), branch_type(BranchType::ANY), is_indirect(false), is_disabled(false){
    mandatory_following_node = -1;
    // Add constraints that must always be verified
    assigned_gadget_constraints.push_back(constraint_branch_type); // Matching branch type
};

bool Node::has_mandatory_following_node(){
    return mandatory_following_node != -1;
}

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

bool Node::is_final_param(param_t param){
    return strategy_edges.out.empty() && has_dst_reg_param() && (param == get_param_num_dst_reg());
}

bool Node::is_initial_param(param_t param){
    return is_src_param(param);
}

bool Node::has_dst_reg_param(){
    return  type == GadgetType::MOV_CST || 
            type == GadgetType::MOV_REG ||
            type == GadgetType::AMOV_CST ||
            type == GadgetType::AMOV_REG ||   
            type == GadgetType::LOAD ||
            type == GadgetType::ALOAD; 
}

bool Node::is_src_param(param_t param){
        switch( type ){
        case GadgetType::MOV_REG:
            return param == PARAM_MOVREG_SRC_REG;
        case GadgetType::MOV_CST:
            return false;
        case GadgetType::AMOV_CST:
            return param == PARAM_AMOVCST_SRC_REG;
        case GadgetType::AMOV_REG:
            return param == PARAM_AMOVREG_SRC_REG1 ||
                   param == PARAM_AMOVREG_SRC_REG2;
        case GadgetType::LOAD:
            return param == PARAM_LOAD_SRC_ADDR_REG;
        case GadgetType::ALOAD:
            return param == PARAM_ALOAD_SRC_ADDR_REG;
        case GadgetType::STORE:
            return param == PARAM_STORE_SRC_REG;
        case GadgetType::ASTORE:
            return param == PARAM_ASTORE_SRC_REG;
        default:
            throw runtime_exception(QuickFmt() << "Node::is_src_param(): got unsupported node type " << (int)type >> QuickFmt::to_str);
    }
}

bool Node::is_generic_param(param_t param){
    return param == get_param_num_gadget_addr() || 
           param == get_param_num_gadget_jmp_reg() || 
           param == get_param_num_gadget_sp_delta() || 
           param == get_param_num_gadget_sp_inc();
}


void Node::add_incoming_strategy_edge(node_t src_node){
    if( std::find(strategy_edges.in.begin(), strategy_edges.in.end(), src_node) == strategy_edges.in.end()){
        strategy_edges.in.push_back(src_node);
    }
}

void Node::add_incoming_param_edge(node_t src_node){
    if( std::find(param_edges.in.begin(), param_edges.in.end(), src_node) == param_edges.in.end()){
        param_edges.in.push_back(src_node);
    }
}
void Node::add_outgoing_strategy_edge(node_t dst_node){
    if( std::find(strategy_edges.out.begin(), strategy_edges.out.end(), dst_node) == strategy_edges.out.end()){
        strategy_edges.out.push_back(dst_node);
    }
}

void Node::add_outgoing_param_edge(node_t dst_node){
    if( std::find(param_edges.out.begin(), param_edges.out.end(), dst_node) == param_edges.out.end()){
        param_edges.out.push_back(dst_node);
    }
}

void Node::remove_incoming_strategy_edge(node_t src_node){
    strategy_edges.in.erase(std::remove(strategy_edges.in.begin(), strategy_edges.in.end(), src_node), strategy_edges.in.end());
}

void Node::remove_incoming_param_edge(node_t src_node){
     param_edges.in.erase(std::remove(param_edges.in.begin(), param_edges.in.end(), src_node), param_edges.in.end());
}

void Node::remove_outgoing_strategy_edge(node_t dst_node){
     strategy_edges.out.erase(std::remove(strategy_edges.out.begin(), strategy_edges.out.end(), dst_node), strategy_edges.out.end());
}

void Node::remove_outgoing_param_edge(node_t dst_node){
     param_edges.out.erase(std::remove(param_edges.out.begin(), param_edges.out.end(), dst_node), param_edges.out.end());
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

int Node::get_param_num_src_reg(){
    switch( type ){
        case GadgetType::MOV_REG: return PARAM_MOVREG_SRC_REG;
        case GadgetType::MOV_CST: return PARAM_MOVCST_DST_REG;
        case GadgetType::AMOV_CST: return PARAM_AMOVCST_SRC_REG;
        case GadgetType::STORE: return PARAM_STORE_SRC_REG;
        case GadgetType::ASTORE: return PARAM_ASTORE_SRC_REG;
        default:
            throw runtime_exception("Node::get_param_num_src_reg(): got unsupported gadget type");
    }
}

int Node::get_param_num_src_addr_offset(){
    switch( type ){
        case GadgetType::LOAD: return PARAM_LOAD_SRC_ADDR_OFFSET;
        case GadgetType::ALOAD: return PARAM_ALOAD_SRC_ADDR_OFFSET;
        default:
            throw runtime_exception("Node::get_param_num_src_addr_offset(): got unsupported gadget type");
    }
}

int Node::get_param_num_src_addr_reg(){
    switch( type ){
        case GadgetType::LOAD: return PARAM_LOAD_SRC_ADDR_REG;
        case GadgetType::ALOAD: return PARAM_ALOAD_SRC_ADDR_REG;
        default:
            throw runtime_exception("Node::get_param_num_src_addr_offset(): got unsupported gadget type");
    }
}

int Node::get_param_num_dst_addr_offset(){
    switch( type ){
        case GadgetType::STORE: return PARAM_STORE_DST_ADDR_OFFSET;
        case GadgetType::ASTORE: return PARAM_ASTORE_DST_ADDR_OFFSET;
        default:
            throw runtime_exception("Node::get_param_num_dst_addr_offset(): got unsupported gadget type");
    }
}

int Node::get_param_num_dst_addr_reg(){
    switch( type ){
        case GadgetType::STORE: return PARAM_STORE_DST_ADDR_REG;
        case GadgetType::ASTORE: return PARAM_ASTORE_DST_ADDR_REG;
        default:
            throw runtime_exception("Node::get_param_num_dst_addr_offset(): got unsupported gadget type");
    }
}

bool Node::modifies_reg(int reg_num){
        return (affected_gadget->modified_regs[reg_num]);
}

addr_t _get_valid_gadget_address(Gadget* gadget, Arch* arch, Constraint* constraint){
    for( addr_t addr : gadget->addresses){
        if( !constraint || constraint->bad_bytes.is_valid_address(addr, arch->octets))
            return addr;
    }
    throw strategy_exception("Fatal error: couldn't get valid gadget address. This should not happen ! ");
}

bool Node::assign_gadget(Gadget* gadget, Arch* arch, Constraint* constraint){
    addr_t addr;
    try{
        addr = _get_valid_gadget_address(gadget, arch, constraint);
    }catch(strategy_exception& e){
        return false;
    }

    affected_gadget = gadget;
    // Set gadget parameters depending on type
    params[get_param_num_gadget_addr()].value = addr;
    params[get_param_num_gadget_sp_inc()].value = gadget->sp_inc;
    params[get_param_num_gadget_jmp_reg()].value = gadget->jmp_reg;
    params[get_param_num_gadget_sp_delta()].value = gadget->max_sp_inc - gadget->sp_inc;
    return true;
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
    // Give names to generic parameters
    nodes.back().params[nodes.back().get_param_num_gadget_addr()].make_cst( -1, new_name("gadget_addr"));
    nodes.back().params[nodes.back().get_param_num_gadget_sp_inc()].make_cst( -1, new_name("gadget_sp_inc"));
    nodes.back().params[nodes.back().get_param_num_gadget_jmp_reg()].make_cst( -1, new_name("gadget_jmp_reg"));
    nodes.back().params[nodes.back().get_param_num_gadget_sp_delta()].make_cst( -1, new_name("gadget_sp_delta"));
    return nodes.size()-1;
}

void StrategyGraph::disable_node(node_t node){
    nodes[node].id = -1; // DEBUG TODO see if we can keep the ID when disabling
    nodes[node].is_disabled = true;
}

string StrategyGraph::new_name(string base){
    return name_generator.new_name(base);
}

// Make the edges that point to the parameter 'curr_param_type' on 'curr_node' point to 'new_node'
// and 'new_param_type'. The edges to 'curr_node' are removed and the new edges are also added as
// 'in' edges in the new node.


bool _redirect_param_dep(ParamDep& dep, node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type){
    if( dep.node == curr_node && dep.param_type == curr_param_type ){
        dep.node = new_node;
        dep.param_type = new_param_type;
        return true;
    }else
        return false;
}

void StrategyGraph::redirect_incoming_param_edges(node_t curr_node, param_t curr_param_type, node_t new_node, param_t new_param_type){
    Node& newn = nodes[new_node];
    bool changed = false;
    for( node_t p = 0; p < nodes.size(); p++ ){
        Node& prev = nodes[p];
        // Redirect parameters
        for( int p = 0; p < prev.nb_params(); p++ ){
            Param& param = prev.params[p];
            for( ParamDep& dep : param.deps ){
                changed |= _redirect_param_dep(dep, curr_node, curr_param_type, new_node, new_param_type);
            }
        }
        // Redirect special paddings
        for( ROPPadding padd : prev.special_paddings ){
            for( ParamDep& dep : padd.offset.deps ){
                changed |= _redirect_param_dep(dep, curr_node, curr_param_type, new_node, new_param_type);
            }
            for( ParamDep& dep : padd.value.deps ){
                changed |= _redirect_param_dep(dep, curr_node, curr_param_type, new_node, new_param_type);
            }
        }

        if( changed ){
            // Remove previous outgoing edge
            prev.remove_outgoing_param_edge(curr_node);
            // Add new outgoing edge
            prev.add_outgoing_param_edge(new_node);
            // Add new incoming edge to new node
            newn.add_incoming_param_edge(prev.id);
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
                prev.add_outgoing_strategy_edge(new_node);
                // Add new incoming in new_node
                newn.add_incoming_strategy_edge(prev.id);
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
    for( ParamDep& dep : param.deps ){
        // Add outgoing edge in new node
        newn.add_outgoing_param_edge(dep.node);
        // Remove incoming edge from curr in next node
        Node& next = nodes[dep.node];
        next.remove_incoming_param_edge(curr_node);
        // And replace it
        next.add_incoming_param_edge(new_node);
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
                next.add_incoming_strategy_edge(new_node);
                // Add new outgoing in new_node
                newn.add_outgoing_strategy_edge(next.id);
            }
        }
    }
}

void StrategyGraph::redirect_generic_param_edges(node_t curr_node, node_t new_node){
    Node& curr = nodes[curr_node];
    Node& newn = nodes[new_node];
    bool changed = false;
    // INCOMING EDGES
    for( node_t p : curr.param_edges.in ){
        Node& prev = nodes[p];
        // Redirect parameters
        for( int p = 0; p < prev.nb_params(); p++ ){
            Param& param = prev.params[p];
            for( ParamDep& dep : param.deps){
                if( dep.node == curr_node && curr.is_generic_param(dep.param_type)){
                    // Change param dep node and type
                    dep.node = new_node;
                    changed = true;
                    if( dep.param_type == curr.get_param_num_gadget_addr()){
                        dep.param_type = newn.get_param_num_gadget_addr();
                    }else if( dep.param_type == curr.get_param_num_gadget_jmp_reg()){
                        dep.param_type = newn.get_param_num_gadget_jmp_reg();
                    }else if( dep.param_type == curr.get_param_num_gadget_sp_delta()){
                        dep.param_type = newn.get_param_num_gadget_sp_delta();
                    }else if( dep.param_type == curr.get_param_num_gadget_sp_inc()){
                        dep.param_type = newn.get_param_num_gadget_sp_inc();
                    }else{
                        throw runtime_exception("redirect_generic_param_edges(): got unsuported generic param");
                    }
                }
            }
        }
        if( changed ){
            // Remove previous outgoing edge
            prev.remove_outgoing_param_edge(curr_node);
            // Add new outgoing edge
            prev.add_outgoing_param_edge(new_node);
            // Add new incoming edge to new node
            newn.add_incoming_param_edge(prev.id);
        }
    }
}

void StrategyGraph::add_strategy_edge(node_t from, node_t to){
    nodes[from].add_outgoing_strategy_edge(to);
    nodes[to].add_incoming_strategy_edge(from);
}

void StrategyGraph::add_param_edge(node_t from, node_t to){
    nodes[from].add_outgoing_param_edge(to);
    nodes[to].add_incoming_param_edge(from);
}

void StrategyGraph::add_interference_edge(node_t from, node_t to){
    nodes[from].interference_edges.out.push_back(to);
    // We don't add an incoming edge in 'to' for interference edges
    // because they are not used
}

// Update all parameter edges according to params and paddings
void StrategyGraph::update_param_edges(){
    // First, clear all param edges
    for( Node& node : nodes ){
        node.param_edges.in.clear();
        node.param_edges.out.clear();
    }

    // Check every couple of nodes
    for( int n1 = 0; n1 < nodes.size(); n1++ ){
        Node& node1 = nodes[n1];
        // Check params
        for( int p = 0; p < node1.nb_params(); p++){
            Param& param = node1.params[p];
            for( ParamDep& dep : param.deps ){
                add_param_edge(n1, dep.node);
            }
        }
        // Check paddings
        for( ROPPadding& padd : node1.special_paddings){
            for( ParamDep& dep : padd.offset.deps ){
                if( dep.node != n1 )
                    add_param_edge(n1, dep.node);
            }
            for( ParamDep& dep : padd.value.deps ){
                if( dep.node != n1 )
                    add_param_edge(n1, dep.node);
            }
        }
    }
}

void StrategyGraph::clear_interference_edges(node_t n){
    nodes[n].interference_edges.out.clear();
}


bool StrategyGraph::modifies_reg(node_t n, int reg_num, bool check_following_node){
    bool res = nodes[n].modifies_reg(reg_num);
    if( check_following_node && nodes[n].mandatory_following_node != -1)
        return res || modifies_reg(nodes[n].mandatory_following_node, reg_num, true);
    else
        return res;
}

bool StrategyGraph::has_dependent_param(node_t n, param_t param){
    for( node_t prev : nodes[n].param_edges.in ){
        for( int p = 0; p < nodes[prev].nb_params(); p++ ){
            for( ParamDep& dep : nodes[prev].params[p].deps){
                if( dep.node == n && dep.param_type == param)
                    return true;
            }
        }
    }
    return false;
}


/* ===============  Ordering ============== */
void StrategyGraph::_dfs_strategy_explore(vector<node_t>& marked, node_t n){
    if( nodes[n].is_disabled || nodes[n].is_indirect || std::count(dfs_strategy.begin(), dfs_strategy.end(), n))
        return; // Ignore disabled or indirect nodes
    if( std::count(marked.begin(), marked.end(), n) != 0 ){
        throw runtime_exception("StrategyGraph: strategy DFS: unexpected cycle detected!");
    }else{
        marked.push_back(n);
    }
    for( node_t n2 : nodes[n].strategy_edges.out ){
        _dfs_strategy_explore(marked, n2);
    }
    dfs_strategy.push_back(n);
}

void StrategyGraph::compute_dfs_strategy(){
    vector<node_t> marked;
    dfs_strategy.clear();
    for( Node& node : nodes ){
        if( node.is_disabled || (std::count(marked.begin(), marked.end(), node.id) != 0))
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
        if( node.is_disabled || (std::count(marked.begin(), marked.end(), node.id) != 0))
            continue;
        else
            _dfs_params_explore(marked, node.id);
    }
}

// Returns false <=> the graph contains a cycle
bool StrategyGraph::_dfs_scheduling_explore(vector<node_t>& marked, node_t n){
    if( nodes[n].is_disabled || std::count(dfs_scheduling.begin(), dfs_scheduling.end(), n))
        return true; // Ignore disabled or indirect nodes or already visited ones

    if( std::count(marked.begin(), marked.end(), n) != 0 ){
        // Cycle detected !
        return false;
    }else{
        marked.push_back(n);
    }
    
    
    for( node_t n2 : nodes[n].strategy_edges.out ){
        if( n2 == nodes[n].mandatory_following_node )
            continue;
        if( ! _dfs_scheduling_explore(marked, n2))
            return false;
    }
    for( node_t n2 : nodes[n].interference_edges.out){
        if( n2 == nodes[n].mandatory_following_node )
            continue;
        if( ! _dfs_scheduling_explore(marked, n2))
            return false;
    }
    // Do mandatory node in the end if any
    if( nodes[n].mandatory_following_node != -1 ){
        if( ! _dfs_scheduling_explore(marked, nodes[n].mandatory_following_node))
            return false;
    }
    
    dfs_scheduling.push_back(n);
    return true;
}

bool StrategyGraph::compute_dfs_scheduling(){
    vector<node_t> marked;
    dfs_scheduling.clear();
    for( Node& node : nodes ){
        if( node.is_disabled || node.is_indirect || 
                (std::count(marked.begin(), marked.end(), node.id) != 0)){
            continue;
        }else{
            if( ! _dfs_scheduling_explore(marked, node.id) )
                return false; // Cycle detected
        }
    }
    return true;
}

/* =============== Gadget Selection ============== */
// Get the concrete value for parameters depending on other 
// gadgets. This functions expects all the parameters in nodes that
// are used by the 'param' argument to have been resolved already
void StrategyGraph::_resolve_param(Param& param){
    if( param.is_dependent()){
        if( param.type == ParamType::REG ){
            param.value = nodes[param.deps[0].node].params[param.deps[0].param_type].value;
        }else if( param.type == ParamType::CST){
            if( param.expr == nullptr ){
                // If not expr, just take the value of the other param
                param.value = nodes[param.deps[0].node].params[param.deps[0].param_type].value;
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

// Must be checked after parameter resolution (padding resolution more precisely)
bool StrategyGraph::_check_special_padding_constraints(Node& node, Arch* arch, Constraint* constraint){
    if( !constraint )
        return true;
    for( ROPPadding& padd: node.special_paddings ){
        if( !constraint->bad_bytes.is_valid_address(padd.value.value, arch->octets))
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
        return schedule_gadgets();
    }

    node_t n = dfs_params[dfs_idx];
    Node& node = nodes[n];
    
    // If the node is a disabled node, juste resolve the parameters
    // and continue the selection 
    if( node.is_disabled){
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
            if( !_check_strategy_constraints(node) || !_check_special_padding_constraints(node, arch, constraint)){
                continue;
            }

            // Prepare assertion for current parameter choice
            node.apply_assertion();

            // 2.b Try all possible gadgets
            for( Gadget* gadget : *(pos.second) ){
                if( ! node.assign_gadget(gadget, arch, constraint))
                    continue;

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
                if( ! node.assign_gadget(gadget, arch, constraint))
                    continue;
                
                // Check if paddings have valid values (no bad bytes)
                if( !_check_special_padding_constraints(node, arch, constraint))
                    continue;

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

/* ==================== Scheduling ======================= */
void StrategyGraph::compute_interference_points(){
    // Clear previous points if any
    interference_points.clear();

    // 1. Compute interfering points for regs
    for( Node& node : nodes ){
        if( node.is_disabled ) // Allow indirect nodes though since they will be executed and interfere 
            continue;
        for( int p = 0; p < node.nb_params(); p++ ){
            Param& param = node.params[p];
            if( ! param.is_data_link )
                continue;
            // Check if this link is modified by another node
            for( Node& other : nodes ){
                // If disabled, indirect, or one part of the data link, ignore
                if( other.is_disabled || other.is_indirect || param.depends_on(other.id) || other.id == node.id)
                    continue;
                if( modifies_reg(other.id, param.value, true)){ // True to check also mandatory_following_gadgets
                    // Add interfering point
                    if( node.is_initial_param(p) && !has_dependent_param(node.id, p)){
                        // If the param is initial (input in the chain), other has to be after (can never be before)
                        interference_points.push_back(InterferencePoint(other.id, -1, node.id));
                    }else if( node.is_final_param(p)){
                        // If the param is final (an output of the chain), other must be before
                        interference_points.push_back(InterferencePoint(other.id, node.id, -1));
                    }else{
                        // Add the first param dependency (since it is for regs we assume there's only one dependency)
                        interference_points.push_back(InterferencePoint(other.id, node.id, param.deps[0].node));
                    }
                }
            }
        }
    }
}


bool StrategyGraph::_do_scheduling(int interference_idx){
    bool success = false;
    if( interference_idx == interference_points.size() ){
        // All choices where made for interference edges, try to schedule
        return compute_dfs_scheduling();
    }else{
        // Need to make a choice
        InterferencePoint& inter = interference_points[interference_idx];
        // Choice 1, put it BEFORE
        if( inter.start_node != -1 ){
            EdgeSet saved_edges = nodes[inter.interfering_node].interference_edges; // Save current edges state
            add_interference_edge(inter.interfering_node, inter.start_node);
            if( inter.end_node != -1 ){
                add_interference_edge(inter.interfering_node, inter.end_node);
            }
            if( _do_scheduling(interference_idx+1) ){
                success = true;
            }
            nodes[inter.interfering_node].interference_edges = saved_edges; // Restore edges state
            if( success )
                return true;
        }

        if( inter.end_node != -1 ){
            EdgeSet saved_start_edges;
            EdgeSet saved_end_edges = nodes[inter.end_node].interference_edges; // Save current edges state
            // Choice 2, put if AFTER
            if( inter.start_node != -1 ){
                saved_start_edges = nodes[inter.start_node].interference_edges; // Save current edges state
                add_interference_edge(inter.start_node, inter.interfering_node);
            }
            add_interference_edge( inter.end_node, inter.interfering_node);
            if( _do_scheduling( interference_idx+1 ) ){
                success = true;
            }
            
            if( inter.start_node != -1 ){
                nodes[inter.start_node].interference_edges = saved_start_edges; // Restore interference edges
            }
            nodes[inter.end_node].interference_edges = saved_end_edges; // Restore interference edges
        }
        
        return success;
    }
}

bool StrategyGraph::schedule_gadgets(){
    bool success = false;
    // Compute inteference points
    compute_interference_points();
    // Go through all interference points and try both possibilities
    // (interfering gadget goes BEFORE or AFTER both linked nodes)
    success = _do_scheduling();
    // Clean-up
    interference_points.clear();
    // Return
    return success;
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
    for( rit = dfs_scheduling.rbegin(); rit != dfs_scheduling.rend(); rit++ ){
        if( nodes[*rit].is_indirect ){
            continue; // Skip indirect nodes
        }

        // Add gadget
        ropchain->add_gadget(nodes[*rit].params[nodes[*rit].get_param_num_gadget_addr()].value, nodes[*rit].affected_gadget);
        // Add padding after gadget
        if( !nodes[*rit].special_paddings.empty()){
            padding = nodes[*rit].special_paddings[0];
            padding_num = 0;
        }

        int nb_paddings = nodes[*rit].affected_gadget->sp_inc / arch->octets;
        if( nodes[*rit].affected_gadget->branch_type == BranchType::RET ){
            nb_paddings--;
        }
        
        // Order paddings by offset
        std::sort(nodes[*rit].special_paddings.begin(), nodes[*rit].special_paddings.end(), 
            [](const ROPPadding& padd1, const ROPPadding& padd2){
                return padd1.offset.value < padd2.offset.value;
                });
        
        for( int offset = 0; offset < nb_paddings*arch->octets; offset += arch->octets){
            // If special padding
            if( padding_num != -1 && padding.offset.value == offset ){
                // If the padding is a gadget address (indirect gadget), add a info msg
                string msg = "";
                if( padding.value.is_dependent() && padding.value.deps[0].param_type == nodes[padding.value.deps[0].node].get_param_num_gadget_addr()){
                    msg = nodes[padding.value.deps[0].node].affected_gadget->asm_str;
                    ropchain->add_gadget_address(cst_sign_trunc(arch->bits, padding.value.value), msg);
                }else{
                    ropchain->add_padding(cst_sign_trunc(arch->bits, padding.value.value), msg);
                }

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
    os << tab << "\t Is data link?: " << param.is_data_link << std::endl;
    os << tab << "\t Depends on : " << std::endl;
    for( ParamDep& dep : param.deps){
        os << tab << "\t\t Node: " << dep.node << "  Param: " << dep.param_type << std::endl;
    }
    if( param.expr != nullptr )
        os << tab << "\t Expr: " << param.expr << std::endl;
    if( !param.name.empty())
        os << tab << "\t Name: " << param.name << std::endl;
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
