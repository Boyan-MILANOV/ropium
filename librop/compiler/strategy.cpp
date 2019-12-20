#include "strategy.hpp"
#include "exception.hpp"
#include <algorithm>

StrategyGraph::StrategyGraph(): has_gadget_selection(false){};


/* =========== Basic manips on edges/nodes =========== */
node_t StrategyGraph::new_node(GadgetType t){
    node_t n = nodes.size();
    for( node_t i = 0; i < nodes.size(); i++ ){
        if( nodes[i].id == -1 ){
            nodes[i] = Node(i, t);
            return i;
        }
    }
    nodes.push_back(Node(nodes.size(), t));
    return nodes.size()-1;
}

void StrategyGraph::remove_node(node_t node){
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
            // Add new outgoing to new_node
            prev.strategy_edges.out.push_back(new_node);
            // Add new incoming in new_node
            newn.strategy_edges.in.push_back(prev.id);
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
            // Add new incoming from new_node
            next.strategy_edges.in.push_back(new_node);
            // Add new outgoing in new_node
            newn.strategy_edges.out.push_back(next.id);
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
void StrategyGraph::rule_mov_reg_transitivity(node_t n){
    // Get/Create nodes
    node_t n1 = new_node(GadgetType::MOV_REG);
    node_t n2 = new_node(GadgetType::MOV_REG);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];
    if( node.type != GadgetType::MOV_REG ){
        throw runtime_exception("Calling MovReg rule on non-MovReg node!");
    }

    // Modify parameters
    Param& dst_reg = node.params[PARAM_MOVREG_DST_REG];
    Param& src_reg = node.params[PARAM_MOVREG_SRC_REG];
    node1.params[PARAM_MOVREG_SRC_REG] = node.params[PARAM_MOVREG_SRC_REG];
    node1.params[PARAM_MOVREG_DST_REG].make_reg(node2.id, PARAM_MOVREG_SRC_REG); // node1 dst is R1, depends on R1 in node2
    node2.params[PARAM_MOVREG_SRC_REG].make_reg(0, false); // node2 src is R1
    node2.params[PARAM_MOVREG_DST_REG] = node.params[PARAM_MOVREG_DST_REG];
    
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
    
    // Remove node
    remove_node(node.id);
}


/* ===============  Ordering ============== */
void StrategyGraph::_dfs_strategy_explore(vector<node_t>& marked, node_t n){
    if( nodes[n].id == -1 || std::count(dfs_strategy.begin(), dfs_strategy.end(), n))
        return; // Ignore invalid/removed nodes
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
        if( node.id == -1 || (std::count(marked.begin(), marked.end(), node.id) != 0))
            continue;
        else
            _dfs_strategy_explore(marked, node.id);
    }
}

void StrategyGraph::_dfs_params_explore(vector<node_t>& marked, node_t n){
    if( nodes[n].id == -1 || std::count(dfs_params.begin(), dfs_params.end(), n))
        return; // Ignore invalid/removed/already visited nodes
    if( std::count(marked.begin(), marked.end(), n) != 0 ){
        throw runtime_exception("StrategyGraph: params DFS: unexpected cycle detected!");
    }else{
        marked.push_back(n);
    }
    for( node_t n2 : nodes[n].param_edges.out ){
        _dfs_params_explore(marked, n2);
    }
    dfs_params.push_back(n);
}

void StrategyGraph::compute_dfs_params(){
    vector<node_t> marked;
    dfs_params.clear();
    for( Node& node : nodes ){
        if( node.id == -1 || (std::count(marked.begin(), marked.end(), node.id) != 0))
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
    if( param.is_fixed)
        return;
    else if( param.is_free())
        throw runtime_exception("_resolved_param(): called on free parameter");


    if( param.type == ParamType::REG ){
        param.value = nodes[param.dep_node].params[param.dep_param_type].value;
    }else if( param.type == ParamType::CST){
        param.value = param.expr->concretize(&params_ctx);
    }else{
        throw runtime_exception("_resolve_param(): got unsupported param type");
    }
}

// Wrapper that queries the database to find the list of gadgets that match
// a strategy node
const vector<Gadget*>& StrategyGraph::_get_matching_gadgets(GadgetDB& db, node_t n){
    Node& node = nodes[n];
    reg_t src_reg, src_reg2, dst_reg, dst_addr_reg, src_addr_reg;
    cst_t src_cst, src_addr_cst, dst_addr_cst;
    Op src_op, op;

    // resolve parameters
    for( int p = 0; p < node.nb_params(); p++){
        _resolve_param(node.params[p]);
        if( node.params[p].is_cst() )
            params_ctx.set(node.params[p].name, node.params[p].value);
    }
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
    // resolve parameters
    for( p = 0; p < node.nb_params(); p++){
        if( node.params[p].is_dependent())
            _resolve_param(node.params[p]);
        if( node.params[p].is_cst() )
            params_ctx.set(node.params[p].name, node.params[p].value);
    }
    
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
        
        // TODO: other types
        default:
            throw runtime_exception("_get_possible_gadgets(): got unsupported gadget type!");
    }
}

/* This function tries to find a gadget selection for a strategy graph.
 It iteratively (the order is the one of the DFS on parameter dependencies) resolves
 parameters and queries the database to find a matching gadget on each node of the
 strategy graph.  
*/
bool StrategyGraph::select_gadgets(GadgetDB& db, node_t dfs_idx){
    if( dfs_idx == -1 ){
        compute_dfs_params();
        compute_dfs_strategy();
        params_ctx = VarContext(); // New context for params
        has_gadget_selection = select_gadgets(db, 0);
        return has_gadget_selection;
    }
    
    if( dfs_idx >= dfs_params.size()){
        // DEBUG TODO 4. If last node, try to schedule gadgets :)
        return true;
    }
    
    // 1. Try all possibilities for parameters
    Node& node = nodes[dfs_params[dfs_idx]];
    // std::cout << "DEBUG REC DOING NODE " << node.id << std::endl;
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
            // 2.b Try all possible gadgets
            for( Gadget* gadget : *(pos.second) ){
                node.affected_gadget = gadget;
                // std::cout << "DEBUG, selected " << gadget->asm_str << std::endl;
                // 3. Recursive call on next node 
                if( select_gadgets(db, dfs_idx+1)){
                    delete possible; possible = nullptr;
                    return true;
                }
            }
        }
        delete possible; possible = nullptr;
    }else{
        // Get matching gadgets
        const vector<Gadget*>& gadgets = _get_matching_gadgets(db, node.id);
        // 2. Try all possible gadgets (or a subset)
        for( Gadget* gadget : gadgets ){
            node.affected_gadget = gadget;
            // 3. Recursive call on next node
            if( select_gadgets(db, dfs_idx+1) )
                return true;
        }
    }
    return false;
}

/* Function that builds a ROPChain from a valid gadget selection
   ==> If no valid selection has been computed for the graph, it 
       returns a NULL pointer
*/
ROPChain* StrategyGraph::get_ropchain(Arch* arch){
    vector<node_t>::reverse_iterator rit;
    
    // Check if there is a selection in the nodes
    if( !has_gadget_selection ){
        return nullptr;
    }
    
    // DEBUG TODO: many things
    // For now just return the gadget list
    ROPChain* ropchain = new ROPChain(arch);
    for( rit = dfs_strategy.rbegin(); rit != dfs_strategy.rend(); rit++ ){
        ropchain->add_gadget(nodes[*rit].affected_gadget->addresses[0], nodes[*rit].affected_gadget);
    }
    return ropchain;
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
