#include "strategy.hpp"
#include "exception.hpp"
#include <algorithm>

// Create new nodes/edges
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

// Strategy rules

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
    os << "STRATEGY GRAPH\n==============\n";
    for( Node& n : graph.nodes ){
        os << n;
    }
    return os;
}
