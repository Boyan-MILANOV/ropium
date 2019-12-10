#include "database.hpp"
#include "exception.hpp"
#include <iostream>

int find_insert_index(vector<Gadget*>& gadget_list, Gadget* gadget){
    int count= gadget_list.size(); 
    int first = 0; 
    int curr;
    while(count > 0){
        curr = first;
        curr += count/2;
        if( gadget_list.at(curr)->lthan(*gadget)){
            first = curr+1;
            count -= count/2 + 1;
        }else{
            count = count/2;
        }
    }
    return first; 
}

gadget_t GadgetDB::add(Gadget* gadget){
    Expr e;
    
    // Add to global list
    gadget->id = all.size();
    all.push_back(gadget);
    
    // Check semantics and classify gadget
    // 1. Register semantics
    for( int reg = 0; reg < gadget->semantics->regs->nb_vars(); reg++){
        e = gadget->semantics->regs->get(reg);
        // MOV_CST
        if( e->is_cst() ){
            mov_cst.add(make_tuple(reg, e->cst()), gadget);
            continue;
        }
        //MOV_REG
        else if( e->is_var() && !e->is_reg(reg) ){
            mov_reg.add(make_tuple(reg, e->reg()), gadget);
            continue;
        }
    }
    return gadget->id;
}

Gadget* GadgetDB::get(gadget_t gadget_num){
    if( gadget_num >= all.size())
        throw runtime_exception("GadgetDB::get() got invalid gadget number");
    return all[gadget_num];
}

vector<Gadget*>& GadgetDB::get_mov_cst(reg_t reg, cst_t cst){
    return mov_cst.get(make_tuple(reg, cst));
}

vector<Gadget*>& GadgetDB::get_mov_reg(reg_t dst_reg, reg_t src_reg){
    return mov_reg.get(make_tuple(dst_reg, src_reg));
}

GadgetDB::~GadgetDB(){
    // Delete all gadgets
    for( auto g : all ){
        delete g;
    }
}
