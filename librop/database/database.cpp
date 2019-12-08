#include "database.hpp"
#include "exception.hpp"


int find_insert_index(vector<gadget_t>& gadget_list, int gadget_num, vector<Gadget*> all){
    int count= gadget_list.size(); 
    int first = 0; 
    int curr;
    while(count > 0){
        curr = first;
        curr += count/2;
        if( all.at(gadget_list.at(curr))->lthan(*(all.at(gadget_num)))){
            first = curr+1;
            count -= count/2 + 1;
        }else{
            count = count/2;
        }
    }
    return first; 
}

gadget_t GadgetDB::add(Gadget* gadget){
    // Add to global list
    gadget->id = all.size();
    all.push_back(gadget);
    
    // Check semantics and classify gadget
    return gadget->id;
}

Gadget* GadgetDB::get(gadget_t gadget_num){
    if( gadget_num >= all.size())
        throw runtime_exception("GadgetDB::get() got invalid gadget number");
    return all[gadget_num];
}

GadgetDB::~GadgetDB(){
    // Delete all gadgets
    for( auto g : all ){
        delete g;
    }
}
