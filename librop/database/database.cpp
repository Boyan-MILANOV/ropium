#include "database.hpp"
#include "exception.hpp"

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
