#include "Symbolic.hpp"
#include "Architecture.hpp"
#include "Gadget.hpp"
#include "Database.hpp"

int main(){
    shared_ptr<IRBlock> block, b2;
    shared_ptr<Gadget> g; 
    int i; 
    
    set_arch(ARCH_X64);
    
    block = make_shared<IRBlock>();
    // Add instructions
    //block->add_instr(IRInstruction(IR_ADD, ArgReg(0,64), ArgCst(19,64), ArgTmp(1,64))); 
    //block->add_instr(IRInstruction(IR_LDM, ArgTmp(1,64), ArgEmpty(), ArgTmp(2,64)));
    block->add_instr(IRInstruction(IR_STR, ArgReg(3,32), ArgEmpty(), ArgTmp(0,32)));
    block->add_instr(IRInstruction(IR_ADD, ArgReg(4,32), ArgTmp(0,32), ArgTmp(1,32)));
    block->add_instr(IRInstruction(IR_STR, ArgTmp(1,32), ArgEmpty(), ArgReg(2,32)));
    
    g = make_shared<Gadget>(block);
    
    init_gadget_db();
    gadget_db()->add(g);

    return 0; 
}
