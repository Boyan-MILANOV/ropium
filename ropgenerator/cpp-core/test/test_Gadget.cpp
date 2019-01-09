#include "Symbolic.hpp"
#include "Gadget.hpp"
#include "Architecture.hpp"

int main(){
    IRBlock* block;
    Gadget *gadget; 
    int i; 
    
    set_arch(ARCH_X86); 
    for( i = 0; i < 1; i++){
        block = new IRBlock();
        // Add instructions
        block->add_instr(IRInstruction(IR_ADD, ArgReg(0,32), ArgReg(1,32), ArgReg(2,32))); 
        block->add_instr(IRInstruction(IR_MUL, ArgReg(2,32), ArgCst(10, 32), ArgTmp(0,32)));
        block->add_instr(IRInstruction(IR_STR, ArgReg(0,32, 30, 15), ArgEmpty(), ArgReg(4,32, 31, 16)));
        block->add_instr(IRInstruction(IR_SUB, ArgTmp(0,32, 15, 0), ArgCst(89,16), ArgReg(4,32, 15, 0)));
        
        block->add_instr(IRInstruction(IR_STM, ArgReg(5,32), ArgEmpty(), ArgReg(6,32)));
        block->add_instr(IRInstruction(IR_STM, ArgReg(7,32), ArgEmpty(), ArgReg(8,32)));
        block->add_instr(IRInstruction(IR_LDM, ArgReg(9,32), ArgEmpty(), ArgReg(10,32)));
        
        gadget = new Gadget(0, block);
        cout << gadget->semantics(); 
        cout << gadget; 
        delete block; 
        delete gadget; 
        
        
    }
    return 0; 
}
