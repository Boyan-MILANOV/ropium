#include "Symbolic.hpp"

int main(){
    IRBlock block = IRBlock();
    Semantics * s;
    // Add instructions
    block.add_instr(IRInstruction(IR_ADD, ArgReg(0,32), ArgReg(1,32), ArgReg(2,32))); 
    block.add_instr(IRInstruction(IR_MUL, ArgReg(2,32), ArgCst(10, 32), ArgTmp(0,32)));
    block.add_instr(IRInstruction(IR_SUB, ArgTmp(0,16), ArgCst(89,16), ArgReg(4,32)));
    
    
    // Execute
    s = block.compute_semantics();
    std::cout << *s;  
    delete s;
    
    return 0; 
}
