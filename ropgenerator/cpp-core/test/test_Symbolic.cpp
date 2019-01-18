#include "Symbolic.hpp"

int main(){
    IRBlock* block;
    Semantics * s;
    int i; 
    
    for( i = 0; i < 1; i++){
        block = new IRBlock();
        // Add instructions
        //block->add_instr(IRInstruction(IR_ADD, ArgReg(0,64), ArgCst(19,64), ArgTmp(1,64))); 
        //block->add_instr(IRInstruction(IR_LDM, ArgTmp(1,64), ArgEmpty(), ArgTmp(2,64)));
        block->add_instr(IRInstruction(IR_STR, ArgReg(3,1), ArgEmpty(), ArgTmp(0,8)));
        block->add_instr(IRInstruction(IR_ADD, ArgReg(4,8), ArgTmp(0,8), ArgTmp(1,8))); 
        
        // Execute
        s = block->compute_semantics();
        s->simplify();
        std::cout << s;  
        delete s;
        delete block; 
    }
    return 0; 
}
