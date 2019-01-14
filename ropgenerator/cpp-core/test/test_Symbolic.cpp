#include "../Symbolic.hpp"

int main(){
    IRBlock* block;
    Semantics * s;
    int i; 
    
    for( i = 0; i < 1; i++){
        block = new IRBlock();
        // Add instructions
        block->add_instr(IRInstruction(IR_ADD, ArgReg(0,32), ArgReg(1,32), ArgReg(2,32))); 
        block->add_instr(IRInstruction(IR_MUL, ArgReg(2,32), ArgCst(10, 32), ArgTmp(0,32)));
        block->add_instr(IRInstruction(IR_STR, ArgReg(0,32, 31, 16), ArgEmpty(), ArgReg(4,32, 30, 15)));
        block->add_instr(IRInstruction(IR_SUB, ArgTmp(0,32, 15, 0), ArgCst(89,16), ArgReg(4,32, 15, 0)));
        
        block->add_instr(IRInstruction(IR_STM, ArgReg(5,32), ArgEmpty(), ArgReg(6,32)));
        block->add_instr(IRInstruction(IR_STM, ArgReg(7,32), ArgEmpty(), ArgReg(8,32)));
        block->add_instr(IRInstruction(IR_LDM, ArgReg(9,32), ArgEmpty(), ArgReg(10,32)));
        
        // Execute
        s = block->compute_semantics();
        s->simplify_expressions(); 
        s->simplify_conditions(); 
        std::cout << s;  
        delete s;
        delete block; 
    }
    return 0; 
}
