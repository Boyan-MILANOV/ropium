#include "ChainingEngine.hpp"
#include <cstring>

/* *****************************************************
 *             Classes to specify queries 
 * *************************************************** */

DestArg::DestArg(DestType t, int r, cst_t c):type(t), reg(r), cst(c){}  /* For DEST_REG */ 
DestArg::DestArg(DestType t, int addr_r, cst_t addr_c, cst_t c ): type(t), 
    addr_reg(addr_r), addr_cst(addr_c), cst(c){} /* For DEST_MEM */
DestArg::DestArg(DestType t, cst_t addr_c, cst_t c): type(t), addr_cst(addr_c), cst(c){} /* For DEST_CSTMEM */

AssignArg::AssignArg(AssignType t, cst_t c):type(t), cst(c){} /* For ASSIGN_CST */
AssignArg::AssignArg(AssignType t, int r, IROperation o, cst_t c):type(t), reg(r), op(o), cst(c){} /* For ASSIGN_REG_BINOP_CST */
AssignArg::AssignArg(AssignType t, int ar, IROperation o, cst_t ac, cst_t c):type(t), addr_reg(ar), addr_cst(ac), op(o), cst(c){} /* For ASSIGN_MEM_BINOP_CST */
AssignArg::AssignArg(AssignType t, cst_t ac, cst_t c):type(t), addr_cst(ac), cst(c){} /* For ASSIGN_CST_MEM */
AssignArg::AssignArg(AssignType t):type(t){} /* For ASSIGN_SYSCALL and INT80 */ 


/* ***************************************************
 *                    FailRecord
 * ************************************************* */ 


FailRecord::FailRecord(){
    _max_len = false;
    memset(_modified_reg, false, NB_REGS_MAX);
}

FailRecord::FailRecord(bool max_len): _max_len(max_len){
    memset(_modified_reg, false, NB_REGS_MAX);
}
 
bool FailRecord::max_len(){ return _max_len;}
bool FailRecord::modified_reg(int reg_num){ return _modified_reg[reg_num];}
vector<unsigned char>& FailRecord::bad_bytes(){ return _bad_bytes;}

void FailRecord::set_max_len(bool val){ _max_len = val;}
void FailRecord::add_modified_reg(int reg_num){ _modified_reg[reg_num] = true;}
void FailRecord::add_bad_byte(unsigned char bad_byte){ 
    _bad_bytes.push_back(bad_byte); // ! We allow duplicates here for perf reasons
}

