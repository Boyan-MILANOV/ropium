#include "expression.hpp"
#include "arch.hpp"
#include "disassembler.hpp"
#include "exception.hpp"
#include "ir.hpp"
#include <cstring>
#include <sstream>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <iostream>

using std::stringstream;

/* =================================== 
 *             ArchX86 
 * ================================== */
ArchX86::ArchX86(): Arch(ArchType::X86, 32, 4, X86_NB_REGS, CPUMode::X86, new DisassemblerX86(CPUMode::X86)){
}

string ArchX86::reg_name(reg_t num){
    switch(num){
        case X86_EAX: return "eax";
        case X86_EBX: return "ebx";
        case X86_ECX: return "ecx";
        case X86_EDX: return "edx";
        case X86_EDI: return "edi";
        case X86_ESI: return "esi";
        case X86_EBP: return "ebp";
        case X86_ESP: return "esp";
        case X86_EIP: return "eip";
        case X86_CS: return "cs";
        case X86_DS: return "ds";
        case X86_ES: return "es";
        case X86_FS: return "fs";
        case X86_GS: return "gs";
        case X86_SS: return "ss";
        case X86_CF: return "cf";
        case X86_PF: return "pf";
        case X86_AF: return "af";
        case X86_ZF: return "zf";
        case X86_SF: return "sf";
        case X86_TF: return "tf";
        case X86_IF: return "if";
        case X86_DF: return "df";
        case X86_OF: return "of";
        case X86_IOPL: return "iopl";
        case X86_VM: return "vm";
        case X86_NT: return "nt";
        case X86_RF: return "rf";
        case X86_AC: return "ac";
        case X86_VIP: return "vip";
        case X86_VIF: return "vif";
        case X86_ID: return "id";
        case X86_TSC: return "tsc";
        default:
            throw runtime_exception("ArchX86::reg_name() got unknown reg num");
    }
    
}
reg_t ArchX86::reg_num(string name){
    if( !name.compare("eax")) return X86_EAX;
    else if( !name.compare("ebx")) return X86_EBX;
    else if( !name.compare("ecx")) return X86_ECX;
    else if( !name.compare("edx")) return X86_EDX;
    else if( !name.compare("edi")) return X86_EDI;
    else if( !name.compare("esi")) return X86_ESI;
    else if( !name.compare("ebp")) return X86_EBP;
    else if( !name.compare("esp")) return X86_ESP;
    else if( !name.compare("eip")) return X86_EIP;
    else if( !name.compare("cs")) return X86_CS;
    else if( !name.compare("ds")) return X86_DS;
    else if( !name.compare("es")) return X86_ES;
    else if( !name.compare("fs")) return X86_FS;
    else if( !name.compare("gs")) return X86_GS;
    else if( !name.compare("ss")) return X86_SS;
    else if( !name.compare("cf")) return X86_CF;
    else if( !name.compare("pf")) return X86_PF;
    else if( !name.compare("af")) return X86_AF;
    else if( !name.compare("zf")) return X86_ZF;
    else if( !name.compare("sf")) return X86_SF;
    else if( !name.compare("tf")) return X86_TF;
    else if( !name.compare("if")) return X86_IF;
    else if( !name.compare("df")) return X86_DF;
    else if( !name.compare("of")) return X86_OF;
    else if( !name.compare("iopl")) return X86_IOPL;
    else if( !name.compare("vm")) return X86_VM;
    else if( !name.compare("nt")) return X86_NT;
    else if( !name.compare("rf")) return X86_RF;
    else if( !name.compare("ac")) return X86_AC;
    else if( !name.compare("vip")) return X86_VIP;
    else if( !name.compare("vif")) return X86_VIF;
    else if( !name.compare("id")) return X86_ID;
    else if( !name.compare("tsc")) return X86_TSC;
    else throw runtime_exception(QuickFmt () << "ArchX86::reg_num() got unknown reg name: " << name >> QuickFmt::to_str);
}

bool ArchX86::is_valid_reg(string& name){
    return ( !name.compare("eax"))
        || (!name.compare("ebx")) 
        || (!name.compare("ecx")) 
        || (!name.compare("edx")) 
        || (!name.compare("edi")) 
        || (!name.compare("esi"))
        || (!name.compare("ebp"))
        || (!name.compare("esp"))
        || (!name.compare("eip"))
        || (!name.compare("cs"))
        || (!name.compare("ds"))
        || (!name.compare("es"))
        || (!name.compare("fs"))
        || (!name.compare("gs")) 
        || (!name.compare("ss")) 
        || (!name.compare("cf")) 
        || (!name.compare("pf")) 
        || (!name.compare("af")) 
        || (!name.compare("zf")) 
        || (!name.compare("sf")) 
        || (!name.compare("tf")) 
        || (!name.compare("if")) 
        || (!name.compare("df")) 
        || (!name.compare("of")) 
        || (!name.compare("iopl")) 
        || (!name.compare("vm")) 
        || (!name.compare("nt")) 
        || (!name.compare("rf")) 
        || (!name.compare("ac")) 
        || (!name.compare("vip")) 
        || (!name.compare("vif")) 
        || (!name.compare("id"))
        || (!name.compare("tsc"));
}

reg_t ArchX86::sp(){
    return X86_ESP;
}

reg_t ArchX86::pc(){
    return X86_EIP;
}

reg_t ArchX86::tsc(){
    return X86_TSC;
}

/* =================================== 
 *             ArchX64 
 * ================================== */
 
ArchX64::ArchX64(): Arch(ArchType::X64, 64, 8, X64_NB_REGS, CPUMode::X64, new DisassemblerX86(CPUMode::X64)){
}

string ArchX64::reg_name(reg_t num){
    switch(num){
        case X64_RAX: return "rax";
        case X64_RBX: return "rbx";
        case X64_RCX: return "rcx";
        case X64_RDX: return "rdx";
        case X64_RDI: return "rdi";
        case X64_RSI: return "rsi";
        case X64_RBP: return "rbp";
        case X64_RSP: return "rsp";
        case X64_RIP: return "rip";
        case X64_R8: return "r8";
        case X64_R9: return "r9";
        case X64_R10: return "r10";
        case X64_R11: return "r11";
        case X64_R12: return "r12";
        case X64_R13: return "r13";
        case X64_R14: return "r14";
        case X64_R15: return "r15";
        case X64_CS: return "cs";
        case X64_DS: return "ds";
        case X64_ES: return "es";
        case X64_FS: return "fs";
        case X64_GS: return "gs";
        case X64_SS: return "ss";
        case X64_CF: return "cf";
        case X64_PF: return "pf";
        case X64_AF: return "af";
        case X64_ZF: return "zf";
        case X64_SF: return "sf";
        case X64_TF: return "tf";
        case X64_IF: return "if";
        case X64_DF: return "df";
        case X64_OF: return "of";
        case X64_IOPL: return "iopl";
        case X64_VM: return "vm";
        case X64_NT: return "nt";
        case X64_RF: return "rf";
        case X64_AC: return "ac";
        case X64_VIP: return "vip";
        case X64_VIF: return "vif";
        case X64_ID: return "id";
        case X64_TSC: return "tsc";
        default:
            throw runtime_exception("ArchX64::reg_name() got unknown reg num");
    }
    
}
reg_t ArchX64::reg_num(string name){
    if( !name.compare("rax")) return X64_RAX;
    else if( !name.compare("rbx")) return X64_RBX;
    else if( !name.compare("rcx")) return X64_RCX;
    else if( !name.compare("rdx")) return X64_RDX;
    else if( !name.compare("rdi")) return X64_RDI;
    else if( !name.compare("rsi")) return X64_RSI;
    else if( !name.compare("rbp")) return X64_RBP;
    else if( !name.compare("rsp")) return X64_RSP;
    else if( !name.compare("rip")) return X64_RIP;
    else if( !name.compare("r8")) return X64_R8;
    else if( !name.compare("r9")) return X64_R9;
    else if( !name.compare("r10")) return X64_R10;
    else if( !name.compare("r11")) return X64_R11;
    else if( !name.compare("r12")) return X64_R12;
    else if( !name.compare("r13")) return X64_R13;
    else if( !name.compare("r14")) return X64_R14;
    else if( !name.compare("r15")) return X64_R15;
    else if( !name.compare("cs")) return X64_CS;
    else if( !name.compare("ds")) return X64_DS;
    else if( !name.compare("es")) return X64_ES;
    else if( !name.compare("fs")) return X64_FS;
    else if( !name.compare("gs")) return X64_GS;
    else if( !name.compare("ss")) return X64_SS;
    else if( !name.compare("cf")) return X64_CF;
    else if( !name.compare("pf")) return X64_PF;
    else if( !name.compare("af")) return X64_AF;
    else if( !name.compare("zf")) return X64_ZF;
    else if( !name.compare("sf")) return X64_SF;
    else if( !name.compare("tf")) return X64_TF;
    else if( !name.compare("if")) return X64_IF;
    else if( !name.compare("df")) return X64_DF;
    else if( !name.compare("of")) return X64_OF;
    else if( !name.compare("iopl")) return X64_IOPL;
    else if( !name.compare("vm")) return X64_VM;
    else if( !name.compare("nt")) return X64_NT;
    else if( !name.compare("rf")) return X64_RF;
    else if( !name.compare("ac")) return X64_AC;
    else if( !name.compare("vip")) return X64_VIP;
    else if( !name.compare("vif")) return X64_VIF;
    else if( !name.compare("id")) return X64_ID;
    else if( !name.compare("tsc")) return X64_TSC;
    else throw runtime_exception(QuickFmt () << "ArchX86::reg_num() got unknown reg name: " << name >> QuickFmt::to_str);
}

bool ArchX64::is_valid_reg(string& name){
    return (!name.compare("rax")) 
        || (!name.compare("rbx")) 
        || (!name.compare("rcx")) 
        || (!name.compare("rdx")) 
        || (!name.compare("rdi")) 
        || (!name.compare("rsi")) 
        || (!name.compare("rbp")) 
        || (!name.compare("rsp")) 
        || (!name.compare("rip")) 
        || (!name.compare("r8")) 
        || (!name.compare("r9")) 
        || (!name.compare("r10")) 
        || (!name.compare("r11")) 
        || (!name.compare("r12")) 
        || (!name.compare("r13")) 
        || (!name.compare("r14")) 
        || (!name.compare("r15")) 
        || (!name.compare("cs")) 
        || (!name.compare("ds")) 
        || (!name.compare("es")) 
        || (!name.compare("fs")) 
        || (!name.compare("gs")) 
        || (!name.compare("ss")) 
        || (!name.compare("cf")) 
        || (!name.compare("pf")) 
        || (!name.compare("af")) 
        || (!name.compare("zf")) 
        || (!name.compare("sf")) 
        || (!name.compare("tf")) 
        || (!name.compare("if")) 
        || (!name.compare("df")) 
        || (!name.compare("of")) 
        || (!name.compare("iopl")) 
        || (!name.compare("vm")) 
        || (!name.compare("nt")) 
        || (!name.compare("rf")) 
        || (!name.compare("ac")) 
        || (!name.compare("vip")) 
        || (!name.compare("vif")) 
        || (!name.compare("id")) 
        || (!name.compare("tsc"));
}

reg_t ArchX64::sp(){
    return X64_RSP;
}

reg_t ArchX64::pc(){
    return X64_RIP;
}

reg_t ArchX64::tsc(){
    return X64_TSC;
}

/* =================================== 
 *        X86 & X64 Disassembler
 * ================================== */
DisassemblerX86::DisassemblerX86(CPUMode mode){
    _mode = mode;
    if( mode == CPUMode::X86 ){
        cs_open(CS_ARCH_X86, CS_MODE_32, &_handle);
    }else if( mode == CPUMode::X64 ){
        cs_open(CS_ARCH_X86, CS_MODE_64, &_handle);
    }else{
        throw runtime_exception("DisassemblerX86: got unsupported mode");
    }
    // Ask for detailed instructions
    cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON);
    // allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
    // (will be freed in destructor)
    _insn = cs_malloc(_handle);
}

inline IROperand x86_32_reg_translate(x86_reg reg){
    switch(reg){
        case X86_REG_AL: return IROperand(IROperandType::VAR, X86_EAX, 7, 0);
        case X86_REG_AH: return IROperand(IROperandType::VAR, X86_EAX, 15, 8);
        case X86_REG_AX: return IROperand(IROperandType::VAR, X86_EAX, 15, 0);
        case X86_REG_EAX: return IROperand(IROperandType::VAR, X86_EAX, 31, 0);
        case X86_REG_BL: return IROperand(IROperandType::VAR, X86_EBX, 7, 0);
        case X86_REG_BH: return IROperand(IROperandType::VAR, X86_EBX, 15, 8);
        case X86_REG_BX: return IROperand(IROperandType::VAR, X86_EBX, 15, 0);
        case X86_REG_EBX: return IROperand(IROperandType::VAR, X86_EBX , 31, 0);
        case X86_REG_CL: return IROperand(IROperandType::VAR, X86_ECX, 7, 0);
        case X86_REG_CH: return IROperand(IROperandType::VAR, X86_ECX, 15, 8);
        case X86_REG_CX: return IROperand(IROperandType::VAR, X86_ECX, 15, 0);
        case X86_REG_ECX: return IROperand(IROperandType::VAR, X86_ECX, 31, 0);
        case X86_REG_DL: return IROperand(IROperandType::VAR, X86_EDX, 7, 0);
        case X86_REG_DH: return IROperand(IROperandType::VAR, X86_EDX, 15, 8);
        case X86_REG_DX: return IROperand(IROperandType::VAR, X86_EDX, 15, 0);
        case X86_REG_EDX: return IROperand(IROperandType::VAR, X86_EDX, 31, 0);
        case X86_REG_DI: return IROperand(IROperandType::VAR, X86_EDI, 15, 0);
        case X86_REG_EDI: return IROperand(IROperandType::VAR, X86_EDI, 31, 0);
        case X86_REG_SI: return IROperand(IROperandType::VAR, X86_ESI, 15, 0);
        case X86_REG_ESI: return IROperand(IROperandType::VAR, X86_ESI, 31, 0);
        case X86_REG_BP: return IROperand(IROperandType::VAR, X86_EBP, 15, 0);
        case X86_REG_EBP: return IROperand(IROperandType::VAR, X86_EBP, 31, 0);
        case X86_REG_SP: return IROperand(IROperandType::VAR, X86_ESP, 15, 0);
        case X86_REG_ESP: return IROperand(IROperandType::VAR, X86_ESP, 31, 0);
        case X86_REG_IP: return IROperand(IROperandType::VAR, X86_EIP, 15, 0);
        case X86_REG_EIP: return IROperand(IROperandType::VAR, X86_EIP, 31, 0);
        case X86_REG_CS: return IROperand(IROperandType::VAR, X86_CS, 31, 0);
        case X86_REG_DS: return IROperand(IROperandType::VAR, X86_DS, 31, 0);
        case X86_REG_ES: return IROperand(IROperandType::VAR, X86_ES, 31, 0);
        case X86_REG_GS: return IROperand(IROperandType::VAR, X86_GS, 31, 0);
        case X86_REG_FS: return IROperand(IROperandType::VAR, X86_FS, 31, 0);
        case X86_REG_SS: return IROperand(IROperandType::VAR, X86_SS, 31, 0);
        default: throw runtime_exception( QuickFmt() <<
        "Disassembler X86: unknown capstone register " << reg 
        >> QuickFmt::to_str);
    }
}

inline IROperand x86_64_reg_translate(x86_reg reg){
    switch(reg){
        case X86_REG_AL: return IROperand(IROperandType::VAR, X64_RAX, 7, 0);
        case X86_REG_AH: return IROperand(IROperandType::VAR, X64_RAX, 15, 8);
        case X86_REG_AX: return IROperand(IROperandType::VAR, X64_RAX, 15, 0);
        case X86_REG_EAX: return IROperand(IROperandType::VAR, X64_RAX, 31, 0);
        case X86_REG_RAX: return IROperand(IROperandType::VAR, X64_RAX, 63, 0);
        case X86_REG_BL: return IROperand(IROperandType::VAR, X64_RBX, 7, 0);
        case X86_REG_BH: return IROperand(IROperandType::VAR, X64_RBX, 15, 8);
        case X86_REG_BX: return IROperand(IROperandType::VAR, X64_RBX, 15, 0);
        case X86_REG_EBX: return IROperand(IROperandType::VAR, X64_RBX , 31, 0);
        case X86_REG_RBX: return IROperand(IROperandType::VAR, X64_RBX , 63, 0);
        case X86_REG_CL: return IROperand(IROperandType::VAR, X64_RCX, 7, 0);
        case X86_REG_CH: return IROperand(IROperandType::VAR, X64_RCX, 15, 8);
        case X86_REG_CX: return IROperand(IROperandType::VAR, X64_RCX, 15, 0);
        case X86_REG_ECX: return IROperand(IROperandType::VAR, X64_RCX, 31, 0);
        case X86_REG_RCX: return IROperand(IROperandType::VAR, X64_RCX, 63, 0);
        case X86_REG_DL: return IROperand(IROperandType::VAR, X64_RDX, 7, 0);
        case X86_REG_DH: return IROperand(IROperandType::VAR, X64_RDX, 15, 8);
        case X86_REG_DX: return IROperand(IROperandType::VAR, X64_RDX, 15, 0);
        case X86_REG_EDX: return IROperand(IROperandType::VAR, X64_RDX, 31, 0);
        case X86_REG_RDX: return IROperand(IROperandType::VAR, X64_RDX, 63, 0);
        case X86_REG_DI: return IROperand(IROperandType::VAR, X64_RDI, 15, 0);
        case X86_REG_EDI: return IROperand(IROperandType::VAR, X64_RDI, 31, 0);
        case X86_REG_RDI: return IROperand(IROperandType::VAR, X64_RDI, 63, 0);
        case X86_REG_SI: return IROperand(IROperandType::VAR, X64_RSI, 15, 0);
        case X86_REG_ESI: return IROperand(IROperandType::VAR, X64_RSI, 31, 0);
        case X86_REG_RSI: return IROperand(IROperandType::VAR, X64_RSI, 63, 0);
        case X86_REG_BP: return IROperand(IROperandType::VAR, X64_RBP, 15, 0);
        case X86_REG_EBP: return IROperand(IROperandType::VAR, X64_RBP, 31, 0);
        case X86_REG_RBP: return IROperand(IROperandType::VAR, X64_RBP, 63, 0);
        case X86_REG_SP: return IROperand(IROperandType::VAR, X64_RSP, 15, 0);
        case X86_REG_ESP: return IROperand(IROperandType::VAR, X64_RSP, 31, 0);
        case X86_REG_RSP: return IROperand(IROperandType::VAR, X64_RSP, 63, 0);
        case X86_REG_IP: return IROperand(IROperandType::VAR, X64_RIP, 15, 0);
        case X86_REG_EIP: return IROperand(IROperandType::VAR, X64_RIP, 31, 0);
        case X86_REG_RIP: return IROperand(IROperandType::VAR, X64_RIP, 63, 0);
        case X86_REG_R8: return IROperand(IROperandType::VAR, X64_R8, 63, 0);
        case X86_REG_R8B: return IROperand(IROperandType::VAR, X64_R8, 7, 0);
        case X86_REG_R8D: return IROperand(IROperandType::VAR, X64_R8, 31, 0);
        case X86_REG_R8W: return IROperand(IROperandType::VAR, X64_R8, 15, 0);
        case X86_REG_R9: return IROperand(IROperandType::VAR, X64_R9, 63, 0);
        case X86_REG_R9B: return IROperand(IROperandType::VAR, X64_R9, 7, 0);
        case X86_REG_R9D: return IROperand(IROperandType::VAR, X64_R9, 31, 0);
        case X86_REG_R9W: return IROperand(IROperandType::VAR, X64_R9, 15, 0);
        case X86_REG_R10: return IROperand(IROperandType::VAR, X64_R10, 63, 0);
        case X86_REG_R10B: return IROperand(IROperandType::VAR, X64_R10, 7, 0);
        case X86_REG_R10D: return IROperand(IROperandType::VAR, X64_R10, 31, 0);
        case X86_REG_R10W: return IROperand(IROperandType::VAR, X64_R10, 15, 0);
        case X86_REG_R11: return IROperand(IROperandType::VAR, X64_R11, 63, 0);
        case X86_REG_R11B: return IROperand(IROperandType::VAR, X64_R11, 7, 0);
        case X86_REG_R11D: return IROperand(IROperandType::VAR, X64_R11, 31, 0);
        case X86_REG_R11W: return IROperand(IROperandType::VAR, X64_R11, 15, 0);
        case X86_REG_R12: return IROperand(IROperandType::VAR, X64_R12, 63, 0);
        case X86_REG_R12B: return IROperand(IROperandType::VAR, X64_R12, 7, 0);
        case X86_REG_R12D: return IROperand(IROperandType::VAR, X64_R12, 31, 0);
        case X86_REG_R12W: return IROperand(IROperandType::VAR, X64_R12, 15, 0);
        case X86_REG_R13: return IROperand(IROperandType::VAR, X64_R13, 63, 0);
        case X86_REG_R13B: return IROperand(IROperandType::VAR, X64_R13, 7, 0);
        case X86_REG_R13D: return IROperand(IROperandType::VAR, X64_R13, 31, 0);
        case X86_REG_R13W: return IROperand(IROperandType::VAR, X64_R13, 15, 0);
        case X86_REG_R14: return IROperand(IROperandType::VAR, X64_R14, 63, 0);
        case X86_REG_R14B: return IROperand(IROperandType::VAR, X64_R14, 7, 0);
        case X86_REG_R14D: return IROperand(IROperandType::VAR, X64_R14, 31, 0);
        case X86_REG_R14W: return IROperand(IROperandType::VAR, X64_R14, 15, 0);
        case X86_REG_R15: return IROperand(IROperandType::VAR, X64_R15, 63, 0);
        case X86_REG_R15B: return IROperand(IROperandType::VAR, X64_R15, 7, 0);
        case X86_REG_R15D: return IROperand(IROperandType::VAR, X64_R15, 31, 0);
        case X86_REG_R15W: return IROperand(IROperandType::VAR, X64_R15, 15, 0);
        case X86_REG_CS: return IROperand(IROperandType::VAR, X64_CS, 63, 0);
        case X86_REG_DS: return IROperand(IROperandType::VAR, X64_DS, 63, 0);
        case X86_REG_ES: return IROperand(IROperandType::VAR, X64_ES, 63, 0);
        case X86_REG_GS: return IROperand(IROperandType::VAR, X64_GS, 63, 0);
        case X86_REG_FS: return IROperand(IROperandType::VAR, X64_FS, 63, 0);
        case X86_REG_SS: return IROperand(IROperandType::VAR, X64_SS, 63, 0);
        default: throw runtime_exception( QuickFmt() <<
        "Disassembler X86: unknown capstone register " << reg 
        >> QuickFmt::to_str);
    }
}

inline IROperand x86_reg_translate(CPUMode mode, x86_reg reg){
    if( mode == CPUMode::X86 ){
        return x86_32_reg_translate(reg);
    }else{
        return x86_64_reg_translate(reg);
    }
}

inline IROperand x86_arg_extract(IROperand& arg, exprsize_t high, exprsize_t low){
    switch(arg.type){
        case IROperandType::CST: return IROperand(IROperandType::CST, arg.cst(), high, low);
        case IROperandType::VAR: return IROperand(IROperandType::VAR, arg.var(), high, low);
        case IROperandType::TMP: return IROperand(IROperandType::TMP, arg.tmp(), high, low);
        case IROperandType::NONE: return IROperand();
        default: throw runtime_exception("x86_arg_extract(): got unknown IROperandType!");
    }
}

/* Translate capstone argument to IR argument 
 * Arguments:
 *      mode - the current CPU mode for registers translation 
 *      addr - the address of the instruction being translated
 *      arg - the capstone operand 
 *      block/bblkid - block and basicblockid where to add instructions if needed 
 *      tmp_var_count - the counter of the tmp variables used in the current IRBlock
 *      load_mem - if TRUE then load memory operands (dereference), else only return the operand (pointer) 
 */
inline IROperand x86_arg_translate(CPUMode mode, addr_t addr, cs_x86_op* arg, IRBlock* block, IRBasicBlockId bblkid, int& tmp_vars_count, bool load_mem=false){
    IROperand base, index, res, disp, segment;
    exprsize_t size = arg->size*8, addr_size = 0, reg_size = (mode==CPUMode::X86)? 32:64;
    try{
        switch(arg->type){
            /* Register */
            case X86_OP_REG:
                return x86_reg_translate(mode, arg->reg);
            /* Immediate */
            case X86_OP_IMM:
                return IROperand(IROperandType::CST, arg->imm, size-1, 0);
            /* Memory */
            case X86_OP_MEM:
                // Arg = segment + base + (index*scale) + disp
                // Get index*scale
                if( arg->mem.index != X86_OP_INVALID ){
                    index = x86_reg_translate(mode, (x86_reg)arg->mem.index);
                    if( arg->mem.scale != 1 ){
                        block->add_instr(bblkid, IRInstruction(IROperation::MUL, ir_tmp(tmp_vars_count++, index.size-1, 0), 
                            ir_cst(arg->mem.scale, index.size-1, 0), index, addr));
                        index = ir_tmp(tmp_vars_count-1, index.size-1, 0);
                    }
                    addr_size = index.size;
                }
                // Get base
                if( arg->mem.base != X86_OP_INVALID ){
                    base = x86_reg_translate(mode, (x86_reg)arg->mem.base);
                    // If too small adjust
                    if( base.size < index.size ){
                        block->add_instr(bblkid, ir_mov(ir_tmp(tmp_vars_count++, index.size-1, 0), ir_cst(0, index.size-1, 0), addr));
                        block->add_instr(bblkid, ir_mov(ir_tmp(tmp_vars_count-1, base.size-1, 0), base, addr));
                        base = ir_tmp(tmp_vars_count-1, base.size-1, 0);
                    }
                    addr_size = base.size;
                }else{
                    //base = ir_cst(0, index.size-1, 0);
                    base = ir_none();
                    //throw runtime_exception("Disassembler X86: didn't expect X86_OP_INVALID base for mem operand in capstone");
                }
                
                // Get displacement
                if( addr_size == 0 )
                    addr_size = reg_size;
                if( arg->mem.disp != 0 ){
                    disp = IROperand(IROperandType::CST, arg->mem.disp, addr_size-1, 0);
                }else{
                    disp = ir_none();
                }

                // Get segment selector (here we consider that the segment selector symbolic register holds the address
                // of the segment, not the index in the GDT
                if( arg->mem.segment != X86_OP_INVALID ){
                    segment = x86_reg_translate(mode, (x86_reg)arg->mem.segment);
                    // If too big, adjust
                    if( segment.size > addr_size ){
                        block->add_instr(bblkid, ir_mov(ir_tmp(tmp_vars_count++, addr_size-1, 0), x86_arg_extract(segment, addr_size-1, 0), addr));
                        segment = ir_tmp(tmp_vars_count-1, addr_size-1, 0);
                    }
                }else{
                    segment = ir_none();
                }
                
                // === Build the operand now ===  
                // Add base and index if any 
                if( !index.is_none() ){
                    if( !base.is_none() ){
                        block->add_instr(bblkid, ir_add(ir_tmp(tmp_vars_count++, index.size-1, 0), base, index, addr));
                        res = IROperand(IROperandType::TMP, tmp_vars_count-1, index.size-1, 0);
                    }else{
                        res = index;
                    }
                }else if (!base.is_none()){
                    res = base;
                }else{
                    res = ir_none();
                }
                // Add displacement if any 
                if( !disp.is_none() ){
                    if( !res.is_none()){
                        block->add_instr(bblkid, ir_add( ir_tmp(tmp_vars_count++, res.size-1, 0), disp, res, addr));
                        res = IROperand(IROperandType::TMP, tmp_vars_count-1, res.size-1, 0);
                    }else{
                        res = disp;
                    }
                }
                // Add segment if any
                if( !segment.is_none() ){
                    if( !res.is_none() ){
                        block->add_instr(bblkid, ir_add( ir_tmp(tmp_vars_count++, res.size-1, 0), segment, res, addr));
                        res = IROperand(IROperandType::TMP, tmp_vars_count-1, res.size-1, 0);
                    }else{
                        res = segment;
                    }
                }
                // Do load memory if requested
                if( load_mem ){
                    block->add_instr(bblkid, IRInstruction(IROperation::LDM,
                        IROperand(IROperandType::TMP, tmp_vars_count++, size-1 , 0), res, addr));
                    res = IROperand(IROperandType::TMP, tmp_vars_count-1, size-1, 0);
                }
                return res;
            default:
                throw runtime_exception(QuickFmt() << "Disassembler X86: at addr: 0x" << std::hex
                    << addr << " :got unknown capstone operand type" >> QuickFmt::to_str);
        }
    }catch(runtime_exception& e){
        throw runtime_exception(QuickFmt() << "Disassembler X86: error at addr: 0x" << std::hex
                    << addr << " :" + string(e.what()) >> QuickFmt::to_str);
    }
    throw runtime_exception(QuickFmt() << "Disassembler X86: at addr: 0x" << std::hex << addr << " :couldn't translate operand"
        >> QuickFmt::to_str);
}

/* Translate a 32bits assignments to a 64bits assignment where the upper
 * 32 bits are cleared. For the bits to be cleared, the following conditions
 * must be fulfilled:
 *  - mode is CPUMOde::X64
 *  - destination is a register (IROperandType::VAR) 
 *  - destination is 32 bits */
inline void x86_adjust_reg_assign(CPUMode mode, addr_t addr, IRBlock* block, IRBasicBlockId bblkid, int& tmp_vars_count, IROperand dest, IROperand val){
    IROperand res;
    if( mode != CPUMode::X64 || dest.size != 32 || dest.type != IROperandType::VAR){
        // No need to adjust, to assign result to destination
        block->add_instr(bblkid, ir_mov(dest, val, addr));
        return;
    }
    // Need to clear upper bits
    block->add_instr(bblkid, ir_concat(ir_var(dest.var(), 63, 0), ir_cst(0, 63-val.size, 0), val, addr));
}

/* ========================================= */
inline IROperand x86_get_pc(CPUMode mode ){
    if( mode == CPUMode::X86 )
        return ir_var(X86_EIP, 31, 0 );
    else if( mode == CPUMode::X64 )
        return ir_var(X64_RIP, 63, 0 );
    else
        throw runtime_exception("x86_get_pc(): got unknown CPUMode!");
}

inline IROperand x86_get_tsc(CPUMode mode ){
    if( mode == CPUMode::X86 )
        return ir_var(X86_TSC, 63, 0 );
    else if( mode == CPUMode::X64 )
        return ir_var(X64_TSC, 63, 0 );
    else
        throw runtime_exception("x86_get_pc(): got unknown CPUMode!");
}

inline void x86_set_zf(CPUMode mode, IROperand& arg, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid){
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz(ir_var(X86_ZF, 31, 0), arg, ir_cst(1, 31, 0), addr));
    else
        block->add_instr(bblkid, ir_bisz(ir_var(X64_ZF, 63, 0), arg , ir_cst(1, 63, 0), addr));
}

inline void x86_add_set_cf(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp2 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf -> higher bits of both operands are already 1 
    
    block->add_instr(bblkid, ir_and(tmp0, msb0, msb1, addr));
    //       or they are 1 and 0 and result has MSB 0
    block->add_instr(bblkid, ir_xor(tmp1, msb0, msb1, addr));
    block->add_instr(bblkid, ir_not(tmp2, msb2, addr));
    block->add_instr(bblkid, ir_and(tmp2, tmp1, tmp2, addr));
    block->add_instr(bblkid, ir_or(tmp2, tmp0, tmp2, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_CF, 31, 0),tmp2, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_CF, 63, 0),tmp2, ir_cst(0, 63, 0), addr));
}

inline void x86_add_set_of(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );     
    
    // of -> msb of both operands have the same MSB but result
    //       has different
    block->add_instr(bblkid, ir_xor(tmp0, msb0, msb1, addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_xor(tmp1, msb0, msb2, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp0, tmp1, addr));
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz(ir_var(X86_OF, 31, 0), tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz(ir_var(X64_OF, 63, 0), tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_sub_set_cf(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf <- (~msb0&msb1) | (msb1&msb2) | (~msb0&msb2)
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb1, addr));
    block->add_instr(bblkid, ir_and(tmp1, msb1, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp0, tmp1, addr));
    
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp1, tmp0, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_CF, 31, 0),tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_CF, 63, 0),tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_sub_set_af(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    /* Like cf but for bit 3 */
    IROperand   msb0 = x86_arg_extract(op0, 3, 3),
                msb1 = x86_arg_extract(op1, 3, 3),
                msb2 = x86_arg_extract(res, 3, 3),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf <- (~msb0&msb1) | (msb1&msb2) | (~msb0&msb2)
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb1, addr));
    block->add_instr(bblkid, ir_and(tmp1, msb1, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp0, tmp1, addr));
    
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp1, tmp0, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_AF, 31, 0),tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_AF, 63, 0),tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_sub_set_of(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );
    
    // of -> msb of both operands have different MSB and result
    //       has the same as second operand
    block->add_instr(bblkid, ir_xor(tmp0, msb0, msb1, addr));
    block->add_instr(bblkid, ir_xor(tmp1, msb1, msb2, addr));
    block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp0, tmp1, addr));
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz(ir_var(X86_OF, 31, 0), tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz(ir_var(X64_OF, 63, 0), tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_set_sf(CPUMode mode, IROperand& arg, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid){
    IROperand sf = mode == CPUMode::X86 ? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0); 
    block->add_instr(bblkid, ir_bisz(sf, x86_arg_extract(arg, arg.high, arg.high), ir_cst(0, sf.high, 0), addr));
}

inline void x86_add_set_af(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    // Basically like cf but for bits 3
    IROperand   msb0 = x86_arg_extract(op0, 3, 3),
                msb1 = x86_arg_extract(op1, 3, 3),
                msb2 = x86_arg_extract(res, 3, 3),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp2 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp3 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp4 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf -> higher bits of both operands are already 1 
    
    block->add_instr(bblkid, ir_and(tmp0, msb0, msb1, addr));
    //       or they are 1 and 0 and result has MSB 0
    block->add_instr(bblkid, ir_xor(tmp1, msb0, msb1, addr));
    block->add_instr(bblkid, ir_not(tmp2, msb2, addr));
    block->add_instr(bblkid, ir_and(tmp3, tmp1, tmp2, addr));
    block->add_instr(bblkid, ir_or(tmp4, tmp0, tmp3, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_AF, 31, 0),tmp4, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_AF, 63, 0),tmp4, ir_cst(0, 63, 0), addr));
}

inline void x86_set_pf(CPUMode mode, IROperand arg, addr_t addr, IRBlock* block, IRBasicBlockId bblkid, int& tmp_var_count){
    // pf number of bits that are equal to zero in the least significant byte 
    // of the result of an operation -> xor all and set flag if zero 
    IROperand tmp =  ir_tmp(tmp_var_count++, 0, 0 );
    block->add_instr(bblkid, ir_mov(tmp, x86_arg_extract(arg, 0, 0), addr));
    for( int i = 1; i < 8; i++){
        block->add_instr(bblkid, ir_xor(tmp, tmp, x86_arg_extract(arg, i, i), addr));
    }
    if( mode == CPUMode::X86 ){
        block->add_instr(bblkid, ir_bisz(ir_var(X86_PF, 31, 0), tmp, ir_cst(1, 31, 0), addr));
    }else if( mode == CPUMode::X64 ){
        block->add_instr(bblkid, ir_bisz(ir_var(X64_PF, 63, 0), tmp, ir_cst(1, 31, 0), addr));
    }
}

/* =====================
 * Instruction prefixes 
 * =====================

*/

IRBasicBlockId _x86_init_prefix(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid){
    IRBasicBlockId start;
    if( instr->detail->x86.prefix[0] != X86_PREFIX_REP &&
        instr->detail->x86.prefix[0] != X86_PREFIX_REPNE ){
        return -1;
    }
    start = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 31, 0), ir_cst(start, 31, 0), ir_none(), addr));
    bblkid = block->new_bblock();
    return start;
}

bool inline _accepts_repe_prefix(cs_insn* instr){
    return  instr->id == X86_INS_CMPSB ||
            instr->id == X86_INS_CMPSW ||
            instr->id == X86_INS_CMPSD ||
            instr->id == X86_INS_CMPSQ ||
            instr->id == X86_INS_SCASB ||
            instr->id == X86_INS_SCASW ||
            instr->id == X86_INS_SCASD ||
            instr->id == X86_INS_SCASQ;
}   

bool inline _accepts_rep_prefix(cs_insn* instr){
    return  instr->id == X86_INS_INSB ||
            instr->id == X86_INS_INSW ||
            instr->id == X86_INS_INSD ||
            instr->id == X86_INS_MOVSB ||
            instr->id == X86_INS_MOVSW ||
            instr->id == X86_INS_MOVSD ||
            instr->id == X86_INS_MOVSQ ||
            instr->id == X86_INS_OUTSB ||
            instr->id == X86_INS_OUTSW ||
            instr->id == X86_INS_OUTSD ||
            instr->id == X86_INS_LODSB ||
            instr->id == X86_INS_LODSW ||
            instr->id == X86_INS_LODSD ||
            instr->id == X86_INS_LODSQ ||
            instr->id == X86_INS_STOSB ||
            instr->id == X86_INS_STOSW ||
            instr->id == X86_INS_STOSD ||
            instr->id == X86_INS_STOSQ;
}

/* Wraps an instruction block with a REP prefix
 * Parameters:
 *      start - the basic block where to test the terminating condition. The instruction semantics start at start+1
 *      last - the current last bblock of the instruction 
 * 
 */
 
inline void _x86_end_prefix(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId start, IRBasicBlockId& last, int& tmp_var_count){
    IROperand cx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0): ir_var(X64_RCX, 63, 0);
    IROperand zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0): ir_var(X64_ZF, 63, 0);  
    IROperand tmp;
    IRBasicBlockId end;
    
    if( instr->detail->x86.prefix[0] != X86_PREFIX_REP &&
        instr->detail->x86.prefix[0] != X86_PREFIX_REPNE ){
        return;
    }
    
    /* Add loop and cx decrement at the end of the instruction */
    block->add_instr(last, ir_sub(cx, cx, ir_cst(1, cx.size-1, 0), addr));
    block->add_instr(last, ir_bcc(ir_cst(1, 31, 0), ir_cst(start, 31, 0), ir_none(), addr));
    
    /* Add REP test in the beginning */
    end = block->new_bblock();
    if( instr->detail->x86.prefix[0] == X86_PREFIX_REP && _accepts_rep_prefix(instr) ){
        block->add_instr(start, ir_bcc(cx, ir_cst(start+1, 31, 0), ir_cst(end, 31, 0), addr));
    }else if( instr->detail->x86.prefix[0] == X86_PREFIX_REP && _accepts_repe_prefix(instr) ){
        tmp = ir_tmp(tmp_var_count++, 0, 0);
        block->add_instr(start, ir_bisz(tmp, cx, ir_cst(0, 0, 0), addr));
        block->add_instr(start, ir_and(tmp, tmp, x86_arg_extract(zf, 0, 0), addr));
        block->add_instr(start, ir_bcc(tmp, ir_cst(start+1, 31, 0), ir_cst(end, 31, 0), addr));
    }else if( instr->detail->x86.prefix[0] == X86_PREFIX_REPNE ){
        tmp = ir_tmp(tmp_var_count++, 0, 0);
        block->add_instr(start, ir_bisz(tmp, cx, ir_cst(1, 0, 0), addr));
        block->add_instr(start, ir_or(tmp, tmp, x86_arg_extract(zf, 0, 0), addr));
        block->add_instr(start, ir_bcc(tmp, ir_cst(end, 31, 0), ir_cst(start+1, 31, 0), addr));
    }
    
    last = end; // Update last basic block
}


/* ========================================= */
/* Instructions translation */


inline void x86_aaa_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand   af, eax, cf, tmp0, tmp1, pc;   
    if( mode == CPUMode::X86 ){
        eax = ir_var(X86_EAX, 31, 0);
        af = ir_var(X86_AF, 31, 0);
        cf = ir_var(X86_CF, 31, 0);
    }else if( mode == CPUMode::X64 ){
        throw illegal_instruction_exception("X86 AAA instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, af.size-1, 0), // Get the size from any register 
    tmp1 = ir_tmp(tmp_var_count++, af.size-1, 0);
    /* If 4 LSB are > 9 or if AF is set then adjust the unpacked BCD values */
    // (4 LSB) > 9
    block->add_instr(bblkid, ir_bisz(tmp0, x86_arg_extract(eax, 3, 3), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_bisz(tmp1, x86_arg_extract(eax, 2, 1), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    // AF
    block->add_instr(bblkid, ir_or(tmp1, af, tmp1, addr));
    // Branch depending on condition 
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(bblkid+1, 31,0), ir_cst(bblkid+2, 31, 0), addr));
    // 1°) Branch 1 - Do the adjust 
    bblkid = block->new_bblock();
    // AL <- AL + 6
    block->add_instr(bblkid, ir_add(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(6, 7, 0), addr));
    // AH ++ 
    block->add_instr(bblkid, ir_add(x86_arg_extract(eax, 15, 8), x86_arg_extract(eax, 15, 8), ir_cst(1, 7, 0), addr));
    // CF <- 1 , AF <- 1
    block->add_instr(bblkid, ir_mov(af, ir_cst(1, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(1, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+2, 31, 0), ir_none(), addr));
    
    // 2°) Branch 2 - Just reset flags
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_mov(af, ir_cst(0, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+1, 31, 0), ir_none(), addr));
    
    // 3°) Common end - Keep only 4 LSB of AL
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_and(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(0xf, 7, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_aad_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand  tmp0, imm, al, pc;   
    if( mode != CPUMode::X86 ){
        throw illegal_instruction_exception("X86 AAD instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, 7, 0), // Get the size from any register 
    imm = ir_cst(0xa, 7, 0); // 2 byte of the encoded instruction always 0xA for AAD
    al = ir_var(X86_EAX, 7,0);
    // AL <- (AL + (AH ∗ imm8)) & 0xFF;
    // AH <- 0
    block->add_instr(bblkid, ir_mul(tmp0, ir_var(X86_EAX, 15, 8), imm, addr));
    block->add_instr(bblkid, ir_add(al, al, tmp0, addr));
    block->add_instr(bblkid, ir_mov(ir_var(X86_EAX, 15, 8), ir_cst(0, 7, 0), addr));
    
    // Set flags : SF, ZF, PF
    x86_set_sf(mode, al, addr, block, bblkid);
    x86_set_zf(mode, al, addr, block, bblkid); 
    x86_set_pf(mode, al, addr, block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    return;
}

inline void x86_aam_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand  tmp0, imm, al, pc;   
    if( mode != CPUMode::X86 ){
        throw illegal_instruction_exception("X86 AAM instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, 7, 0), // Get the size from any register 
    imm = ir_cst(0xa, 7, 0); // 2 byte of the encoded instruction always 0xA for AAM
    al = ir_var(X86_EAX, 7,0);
    // AH <- AL / 10
    // AL <- AL % 10
    block->add_instr(bblkid, ir_mov(tmp0, al, addr));
    block->add_instr(bblkid, ir_div(ir_var(X86_EAX, 15, 8), tmp0, imm, addr));
    block->add_instr(bblkid, ir_mod(al, tmp0, imm, addr));
    
    // Set flags : SF, ZF, PF
    x86_set_sf(mode, al, addr, block, bblkid);
    x86_set_zf(mode, al, addr, block, bblkid); 
    x86_set_pf(mode, al, addr, block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    return;
}


inline void x86_aas_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand   af, eax, cf, tmp0, tmp1, pc;   
    if( mode == CPUMode::X86 ){
        eax = ir_var(X86_EAX, 31, 0);
        af = ir_var(X86_AF, 31, 0);
        cf = ir_var(X86_CF, 31, 0);
    }else if( mode == CPUMode::X64 ){
        throw illegal_instruction_exception("X86 AAS instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, af.size-1, 0), // Get the size from any register 
    tmp1 = ir_tmp(tmp_var_count++, af.size-1, 0);
    /* If 4 LSB are > 9 or if AF is set then adjust the unpacked BCD values */
    // (4 LSB) > 9
    block->add_instr(bblkid, ir_bisz(tmp0, x86_arg_extract(eax, 3, 3), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_bisz(tmp1, x86_arg_extract(eax, 2, 1), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    // AF
    block->add_instr(bblkid, ir_or(tmp1, af, tmp1, addr));
    // Branch depending on condition 
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(bblkid+1, 31,0), ir_cst(bblkid+2, 31, 0), addr));
    // 1°) Branch 1 - Do the adjust 
    bblkid = block->new_bblock();
    // AL <- AL - 6
    block->add_instr(bblkid, ir_sub(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(6, 7, 0), addr));
    // AH    
    block->add_instr(bblkid, ir_sub(x86_arg_extract(eax, 15, 8), x86_arg_extract(eax, 15, 8), ir_cst(1, 7, 0), addr));
    // CF <- 1 , AF <- 1
    block->add_instr(bblkid, ir_mov(af, ir_cst(1, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(1, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+2, 31, 0), ir_none(), addr));
    
    // 2°) Branch 2 - Just reset flags
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_mov(af, ir_cst(0, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+1, 31, 0), ir_none(), addr));
    
    // 3°) Common end - Keep only 4 LSB of AL
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_and(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(0xf, 7, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_adc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, prev_cf, pc;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    if( mode == CPUMode::X86 )
        prev_cf = ir_var(X86_CF, res.size-1, 0);
    else if( mode == CPUMode::X64 )
        prev_cf = ir_var(X64_CF, res.size-1, 0);
    /* Do the add */
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    block->add_instr(bblkid, ir_add(res, res, prev_cf, addr));
    
    /* Update flags */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_af(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_of(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_adcx_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, prev_cf, pc;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    if( mode == CPUMode::X86 )
        prev_cf = ir_var(X86_CF, res.size-1, 0);
    else if( mode == CPUMode::X64 )
        prev_cf = ir_var(X64_CF, res.size-1, 0);
    /* Do the add */
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    block->add_instr(bblkid, ir_add(res, res, prev_cf, addr));
    
    /* Update flags */
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    
    /* Finally assign the result to the destination */ 
    /* ADCX destination is always a general purpose reg */
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_add_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, pc;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the add */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    
    /* Update flags */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_af(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_of(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_and_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the and */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_and(res, op0, op1, addr));
    
    /* Update flags: SF, ZF, PF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_andn_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[2]), block, bblkid, tmp_var_count, true);
    /* Do the not then the and */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_not(res, op0, addr));
    block->add_instr(bblkid, ir_and(res, res, op1, addr));
    
    /* Update flags: SF, ZF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_blsi_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the not then the and */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_neg(res, op0, addr));
    block->add_instr(bblkid, ir_and(res, res, op0, addr));
    
    /* Update flags: SF, ZF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    /* CF set if op0 is source is not zero */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(0, cf.size-1, 0), addr));
    /* OF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    
    /* Finally assign the result to the destination */ 
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_blsmsk_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, zf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* res <- (op0-1) XOR op0 */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(res, op0, ir_cst(1, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_xor(res, res, op0, addr));
    
    /* Update flags: SF */
    x86_set_sf(mode, res, addr, block, bblkid);
    /* CF set if op0 is source is zero */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(1, cf.size-1, 0), addr));
    /* OF and ZF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(zf, ir_cst(0, of.high, of.low), addr));
    
    /* Finally assign the result to the destination */ 
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_blsr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, zf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* res <- (op0-1) AND op0 */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(res, op0, ir_cst(1, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_and(res, res, op0, addr));
    
    /* Update flags: SF, ZF */
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_zf(mode, res, addr, block, bblkid);
    /* CF set if op0 is source is zero */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(1, cf.size-1, 0), addr));
    /* OF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    
    /* Finally assign the result to the destination */
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_bsf_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, op0, counter, tmp0, zf, pc;
    IRBasicBlockId loop_test, loop_body, loop_exit, op_is_zero, op_not_zero, end;
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0); 
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    op_not_zero = block->new_bblock();
    loop_test = block->new_bblock();
    loop_body = block->new_bblock();
    loop_exit = block->new_bblock();
    op_is_zero = block->new_bblock();
    end = block->new_bblock();
    
    // Update PC first because then we don't know what branch we take
    pc = x86_get_pc(mode);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    // op0 == 0 ??
    block->add_instr(bblkid, ir_bcc(op0, ir_cst(op_not_zero, 31, 0), ir_cst(op_is_zero, 31, 0), addr));
    // 1°) Branch1 : op_not_zero
    counter = ir_tmp(tmp_var_count++, dest.size-1, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(op_not_zero, ir_mov(counter, ir_cst(0, counter.size-1, 0), addr)); // counter <- 0
    block->add_instr(op_not_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop test: while ( op0[i] == 0 )
    block->add_instr(loop_test, ir_shr(tmp0, op0, counter, addr));
    block->add_instr(loop_test, ir_bcc(x86_arg_extract(tmp0,0,0) , ir_cst(loop_exit, 31, 0), ir_cst(loop_body, 31, 0), addr));
    // loop body: counter = counter + 1
    block->add_instr(loop_body, ir_add(counter, counter, ir_cst(1, counter.size-1, 0), addr));
    block->add_instr(loop_body, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop exit: dest <- counter  and ZF <- 0
    x86_adjust_reg_assign(mode, addr, block, loop_exit, tmp_var_count, dest, counter);
    x86_set_zf(mode, op0, addr, block, loop_exit );
    block->add_instr(loop_exit, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // 2°) Branch2: op_is_zero
    // ZF <- 1
    block->add_instr(op_is_zero, ir_mov(zf, ir_cst(1, zf.size-1, 0), addr));
    block->add_instr(op_is_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    bblkid = end;
    return;
}

inline void x86_bsr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, op0, counter, tmp0, zf, pc;
    IRBasicBlockId loop_test, loop_body, loop_exit, op_is_zero, op_not_zero, end;
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0); 
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    op_not_zero = block->new_bblock();
    loop_test = block->new_bblock();
    loop_body = block->new_bblock();
    loop_exit = block->new_bblock();
    op_is_zero = block->new_bblock();
    end = block->new_bblock();
    
    // Update PC first because then we don't know what branch we take
    pc = x86_get_pc(mode);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    // op0 == 0 ??
    block->add_instr(bblkid, ir_bcc(op0, ir_cst(op_not_zero, 31, 0), ir_cst(op_is_zero, 31, 0), addr));
    // 1°) Branch1 : op_not_zero
    counter = ir_tmp(tmp_var_count++, dest.size-1, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(op_not_zero, ir_mov(counter, ir_cst((dest.size-1), counter.size-1, 0), addr)); // counter <- sizeof(op0)-1
    block->add_instr(op_not_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop test: while ( op0[i] == 0 )
    block->add_instr(loop_test, ir_shr(tmp0, op0, counter, addr));
    block->add_instr(loop_test, ir_bcc(x86_arg_extract(tmp0,0,0) , ir_cst(loop_exit, 31, 0), ir_cst(loop_body, 31, 0), addr));
    // loop body: counter = counter - 1
    block->add_instr(loop_body, ir_sub(counter, counter, ir_cst(1, counter.size-1, 0), addr));
    block->add_instr(loop_body, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop exit: dest <- counter  and ZF <- 0
    x86_adjust_reg_assign(mode, addr, block, loop_exit, tmp_var_count, dest, counter);
    x86_set_zf(mode, op0, addr, block, loop_exit );
    block->add_instr(loop_exit, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // 2°) Branch2: op0 == 0
    // ZF <- 1
    block->add_instr(op_is_zero, ir_mov(zf, ir_cst(1, zf.size-1, 0), addr));
    block->add_instr(op_is_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    bblkid = end;
    return;
}

inline void x86_bswap_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, pc, res;
    /* Get operand */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( dest.size == 64 ){
        res = ir_tmp(tmp_var_count++, 63, 0);
        tmp0 = ir_tmp(tmp_var_count++, 7, 0);
        tmp1 = ir_tmp(tmp_var_count++, 7, 0);
        tmp2 = ir_tmp(tmp_var_count++, 7, 0);
        tmp3 = ir_tmp(tmp_var_count++, 7, 0);
        tmp4 = ir_tmp(tmp_var_count++, 7, 0);
        tmp5 = ir_tmp(tmp_var_count++, 7, 0);
        tmp6 = ir_tmp(tmp_var_count++, 7, 0);
        tmp7 = ir_tmp(tmp_var_count++, 7, 0);
        block->add_instr(bblkid, ir_mov(tmp0, x86_arg_extract(dest, 7, 0), addr));
        block->add_instr(bblkid, ir_mov(tmp1, x86_arg_extract(dest, 15, 8), addr));
        block->add_instr(bblkid, ir_mov(tmp2, x86_arg_extract(dest, 23, 16), addr));
        block->add_instr(bblkid, ir_mov(tmp3, x86_arg_extract(dest, 31, 24), addr));
        block->add_instr(bblkid, ir_mov(tmp4, x86_arg_extract(dest, 39,32), addr));
        block->add_instr(bblkid, ir_mov(tmp5, x86_arg_extract(dest, 47, 40), addr));
        block->add_instr(bblkid, ir_mov(tmp6, x86_arg_extract(dest, 55, 48), addr));
        block->add_instr(bblkid, ir_mov(tmp7, x86_arg_extract(dest, 63, 56), addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 63, 56), tmp0, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 55, 48), tmp1, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 47, 40), tmp2, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 39, 32), tmp3, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 31, 24), tmp4, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 23, 16), tmp5, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 15, 8), tmp6, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 7, 0), tmp7, addr));
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }else if( dest.size == 32 ){
        res = ir_tmp(tmp_var_count++, 31, 0);
        tmp0 = ir_tmp(tmp_var_count++, 7, 0);
        tmp1 = ir_tmp(tmp_var_count++, 7, 0);
        tmp2 = ir_tmp(tmp_var_count++, 7, 0);
        tmp3 = ir_tmp(tmp_var_count++, 7, 0);
        block->add_instr(bblkid, ir_mov(tmp0, x86_arg_extract(dest, 7, 0), addr));
        block->add_instr(bblkid, ir_mov(tmp1, x86_arg_extract(dest, 15, 8), addr));
        block->add_instr(bblkid, ir_mov(tmp2, x86_arg_extract(dest, 23, 16), addr));
        block->add_instr(bblkid, ir_mov(tmp3, x86_arg_extract(dest, 31, 24), addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 31, 24), tmp0, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 23, 16), tmp1, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 15, 8), tmp2, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(res, 7, 0), tmp3, addr));
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }else{
        throw runtime_exception("X86 BSWAP translation: accepts operands of size 32 or 64 only");
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
}


inline void x86_bt_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand base, off, cf, pc, tmp0;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp0, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp0,0,0), ir_cst(0, cf.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_btc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, base, off, cf, pc, tmp0, tmp1;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp1, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp1,0,0), ir_cst(0, cf.size-1, 0), addr));
    /* invert bit(base, off % ... )*/
    block->add_instr(bblkid, ir_shl(tmp1, ir_cst(1, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(bblkid, ir_xor(tmp1, base, tmp1, addr));
    
    /* Set the bit in the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp1, addr));
    /* Else direct register assign */
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp1);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_btr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, base, off, cf, pc, tmp0, tmp1;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp1, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp1,0,0), ir_cst(0, cf.size-1, 0), addr));
    /* bit(base, off % ... ) <- 0 */
    block->add_instr(bblkid, ir_shl(tmp1, ir_cst(1, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
    block->add_instr(bblkid, ir_and(tmp1, base, tmp1, addr));
    
    /* Set the bit in the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp1, addr));
    /* Else direct register assign */
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp1);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_bts_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, base, off, cf, pc, tmp0, tmp1;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp1, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp1,0,0), ir_cst(0, cf.size-1, 0), addr));
    /* bit(base, off % ... ) <- 1 */
    block->add_instr(bblkid, ir_shl(tmp1, ir_cst(1, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(bblkid, ir_or(tmp1, base, tmp1, addr));
    
    /* Set the bit in the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp1, addr));
    /* Else direct register assign */
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp1);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_bzhi_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, op0, op1, cf, of, pc, index, tmp0, tmp1, opsize, res;
    IRBasicBlockId  index_too_big = block->new_bblock(), 
                    index_ok = block->new_bblock(),
                    end = block->new_bblock(); 
    /* Get operands */
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[2]), block, bblkid, tmp_var_count, true);
    index = ir_tmp(tmp_var_count++, dest.size-1, 0);
    tmp0 = ir_tmp(tmp_var_count++, dest.size-1, 0);
    res = ir_tmp(tmp_var_count++, dest.size-1, 0);
    
    /* index <- op1[7:0]   
     * dest <- op0
     * dest[size(dest)-1:index] <- 0 
     * cf = 1 iff index > size(dest)-1 
     */
    // Get index
    block->add_instr(bblkid, ir_mov(index, op1, addr));
    block->add_instr(bblkid, ir_and(index, index, ir_cst(0xff, index.size-1, 0), addr));
    // Compare index and size operands
    opsize = ir_cst(dest.size, dest.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp0, opsize, ir_cst(1, opsize.size-1, 0), addr));
    block->add_instr(bblkid, ir_sub(tmp0, tmp0, index, addr));
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), 
                                    ir_cst(index_too_big, 31, 0),
                                    ir_cst(index_ok, 31, 0),
                                    addr));
    // 1°) Index > size operands -1
    block->add_instr(index_too_big, ir_mov(cf, ir_cst(1, cf.size-1, 0), addr));
    block->add_instr(index_too_big, ir_mov(res, op0, addr));
    x86_adjust_reg_assign(mode, addr, block, index_too_big, tmp_var_count, dest, res);
    block->add_instr(index_too_big, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    // 2°) Index < size operands
    tmp1 = ir_tmp(tmp_var_count++, dest.size-1, 0);
    block->add_instr(index_ok, ir_mov(cf, ir_cst(0, cf.size-1, 0), addr ));
    // Get mask size(dest)-1 .. index
    block->add_instr(index_ok, ir_shl(tmp0, ir_cst(1, index.size-1, 0), index, addr));
    block->add_instr(index_ok, ir_neg(tmp1, tmp0, addr));
    block->add_instr(index_ok, ir_or(tmp1, tmp1, tmp0, addr));
    block->add_instr(index_ok, ir_not(tmp1, tmp1, addr));
    // Mask res 
    block->add_instr(index_ok, ir_mov(res, dest, addr));
    block->add_instr(index_ok, ir_and(res, op0, tmp1, addr));
    x86_adjust_reg_assign(mode, addr, block, index_ok, tmp_var_count, dest, res);
    block->add_instr(index_ok, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    // 3° ) Common end: set flags and pc
    // OF cleared 
    block->add_instr(end, ir_mov(of, ir_cst(0, of.size-1, 0), addr ));
    // Set zf, cf
    x86_set_sf(mode, res, addr, block, end);
    x86_set_zf(mode, res, addr, block, end);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    bblkid = end;
    return;
}

inline void x86_call_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc;
    
    /* Increment program counter first because
     * the call is maybe relative to EIP/RIP */
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.high, 0), addr));

    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    
    /* Get and push next instruction address */
    block->add_instr(bblkid, ir_sub(sp, sp, ir_cst(pc.size/8, pc.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(sp, pc, addr));
    
    /* Jump to called address */
    block->add_instr(bblkid, ir_jcc(ir_cst(1, pc.size-1, 0), op0, ir_none(), addr));
    
    return;
}

inline void x86_cbw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* ax <- sign_extend(al)   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg, 7, 7), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg, 15, 8), ir_cst(0xff, 7, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg, 15, 8), ir_cst(0x0, 7, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cdq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg_a, reg_d, pc, cst0, cst1;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg_a = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    reg_d = (mode==CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    reg_d = x86_arg_extract(reg_d, 31, 0);
    cst1 = ir_cst(0xffffffff, 31, 0);
    cst0 = ir_cst(0, 31, 0);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* edx <- replicate(eax[31])   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg_a, 31, 31), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    x86_adjust_reg_assign(mode, addr, block, ext1, tmp_var_count, reg_d, cst1);
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    x86_adjust_reg_assign(mode, addr, block, ext0, tmp_var_count, reg_d, cst0);
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cdqe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg, pc;
    if( mode == CPUMode::X86 ){
        throw runtime_exception("CDQE: invalid instruction in X86 mode");
    }
    
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg = ir_var(X64_RAX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* rax <- sign_extend(eax)   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg, 31, 31), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg, 63, 32), ir_cst(0xffffffff, 31, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg, 63, 32), ir_cst(0x0, 31, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_clc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc;
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // cf <- 0
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0x0, cf.size-1, 0), addr));
    return;
}

inline void x86_cld_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand df, pc;
    df = (mode==CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // df <- 0
    block->add_instr(bblkid, ir_mov(df, ir_cst(0x0, df.size-1, 0), addr));
    return;
}

inline void x86_cli_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand if_flag, pc;
    if_flag = (mode==CPUMode::X86)? ir_var(X86_IF, 31, 0) : ir_var(X64_IF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // if_flag <- 0
    block->add_instr(bblkid, ir_mov(if_flag, ir_cst(0x0, if_flag.size-1, 0), addr));
    return;
}

inline void x86_cmc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc;
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // complement cf
    block->add_instr(bblkid, ir_xor(cf, cf, ir_cst(0x1, cf.size-1, 0), addr));
    return;
}

inline void x86_cmova_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, tmp1, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0 and ZF = 0 
    block->add_instr(bblkid, ir_not(tmp0, cf, addr));
    block->add_instr(bblkid, ir_not(tmp1, zf, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovae_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovbe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1 or ZF = 1 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmove_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if zf = 1
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, tmp1, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0 and OF = SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_not(tmp1, zf, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovge_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF != SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovle_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 1 or OF != SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_or(tmp0, x86_arg_extract(zf, 0, 0), tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovne_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovno_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 0
    block->add_instr(bblkid, ir_bcc(of, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}


inline void x86_cmovnp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if PF = 0
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovns_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 0
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}


inline void x86_cmovo_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 1
    block->add_instr(bblkid, ir_bcc(of, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 1
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovs_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 1
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    x86_adjust_reg_assign(mode, addr, block, do_mov, tmp_var_count, op0, op1);
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    /* but still assign op0 to itself if 64 bits (because in 64 bits, the instruction 
     * clears the upper bits when operands are 32 bits, even when the condition
     * is false */
    if( mode == CPUMode::X64 && op0.size == 32 ){
        x86_adjust_reg_assign(mode, addr, block, dont_mov, tmp_var_count, op0, op0);
    }
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    // Check if op1 is a imm and needs sign extend
    if( op1.size < op0.size && op1.is_cst()){
        op1 = ir_cst(cst_sign_extend(op1.size, op1.cst()), op0.size-1, 0);
    }
    // tmp <- op0 - op1
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp, op0, op1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp, addr, block, bblkid );
    x86_set_sf( mode, tmp, addr, block, bblkid );
    x86_sub_set_of( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
   
    return;
}

inline void x86_cmpsb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    /* Get operands */
    si = (mode == CPUMode::X86) ? ir_var(X86_ESI, 31, 0) : ir_var(X64_RSI, 63, 0);
    di = (mode == CPUMode::X86) ? ir_var(X86_EDI, 31, 0) : ir_var(X64_RDI, 63, 0);
    df = (mode == CPUMode::X86) ? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read bytes from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 7, 0);
    tmp1 = ir_tmp(tmp_var_count++, 7, 0);
    tmp2 = ir_tmp(tmp_var_count++, 7, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpsd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    /* Get operands */
    si = (mode == CPUMode::X86) ? ir_var(X86_ESI, 31, 0) : ir_var(X64_RSI, 63, 0);
    di = (mode == CPUMode::X86) ? ir_var(X86_EDI, 31, 0) : ir_var(X64_RDI, 63, 0);
    df = (mode == CPUMode::X86) ? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read dwords from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 31, 0);
    tmp1 = ir_tmp(tmp_var_count++, 31, 0);
    tmp2 = ir_tmp(tmp_var_count++, 31, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpsq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    if( mode == CPUMode::X86 ){
        throw runtime_exception("CMPSQ: instruction is invalid in X86 mode");
    }
    
    /* Get operands */
    si = ir_var(X64_RSI, 63, 0);
    di = ir_var(X64_RDI, 63, 0);
    df = ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read words from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 63, 0);
    tmp1 = ir_tmp(tmp_var_count++, 63, 0);
    tmp2 = ir_tmp(tmp_var_count++, 63, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpsw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    /* Get operands */
    si = (mode == CPUMode::X86) ? ir_var(X86_ESI, 31, 0) : ir_var(X64_RSI, 63, 0);
    di = (mode == CPUMode::X86) ? ir_var(X86_EDI, 31, 0) : ir_var(X64_RDI, 63, 0);
    df = (mode == CPUMode::X86) ? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read words from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 15, 0);
    tmp1 = ir_tmp(tmp_var_count++, 15, 0);
    tmp2 = ir_tmp(tmp_var_count++, 15, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpxchg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, dest, op0, op1, ax, zf, tmp;
    IRBasicBlockId eq, neq, end;
    
    eq = block->new_bblock();
    neq = block->new_bblock();
    end = block->new_bblock();
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86) ? ir_var(X86_EAX, op0.size-1, 0) : ir_var(X64_RAX, op0.size-1, 0);
    zf = (mode == CPUMode::X86) ? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
   /* Compare op0 and op1 */
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp, ax, op0, addr ));
    /* Set flags */
    x86_set_pf(mode, tmp, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, tmp, addr, block, bblkid );
    x86_set_zf(mode, tmp, addr, block, bblkid );
    x86_sub_set_af(mode, ax, op0, tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_cf(mode, ax, op0, tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, ax, op0, tmp, addr, block, bblkid, tmp_var_count);
    
    /* Exchange values depending on zf */
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(eq, 31, 0), ir_cst(neq, 31, 0), addr));
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(eq, ir_stm(op0, op1, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, eq, tmp_var_count, op0, op1);
    }
    block->add_instr(eq, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    x86_adjust_reg_assign(mode, addr, block, neq, tmp_var_count, ax, op0);
    block->add_instr(neq, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cpuid_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IRBasicBlockId  leaf_0 = block->new_bblock(),
                    end = block->new_bblock();
    IROperand eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    IROperand ebx = (mode == CPUMode::X86)? ir_var(X86_EBX, 31, 0) : ir_var(X64_RBX, 63, 0);
    IROperand ecx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0) : ir_var(X64_RCX, 63, 0);
    IROperand edx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);

    /* Test eax to know what cpuid leaf is requested */
    block->add_instr(bblkid, ir_bcc(eax, ir_cst(end, 31, 0), ir_cst(leaf_0, 31, 0), addr));
    
    /* Leaf 0
     * Return the CPU's manufacturer ID string in ebx, edx and ecx
     * Set EAX to the higher supported leaf */
    // Set registers to "GenuineIntel"
    x86_adjust_reg_assign(mode, addr, block, leaf_0, tmp_var_count, ebx, ir_cst(0x756e6547, 31, 0));
    x86_adjust_reg_assign(mode, addr, block, leaf_0, tmp_var_count, edx, ir_cst(0x49656e69, 31, 0));
    x86_adjust_reg_assign(mode, addr, block, leaf_0, tmp_var_count, ecx, ir_cst(0x6c65746e, 31, 0));
    // Set eax to 0 because other leafs are not supported yet
    x86_adjust_reg_assign(mode, addr, block, leaf_0, tmp_var_count, eax, ir_cst(0, 31, 0));
    block->add_instr(leaf_0, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    bblkid = end;
    return;
}

inline void x86_cqo_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg_a, reg_d, pc, cst0, cst1;
    if( mode == CPUMode::X86 ){
        throw runtime_exception("CQO: invalid instruction in X86 mode");
    }
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg_a = ir_var(X64_RAX, 63, 0);
    reg_d = ir_var(X64_RDX, 63, 0);
    cst1 = ir_cst(0xffffffffffffffff, 63, 0);
    cst0 = ir_cst(0, 63, 0);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* edx <- replicate(eax[63]) */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg_a, 63, 63), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    x86_adjust_reg_assign(mode, addr, block, ext1, tmp_var_count, reg_d, cst1);
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    x86_adjust_reg_assign(mode, addr, block, ext0, tmp_var_count, reg_d, cst0);
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}


inline void x86_cwd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg_a, reg_d, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg_a = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    reg_d = (mode==CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* dx <- replicate(ax[15])   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg_a, 15, 15), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg_d, 15, 0), ir_cst(0xffff, 15, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg_d, 15, 0), ir_cst(0x0, 15, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cwde_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* eax <- sign_extend(ax)   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg, 15, 15), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    if( mode == CPUMode::X64 ){ // zero higher bits
        block->add_instr(ext1, ir_mov(x86_arg_extract(reg, 63, 32), ir_cst(0, 31, 0), addr));
    }
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg, 31, 16), ir_cst(0xffff, 15, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    if( mode == CPUMode::X64 ){ // zero higher bits
        block->add_instr(ext0, ir_mov(x86_arg_extract(reg, 63, 32), ir_cst(0, 31, 0), addr));
    }
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg, 31, 16), ir_cst(0x0, 15, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_dec_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, dest, op0, tmp;
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    
    /* Decrement op0 */
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0); 
    block->add_instr(bblkid, ir_sub(tmp, op0, ir_cst(1, op0.size-1, 0), addr ));
    
    /* Set flags (except CF) */
    x86_set_pf(mode, tmp, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, tmp, addr, block, bblkid );
    x86_set_zf(mode, tmp, addr, block, bblkid );
    x86_sub_set_af(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    
    /* Store result */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}


inline void x86_div_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, dividend, remainder, tmp, ax, dx, tmp_dividend, tmp_remainder;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    dx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp_dividend = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp_remainder = ir_tmp(tmp_var_count++, op0.size-1, 0);
    if( op0.size == 8 ){
        dividend = x86_arg_extract(ax, 7, 0);
        remainder = x86_arg_extract(ax, 15, 8);
    }else{
        dividend = x86_arg_extract(ax, op0.size-1, 0);
        remainder = x86_arg_extract(dx, op0.size-1, 0);
    }
    
    /* Do the div */
    block->add_instr(bblkid, ir_mov(tmp, x86_arg_extract(ax, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_div(tmp_dividend, tmp , op0, addr ));
    block->add_instr(bblkid, ir_mod(tmp_remainder, tmp , op0, addr ));
    /* Assign results to registers */
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dividend, tmp_dividend);
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, remainder, tmp_remainder);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_idiv_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, ax, dx, tmp, dividend, remainder, tmp_dividend, tmp_remainder;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    dx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp_dividend = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp_remainder = ir_tmp(tmp_var_count++, op0.size-1, 0);
    
    if( op0.size == 8 ){
        dividend = x86_arg_extract(ax, 7, 0);
        remainder = x86_arg_extract(ax, 15, 8);
    }else{
        dividend = x86_arg_extract(ax, op0.size-1, 0);
        remainder = x86_arg_extract(dx, op0.size-1, 0);
    }

    /* Quotient in *ax, remainder in *dx */
    block->add_instr(bblkid, ir_mov(tmp, x86_arg_extract(ax, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_sdiv(tmp_dividend, tmp , op0, addr ));
    block->add_instr(bblkid, ir_smod(tmp_remainder, tmp , op0, addr ));
    /* Assign results to registers */
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dividend, tmp_dividend);
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, remainder, tmp_remainder);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_imul_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, op2, lower, higher, tmp0, tmp1, ax, tmp2, tmp3, tmp4, cf, of;
    
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0): ir_var(X64_OF, 63, 0);
    
    /* One-operand form */
    if( instr->detail->x86.op_count == 1 ){
        /* Get operands */
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        ax = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
        if( op0.size == 8 ){
            lower = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 7, 0);
            higher = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 8): ir_var(X64_RAX, 15, 8);
        }else{
            lower = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
            higher = (mode == CPUMode::X86)? ir_var(X86_EDX, op0.size-1, 0): ir_var(X64_RDX, op0.size-1, 0);
        }
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp2 = ir_tmp(tmp_var_count++, 0, 0);
        tmp3 = ir_tmp(tmp_var_count++, 0, 0);
        
        /* Do the multiplication */
        block->add_instr(bblkid, ir_smull(tmp0, ax, op0, addr));
        block->add_instr(bblkid, ir_smulh(tmp1, ax, op0, addr));
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, lower, tmp0);
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, higher, tmp1);
        
        /* Set OF and CF iff the higher:lower != signextend(lower) 
         * SO we do 
         *      higher==0 && lower[n-1] == 0 
         *  OR  higher==0xfff.... && lower[n-1] == 1 */
        block->add_instr(bblkid, ir_bisz(tmp2, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_not(tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), addr));
        block->add_instr(bblkid, ir_and(tmp2, tmp2, tmp3, addr));
        block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
        block->add_instr(bblkid, ir_bisz(tmp3, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_and(tmp3, tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1),  addr));
        block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr));
        
        block->add_instr(bblkid, ir_bisz(cf, tmp3, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_bisz(of, tmp3, ir_cst(1, 0, 0), addr));
    
    /* Two-operands form */
    }else if( instr->detail->x86.op_count == 2){
        /* Get operands */
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp2 = ir_tmp(tmp_var_count++, 0, 0);
        tmp3 = ir_tmp(tmp_var_count++, 0, 0);
        
        /* Do the multiplication */
        block->add_instr(bblkid, ir_smull(tmp0, op0, op1, addr));
        block->add_instr(bblkid, ir_smulh(tmp1, op0, op1, addr));
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op0, tmp0);
        
        /* Set OF and CF iff the higher:lower != signextend(lower) 
         * SO we do 
         *      higher==0 && lower[n-1] == 0 
         *  OR  higher==0xfff.... && lower[n-1] == 1 */
        block->add_instr(bblkid, ir_bisz(tmp2, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_not(tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), addr));
        block->add_instr(bblkid, ir_and(tmp2, tmp2, tmp3, addr));
        block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
        block->add_instr(bblkid, ir_bisz(tmp3, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_and(tmp3, tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1),  addr));
        block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr));
        
        block->add_instr(bblkid, ir_bisz(cf, tmp3, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_bisz(of, tmp3, ir_cst(1, 0, 0), addr));
         
        
    /* Three-operands form */
    }else{
        /* Get operands */
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
        op2 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[2]), block, bblkid, tmp_var_count, true);
        if( op2.size == 8 )
            op2 = ir_cst(op2.cst(), op1.size-1, 0); // Already sign extended in IROperand() constructor
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp2 = ir_tmp(tmp_var_count++, 0, 0);
        tmp3 = ir_tmp(tmp_var_count++, 0, 0);
        
        /* Do the multiplication */
        block->add_instr(bblkid, ir_smull(tmp0, op1, op2, addr));
        block->add_instr(bblkid, ir_smulh(tmp1, op1, op2, addr));
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op0, tmp0);
        
        /* Set OF and CF iff the higher:lower != signextend(lower) 
         * SO we do 
         *      higher==0 && lower[n-1] == 0 
         *  OR  higher==0xfff.... && lower[n-1] == 1 */
        block->add_instr(bblkid, ir_bisz(tmp2, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_not(tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), addr));
        block->add_instr(bblkid, ir_and(tmp2, tmp2, tmp3, addr));
        block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
        block->add_instr(bblkid, ir_bisz(tmp3, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_and(tmp3, tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1),  addr));
        block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr));
        
        block->add_instr(bblkid, ir_bisz(cf, tmp3, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_bisz(of, tmp3, ir_cst(1, 0, 0), addr));
        
    }
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_inc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, dest, op0, tmp;
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    
    /* Increment op0 */
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0); 
    block->add_instr(bblkid, ir_add(tmp, op0, ir_cst(1, op0.size-1, 0), addr ));
    
    /* Set flags (except CF) */
    x86_set_pf(mode, tmp, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, tmp, addr, block, bblkid );
    x86_set_zf(mode, tmp, addr, block, bblkid );
    x86_sub_set_af(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    
    /* Store result */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_int_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, num, next_pc;
    
    /* Get operands */
    pc = x86_get_pc(mode);
    next_pc = ir_tmp(tmp_var_count++, pc.size-1, 0); 
    block->add_instr(bblkid, ir_add(next_pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    num = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    /* Create interrupt */
    block->add_instr(bblkid, ir_int(num, next_pc, addr));
    return;
}

inline void x86_int3_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, num, next_pc;
    
    /* Get operands */
    pc = x86_get_pc(mode);
    next_pc = ir_tmp(tmp_var_count++, pc.size-1, 0);
    block->add_instr(bblkid, ir_add(next_pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* Create interrupt 3 */
    block->add_instr(bblkid, ir_int(ir_cst(3, 7, 0), next_pc, addr));
    return;
}

inline void x86_leave_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, bp, sp;
    
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0) : ir_var(X64_RSP, 63, 0);
    bp = (mode == CPUMode::X86)? ir_var(X86_EBP, 31, 0) : ir_var(X64_RBP, 63, 0);    
       
    /* esp <- ebp
     * ebp <- pop() */ 
    block->add_instr(bblkid, ir_mov(sp, bp, addr ));
    block->add_instr(bblkid, ir_ldm(bp, sp, addr ));
    block->add_instr(bblkid, ir_add(sp, sp, ir_cst(bp.size/8, sp.size-1, 0), addr ));
    
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_ja_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp2, zf, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, cf.size-1, 0);

    /* Condition CF = ZF = 0 */ 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr));
    
    return;
}

inline void x86_jae_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Condition CF = 0 */ 
    block->add_instr(bblkid, ir_jcc(cf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr));
    
    return;
}

inline void x86_jb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);

    /* Condition CF = 1 */ 
    block->add_instr(bblkid, ir_jcc(cf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr));
    
    return;
}

inline void x86_jbe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, zf, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, cf.size-1, 0);
    
    /* Condition CF = 1 or ZF = 1 */ 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jcxz_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, cx, op0;
    if( mode == CPUMode::X64 ){
        throw runtime_exception("JCXZ: invalid in X64 mode");
    }
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cx = (mode == CPUMode::X86)? ir_var(X86_ECX, 15, 0) : ir_var(X64_RCX, 15, 0);
    
    /* Condition CX = 0 */ 
    block->add_instr(bblkid, ir_jcc(cx, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_je_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, zf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);

    /* Condition ZF = 1 */ 
    block->add_instr(bblkid, ir_jcc(zf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr));
    
    return;
}

inline void x86_jecxz_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ecx, op0;

    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    ecx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0) : ir_var(X64_RCX, 31, 0);
    
    /* Condition ECX = 0 */ 
    block->add_instr(bblkid, ir_jcc(ecx, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, zf, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);

    /* Condition ZF = 0 and SF = OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    block->add_instr(bblkid, ir_or(tmp0, tmp0, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jge_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);
    
    /* Condition SF = OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);

    /* Condition SF != OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jle_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, zf, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);

    /* Condition ZF = 1 or SF != OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    block->add_instr(bblkid, ir_or(tmp0, tmp0, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jmp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0;

    // Update PC first in case jmp is PC relative
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    block->add_instr(bblkid, ir_jcc(ir_cst(1, pc.size-1, 0), op0, ir_none(), addr ));

    return;
}

inline void x86_jne_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, zf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);

    /* Condition ZF = 0 */ 
    block->add_instr(bblkid, ir_jcc(zf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jno_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Condition OF = 0 */ 
    block->add_instr(bblkid, ir_jcc(of, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jnp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, pf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    pf = (mode == CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Condition PF = 0 */ 
    block->add_instr(bblkid, ir_jcc(pf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jns_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, sf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);

    /* Condition SF = 0 */ 
    block->add_instr(bblkid, ir_jcc(sf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jo_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Condition OF = 1 */ 
    block->add_instr(bblkid, ir_jcc(of, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, pf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    pf = (mode == CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Condition PF = 1 */ 
    block->add_instr(bblkid, ir_jcc(pf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}


inline void x86_jrcxz_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, rcx, op0;
    
    if( mode == CPUMode::X86 ){
        throw runtime_exception("JRCXZ: invalid in X86 mode");
    }
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = ir_var(X64_RIP, 63, 0);
    rcx = ir_var(X64_RCX, 63, 0);
    
    /* Condition RCX = 0 */ 
    block->add_instr(bblkid, ir_jcc(rcx, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}


inline void x86_js_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, sf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);

    /* Condition SF = 1 */ 
    block->add_instr(bblkid, ir_jcc(sf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}


inline void x86_lahf_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, sf, zf, af, pf, cf, ax;

    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    af = (mode == CPUMode::X86)? ir_var(X86_AF, 31, 0) : ir_var(X64_AF, 63, 0);
    pf = (mode == CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    
    /* AH <- EFLAGS(SF:ZF:0:AF:0:PF:1:CF) */ 
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 15, 15), x86_arg_extract(sf, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 14, 14), x86_arg_extract(zf, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 13, 13), ir_cst(0, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 12, 12), x86_arg_extract(af, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 11, 11), ir_cst(0, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 10, 10), x86_arg_extract(pf, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 9, 9), ir_cst(1, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 8, 8), x86_arg_extract(cf, 0, 0), addr ));
    
    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_lea_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, op0, op1;
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    
    // Update PC first in case PC relative load!
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count);

    /* Check operand sizes */
    if( op0.size > op1.size ){
        /* Zero extend */
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        block->add_instr(bblkid, ir_mov(tmp0, ir_cst(0, op0.size-1, 0), addr ));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op0, tmp0);
    }else{
        /* Truncate if needed */
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op0, x86_arg_extract(op1, op0.size-1, 0));
    }
}

inline void x86_lodsb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, al, si, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    al = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 7, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(al, si, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_lodsd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, eax, si, df, tmp;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 31, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    tmp = ir_tmp(tmp_var_count++, eax.size-1, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(tmp, si, addr));
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, eax, tmp);
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_lodsq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, rax, si, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = ir_var(X64_DF, 63, 0);
    rax = ir_var(X64_RAX, 63, 0);
    si = ir_var(X64_RSI, 63, 0);
    pc = ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(rax, si, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_lodsw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ax, si, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 0): ir_var(X64_RAX, 15, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(ax, si, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_mov_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1;

    // Update PC (in case PC-relative addressing)
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    /*  Do the mov */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(op0, op1, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op0, op1);
    }
    
    return;
}

inline void x86_movsb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, 7, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load dword */
    tmp0 = ir_tmp(tmp_var_count++, 31, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load qword */
    tmp0 = ir_tmp(tmp_var_count++, 63, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load word */
    tmp0 = ir_tmp(tmp_var_count++, 15, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsx_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp0;
    IRBasicBlockId pos, neg, end;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    /*  Test MSB */
    pos = block->new_bblock();
    neg = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(op1, op1.size-1, op1.size-1), ir_cst(neg, 31, 0), ir_cst(pos, 31, 0), addr));
    /* Positive (0 extend) */
    block->add_instr(pos, ir_mov(tmp0, ir_cst(0, tmp0.size-1, 0), addr));
    block->add_instr(pos, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    x86_adjust_reg_assign(mode, addr, block, pos, tmp_var_count, op0, tmp0);
    block->add_instr(pos, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Negative (1 extend) */
    block->add_instr(neg, ir_mov(tmp0, ir_cst((ucst_t)0xffffffffffffffff<<op1.size, tmp0.size-1, 0), addr));
    block->add_instr(neg, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    x86_adjust_reg_assign(mode, addr, block, neg, tmp_var_count, op0, tmp0);
    block->add_instr(neg, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_movsxd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp0;
    IRBasicBlockId pos, neg, end;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    /* If already same size, just mov */
    if( op0.size == op1.size ){
        block->add_instr(bblkid, ir_mov(op0, op1, addr));
        return;
    }
    /*  Else extend : Test MSB */
    pos = block->new_bblock();
    neg = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(op1, op1.size-1, op1.size-1), ir_cst(neg, 31, 0), ir_cst(pos, 31, 0), addr));
    /* Positive (0 extend) */
    block->add_instr(pos, ir_mov(tmp0, ir_cst(0, tmp0.size-1, 0), addr));
    block->add_instr(pos, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    x86_adjust_reg_assign(mode, addr, block, pos, tmp_var_count, op0, tmp0);
    block->add_instr(pos, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Negative (1 extend) */
    block->add_instr(neg, ir_mov(tmp0, ir_cst((ucst_t)0xffffffffffffffff<<op1.size, tmp0.size-1, 0), addr));
    block->add_instr(neg, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    x86_adjust_reg_assign(mode, addr, block, neg, tmp_var_count, op0, tmp0);
    block->add_instr(neg, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_movzx_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);

    /* Positive (0 extend) */
    block->add_instr(bblkid, ir_mov(tmp0, ir_cst(0, tmp0.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op0, tmp0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_mul_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, lower, higher, tmp0, tmp1, ax, tmp2, tmp3, tmp4, cf, of;
    
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0): ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
    if( op0.size == 8 ){
        lower = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 15, 0);
        higher = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 8): ir_var(X64_RAX, 15, 8);
    }else{
        lower = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
        higher = (mode == CPUMode::X86)? ir_var(X86_EDX, op0.size-1, 0): ir_var(X64_RDX, op0.size-1, 0);
    }
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp2 = ir_tmp(tmp_var_count++, 0, 0);
    tmp3 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Do the multiplication */
    block->add_instr(bblkid, ir_mul(tmp0, ax, op0, addr));
    block->add_instr(bblkid, ir_mulh(tmp1, ax, op0, addr));
    
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, lower, tmp0);
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, higher, tmp1);

    /* Set OF and CF to 1 if high order bits are not zero, else clear */
    block->add_instr(bblkid, ir_bisz(cf, tmp1, ir_cst(0, cf.size-1, 0), addr));
    block->add_instr(bblkid, ir_bisz(of, tmp1, ir_cst(0, of.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}


inline void x86_neg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, cf, tmp0, dest;

    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);

    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);

    /* CF = (op0 != 0) */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(0, cf.size-1, 0), addr));
    /* Do the neg */
    block->add_instr(bblkid, ir_neg(tmp0, op0, addr));

    /* Set flags according to the result (same that for a sub from 0) */
    x86_set_sf(mode, tmp0, addr, block, bblkid);
    x86_set_zf(mode, tmp0, addr, block, bblkid);
    x86_set_pf(mode, tmp0, addr, block, bblkid, tmp_var_count);
    x86_sub_set_af(mode, ir_cst(0, op0.size-1, 0), op0, tmp0, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, ir_cst(0, op0.size-1, 0), op0, tmp0, addr, block, bblkid, tmp_var_count);

    /*  Assign result */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp0, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp0);
    }

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    return;
}

inline void x86_nop_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc;
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_not_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, dest, tmp;
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);

    /* Do the not */
    block->add_instr(bblkid, ir_not(tmp, op0, addr));
    
    /*  Assign result */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp);
    } 

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_or_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the or */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_or(res, op0, op1, addr));
    
    /* Update flags: SF, ZF, PF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_pop_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc, tmp0;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    
    /* Get the value on the stack */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, sp, addr));
    
    /* Increment stack pointer */
    block->add_instr(bblkid, ir_add(sp, sp, ir_cst(instr->detail->x86.operands[0].size, sp.size-1, 0), addr));
    
    /* Assign the value that was on the stack (AFTER incrementing ESP) */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(op0, tmp0, addr));
    }else{
        block->add_instr(bblkid, ir_mov(op0, tmp0, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_popad_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand esp, pc, edi, esi, ebp, ebx, edx, ecx, eax;
    if( mode == CPUMode::X64 ){
        throw runtime_exception("POPAD: invalid in X64 mode");
    }

    /* Get operands */
    esp = ir_var(X86_ESP, 31, 0);
    edi = ir_var(X86_EDI, 31, 0); 
    esi = ir_var(X86_ESI, 31, 0); 
    ebp = ir_var(X86_EBP, 31, 0); 
    ebx = ir_var(X86_EBX, 31, 0); 
    edx = ir_var(X86_EDX, 31, 0); 
    ecx = ir_var(X86_ECX, 31, 0); 
    eax = ir_var(X86_EAX, 31, 0);  
    
    /* Get the registers on the stack:
        EDI ← Pop();
        ESI ← Pop();
        EBP ← Pop();
        Increment ESP by 4; (* Skip next 4 bytes of stack *)
        EBX ← Pop();
        EDX ← Pop();
        ECX ← Pop();
        EAX ← Pop(); */
    
    block->add_instr(bblkid, ir_ldm(edi, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(esi, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(ebp, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/4, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(ebx, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(edx, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(ecx, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(eax, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_push_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    
    /* Decrement stack pointer */
    block->add_instr(bblkid, ir_sub(sp, sp, ir_cst(instr->detail->x86.operands[0].size, sp.size-1, 0), addr));
    
    /* Get the value on the stack */
    block->add_instr(bblkid, ir_stm(sp, op0, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_pushad_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand esp, pc, edi, esi, ebp, ebx, edx, ecx, eax, tmp0;
    
    /* Get operands */
    esp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0);
    edi = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0); 
    esi = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0); 
    ebp = (mode == CPUMode::X86)? ir_var(X86_EBP, 31, 0): ir_var(X64_RBP, 63, 0); 
    ebx = (mode == CPUMode::X86)? ir_var(X86_EBX, 31, 0): ir_var(X64_RBX, 63, 0); 
    edx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0): ir_var(X64_RDX, 63, 0); 
    ecx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0): ir_var(X64_RCX, 63, 0); 
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 63, 0);  
    tmp0 = ir_tmp(tmp_var_count++, esp.size-1, 0);
    
    /* Get the registers on the stack:
        Temp ← (ESP);
        Push(EAX);
        Push(ECX);
        Push(EDX);
        Push(EBX);
        Push(Temp);
        Push(EBP);
        Push(ESI);
        Push(EDI); */
    
    block->add_instr(bblkid, ir_mov(tmp0, esp, addr));
    
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, eax, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, ecx, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, edx, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, ebx, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, tmp0, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, ebp, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, esi, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, edi, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_rcl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, of, res;
    IRBasicBlockId set_of, cont, rotate;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);

    /* Blocks */
    rotate = block->new_bblock();
    set_of = block->new_bblock();
    cont = block->new_bblock();

    // mask is 5 bits <= 32 bits operands, 6 bits for 64 bits operands
    unsigned int mask = (op0.size == 64)? 0b111111 : 0b11111;

    /* Mask the number of rotations N */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr));
    
    /* If masked count is zero, go to end, else do rotate */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(rotate, 31, 0), ir_cst(cont, 31, 0), addr));
    
    // Rotate 
    /* REG[up] = REG[size-1-N:N] = tmp1 */
    block->add_instr(rotate, ir_shl(tmp1, op0, tmp0, addr)); // Just shift left
    
    /* REG[N-1] = CF = tmp2 */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_sub(tmp3, tmp0, ir_cst(1, tmp0.size-1, 0), addr)); // tmp3 = N-1
    block->add_instr(rotate, ir_shl(tmp2, x86_arg_extract(cf, op0.size-1, 0), tmp3, addr)); // Just shift left of N-1
    
    /* REG[N-2:0] = REG[:size-N+1] = tmp5 */
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp5 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_sub(tmp4, ir_cst(op0.size+1, op0.size-1, 0), tmp0, addr)); // tmp4 = size-N+1
    block->add_instr(rotate, ir_shr(tmp5, op0, tmp4, addr)); // Shift right of size-N+1

    /* Res is the OR of everything */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_or(res, tmp1, tmp2, addr));
    block->add_instr(rotate, ir_or(res, res, tmp5, addr));

    /* Assign res to dest and CF */
    /* CF = REG[size-N] (first CF because after we modify reg ! */
    tmp6 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_shl(tmp6, op0, tmp3, addr)); // Just shift left of N-1
    block->add_instr(rotate, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp6, tmp6.size-1, tmp6.size-1), addr));
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(rotate, ir_stm(dest, res, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, rotate, tmp_var_count, dest, res);
    }
    
    /* Affect OF flag iff masked count == 1 (cf.res in tmp3)*/
    tmp7 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(rotate, ir_xor(tmp7, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(rotate, ir_bcc(tmp7, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(res, res.size-1, res.size-1), x86_arg_extract(cf, 0, 0), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(cont, 31, 0), ir_none(), addr));

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(cont, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    bblkid = cont;
    return;
}

inline void x86_rcr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, of, res;
    IRBasicBlockId set_of, cont, rotate;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);

    /* Blocks */
    rotate = block->new_bblock();
    set_of = block->new_bblock();
    cont = block->new_bblock();

    // mask is 5 bits <= 32 bits operands, 6 bits for 64 bits operands
    unsigned int mask = (op0.size == 64)? 0b111111 : 0b11111;

    /* Mask the number of rotations N */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr));
    
    /* If masked count is zero, go to end, else do rotate */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(rotate, 31, 0), ir_cst(cont, 31, 0), addr));
    
    // Rotate 
    /* REG[down] = REG[size-1:N] = tmp1 */
    block->add_instr(rotate, ir_shr(tmp1, op0, tmp0, addr)); // Just shift right
    
    /* REG[size-N] = CF = tmp2 */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_sub(tmp3, ir_cst(tmp0.size, tmp0.size-1, 0), tmp0, addr)); // tmp3 = size-N
    block->add_instr(rotate, ir_shl(tmp2, x86_arg_extract(cf, op0.size-1, 0), tmp3, addr)); // Just shift left of size-N
    
    /* REG[size:N] = REG[N-2:] = tmp5 */
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp5 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_add(tmp4, ir_cst(1, op0.size-1, 0), tmp3, addr)); // tmp4 = size-N+1
    block->add_instr(rotate, ir_shl(tmp5, op0, tmp4, addr)); // Shift left of size-N+1

    /* Res is the OR of everything */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_or(res, tmp1, tmp2, addr));
    block->add_instr(rotate, ir_or(res, res, tmp5, addr));

    /* Assign res to dest and CF */
    /* CF = REG[size-N] (first CF because after we modify reg ! */
    tmp6 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_shl(tmp6, op0, tmp3, addr)); // Just shift left of N-1
    block->add_instr(rotate, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp6, tmp6.size-1, tmp6.size-1), addr));
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(rotate, ir_stm(dest, res, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, rotate, tmp_var_count, dest, res);
    }
    
    /* Affect OF flag iff masked count == 1 (cf.res in tmp3)*/
    tmp7 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(rotate, ir_xor(tmp7, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(rotate, ir_bcc(tmp7, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(res, res.size-1, res.size-1), x86_arg_extract(res, res.size-2, res.size-2), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(cont, 31, 0), ir_none(), addr));

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(cont, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    bblkid = cont;
    return;
}

inline void x86_rdtsc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand   eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 63, 0),
                edx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0): ir_var(X64_RDX, 63, 0),
                tsc = x86_get_tsc(mode), // TSC is always 64 bits
                pc = x86_get_pc(mode);
                    
    // Higher 32 bits in edx, lower 32 bits in eax
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, edx, x86_arg_extract(tsc, 63, 32));
    x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, eax, x86_arg_extract(tsc, 31, 0));

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
}


inline void x86_ret_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc, tmp0;
    
    /* Get operands */
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0): ir_var(X64_RIP, 63, 0);
    
    /* Pop program counter */
    tmp0 = ir_tmp(tmp_var_count++, pc.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, sp, addr));
    block->add_instr(bblkid, ir_add(sp, sp, ir_cst(pc.size/8, sp.size-1, 0), addr));
    
    /* If source operand adjust sp */
    if( instr->detail->x86.op_count != 0 ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        block->add_instr(bblkid, ir_add(sp, sp, op0, addr));
    }
    
    block->add_instr(bblkid, ir_jcc(ir_cst(1, pc.size-1, 0), tmp0, ir_none(), addr));
    
    return;
}

inline void x86_rol_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, of;
    IRBasicBlockId set_of, cont, set_cf, end, rotate;
    
    rotate = block->new_bblock();
    set_cf = block->new_bblock();
    cont = block->new_bblock();
    set_of = block->new_bblock();
    end = block->new_bblock();
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    // mask is 5 bits for <= 32 bits operands, 6 bits for 64 bits operands
    unsigned int mask = (op0.size == 64)? 0b111111 : 0b11111;
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr)); 

    /* Check if count is 0 */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(rotate, 31, 0), ir_cst(end, 31, 0), addr));

    // Do rotate
    /* Set rotations */
    tmp4 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(rotate, ir_sub(tmp4, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr));
    
    /* Rotate it (2 shifts) */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_shl(tmp2, op0, tmp0, addr));
    block->add_instr(rotate, ir_shr(tmp3, op0, tmp4, addr));
    block->add_instr(rotate, ir_or(tmp3, tmp3, tmp2, addr)); // res in tmp3
    
    /* Assign result to operand */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(rotate, ir_stm(dest, tmp3, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, rotate, tmp_var_count, dest, tmp3);
    }
    
    /* Affect CF flag iff masked count != 0 */
    block->add_instr(rotate, ir_bcc(tmp0, ir_cst(set_cf, 31, 0), ir_cst(end, 31, 0), addr));
    block->add_instr(set_cf, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp3, 0, 0), addr));
    block->add_instr(set_cf, ir_bcc(ir_cst(1, 31, 0), ir_cst(cont, 31, 0), ir_none(), addr));
    
    /* Affect OF flag iff masked count == 1 (res in tmp3) */
    tmp7 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(cont, ir_xor(tmp7, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(cont, ir_bcc(tmp7, ir_cst(end, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(tmp3, tmp3.size-1, tmp3.size-1), x86_arg_extract(cf, 0, 0), addr)); 
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    bblkid = end;
    return;
}

inline void x86_ror_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, of;
    IRBasicBlockId set_of, cont, set_cf, end, rotate;
    
    rotate = block->new_bblock();
    set_cf = block->new_bblock();
    cont = block->new_bblock();
    set_of = block->new_bblock();
    end = block->new_bblock();
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    // mask is 5 bits <= 32 bits operands, 6 bits for 64 bits operands
    unsigned int mask = (op0.size == 64)? 0b111111 : 0b11111;
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr));

    /* Check if count is 0 */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(rotate, 31, 0), ir_cst(end, 31, 0), addr));

    // Do rotate
    block->add_instr(rotate, ir_mov(tmp1, tmp0, addr)); // copy of tmp0
    /* Set rotations */
    tmp4 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(rotate, ir_sub(tmp4, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr));
    
    /* Rotate it (2 shifts) */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(rotate, ir_shr(tmp2, op0, tmp0, addr));
    block->add_instr(rotate, ir_shl(tmp3, op0, tmp4, addr));
    block->add_instr(rotate, ir_or(tmp3, tmp3, tmp2, addr)); // res in tmp3
    
    /* Assign result to operand */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(rotate, ir_stm(dest, tmp3, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, rotate, tmp_var_count, dest, tmp3);
    }

    /* Affect CF flag iff masked count != 0 */
    block->add_instr(rotate, ir_bcc(tmp0, ir_cst(set_cf, 31, 0), ir_cst(end, 31, 0), addr));
    block->add_instr(set_cf, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp3, tmp3.size-1, tmp3.size-1), addr));
    block->add_instr(set_cf, ir_bcc(ir_cst(1, 31, 0), ir_cst(cont, 31, 0), ir_none(), addr));

    /* Affect OF flag iff masked count == 1 (res in tmp3) */
    tmp5 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(cont, ir_xor(tmp5, tmp1, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(cont, ir_bcc(tmp5, ir_cst(end, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(tmp3, tmp3.size-2, tmp3.size-2), x86_arg_extract(cf, 0, 0), addr)); 
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    bblkid = end;
    return;
}

inline void x86_sal_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, of;
    IRBasicBlockId set_of, cont, shift;

    shift = block->new_bblock();
    set_of = block->new_bblock();
    cont = block->new_bblock();

    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    // mask is 5 bits for operands <= 32bits, 6 bits for 64 bits operands
    unsigned int mask = (op0.size == 64)? 0b111111 : 0b11111;

    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr));

    /* Check if count is 0 */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(shift, 31, 0), ir_cst(cont, 31, 0), addr));

    // Do shift
    /* Affect CF (last bit shifted out) */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(shift, ir_sub(tmp1, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr)); // Num of the last bit that'll be shifted out
    //block->add_instr(shift, ir_neg(tmp1, tmp1, addr)); // Shift right to get the bit
    block->add_instr(shift, ir_shr(tmp4, op0, tmp1, addr));
    block->add_instr(shift, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp4, 0, 0), addr));
    
    /* Do the shift */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(shift, ir_shl(tmp2, op0, tmp0, addr));
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(shift, ir_stm(dest, tmp2, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, shift, tmp_var_count, dest, tmp2);
    }
    
    /* Affect OF flag iff masked count == 1 */
    tmp3 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(shift, ir_xor(tmp3, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(shift, ir_bcc(tmp3, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(tmp2, tmp2.size-1, tmp2.size-1), x86_arg_extract(cf, 0, 0), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(cont, 31, 0), ir_none(), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(cont, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    bblkid = cont;
    return;
}

inline void x86_sar_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, of;
    IRBasicBlockId set_of, cont, pos, neg, shift;
    
    shift = block->new_bblock();
    pos = block->new_bblock();
    neg = block->new_bblock();
    set_of = block->new_bblock();
    cont = block->new_bblock();
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    // mask is 5 bits for operands <= 32bits, 6 bits for 64 bits operands
    unsigned int mask = (op0.size == 64)? 0b111111 : 0b11111;
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(tmp3, tmp0, addr)); // save in tmp3
    
    /* Check if count is 0 */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(shift, 31, 0), ir_cst(cont, 31, 0), addr));

    // Do shift
    /* Affect CF (last bit shifted out) */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(shift, ir_sub(tmp1, tmp0, ir_cst(1, tmp0.size-1, 0), addr)); // Num of the last bit that'll be shifted out
    //block->add_instr(shift, ir_neg(tmp1, tmp1, addr)); // Shift right to get the bit
    block->add_instr(shift, ir_shr(tmp4, op0, tmp1, addr));
    block->add_instr(shift, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp4, 0, 0), addr));
    
    /* Get mask for sign propagation when shifting */
    tmp5 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp6 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(shift, ir_bcc(x86_arg_extract(op0, op0.size-1, op0.size-1), ir_cst(neg, 31, 0), ir_cst(pos, 31, 0), addr));
    shift = block->new_bblock();
    block->add_instr(pos, ir_mov(tmp5, ir_cst(0, tmp5.size-1, 0), addr));
    block->add_instr(pos, ir_bcc(ir_cst(1, 31, 0), ir_cst(shift, 31, 0), ir_none(), addr));
    block->add_instr(neg, ir_mov(tmp5, ir_cst(-1, tmp5.size-1, 0), addr));
    block->add_instr(neg, ir_sub(tmp6, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(neg, ir_shl(tmp5, tmp5, tmp6, addr));
    block->add_instr(neg, ir_bcc(ir_cst(1, 31, 0), ir_cst(shift, 31, 0), ir_none(), addr));
    
    /* Do the shift */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(shift, ir_shr(tmp2, op0, tmp0, addr));
    block->add_instr(shift, ir_or(tmp2, tmp2, tmp5, addr));

    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(shift, ir_stm(dest, tmp2, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, shift, tmp_var_count, dest, tmp2);
    }
    
    /* Affect OF flag iff masked count == 1 */
    block->add_instr(shift, ir_xor(tmp3, tmp3, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(shift, ir_bcc(tmp3, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_mov(of, ir_cst(0, of.size-1, 0), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(cont, 31, 0), ir_none(), addr));
    
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(cont, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = cont;
    return;
}

inline void x86_scasb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, al, di, df, tmp0, tmp1;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    al = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 7, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, al.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, al.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, di, addr));
    block->add_instr(bblkid, ir_sub(tmp1, al, tmp0, addr));
    
    /* Set flags */
    x86_set_pf( mode, tmp1, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp1, addr, block, bblkid );
    x86_set_sf( mode, tmp1, addr, block, bblkid );
    x86_sub_set_of( mode, al, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, al, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, al, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_scasd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, eax, di, df, tmp0, tmp1;
    IRBasicBlockId inc, dec, end, prefix_start;

    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 31, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 31, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, eax.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, eax.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, di, addr));
    block->add_instr(bblkid, ir_sub(tmp1, eax, tmp0, addr));
    
    /* Set flags */
    x86_set_pf( mode, tmp1, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp1, addr, block, bblkid );
    x86_set_sf( mode, tmp1, addr, block, bblkid );
    x86_sub_set_of( mode, eax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, eax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, eax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_scasq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, rax, di, df, tmp0, tmp1;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = ir_var(X64_DF, 63, 0);
    rax = ir_var(X64_RAX, 63, 0);
    di = ir_var(X64_RDI, 63, 0);
    pc = ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, rax.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, rax.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, di, addr));
    block->add_instr(bblkid, ir_sub(tmp1, rax, tmp0, addr));
    
    /* Set flags */
    x86_set_pf( mode, tmp1, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp1, addr, block, bblkid );
    x86_set_sf( mode, tmp1, addr, block, bblkid );
    x86_sub_set_of( mode, rax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, rax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, rax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_scasw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ax, di, df, tmp0, tmp1;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 0): ir_var(X64_RAX, 15, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, ax.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, ax.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, di, addr));
    block->add_instr(bblkid, ir_sub(tmp1, ax, tmp0, addr));
    
    /* Set flags */
    x86_set_pf( mode, tmp1, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp1, addr, block, bblkid );
    x86_set_sf( mode, tmp1, addr, block, bblkid );
    x86_sub_set_of( mode, ax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, ax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, ax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_seta_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0 and ZF = 0 
    block->add_instr(bblkid, ir_not(tmp0, cf, addr));
    block->add_instr(bblkid, ir_not(tmp1, zf, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setae_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0 
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setbe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, cf.size-1, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1 or ZF = 1 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_sete_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 1
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, zf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0 and  SF=OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_not(tmp1, x86_arg_extract(zf, 0, 0), addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setge_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF=OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF != OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setle_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, zf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 1 or  SF != OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_or(tmp0, x86_arg_extract(zf, 0, 0), tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setne_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setno_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 0
    block->add_instr(bblkid, ir_bcc(of, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setnp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if PF = 0
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setns_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 0
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_seto_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 1
    block->add_instr(bblkid, ir_bcc(of, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if PF = 1
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_sets_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 1
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_shr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, of;
    IRBasicBlockId set_of, cont, end;
    
    cont = block->new_bblock();
    set_of = block->new_bblock();
    end = block->new_bblock();
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    // 5 bits for <= 32bits, 6 bits for 64bits
    unsigned int mask = (op0.size == 64 )? 0b111111 : 0b11111;

    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr)); 
    
    /* Test if masked count is 0 */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(cont, 31, 0), ir_cst(end, 31, 0), addr));

    // Do shift
    /* Affect CF (last bit shifted out) */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(cont, ir_sub(tmp1, tmp0, ir_cst(1, tmp0.size-1, 0), addr)); // Num of the last bit that'll be shifted out
    block->add_instr(cont, ir_shr(tmp4, op0, tmp1, addr));
    block->add_instr(cont, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp4, 0, 0), addr));

    /* Shift */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(cont, ir_shr(tmp2, op0, tmp0, addr));
    /* Save op0 */
    tmp5 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(cont, ir_mov(tmp5, op0, addr));
    // Assign res
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(cont, ir_stm(dest, tmp2, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, cont, tmp_var_count, dest, tmp2);
    }

    /* Affect OF flag iff masked count == 1 */
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(cont, ir_xor(tmp3, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(cont, ir_bcc(tmp3, ir_cst(end, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_mov(x86_arg_extract(of,0,0), x86_arg_extract(op0, op0.size-1, op0.size-1), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_stc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, cf;
    
    /* Get operand */
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Set flag */
    block->add_instr(bblkid, ir_mov(cf, ir_cst(1, cf.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_std_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, df;
    
    /* Get operand */
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    /* Set flag */
    block->add_instr(bblkid, ir_mov(df, ir_cst(1, df.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_sti_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, iflag;
    
    /* Get operand */
    iflag = (mode == CPUMode::X86)? ir_var(X86_IF, 31, 0) : ir_var(X64_IF, 63, 0);
    
    /* Set flag */
    block->add_instr(bblkid, ir_mov(iflag, ir_cst(1, iflag.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_stosb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, al, di, df;
    IRBasicBlockId inc, dec, end;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    al = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 7, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /*  Store byte */
    block->add_instr(bblkid, ir_stm(di, al, addr));
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    bblkid = end;
    return;
}

inline void x86_stosd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, eax, di, df;
    IRBasicBlockId inc, dec, end;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 31, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /*  Store byte */
    block->add_instr(bblkid, ir_stm(di, eax, addr));
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    bblkid = end;
    return;
}

inline void x86_stosq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, rax, di, df;
    IRBasicBlockId inc, dec, end;
    
    df = ir_var(X64_DF, 63, 0);
    rax = ir_var(X64_RAX, 63, 0);
    di = ir_var(X64_RDI, 63, 0);
    pc = ir_var(X64_RIP, 63, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    /*  Store byte */
    block->add_instr(bblkid, ir_stm(di, rax, addr));
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    bblkid = end;
    return;
}

inline void x86_stosw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ax, di, df;
    IRBasicBlockId inc, dec, end;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 0): ir_var(X64_RAX, 15, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /*  Store byte */
    block->add_instr(bblkid, ir_stm(di, ax, addr));
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_sub_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp, dest;
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // tmp <- op0 - op1
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp, op0, op1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp, addr, block, bblkid );
    x86_set_sf( mode, tmp, addr, block, bblkid );
    x86_sub_set_of( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    
    /* Set dest operand */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    return;
}

inline void x86_sysenter_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, type, next_pc;
    
    if( mode == CPUMode::X64 ){
        throw unsupported_instruction_exception("SYSENTER: not supported in X64 mode");
    }
    
    /* Get operands */
    pc = x86_get_pc(mode);
    next_pc = ir_tmp(tmp_var_count++, pc.size-1, 0); 
    block->add_instr(bblkid, ir_add(next_pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    type = ir_cst(SYSCALL_X86_SYSENTER, 31, 0);
    
    /* Create interrupt */
    block->add_instr(bblkid, ir_syscall(type, next_pc, addr));
    return;
}

inline void x86_test_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp, cf, of;

    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0): ir_var(X64_OF, 63, 0);

    // tmp <- op0 & op1
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp, op0, op1, addr));

    // Update flags (except AF that is undefined)
    x86_set_pf( mode, tmp, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp, addr, block, bblkid );
    x86_set_sf( mode, tmp, addr, block, bblkid );
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.size-1, 0), addr));

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    return;
}

inline void x86_xadd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, pc, tmp;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);

    /* Do the add */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    
    /* Update flags */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_af(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_of(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    
    /* Exchange operands */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        tmp = ir_tmp(tmp_var_count++, dest.size-1, 0);
        block->add_instr(bblkid, ir_mov(tmp, dest, addr)); // In case dest is op1
        block->add_instr(bblkid, ir_mov(op1, op0, addr));
        block->add_instr(bblkid, ir_stm(tmp, res, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op1, op0);
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_xchg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp, tmp2;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    tmp2 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    block->add_instr(bblkid, ir_mov(tmp2, op1, addr));
    
    /* Exchange operands */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        tmp = ir_tmp(tmp_var_count++, dest.size-1, 0);
        block->add_instr(bblkid, ir_mov(tmp, dest, addr)); // In case dest is op1
        block->add_instr(bblkid, ir_mov(op1, op0, addr));
        block->add_instr(bblkid, ir_stm(tmp, tmp2, addr));
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, op1, op0);
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, tmp2);
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_xor_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the xor */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_xor(res, op0, op1, addr));
    
    /* Update flags: SF, ZF, PF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        x86_adjust_reg_assign(mode, addr, block, bblkid, tmp_var_count, dest, res);
    }

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

/* ==================================== */
/* Disassembly wapper 
 * 
 * If sym is not null, then is_symbolic and is_tainted should not be null.
 * If they are not null, then the disassembler should check for symbolic/tainted 
 * code and update the booleans accordingly. Disassembly ends immediately if 
 * symbolic code is detected.
 * */
IRBlock* DisassemblerX86::disasm_block(addr_t addr, code_t code, size_t code_size){
    // Create new ir block
    IRBlock * block = new IRBlock("", addr);
    IRBasicBlockId bblkid = block->new_bblock();
    int tmp_var_count = 0;
    addr_t curr_addr = addr;
    bool stop = false;
    stringstream asm_str;

    while( (!stop) && cs_disasm_iter(_handle, (const uint8_t**)&code, &code_size, &addr, _insn) ){
        // DEBUG
        // std::cout << "DEBUG, dissassembled " << _insn->mnemonic << " " << _insn->op_str << std::endl;
        
        // Add instruction to IRBlock
        switch(_insn->id){
            case X86_INS_AAA:       x86_aaa_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AAD:       x86_aad_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AAM:       x86_aam_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AAS:       x86_aas_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ADC:       x86_adc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ADCX:      x86_adcx_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ADD:       x86_add_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AND:       x86_and_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ANDN:      x86_andn_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BLSI:      x86_blsi_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BLSMSK:    x86_blsmsk_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BLSR:      x86_blsr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BSF:       x86_bsf_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BSR:       x86_bsr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BSWAP:     x86_bswap_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BT:        x86_bt_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BTC:       x86_btc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BTR:       x86_btr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BTS:       x86_bts_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BZHI:      x86_bzhi_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CALL:      x86_call_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CBW:       x86_cbw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CDQ:       x86_cdq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CDQE:      x86_cdqe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CLC:       x86_clc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CLD:       x86_cld_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CLI:       x86_cli_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMC:       x86_cmc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVA:     x86_cmova_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVAE:    x86_cmovae_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVB:     x86_cmovb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVBE:    x86_cmovbe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVE:     x86_cmove_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVG:     x86_cmovg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVGE:    x86_cmovge_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVL:     x86_cmovl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVLE:    x86_cmovle_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNE:    x86_cmovne_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNO:    x86_cmovno_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNP:    x86_cmovnp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNS:    x86_cmovns_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVO:     x86_cmovo_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVP:     x86_cmovp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVS:     x86_cmovs_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMP:       x86_cmp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSB:     x86_cmpsb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSD:     x86_cmpsd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSQ:     x86_cmpsq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSW:     x86_cmpsw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPXCHG:   x86_cmpxchg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CPUID:     x86_cpuid_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CQO:       x86_cqo_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CWD:       x86_cwd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CWDE:      x86_cwde_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_DEC:       x86_dec_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_DIV:       x86_div_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_IDIV:      x86_idiv_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_IMUL:      x86_imul_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_INC:       x86_inc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_INT:       x86_int_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_INT3:      x86_int3_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JA:        x86_ja_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JAE:       x86_jae_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JB:        x86_jb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JBE:       x86_jbe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JCXZ:      x86_jcxz_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JE:        x86_je_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JECXZ:     x86_jecxz_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JG:        x86_jg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JGE:       x86_jge_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JL:        x86_jl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JLE:       x86_jle_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JMP:       x86_jmp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNE:       x86_jne_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNO:       x86_jno_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNP:       x86_jnp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNS:       x86_jns_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JO:        x86_jo_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JP:        x86_jp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JRCXZ:     x86_jrcxz_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JS:        x86_js_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LAHF:      x86_lahf_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LEA:       x86_lea_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LEAVE:     x86_leave_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSB:     x86_lodsb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSD:     x86_lodsd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSQ:     x86_lodsq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSW:     x86_lodsw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOV:       x86_mov_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVABS:    x86_mov_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break; // Just mov with 64b imm/mem
            case X86_INS_MOVSB:     x86_movsb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSD:     x86_movsd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSQ:     x86_movsq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSW:     x86_movsw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSX:     x86_movsx_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSXD:    x86_movsxd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVZX:     x86_movzx_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MUL:       x86_mul_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_NEG:       x86_neg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_NOP:       x86_nop_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_NOT:       x86_not_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_OR:        x86_or_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_POP:       x86_pop_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_POPAL:     x86_popad_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_PUSH:      x86_push_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_PUSHAL:    x86_pushad_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_RCL:       x86_rcl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_RCR:       x86_rcr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_RDTSC:     x86_rdtsc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_RET:       x86_ret_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ROL:       x86_rol_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ROR:       x86_ror_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SAL:       x86_sal_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SAR:       x86_sar_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SCASB:     x86_scasb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SCASD:     x86_scasd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SCASQ:     x86_scasq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SCASW:     x86_scasw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETA:      x86_seta_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETAE:     x86_setae_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETB:      x86_setb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETBE:     x86_setbe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETE:      x86_sete_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETG:      x86_setg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETGE:     x86_setge_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETL:      x86_setl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETLE:     x86_setle_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNE:     x86_setne_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNO:     x86_setno_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNP:     x86_setnp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNS:     x86_setns_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETO:      x86_seto_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETP:      x86_setp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETS:      x86_sets_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SHL:       x86_sal_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break; // Same as SAL
            case X86_INS_SHR:       x86_shr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STC:       x86_stc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STD:       x86_std_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STI:       x86_sti_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STOSB:     x86_stosb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STOSD:     x86_stosd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STOSQ:     x86_stosq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STOSW:     x86_stosw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SUB:       x86_sub_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SYSENTER:  x86_sysenter_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_TEST:      x86_test_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_XADD:      x86_xadd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_XCHG:      x86_xchg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_XOR:       x86_xor_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            default: 
                string error_str = QuickFmt() << "unsupported instruction " << _insn->mnemonic >> QuickFmt::to_str;
                throw unsupported_instruction_exception(error_str);
        }
        
        // Update asm_str
        asm_str << " " << _insn->mnemonic << " " << _insn->op_str << ";";
        
        // Increment instruction count
        block->_nb_instr++;
        
        // Stop if last operation is a branch operation 
        for( int i = 0; i < _insn->detail->groups_count; i++){
            if(     _insn->detail->groups[i] == X86_GRP_JUMP ||
                    _insn->detail->groups[i] == X86_GRP_CALL ||
                    _insn->detail->groups[i] == X86_GRP_RET ||
                    _insn->detail->groups[i] == X86_GRP_INT ||
                    _insn->detail->groups[i] == X86_GRP_IRET /*||
                    _insn->detail->groups[i] == X86_GRP_PRIVILEGE ||
                    _insn->detail->groups[i] == X86_GRP_BRANCH_RELATIVE */
            ){
                stop = true;
            }
        }
        curr_addr = addr;
    }

    // Check if we stopped for a legit reason or because capstone failed
    if( !stop ){
        throw runtime_exception(QuickFmt() << 
                "DisassemblerX86:disasm_block(): capstone error at addr 0x" << std::hex << curr_addr
                >> QuickFmt::to_str );
    }

    /* Set some infos about the block */
    block->end_addr = addr;
    block->raw_size = block->start_addr - addr;

    /* Save number of tmp variables */
    block->_nb_tmp_vars = tmp_var_count;
    
    // Get number of IR instructions
    block->_nb_instr_ir = 0;
    for( auto bblk : block->bblocks()){
        block->_nb_instr_ir += bblk.size();
    }

    // Set asm_str as name
    string s = asm_str.str();
    block->name = s.substr(1, s.size()-2-1); // Remove last ';' and space
    return block;
}
