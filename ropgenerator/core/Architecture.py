from ropgenerator_core_ import\
Architecture, ArchType, BinType, set_arch, set_bin_type,\
curr_arch_bits, curr_arch_type, curr_arch_ip,\
RegX86, RegX64

OPTION_ARCH_NAMES = {'X86':'X86', 'X64':'X64'}

def is_supported_reg(reg_str):
    if( curr_arch_type() == ArchType.ARCH_X86 ):
        return (reg_str in map_x86_reg_names)
    elif( curr_arch_type() == ArchType.ARCH_X64 ):
        return (reg_str in map_x64_reg_names.get)
    else:
        return False

map_x86_reg_names = { 
"eax",RegX86.EAX,
"ebx",RegX86.EBX,
"ecx",RegX86.ECX,
"edx",RegX86.EDX,
"esi",RegX86.ESI,
"edi",RegX86.EDI,
"esp",RegX86.ESP,
"eip",RegX86.EIP,
"ebp",RegX86.EBP,
"zf",RegX86.ZF,
"cf",RegX86.CF,
"sf",RegX86.SF,
"pf",RegX86.PF,
"af",RegX86.AF,
"of",RegX86.OF
}

map_x64_reg_names = {
"rax":RegX64.RAX,
"rbx":RegX64.RBX,
"rcx":RegX64.RCX,
"rdx":RegX64.RDX,
"rsi":RegX64.RSI,
"rdi":RegX64.RDI,
"rsp":RegX64.RSP,
"rbp":RegX64.RBP,
"rip":RegX64.RIP,
"r8":RegX64.R8,
"r9":RegX64.R9,
"r10":RegX64.R10,
"r11":RegX64.R11,
"r12":RegX64.R12,
"r13":RegX64.R13,
"r14":RegX64.R14,
"r15":RegX64.R15,
"sf":RegX64.SF,
"zf":RegX64.ZF,
"af":RegX64.AF,
"cf":RegX64.CF,
"df":RegX64.DF,
"es":RegX64.ES,
"fs":RegX64.FS,
"of":RegX64.OF,
"pf":RegX64.PF
}
