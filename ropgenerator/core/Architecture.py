from ropgenerator_core_ import\
Architecture, ArchType, BinType, EndiannessType, set_arch, set_bin_type, curr_bin_type,\
curr_arch_bits, curr_arch_octets, curr_arch_type, curr_arch_ip, curr_arch_sp, curr_arch_endianess, curr_arch_min_page_size,\
RegX86, RegX64, RegARM32, is_ignored_reg

OPTION_ARCH_NAMES = {ArchType.ARCH_X86:'X86', ArchType.ARCH_X64:'X64', ArchType.ARCH_ARM32:'ARM32'}
OPTION_ARCH_NAMES_REVERSE = {'X86':ArchType.ARCH_X86, 'X64':ArchType.ARCH_X64, 'ARM32':ArchType.ARCH_ARM32}

def str_to_arch_type(string):
    if( string in OPTION_ARCH_NAMES_REVERSE ):
        return OPTION_ARCH_NAMES_REVERSE[string]
    return None

def arch_type_to_str(t):
    return OPTION_ARCH_NAMES[t]

def is_supported_arch_str(arch):
    return arch in OPTION_ARCH_NAMES_REVERSE

def available_archs_str():
    return OPTION_ARCH_NAMES_REVERSE.keys()
    
def available_archs_type():
    return OPTION_ARCH_NAMES.keys()

def is_supported_reg(reg_str):
    if( curr_arch_type() == ArchType.ARCH_X86 ):
        return (reg_str in map_x86_reg_names)
    elif( curr_arch_type() == ArchType.ARCH_X64 ):
        return (reg_str in map_x64_reg_names)
    elif( curr_arch_type() == ArchType.ARCH_ARM32 ):
        return (reg_str in map_arm32_reg_names)
    else:
        return False

def reg_str_to_num(reg_str):
    if( curr_arch_type() == ArchType.ARCH_X86 ):
        return map_x86_reg_names[reg_str]
    elif( curr_arch_type() == ArchType.ARCH_X64 ):
        return map_x64_reg_names[reg_str]
    elif( curr_arch_type() == ArchType.ARCH_ARM32 ):
        return map_arm32_reg_names[reg_str]
    else:
        raise Exception("Arch not supported in this function")

def is_arm(arch_type):
    return arch_type in [ArchType.ARCH_ARM32]

map_x86_reg_names = { 
"eax":RegX86.EAX,
"ebx":RegX86.EBX,
"ecx":RegX86.ECX,
"edx":RegX86.EDX,
"esi":RegX86.ESI,
"edi":RegX86.EDI,
"esp":RegX86.ESP,
"eip":RegX86.EIP,
"ebp":RegX86.EBP,
"zf":RegX86.ZF,
"cf":RegX86.CF,
"sf":RegX86.SF,
"pf":RegX86.PF,
"af":RegX86.AF,
"of":RegX86.OF
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

map_arm32_reg_names = {
"r0":RegARM32.R0,
"r1":RegARM32.R1,
"r2":RegARM32.R2,
"r3":RegARM32.R3,
"r4":RegARM32.R4,
"r5":RegARM32.R5,
"r6":RegARM32.R6,
"r7":RegARM32.R7,
"r8":RegARM32.R8,
"r9":RegARM32.R9,
"r10":RegARM32.R10,
"r11":RegARM32.R11,
"r12":RegARM32.R12,
"r13":RegARM32.R13,
"r14":RegARM32.R14,
"r15":RegARM32.R15,
"apsr":RegARM32.APSR
}

def get_curr_reg_map():
    if( curr_arch_type() == ArchType.ARCH_X86 ):
        return map_x86_reg_names
    elif( curr_arch_type() == ArchType.ARCH_X64 ):
        return map_x64_reg_names
    elif( curr_arch_type() == ArchType.ARCH_ARM32 ):
        return map_arm32_reg_names
    else:
        return None
        
