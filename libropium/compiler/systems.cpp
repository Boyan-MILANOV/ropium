#include "systems.hpp"
#include <vector>

using std::vector;

// Supported syscalls
vector<SyscallDef> linux_x86_syscalls = {
    SyscallDef("exit", 1, 1),
    SyscallDef("read", 3, 3),
    SyscallDef("write", 4, 3),
    SyscallDef("open", 5, 3),
    SyscallDef("close", 6, 2),
    SyscallDef("execve", 11, 3),
    SyscallDef("chmod", 15, 2),
    SyscallDef("setuid", 23, 1),
    SyscallDef("mmap", 90, 6),
    SyscallDef("mprotect", 0x7d, 3)
};

vector<SyscallDef> linux_x64_syscalls = {
    SyscallDef("exit", 60, 1),
    SyscallDef("read", 0, 3),
    SyscallDef("write", 1, 3),
    SyscallDef("open", 2, 3),
    SyscallDef("close", 3, 2),
    SyscallDef("execve", 59, 3),
    SyscallDef("chmod", 90, 2),
    SyscallDef("setuid", 105, 1),
    SyscallDef("mmap", 9, 6),
    SyscallDef("mprotect", 10, 3)
};

SyscallDef* get_syscall_def(ArchType arch, System sys, string name){
    vector<SyscallDef>* list = nullptr;
    if( arch == ArchType::X86 ){
        switch( sys ){
            case System::LINUX: list = &linux_x86_syscalls; break;
            default: throw runtime_exception("get_syscall_def(): got unsupported system for arch X86");
        }
    }else if( arch == ArchType::X64 ){
        switch( sys ){
            case System::LINUX: list = &linux_x64_syscalls; break;
            default: throw runtime_exception("get_syscall_def(): got unsupported system for arch X64");
        }
    }else{
        throw runtime_exception("get_syscall_def(): got unknown arch");
    }
    // Find syscall in list
    for( SyscallDef& def : *list ){
        if( def.name == name )
            return &def; // Found
    }
    return nullptr; // Not found
}
