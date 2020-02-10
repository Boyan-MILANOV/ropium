#include "systems.hpp"
#include <vector>

using std::vector;

// Supported syscalls
vector<SyscallDef> linux_x86_syscalls = {
    SyscallDef("exit", 1, 1),
    SyscallDef("fork", 2, 1),
    SyscallDef("read", 3, 3),
    SyscallDef("write", 4, 3),
    SyscallDef("open", 5, 3),
    SyscallDef("close", 6, 2),
    SyscallDef("waitpid", 7, 3),
    SyscallDef("creat", 8, 2),
    SyscallDef("link", 9, 2),
    SyscallDef("unlink", 10, 1),
    SyscallDef("execve", 11, 3),
    SyscallDef("chdir", 12, 1),
    SyscallDef("time", 13, 1),
    SyscallDef("mknod", 14, 3),
    SyscallDef("chmod", 15, 2),
    SyscallDef("lchown", 16, 2),
    //SyscallDef("", 17, ),
    SyscallDef("stat", 18, 2),
    SyscallDef("lseek", 19, 3),
    SyscallDef("getpid", 20, 0),
    SyscallDef("mount", 21, 3),
    SyscallDef("umount", 22, 1),
    SyscallDef("setuid", 23, 1),
    SyscallDef("getuid", 24, 0),
    SyscallDef("stime", 25, 1),
    SyscallDef("ptrace", 26, 4),
    SyscallDef("alarm", 27, 1),
    // DEBUG TODO continue
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
