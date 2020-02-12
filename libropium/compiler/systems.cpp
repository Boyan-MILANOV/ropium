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
    SyscallDef("pause", 29, 0),
    SyscallDef("access", 33, 2),
    SyscallDef("sync", 36, 0),
    SyscallDef("kill", 37, 2),
    SyscallDef("rename", 38, 2),
    SyscallDef("mkdir", 39, 2),
    SyscallDef("rmdir", 40, 1),
    SyscallDef("dup", 41, 1),
    SyscallDef("umount", 52, 2),
    SyscallDef("setpgid", 57, 2),
    SyscallDef("chroot", 61, 1),
    SyscallDef("sigaction", 67, 3),
    SyscallDef("symlink", 83, 2),
    SyscallDef("reboot", 88, 4),
    SyscallDef("mmap", 90, 6),
    SyscallDef("munmap", 91, 2),
    SyscallDef("uname", 109, 1),
    SyscallDef("mprotect", 125, 3),
    SyscallDef("sysctl", 149, 1),
    SyscallDef("setreuid", 203, 2),
    SyscallDef("setregid", 204, 2),
    SyscallDef("setuid", 213, 1),
    SyscallDef("setgid", 214, 1)
};

vector<SyscallDef> linux_x64_syscalls = {
    SyscallDef("read", 0, 3),
    SyscallDef("write", 1, 3),
    SyscallDef("open", 2, 3),
    SyscallDef("close", 3, 2),
    SyscallDef("mmap", 9, 6),
    SyscallDef("mprotect", 10, 3),
    SyscallDef("munmap", 11, 2),
    SyscallDef("rt_sigaction", 14, 4),
    SyscallDef("rt_sigreturn", 15, 1),
    SyscallDef("access", 21, 2),
    SyscallDef("mremap", 25, 5),
    SyscallDef("pause", 34, 0),
    SyscallDef("alarm", 37, 1),
    SyscallDef("getpid", 39, 0),
    SyscallDef("connect", 42, 3),
    SyscallDef("accept", 43, 3),
    SyscallDef("sendto", 44, 5),
    SyscallDef("rcvfrom", 45, 5),
    SyscallDef("shutdown", 48, 2),
    SyscallDef("bind", 49, 3),
    SyscallDef("listen", 50, 2),
    SyscallDef("execve", 59, 3),
    SyscallDef("exit", 60, 1),
    SyscallDef("kill", 62, 2),
    SyscallDef("uname", 63, 1),
    SyscallDef("mkdir", 83, 2),
    SyscallDef("rmdir", 84, 1),
    SyscallDef("creat", 85, 2),
    SyscallDef("link", 86, 2),
    SyscallDef("unlink", 87, 1),
    SyscallDef("chmod", 90, 2),
    SyscallDef("chown", 92, 3),
    SyscallDef("ptrace", 101, 4),
    SyscallDef("getuid", 102, 0),
    SyscallDef("getgid", 104, 0),
    SyscallDef("setuid", 105, 1),
    SyscallDef("setgid", 106, 1),
    SyscallDef("setreuid", 113, 2),
    SyscallDef("setregid", 114, 2),
    SyscallDef("chroot", 161, 1),
    SyscallDef("mount", 165, 5),
    SyscallDef("umount2", 166, 2),
    SyscallDef("reboot", 169, 4)
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
