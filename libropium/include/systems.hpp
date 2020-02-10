#ifndef SYSTEMS_H
#define SYSTEMS_H

#include <string>
#include "arch.hpp"

using std::string;

enum class System{
    LINUX,
    WINDOWS,
    NONE
};

// Specification of a syscall
class SyscallDef{
public:
    string name;
    int nb_args;
    cst_t num;
    SyscallDef(string n, cst_t sysn, int nb):name(n), nb_args(nb), num(sysn){};
};

// Get syscall definition by name
SyscallDef* get_syscall_def(ArchType arch, System sys, string name);

#endif
