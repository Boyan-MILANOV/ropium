#ifndef ASSERTION_H
#define ASSERTION_H

#include "ropchain.hpp"
#include "arch.hpp"
#include <algorithm>

class ValidPointers{
    vector<int> _regs;
public:
    void add_valid_pointer(int reg);
    bool is_valid_pointer(int reg);
};


class Assertion{
public:
    ValidPointers valid_pointers;
};

#endif
