#ifndef ROPCHAIN_H
#define ROPCHAIN_H

#include "Expression.hpp"
#include "Gadget.hpp"
#include <vector>
using std::vector;
#include <string>
using std::string;  
#include <sstream>
using std::stringstream; 

class ROPChain{
    vector<int> _chain;
    vector<cst_t> _padding_values;  // Padding number n is stored in _chain 
                                    // as -n-1
    vector<string> _padding_comments; 
    int _len; 
    int _nb_gadgets; 
    int _nb_instr, _nb_instr_ir;
    public: 
        //Constructor
        ROPChain(); 
        // Accessors
        int len();
        int nb_gadgets(); 
        int nb_instr(); 
        int nb_instr_ir(); 
        // Modifiers
        void add_gadget(Gadget* g);
        void add_padding(cst_t value, string comment, int n); 
        void add_chain(ROPChain* other);
        // Sort
        bool lthan(ROPChain* other); 
        // IO
        string to_str_console(int bits, vector<unsigned char> bad_bytes); 
}; 

#endif 
