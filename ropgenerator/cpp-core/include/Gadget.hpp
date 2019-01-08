#ifndef GADGET_H
#define GADGET_H

#include "Symbolic.hpp"

using std::vector; 
using std::string; 

enum GadgetType{ REGULAR, INT80, SYSCALL}; 
enum RetType{ RET, CALL, JMP, UNKNOWN};
using addr_t= unsigned long long; 

class Gadget{
    int _id; 
    GadgetType _type; 
    vector<addr_t> _addresses; 
    string _asm_str, _hex_str;
    int _nb_instr, _nb_instr_ir; 
    int _sp_inc; 
    bool _known_sp_inc; 
    int _reg_modified[NB_REGS_MAX]; 
    vector<ExprObjectPtr> _mem_read; 
    vector<ExprObjectPtr> _mem_write; 
    RetType _ret_type;
    Semantics * _semantics;  
    bool unknown_sp_inc, unknown_ret_type; 
    
    public:
        // Constructor 
        Gadget(int id, IRBlock* irblock); 
        // Accessors 
        int id(); 
        GadgetType type(); 
        vector<addr_t>* addresses(); 
        string asm_str();
        string hex_str();
        int nb_instr();
        int nb_instr_ir(); 
        int sp_inc(); 
        bool known_sp_inc();
        vector<ExprObjectPtr>* mem_read(); 
        vector<ExprObjectPtr>* mem_write(); 
        RetType ret_type();
        Semantics * semantics(); 
        // Modifiers
        void add_address(addr_t addr); 
        // Destructor 
        ~Gadget();
        // Other
        void print(ostream& os);
        bool lthan(Gadget* other);
    private:
};

ostream& operator<<(ostream& os, Gadget* g);
#endif
