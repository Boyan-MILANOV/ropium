#ifndef GADGET_H
#define GADGET_H

#include "Symbolic.hpp"
#include <memory>
#include <cstdint>

using std::vector; 
using std::string; 
using std::shared_ptr;

enum GadgetType{ REGULAR, INT80, SYSCALL}; 
enum RetType{ RET_RET, RET_CALL, RET_JMP, RET_UNKNOWN};
using addr_t= uint64_t; 

class Gadget{
    /* General */ 
    string _asm_str, _hex_str;
    GadgetType _type; 
    Semantics * _semantics;
    vector<addr_t> _addresses; 
    int _nb_instr, _nb_instr_ir; 
    /* Stack pointer */ 
    int _sp_inc; 
    bool _known_sp_inc; 
    /* Modified memory/regs */ 
    bool _reg_modified[NB_REGS_MAX]; 
    vector<ExprObjectPtr> _mem_read; 
    vector<ExprObjectPtr> _mem_write;
    /* Return */  
    RetType _ret_type;
    int _ret_reg; 
    CondObjectPtr _ret_pre_cond; 
    
    
    public:
        // Constructor 
        Gadget(shared_ptr<IRBlock> irblock); 
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
        bool* modified_regs();
        vector<ExprObjectPtr>* mem_read(); 
        vector<ExprObjectPtr>* mem_write(); 
        RetType ret_type();
        CondObjectPtr ret_pre_cond();
        Semantics * semantics(); 
        // Modifiers
        void add_address(addr_t addr); 
        void set_ret_type(RetType t);
        void set_asm_str(string s);
        void set_hex_str(string s);
        // Destructor 
        ~Gadget();
        // Other
        void print(ostream& os);
        bool lthan(shared_ptr<Gadget> other);
    private:
};

ostream& operator<<(ostream& os, Gadget* g);
#endif
