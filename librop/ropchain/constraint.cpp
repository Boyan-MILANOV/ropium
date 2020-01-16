#include "constraint.hpp"
#include <cstring>
#include <iostream> // DEBUG

/* =============== Bad Bytes ================= */

void BadBytes::add_bad_byte(unsigned char byte){
    _bad_bytes.push_back(byte);
}

void BadBytes::clear(){
    _bad_bytes.clear();
}

bool BadBytes::is_valid_byte(unsigned char byte){
    return std::count(_bad_bytes.begin(), _bad_bytes.end(), byte) == 0;
}

unsigned char BadBytes::get_valid_byte(){
    for( unsigned char byte = 0xff; byte >= 0; byte--){
        if( is_valid_byte(byte) ){
            return byte;
        }
    }
    throw runtime_exception("BadBytes::get_valid_byte(): all bytes are invalid!");
}

addr_t BadBytes::get_valid_padding(int nb_bytes){
    unsigned char byte = get_valid_byte();
    addr_t res = 0;
    for(; nb_bytes > 0; nb_bytes--){
        res = (res<<8) + byte;
    }
    return res;
}

bool BadBytes::is_valid_address(addr_t addr, int arch_bytes){
    for( int i = 0; i < arch_bytes; i++){
        if( ! is_valid_byte(addr & 0xff))
            return false;
        addr >>= 8;
    }
    return true;
}

addr_t BadBytes::get_valid_address(Gadget* gadget, int arch_bytes){
    for( addr_t addr : gadget->addresses )
        if( is_valid_address(addr, arch_bytes) )
            return addr;
    throw runtime_exception("BadBytes::get_valid_address(): all addresses are invalid!");
}

bool BadBytes::check(Gadget* gadget, int arch_bytes){
    for( addr_t addr : gadget->addresses )
        if( is_valid_address(addr, arch_bytes) )
            return true;
    return false;
}

/* ================ Keep Regs ================= */

void KeepRegs::add_keep_reg(int reg_num){
    _keep.push_back(reg_num);
}

void KeepRegs::clear(){
    _keep.clear();
}

bool KeepRegs::check(Gadget* gadget){
    for( int reg : _keep ){
        if( gadget->modified_regs[reg])
            return false;
    }
    return true;
}


/* ================ Memory Safety ================= */

MemSafety::MemSafety(){
    _force_safe = true; // Enforce pointer safety by default
    memset(_safe_reg_pointers, false, sizeof(_safe_reg_pointers));
}
void MemSafety::force_safe(){ _force_safe = true; }
void MemSafety::enable_unsafe(){ _force_safe = false; }

void MemSafety::add_safe_reg(int reg_num){
    _safe_reg_pointers[reg_num] = true;
}

void MemSafety::clear(){
    _force_safe = true;
    memset(_safe_reg_pointers, false, sizeof(_safe_reg_pointers));
}

bool MemSafety::check(Gadget* gadget, int arch_nb_regs, Assertion* assertion){
    if( !_force_safe)
        return true;
    for( int i = 0; i < arch_nb_regs; i++){
        if( gadget->dereferenced_regs[i] ){ 
            if( !_safe_reg_pointers[i] &&
            (assertion == nullptr || !assertion->valid_pointers.is_valid_pointer(i)))
                return false;
        }
    }
    return true;
}

/* =============== Full Constraint =================== */

void Constraint::clear(){
    bad_bytes.clear();
    keep_regs.clear();
    mem_safety.clear();
}

bool Constraint::check(Gadget* gadget, Arch* arch, Assertion* assertion){
    return  bad_bytes.check(gadget, arch->octets) &&
            keep_regs.check(gadget) &&
            mem_safety.check(gadget, arch->nb_regs, assertion);
}
