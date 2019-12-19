#include "il.hpp"
#include <string>
#include <cctype>
#include "exception.hpp"

using std::string;

/* ======= Parse IL Instructions ========== */

void _skip_whitespace(string& str, int& idx){
    while( isspace(str[idx]) && str[idx] != '\n' && idx < str.size()){
        idx++;
    }
}

bool _parse_il_reg(Arch& arch, string& str, int& idx){
    string s;
    int i;
    _skip_whitespace(str, idx);
    i = idx;
    while( i < str.size() && !isspace(str[i])){
        s += str[i];
        if( arch.is_valid_reg(s) ){
            idx = i;
            return true;
        } 
    }
    return false;
}

bool _parse_il_affect(string& str, int& idx){
    _skip_whitespace(str, idx);
    if( idx == str.size())
        return false;
    return str[idx] == '=';
}

bool _parse_il_mov_reg(Arch& arch, ILInstruction* instr, string& str){
    int idx = 0;
    return _parse_il_reg(arch, str, idx) && 
           _parse_il_affect(str, idx) && 
           _parse_il_reg(arch, str, idx);
}

bool _parse_il_instruction(Arch& arch, ILInstruction* instr, string& str){
    return _parse_il_mov_reg(arch, instr, str);
}

ILInstruction::ILInstruction(Arch& arch, string str){
    if( !_parse_il_instruction(arch, this, str)){
        throw il_exception("Invald instruction string");
    }
}
