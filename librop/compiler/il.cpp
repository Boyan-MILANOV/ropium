#include "il.hpp"
#include <string>
#include <cctype>
#include "exception.hpp"
#include <iostream>

using std::string;

/* ======= Parse IL Instructions ========== */

void _skip_whitespace(string& str, int& idx){
    while( isspace(str[idx]) && str[idx] != '\n' && idx < str.size()){
        idx++;
    }
}

bool _parse_end(string& str, int& idx){
    while( idx < str.size() ){
        if( !isspace(str[idx]) )
            return false;
        idx++;
    }
    return true;
}

bool _parse_il_cst(Arch& arch, vector<cst_t>& args, string& str, int& idx){
    string s;
    int i;
    bool found = false;
    int base = 10;
    ucst_t cst;

    _skip_whitespace(str, idx);
    if( str.substr(idx, 2) == "0x"){
        idx += 2;
        s = "0x";
        base = 16;
    }

    i = idx;
    if( base == 10 ){
        while( i < str.size() && isdigit(str[i])){
            s += str[i++];
        }
    }else if( base == 16 ){
        while( i < str.size() && isxdigit(str[i])){
            s += str[i++];
        }
    }
    
    try{
        cst = std::stoll(s, 0, base);
        // Check if cst is not too big
        if( arch.octets < 8 && (cst >= (ucst_t)((ucst_t)1<<(arch.bits)))){
            return false;
        }
        idx = i;
        args.push_back(cst);
        return true;
    }catch(std::invalid_argument const& e){
        return false;
    }catch(std::out_of_range const& e){
        return false;
    }
}

bool _parse_il_reg(Arch& arch, vector<cst_t>& args, string& str, int& idx){
    string s;
    string prev;
    int i, prev_i;
    bool found = false;
    
    _skip_whitespace(str, idx);
    i = idx;
    
    while( i < str.size() && !isspace(str[i])){
        s += str[i++];

        if( arch.is_valid_reg(s) ){
            found = true;
            prev = s;
            prev_i = i;
        }else if( found ){
            break;
        }
    }
    if( found ){
        args.push_back(arch.reg_num(prev));
        idx = prev_i;
        return true;        
    }else
        return false;
}

bool _parse_il_affect(string& str, int& idx){
    _skip_whitespace(str, idx);
    if( idx == str.size())
        return false;
    if( str[idx] == '=' ){
        idx++;
        return true;
    }else
        return false;
}

bool _parse_il_binop(vector<cst_t>& args, string& str, int& idx){
    Op res = Op::NONE;
    
    _skip_whitespace(str, idx);
    if( idx == str.size())
        return false;
    switch( str[idx] ){
        case '+': idx++; res =  Op::ADD; break;
        case '/': idx++; res =  Op::DIV; break;
        case '*': idx++; res =  Op::MUL; break;
        case '^': idx++; res =  Op::XOR; break;
        case '&': idx++; res =  Op::AND; break;
        case '|': idx++; res =  Op::OR; break;
        case '%': idx++; res =  Op::MOD; break;
        default: break;
    }
    if( res == Op::NONE ){
        if( str.substr(idx,2) == "<<" ){
            idx += 2; res =  Op::SHL;
        }else if( str.substr(idx,2) == ">>" ){
            idx += 2; res =  Op::SHR;
        }else{
            return false;
        }
    }
    
    args.push_back((int)res);
    return true;
}

bool _parse_il_unop(vector<cst_t>& args, string& str, int& idx){
    Op res;
    _skip_whitespace(str, idx);
    if( idx == str.size())
        return false;
    switch( str[idx] ){
        case '-': idx++; res = Op::NEG; break;
        case '~': idx++; res = Op::NOT; break;
        default:
            return false;
    }
    args.push_back((int)res);
    return true;
}

bool _parse_il_mov_reg(Arch& arch, ILInstruction* instr, string& str){
    int idx = 0;
    vector<cst_t> args;
    if  (_parse_il_reg(arch, args, str, idx) && 
        _parse_il_affect(str, idx) && 
        _parse_il_reg(arch, args, str, idx) &&
        _parse_end(str, idx))
    {
        instr->args = args;
        instr->type = ILInstructionType::MOV_REG;
        return true;
    }
    return false;
}

bool _parse_il_mov_cst(Arch& arch, ILInstruction* instr, string& str){
    int idx = 0;
    vector<cst_t> args;
    if  (_parse_il_reg(arch, args, str, idx) && 
        _parse_il_affect(str, idx) && 
        _parse_il_cst(arch, args, str, idx) &&
        _parse_end(str, idx))
    {
        instr->args = args;
        instr->type = ILInstructionType::MOV_CST;
        return true;
    }
    return false;
}

bool _parse_il_amov_cst(Arch& arch, ILInstruction* instr, string& str){
    int idx = 0;
    vector<cst_t> args;
    if  (_parse_il_reg(arch, args, str, idx) && 
        _parse_il_affect(str, idx) && 
        _parse_il_reg(arch, args, str, idx) &&
        _parse_il_binop(args, str, idx) &&
        _parse_il_cst(arch, args, str, idx) &&
        _parse_end(str, idx))
    {
        instr->args = args;
        instr->type = ILInstructionType::AMOV_CST;
        return true;
    }
    return false;
}

bool _parse_il_instruction(Arch& arch, ILInstruction* instr, string& str){
    return  _parse_il_mov_cst(arch, instr, str) || 
            _parse_il_mov_reg(arch, instr, str) ||
            _parse_il_amov_cst(arch, instr, str);
}


ILInstruction::ILInstruction(Arch& arch, string str){
    if( !_parse_il_instruction(arch, this, str)){
        throw il_exception("Invald instruction string");
    }
}
