#include "CommonUtils.hpp"
#include <cstdio>
#include <sstream>

using std::string; 

string value_to_hex_str(int octets, addr_t addr){
    char res[32], format[32];
    // Get format (32 or 64 bits)
    snprintf(format, sizeof(format), "%%0%02dllx", octets*2);
    // Write hex bytes 
    snprintf(res, sizeof(res), format, addr);
    return "0x"+string(res);
}


