#include "utils.hpp"
#include "exception.hpp"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>
#include <exception>

using std::ifstream;
using std::ofstream;
using std::ios;
using std::stringstream;
using std::vector;

/* ======== Raw gadgets interface ======== */
// Read gadgets from file
vector<RawGadget>* raw_gadgets_from_file(string filename){
    vector<RawGadget>* res = new vector<RawGadget>();
    RawGadget raw;
    bool got_addr;
    ifstream file;
    string line;
    string addr_str;
    string byte;
    
    file.open(filename, ios::in | ios::binary );
    while( getline(file, line)){
        raw = RawGadget();
        got_addr = false;
        addr_str = "";
        byte = "";
        for( char& c : line ){
            // First the gadget address
            if( c == '$' ){
                try{
                    raw.addr = std::stoi(addr_str, 0, 16);
                    if( raw.addr == 0 )
                        throw std::invalid_argument("");
                    got_addr = true;
                }catch(std::invalid_argument& e){
                    throw runtime_exception(QuickFmt() << "raw_gadgets_from_file: error, bad address string: " << line >> QuickFmt::to_str);
                }
            }else if( !got_addr){
                addr_str += c;
            }else{
                byte += c;
                if( byte.size() == 2 ){
                    try{
                        raw.raw += (char)(std::stoi(byte, 0, 16));
                        byte = "";
                    }catch(std::invalid_argument& e){
                        throw runtime_exception(QuickFmt() << "raw_gadgets_from_file: error, bad byte in: " << line >> QuickFmt::to_str);
                    }
                }
            }
        }
        res->push_back(raw);
    }
    
    file.close();
    return res;
}


// Write gadgets to file from ROPgadget output
void split(const std::string& str, vector<string>& cont, char delim = ' ')
{
    std::size_t current, previous = 0;
    current = str.find(delim);
    while (current != std::string::npos) {
        cont.push_back(str.substr(previous, current - previous));
        previous = current + 1;
        current = str.find(delim, previous);
    }
    cont.push_back(str.substr(previous, current - previous));
}

bool ropgadget_to_file(string out, string bin){
    stringstream cmd;
    ofstream out_file;
    string output;
    
    out_file.open(out, ios::out);
    
    cmd << "ROPgadget --binary " << bin << " --dump --all --depth 5 " << std::endl; 
    try{
        std::array<char, 128> buffer;
        string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.str().c_str(), "r"), pclose);
        string addr_str, raw_str;
        stringstream ss;
        vector<string> splited;
        
        if (!pipe) {
            throw std::runtime_error("popen() failed!");
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            ss.str(""); ss << buffer.data();
            splited.clear();
            split(ss.str(), splited);
            
            // Get address string
            if( splited.size() > 3 ){
                addr_str = splited[0];
            }else{
                continue;
            }
            if( addr_str.substr(0, 2) != "0x" ){
                continue;
            }
            // Get raw string
            raw_str = splited.back();
            if( raw_str.back() != '\n' )
                raw_str += '\n';

            // Write them to file
            out_file << addr_str << "$" << raw_str;
        }
        
    }catch(std::runtime_error& e){
        return false;
    }
    
    out_file.close();
    return true;
}


/* ========== Printing stuff ============== */

// Colors 
string g_ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI;
string g_BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI;
string g_SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI;
string g_PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI;
string g_EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI;
string g_END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI ;

// String coloration 
string str_bold(string s){
    return g_BOLD_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}

string str_special(string s){
    return g_SPECIAL_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}

string value_to_hex_str(int octets, addr_t addr){
    char res[32], format[32];
    // Get format (32 or 64 bits)
    snprintf(format, sizeof(format), "%%0%02dllx", octets*2);
    // Write hex bytes 
    snprintf(res, sizeof(res), format, addr);
    return "0x"+string(res);
}

void disable_colors(){
    g_ERROR_COLOR_ANSI = "";
    g_BOLD_COLOR_ANSI = "";
    g_SPECIAL_COLOR_ANSI = "";
    g_PAYLOAD_COLOR_ANSI = "";
    g_EXPLOIT_DESCRIPTION_ANSI = "";
    g_END_COLOR_ANSI = "";
}

void enable_colors(){
    g_ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI;
    g_BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI;
    g_SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI;
    g_PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI;
    g_EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI;
    g_END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI ;    
}
