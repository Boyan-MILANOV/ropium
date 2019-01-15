#include "IO.hpp"
#include <iostream>
#include <cstdio>
#include <sstream>

using std::cout; 
using std::endl; 
using std::stringstream;

// Colors 
string g_ROPGENERATOR_COLOR_ANSI = DEFAULT_ROPGENERATOR_COLOR_ANSI;
string g_SEMANTIC_MODE_ANSI = DEFAULT_SEMANTIC_MODE_ANSI;
string g_EXPLOIT_MODE_ANSI = DEFAULT_EXPLOIT_MODE_ANSI;
string g_ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI;
string g_BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI;
string g_SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI;
string g_PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI;
string g_EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI;
string g_END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI ;

// IO functions 
void info(string s){
    cout << "[" << str_ropg("+") << "] " << s; 
}
void notify(string s){
    cout << "\t" << str_ropg("% ") << s << endl; 
}
void error(string s){
    cout << "\n\t" << str_bold(s) << endl; 
}
void fatal(string s){
    cout << g_ERROR_COLOR_ANSI << "[!] " << s << g_END_COLOR_ANSI << endl; 
}

bool g_VERBOSE = false; 
void verbose(string s){
    if( g_VERBOSE )
        cout << str_ropg("\t\t> ") << s << endl; 
}

// String coloration 
string str_bold(string s){
    return g_BOLD_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}
string str_special(string s){
    return g_SPECIAL_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}
string str_payload(string s){
    return g_PAYLOAD_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}
string str_ropg(string s){
    return g_ROPGENERATOR_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}
string str_exploit(string s){
    return g_EXPLOIT_MODE_ANSI + s + g_END_COLOR_ANSI; 
}
string str_semantic(string s){
    return g_SEMANTIC_MODE_ANSI + s + g_END_COLOR_ANSI; 
}

string banner(vector<string> s){
    char c = '_'; 
    unsigned int max_len = 0; 
    vector<string>::iterator it; 
    string res = ""; 
    stringstream ss; 
    for( it = s.begin(); it != s.end(); it++){
        res += *it + "\n\t"; 
        if( it->length() > max_len )
            max_len = it->length(); 
    }
    ss << "\t" << str_bold(string(max_len, c)) << "\n\n\t" << res << str_bold(string(max_len, c)) << "\n";
    return ss.str();
}

void remove_substr(string s, string sub ){
    size_t pos; 
    // Remove all substrings 
    pos = std::string::npos; 
    while ((pos  = s.find(sub) )!= std::string::npos){
		// If found then erase it from string
		s.erase(pos, sub.length());
	}
}

string remove_colors(string s){
    string res = s; 
    remove_substr(s, g_ROPGENERATOR_COLOR_ANSI);
    remove_substr(s, g_SEMANTIC_MODE_ANSI);
    remove_substr(s, g_EXPLOIT_MODE_ANSI);
    remove_substr(s, g_ERROR_COLOR_ANSI);
    remove_substr(s, g_BOLD_COLOR_ANSI);
    remove_substr(s, g_SPECIAL_COLOR_ANSI);
    remove_substr(s, g_PAYLOAD_COLOR_ANSI);
    remove_substr(s, g_EXPLOIT_DESCRIPTION_ANSI);
    remove_substr(s, g_END_COLOR_ANSI);
    return res; 
}



// Other 
int last_percent = -1; 
void charging_bar(int nb_iter, int curr_iter, int bar_len=30, string msg="", string c="\u2588"){
    int percent = (100*curr_iter)/nb_iter; 
    int div;  
    string full_part = ""; 
    string empty_part = ""; 
    string percent_part = "";
    char buff[8];
    
    if( curr_iter == nb_iter ){
        cout << "\r" << string(bar_len+msg.size()+30, ' ') << '\r'; 
        last_percent = -1; 
    }else{
        last_percent = percent; 
        div = nb_iter/bar_len;
        if( div == 0 )
            div = 1;
        if( nb_iter == 0 )
            nb_iter = 1; 
        for( int n = 0; n < curr_iter/div; n++ )
            full_part += c; 
        empty_part = string(bar_len-full_part.size(), ' ');
        snprintf(buff, sizeof(buff), "%03d%%", percent); 
        percent_part = buff; 
        // Write 
        cout << "\r\t"+g_ROPGENERATOR_COLOR_ANSI+"%"+g_END_COLOR_ANSI
        << msg  << " |" << full_part << empty_part << "| " << percent_part
        << std::flush; 
    }
}

void disable_colors(){
    g_ROPGENERATOR_COLOR_ANSI = "";
    g_SEMANTIC_MODE_ANSI = "";
    g_EXPLOIT_MODE_ANSI = "";
    g_ERROR_COLOR_ANSI = "";
    g_BOLD_COLOR_ANSI = "";
    g_SPECIAL_COLOR_ANSI = "";
    g_PAYLOAD_COLOR_ANSI = "";
    g_EXPLOIT_DESCRIPTION_ANSI = "";
    g_END_COLOR_ANSI = "" ;
} 

void enable_colors(){
    g_ROPGENERATOR_COLOR_ANSI = DEFAULT_ROPGENERATOR_COLOR_ANSI;
    g_SEMANTIC_MODE_ANSI = DEFAULT_SEMANTIC_MODE_ANSI;
    g_EXPLOIT_MODE_ANSI = DEFAULT_EXPLOIT_MODE_ANSI;
    g_ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI;
    g_BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI;
    g_SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI;
    g_PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI;
    g_EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI;
    g_END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI ;
}

