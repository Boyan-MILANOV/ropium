#ifndef IO_H
#define IO_H

#include <string>
using std::string; 
#include <vector>
using std::vector; 

#define DEFAULT_ROPGENERATOR_COLOR_ANSI  "\033[92m" 
#define DEFAULT_SEMANTIC_MODE_ANSI  "\033[96m"
#define DEFAULT_EXPLOIT_MODE_ANSI  "\033[91m"
#define DEFAULT_ERROR_COLOR_ANSI  "\033[91m"
#define DEFAULT_BOLD_COLOR_ANSI  "\033[1m"
#define DEFAULT_SPECIAL_COLOR_ANSI  "\033[93m"
#define DEFAULT_PAYLOAD_COLOR_ANSI "\033[96m"
#define DEFAULT_EXPLOIT_DESCRIPTION_ANSI  "\033[95m"
#define DEFAULT_END_COLOR_ANSI "\033[0m"

void info(string s);
void notify(string s);
void error(string s);
void fatal(string s);
void verbose(string s);

string banner(vector<string> s);
string str_bold(string s);
string str_special(string s);
string str_payload(string s);
string str_ropg(string s);
string str_exploit(string s);
string str_semantic(string s);
string remove_colors(string s);

void charging_bar(int nb_iter, int curr_iter, int bar_len, string msg, string c);

void disable_colors(); 
void enable_colors();  


#endif 
