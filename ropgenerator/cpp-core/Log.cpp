#include "Log.hpp"
#include <iostream>
#include <fstream>

using std::string;
using std::ofstream;

ofstream log_file; 

bool init_logs(string filename){
    log_file.open(filename);
    if( ! log_file.is_open() )
        return false;
    log_file << "ROPGenerator - Logs\n\n"; 
}

void close_logs(){
    if( log_file.is_open() )
        log_file.close();
}

void log_message( string msg ){
    if( log_file.is_open() ){
        log_file << "(log)> " << msg << std::endl << std::endl;
    }
}


