#ifndef LOG_H
#define LOG_H

#include <string>

bool init_logs(std::string filename);
void close_logs();
void log_message(std::string msg);

#endif 
