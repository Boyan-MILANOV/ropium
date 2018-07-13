# -*- coding:utf-8 -*- 
# Log module: log informations 

log_file = ".ROPGenerator-logs"
log_file_d = None

def init():
    global log_file
    global log_file_d
    try:
        log_file_d = open(log_file, "w")
    except:
        log_file_d = None
    if(log_file_d == None ):
        #print "[!] Log file could not be created, logs will not be recorded"
        pass
    else:
        log_file_d.write("ROPGenerator logs\n\n")

def log( msg ):
	if( log_file_d == None):
		return
	else:
		log_file_d.write( ">>> " + msg + "\n\n") 
