# ROPGenerator - Logs.py module
# Used to store some logs on ropgenerator activity 

log_file = "tests-logs.log"
log_file_d = open(log_file, "w")

if(log_file_d == None ):
	#print "[!] Log file could not be created, logs will not be recorded"
	pass
else:
	#print"[+] Logs recorded in file: " + log_file
	log_file_d.write("ROPGenerator logs\n\n")

def log( msg ):
	if( log_file_d == None):
		return
	else:
		log_file_d.write( ">>> " + msg + "\n") 
	

