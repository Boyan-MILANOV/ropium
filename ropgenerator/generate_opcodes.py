import subprocess
import os
import sys
import Config


def generate(filename):
	"""
	Returns true if success, false otherwise 
	
	"""
	#if(not "PATH_ROPGADGET" in os.environ):
	#    print "Need to set PATH_ROPGADGET"
	#    print "export PATH_ROPGADGET=..."
	#    exit()

	#if(len(sys.argv)!=2):
	#    print "Use ./generate_opcode.py BINARY"
	#    exit()

	#ropgadget = os.environ["PATH_ROPGADGET"]+"/ROPgadget.py"
	
	if( not os.path.isfile(filename)):
		print("Error. Could not find file '{}'".format(filename))
		return False
		 
	ropgadget = Config.PATH_ROPGADGET+"/ROPgadget.py"
	print("Executing ROPgadget as: " + ropgadget )
	try:
		p = subprocess.Popen([ropgadget,"--binary",filename,"--dump"],stdout=subprocess.PIPE)
	except Exception as e:
		print("Error. Could not execute ' " +ropgadget+ " --binary " + filename + " --dump '")
		print("Error message is: " + str(e))
		print("\n(Maybe check/update your config with the 'config' command)")
		return False
		  
	f = open("Generated_opcodes.py","w")

	# Write binary name 
	f.write("\n")

	# Write gadgets 
	f.write("opcodes_gadget = [")

	first = True
	count = 0
	for l in p.stdout.readlines():
	    if("0x" in l):
		arr = l.split(' ')
		addr = arr[0]
		gadget = arr[-1]
		it = iter(gadget)
		gadget = "\\x"+"\\x".join(a+b for a,b in zip(it,it))
		if(first):
		    buf = "("+addr+",\""+gadget+"\")"
		    first = False
		else:
		    buf = ",("+addr+",\""+gadget+"\")"
		f.write(buf)
		count += 1 
	f.write("]")
	f.close()
		
	print "Finished : %d gadgets generated" % (count)
	
	return ( count > 0)
