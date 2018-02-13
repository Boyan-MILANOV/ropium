# ROPGenerator - Database.py module
# Storing the gadgets that are used during analysis 

import sys
from Analysis import *
from Gadget import *
from datetime import datetime
from Cond import *
import Expr
import signal 

# List of the available gadgets 
gadgetDB = [] 

#################################################
# VARIOUS DATA STRUCTURES TO STORE DEPENDENCIES #
#################################################


# exprLookUp

class exprLookUp:
	"""
	Class used to store dependencies of type EXPRtoREG
	Each register should have its own exprLookUp
	"""
	def __init__(self):
		self.expr_list = [] # LIst of EXPR that are stored in REG 
		self.gadget_list = [] # gadget_list[i] = list of gadgets that put expr_list[i] in the regiter 
		
	
	def lookUpEXPRtoREG(self, expr, n=10):
		"""
		Return at most n gadgets that correspond to expr 
		"""
		i = 0
		found = 0
		res = [] 
		while( i < len(self.expr_list ) and len(res) < n):
			cond = Cond(CT.EQUAL, self.expr_list[i], expr)
			if( cond.isTrue(hard=True)):
				res += self.gadget_list[i]
			i = i + 1
		return res 


# memLookUp:

class memLookUp:
	"""
	Class used to help storing the dependencies for the memory in gadgetLookUp
	
	- addr_list is a list of expressions corresponding to memory addresses 
	- written_values is a list of dictionnaries whose content depends on the type of dependency the structure is used to store
	Depending on the use: 
		REGtoMEM : keys are register uid (int)
		CSTtoMEM : keys are the constant value (int)
	"""
	
	def __init__(self):
		self.addr_list=[] # To check if an access to an address is available
		self.written_values=[] # List of dictionnaries 
		
	def lookUpREGtoMEM( self, addr, reg, n=10 ):
		"""
		Returns gadgets numbers that put reg at mem(addr) as a list of gadgets uids 
		reg - (int)
		addr - Expr
		"""
		i = 0
		found = 0
		res = []
		# Iterate for all write addresses 
		while( i < len(self.addr_list ) and len(res) < n):
			# If we have a dependencie for the requested register 
			if( reg in self.written_values[i]):
				# Comparing the addresses with hard=True so we call z3 solver 
				cond = Cond(CT.EQUAL, self.addr_list[i], addr)
				if( cond.isTrue(hard=True)):
					res += self.written_values[i][reg]
			i = i + 1
		return res 
		
	def lookUpCSTtoMEM( self, addr, cst, n=10):
		"""
		Returns gadgets numbers that put cst at mem(addr) as a list of gadgets uids 
		cst - (int)
		addr - Expr
		"""
		i = 0
		found = 0
		res = []
		# Iterate for all write addresses 
		while( i < len(self.addr_list ) and len(res) < n):
			# If we have a dependencie for the requested constant
			if( cst in self.written_values[i]):
				# Comparing the addresses with hard=True so we call z3 solver 
				cond = Cond(CT.EQUAL, self.addr_list[i], addr)
				if( cond.isTrue(hard=True)):
					res += self.written_values[i][cst]
			i = i + 1
		return res 

	


# Hash tables to look up registers
# Different kinds :
# REGtoREG, REGtoMEM, MEMtoREG, MEMtoMEM, CSTtoREG, CSTtoMEM, EXPRtoREG, ... (see GadgetType class )

# gadgetLookUp: 
# keys are GadgetTypes
# values are dictionnaries (different organization for all of them 

# REGtoREG dictionnary : gadgetLookUp[REGtoREG][REG1][REG2] = uid (number) of gadget in the gadgetDB list that puts REG2 in REG1 
# CSTtoREG dictionnary : gadgetLookUp[REGtoREG][REG][CST] = uid (number) of gadget in the gadgetDB list that puts CST in REG
# MEMtoREG dictionnary : gadgetLookUp[MEMtoREG][REG][ADDR] = uid (number) of gadget in the gadgetDB that puts MEM[addr] in REG 
# REGtoMEM dictionnary : gadgetLookUp[REGtoMEM] = memLookUp() for gadgets  that writes reg in the memory 
# CSTtoMEM dictionnary : gadgetLookUp[CSTtoMEM] = memLookUp() for gadgets that writes cst in the memory 
# EXPRtoREG dictionnary : gadgetLookUp[EXPRtoREG][REG] = exprLookUp() 
# MEMEXPRtoREG dictionnary : gadgetLookUp[MEMEXPRtoREG][REG] = exprLookUp (stored expressions are not MEMEXPR but only the address)
 
gadgetLookUp = {GadgetType.REGtoREG:dict(), GadgetType.REGtoMEM:memLookUp(), GadgetType.MEMtoREG:dict(),GadgetType.CSTtoREG:dict(),GadgetType.CSTtoMEM:memLookUp(), GadgetType.EXPRtoREG:dict(), GadgetType.MEMEXPRtoREG:dict()}



#############################################
# GENERATING GADGETS AND STORING 	    #
# THEM IN THE DATABASE & SEARCH STRUCTURES  #
#############################################

sigint = False

def generated_gadgets_to_DB():
	"""
	Generates the list of the available gadgets for ROP 
	Usage : must be called after the gadgets opcodes have been stored into the opcodes_gadget array in Generated_opcodes.py file.
	Result : 
		No value returned. But the gadgets are stored in the gadgets[] array in Database module.  
	"""
	global sigint 
	
	def sigint_handler(signal, frame):
		global sigint
		sigint = True
		
		
	
	 # Read all gadgets that have been generated ! 
	f = open('.generated_opcodes', "r")
	asmGadgets = []
	for line in f:
		(addr,instr) = line[:-1].split('#')
		addr = int(addr,16)
		instr = instr.decode("hex")
		asmGadgets.append((addr, instr))
	f.close()
	# Analyze them 
	i = 0
	success = 0
	warnings = 0
	startTime = datetime.now()
	chargingBarSize = 30
	chargingBarStr = " "*chargingBarSize
	sys.stdout.write("[+] Working under architecture: " + ArchInfo.currentArch + '\n')
	sys.stdout.write("[+] Creating gadget database : \n") 
	sys.stdout.write("\tProgression [")
	sys.stdout.write(chargingBarStr)
	sys.stdout.write("]\r\tProgression [")
	sys.stdout.flush()    
	f = open(".warnings.log", "w") 
	original_sigint_handler = signal.getsignal(signal.SIGINT)   
	signal.signal(signal.SIGINT, sigint_handler)             
	for g in asmGadgets:
		if( sigint ):
			break
		asm = g[1]
		addr = g[0]
		try:
			if( i % (len(asmGadgets)/30) == 0 and i > 0 or i == len(asmGadgets)):
				sys.stdout.write("|")
				sys.stdout.flush()
			f.write("Gadget : " + '\\x'.join(["%02x" % ord(c) for c in asm]) + "\n")
			gadget = Gadget(i, addr, asm)
			success += 1
			gadgetDB.append( gadget )
		except Exception as e:
			#print e
			if( not isinstance(e, GadgetException)):
				warnings = warnings + 1
				f.write("Error in : " + '\\x'.join(["%02x" % ord(c) for c in asm]) + "\nException message: " + str(e) + '\n\n')
				
		i += 1
	f.close()
	signal.signal(signal.SIGINT, original_sigint_handler)
	sigint = False
		
	# This variable should be written before calculating spInc or simplifying conditions !!!
	Expr.nb_regs = Analysis.ssaRegCount-1
	
	
	# Second pass analysis once all gadgets are collected 
	for gadget in gadgetDB:
		gadget.calculateSpInc()	
		gadget.calculateRet()
	
	sys.stdout.write("\r"+" "*90+"\r")
		
	cTime = datetime.now() - startTime	
	print "\tGadgets analyzed : " + str(len(asmGadgets))
	print "\tSuccessfully translated : " + str(success)
	print "\tComputation time : " + str(cTime)
	if( warnings > 0 ):
		print("\tUnexpected exceptions : " + str(warnings) + " (logs in '.warnings.log')")
	
def simplifyGadgets():
	"""
	Apply some simplifications on the gadget dependencies 
	"""
	for gadget in gadgetDB:
		gadget.getDependencies().simplifyConditions()
	
def fillGadgetLookUp():
	"""
	Fill the gadgetLookUp dictionnary with gadgets from the gadgetDB list 
	"""
	
	def add_gadget( gadget_list, gadget_num ):
		"""
		Adds a gadget in a list of gadgets in increasing order ( order is gadget.nbInstr value )
		"""
		for i in range(0,len(gadget_list)):
			if( gadget_num == gadget_list[i] ):
				return 
			elif( gadgetDB[gadget_list[i]].nbInstr >= gadgetDB[gadget_num].nbInstr ):
				gadget_list.insert(i, gadget_num )
				return 
		gadget_list.append(gadget_num)
				
	
	# Initialize the gadgetLookUp dictionnaries 
	# Only done for REGtoREG so far 
	for reg_num in revertRegNamesTable.keys():
		# For REGtoREG
		gadgetLookUp[GadgetType.REGtoREG][reg_num] = dict()
		for reg_num2 in revertRegNamesTable.keys():
			gadgetLookUp[GadgetType.REGtoREG][reg_num][reg_num2] = []
		# For CSTtoREG
		gadgetLookUp[GadgetType.CSTtoREG][reg_num] = dict()
		# For MEMtoREG
		gadgetLookUp[GadgetType.MEMtoREG][reg_num] = dict()
		# For EXPRtoREG
		gadgetLookUp[GadgetType.EXPRtoREG][reg_num] = exprLookUp() 
		# For MEMEXPRtoREG 
		gadgetLookUp[GadgetType.MEMEXPRtoREG][reg_num] = exprLookUp()
		# For REGtoMEM
		# No initialisation needed 
			
	
	# Update the gadgetLookUp table 
	hard_simplify=False
	for i in range(0, len(gadgetDB) ):
		gadget = gadgetDB[i]
		for reg, deps in gadget.getDependencies().regDep.iteritems():	
			for dep in deps:
				# For REGtoREG
				if( isinstance(dep[0], SSAExpr) and dep[1].isTrue(hard=hard_simplify)):
					add_gadget(gadgetLookUp[GadgetType.REGtoREG][reg.num][dep[0].reg.num], i)
				# For CSTtoREG
				elif( isinstance(dep[0], ConstExpr) and dep[1].isTrue(hard=hard_simplify)):
					if( not dep[0].value in gadgetLookUp[GadgetType.CSTtoREG][reg.num] ):
						gadgetLookUp[GadgetType.CSTtoREG][reg.num][dep[0].value] = [i]
					else:	
						add_gadget(gadgetLookUp[GadgetType.CSTtoREG][reg.num][dep[0].value], i)
				# For XXXtoREG
				elif( isinstance(dep[0], MEMExpr) and dep[1].isTrue(hard=hard_simplify) ):
					# For MEMtoREG
					if( isinstance(dep[0].addr, SSAExpr)): 
						addrKey = dep[0].addr.reg.num
						if( not addrKey in gadgetLookUp[GadgetType.MEMtoREG][reg.num]):
							gadgetLookUp[GadgetType.MEMtoREG][reg.num][addrKey] = [i]
						else:
							add_gadget(gadgetLookUp[GadgetType.MEMtoREG][reg.num][addrKey], i)
					# For MEMEXPRtoREG
					else:
						gadgetLookUp[GadgetType.MEMEXPRtoREG][reg.num].expr_list.append(dep[0].addr)
						gadgetLookUp[GadgetType.MEMEXPRtoREG][reg.num].gadget_list.append([i])
				# FOR EXPRtoREG
				elif( dep[1].isTrue() ):
					exprLookUpEXPRtoREG = gadgetLookUp[GadgetType.EXPRtoREG][reg.num]
					exprLookUpEXPRtoREG.expr_list.append(dep[0])
					exprLookUpEXPRtoREG.gadget_list.append([i])
					
					
		for addr, deps in gadget.getDependencies().memDep.iteritems():
			# For REGtoMEM
			memLookUpREGtoMEM = gadgetLookUp[GadgetType.REGtoMEM]
			memLookUpREGtoMEM.addr_list.append(addr)
			memLookUpREGtoMEM.written_values.append(dict())
			
			# For CSTtoMEM
			memLookUpCSTtoMEM = gadgetLookUp[GadgetType.CSTtoMEM]
			memLookUpCSTtoMEM.addr_list.append(addr)
			memLookUpCSTtoMEM.written_values.append(dict())
			
			for dep in deps:
				# For REGtoMEM
				if( isinstance( dep[0], SSAExpr ) and dep[1].isTrue(hard=hard_simplify)):
					if( dep[0].reg.num in memLookUpREGtoMEM.written_values[-1]):
						add_gadget(memLookUpREGtoMEM.written_values[-1][dep[0].reg.num], i)	
					else:
						memLookUpREGtoMEM.written_values[len(memLookUpREGtoMEM.addr_list)-1][dep[0].reg.num] = [i]
				elif( isinstance(dep[0], ConstExpr) and dep[1].isTrue(hard=hard_simplify)):
					if( dep[0].value in memLookUpCSTtoMEM.written_values[-1]):
						add_gadget(memLookUpCSTtoMEM.written_values[-1][dep[0].value], i)
					else:
						memLookUpCSTtoMEM.written_values[-1][dep[0].value] = [i]
				# FOR THE REST --> IMPLEMENT LATER !! 
				else:
					pass



				
def pretty_print_registers():
	if( not gadgetDB ):
		print("You should generate gadgets before looking at the registers. Type 'load help' for help")
	else:
		print("\n\tRegisters present in the gadget database:")
		print("\t(Architeture is '" + ArchInfo.currentArch +"')\n")
		for reg in regNamesTable.keys():
			if( reg == ArchInfo.ip ):
				print('\t'+reg+ " (instruction pointer)")
			elif( reg == ArchInfo.sp ):
				print('\t'+reg+ " (stack pointer)")
			else:
				print('\t'+reg)

