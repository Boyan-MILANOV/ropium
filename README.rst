ROPGenerator
############

**ROPGenerator** is a tool that makes ROP exploits easy. It enables you to automatically find gadgets or build ROP chains.

ROPGenerator Tool
=================

Overview
--------
**ROPGenerator** uses the tool ROPgadget (https://github.com/JonathanSalwan/ROPgadget) to extract gadgets from binaries and the barf-project (https://github.com/programa-stic/barf-project) to disassembly them. After gadgets are extracted, it performs semantic analysis in order to compute their semantic and stores them according to their utility. Once the analysis is done, you can request **ROPGenerator** to automatically find gadgets or ROP chains by supplying semantic queries. 

**ROPGenerator** is written in python. The current version is still a beta and the tool is still under active development. The tool has python2-only dependencies so it runs under python2 so far.  

Features
--------
Why using **ROPGenerator** ? 
- *Command Line Interface* : Enjoy a nice and smooth CLI with easy-to-use commands 
- *Semantic gadget search* : Find your gadgets quickly by only specifying the desired semantics
- *Gadget chaining engine* : No suitable single gadget ? **ROPGenerator** will build ROP chains for you 

Installation
============

ROPGenerator
------------
You can install **ROPGenerator** with pip 
.. code-block:: bash
	$ pip install ropgenerator

Or you can download the source and run 
.. code-block:: bash
	$ python setup.py install

Or even run the tool without installing 
.. code-block:: bash 
    	$ python ROPGenerator.py 
    
Dependencies
------------
*ROPgadget* should be added automaticaly during installation.

*z3* and *barf* don't support pip installation, so you should install them manually: 
- The z3 solver (https://github.com/Z3Prover/z3)
- The barf-project (https://github.com/programa-stic/barf-project)
 

Getting started
===============

Launch **ROPGenerator** 
.. code-block:: bash
	$ROPGenerator 

	   ___  ____  ___  _____                     __          
	  / _ \/ __ \/ _ \/ ______ ___ ___ _______ _/ /____  ________
	 / , _/ /_/ / ___/ (_ / -_/ _ / -_/ __/ _ `/ __/ _ \/ ______/
	/_/|_|\____/_/   \___/\__/_//_\__/_/  \_,_/\__/\___/_/ v0.2 
	
	 

	>>> help

		-----------------------------------------------------------
		ROPGenerator commands
		(For more information about a command type '<command> help')
		-----------------------------------------------------------

			help: 		print available commands
			load: 		load usable gadgets from a binary file
			find: 		find gadgets that execute specific operations
			registers: 	print available registers for the current architecture
			config: 	configure ROPGenerator
			exit: 		exit ROPGenerator
			
Quickly configure the tool
.. code-block:: bash
	>>> config arch=X86_64 ropgadget=/home/ropgenerator/ROPgadget
	Now working under architecture: X86_64
	New ropgadget location : /home/ropgenerator/ROPgadget/ROPgadget.py
 			
Load gadgets from a binary
.. code-block:: bash
	>>> load /bin/ls
	Extracting gadgets from file '/bin/ls'
	Executing ROPgadget as: /home/ropgenerator/ROPgadget/ROPgadget.py
	Finished : 1425 gadgets generated
	[+] Working under architecture: X86_64
	[+] Creating gadget database : 
		Gadgets analyzed : 1425
		Successfully translated : 962
		Computation time : 0:00:29.704368

Look for gadgets 
.. code-block:: bash
	>>> find rax=rbx

		Found matching gadget(s):

		0x000000000040d7db (mov rax, rbx; pop rbx; pop rbp; pop r12; pop r13; ret)  
		0x000000000040ca7f (mov rax, rbx; pop rbx; pop rbp; pop r12; ret) 

	>>> find rbx=rdx

		Built matching ROP Chain(s):

		-------------------
		0x0000000000404988 (mov rax, rdx; ret)
		0x000000000040b857 (push rax; mov eax, ebp; pop rbx; pop rbp; pop r12; ret)
		0xffffffffffffffff (Padding)
		0xffffffffffffffff (Padding)
		-------------------
		0x0000000000404988 (mov rax, rdx; ret)
		0x000000000040b873 (push rax; xor ebp, ebp; pop rbx; mov eax, ebp; pop rbp; pop r12; ret)
		0xffffffffffffffff (Padding)
		0xffffffffffffffff (Padding)
		-------------------
		0x000000000040a2f7 (mov rax, rdx; pop rbx; pop rbp; ret)
		0xffffffffffffffff (Padding)
		0xffffffffffffffff (Padding)
		0x000000000040b857 (push rax; mov eax, ebp; pop rbx; pop rbp; pop r12; ret)
		0xffffffffffffffff (Padding)
		0xffffffffffffffff (Padding)


	>>> find mem(rsp-8)=rax

		Found matching gadget(s):

		0x000000000040b857 (push rax; mov eax, ebp; pop rbx; pop rbp; pop r12; ret)  
		0x000000000040b873 (push rax; xor ebp, ebp; pop rbx; mov eax, ebp; pop rbp; pop r12; ret)  



