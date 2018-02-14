ROPGenerator
============

ROPGenerator is a tool that makes ROP exploits easy. It enables you to automatically find gadgets or build ROP chains.
The current version supports *x86* and *x64* binaries. 

Overview
--------
ROPGenerator uses the tool ROPgadget (https://github.com/JonathanSalwan/ROPgadget) to extract gadgets from binaries and the barf-project (https://github.com/programa-stic/barf-project) to disassembly them. After gadgets are extracted, it performs semantic analysis in order to compute their semantic and stores them according to their utility. Once the analysis is done, you can request ROPGenerator to automatically find gadgets or ROP chains by supplying semantic queries. 

ROPGenerator is written in python. The current version is still a beta and the tool is still under active development. The tool has python2-only dependencies so it runs under python2 so far.  

Why using ROPGenerator ? 
----------------------------
- **Nice Command Line Interface** : Enjoy a nice and smooth CLI with easy-to-use commands 
- **Semantic gadget search** : Find your gadgets quickly by only specifying the desired semantics
- **Gadget chaining engine** : No suitable single gadget ? ROPGenerator will build ROP chains for you 

Installation
============
Install ROPGenerator
--------------------
You can install **ROPGenerator** with pip 

	$ pip install ropgenerator
	$ ROPGenerator
	
Or download the source (prefer this method if you want the last version of the tool) and run 

	$ python setup.py install
	$ ROPGenerator

    
Install Dependencies
--------------------
**ROPGenerator** depends on **ROPgadget**, **prompt_toolkit**, **z3-solver**, **enum**, and **barf**:

- **enum**, **ROPgadget**, **prompt_toolkit**, and **z3-solver** packages will be added automaticaly during installation

- **barf v0.4.0** will also be installed automatically. In case you already have barf on your computer, note that ROPGenerator is not compatible with later versions than 0.4.0


Getting started
===============
Launch **ROPGenerator** 

	$ ROPGenerator 

	   ___  ____  ___  _____                     __          
	  / _ \/ __ \/ _ \/ ______ ___ ___ _______ _/ /____  ________
	 / , _/ /_/ / ___/ (_ / -_/ _ / -_/ __/ _ `/ __/ _ \/ ______/
	/_/|_|\____/_/   \___/\__/_//_\__/_/  \_,_/\__/\___/_/ v0.3 
        
        >>>
Get help

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
			
If you are using ROPGenerator for the first time, quickly configure the tool

	>>> config arch=X86_64 ropgadget=/home/ropgenerator/ROPgadget
	Now working under architecture: X86_64
	New ropgadget location : /home/ropgenerator/ROPgadget/ROPgadget.py
 			
Load gadgets from a binary

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

	>>> find rbx=0x4041424344454748

		Built matching ROP Chain(s):

		-------------------
		0x0000000000404dc0 (pop rbx; ret)
		0x4041424344454748
		-------------------
		0x0000000000404dbb (nop dword ptr [rax+rax*1]; pop rbx; ret)
		0x4041424344454748
		-------------------
		0x0000000000409cb4 (mov eax, 0x1; pop rbx; ret)
		0x4041424344454748
		-------------------
		0x0000000000404f90 (pop rbx; pop rbp; ret)
		0x4041424344454748
		0xffffffffffffffff (Padding)
		-------------------
		0x000000000040a2f7 (mov rax, rdx; pop rbx; pop rbp; ret)
		0x4041424344454748
		0xffffffffffffffff (Padding)
		
