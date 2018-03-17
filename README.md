ROPGenerator
============

ROPGenerator is a tool that makes ROP exploits easy. It enables you to automatically find gadgets or build ROP chains.
The current version supports *x86* and *x64* binaries. 

Overview
--------
ROPGenerator uses the tool ROPgadget (https://github.com/JonathanSalwan/ROPgadget) to extract gadgets from binaries and the barf-project (https://github.com/programa-stic/barf-project) to disassembly them. After gadgets are extracted, it analyzes them in order to compute their semantic and stores them according to their usefullness. Once the analysis is done, you can request ROPGenerator to automatically find gadgets or ROP chains by supplying semantic queries. 

ROPGenerator is written in python. The tool has python2-only dependencies so it runs under python2 so far.  

**Please note** that the current ROPGenerator version is still a beta under active development, therefore it might be a little unstable on some systems. 

Why using ROPGenerator ? 
----------------------------
- **Nice Command Line Interface** : Enjoy a nice and smooth CLI with easy-to-use commands 
- **Semantic gadget search** : Find your gadgets quickly by only specifying the desired semantics
- **Gadget chaining engine** : No suitable single gadget ? ROPGenerator will build ROP chains for you 

Installation
============
Install ROPGenerator
--------------------
You can download the source (prefer this method if you want the latest and more stable version of the tool) and run 

	$ sudo python setup.py install
	$ sudo ROPGenerator

Or install **ROPGenerator** with pip 

	$ sudo pip install ropgenerator
	$ sudo ROPGenerator
	


    
Install Dependencies
--------------------
**ROPGenerator** depends on **ROPgadget**, **prompt_toolkit**, **z3-solver**, **enum**, and **barf**:

- **enum**, **z3-solver**, **barf v0.4.0**, and **prompt_toolkit** packages will be added automaticaly during installation

- **ROPgadget** will also be installed automatically if you don't have it already. However, the currently available package on pypi is not up-to-date. Therefore, it will be installed as "**ROPgadget4ROPGenerator**", a recent fork of ROPgadget.


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

	>>> config arch=X86_64 ropgadget=/home/ROPgadget/ROPgadget.py
	Now working under architecture: X86_64
	New ropgadget command : /home/ROPgadget/ROPgadget.py
 			
Load gadgets from a binary

	>>> load /bin/tar
	[+] Extracting gadgets from file '/bin/tar'
		Executing ROPgadget as: ROPgadget4ROPGenerator
		Finished : 12534 gadgets generated
	[+] Working under architecture: X86_64
	[+] Creating gadget database
		Gadgets analyzed : 12534                                      
		Successfully translated : 10189
		Computation time : 0:01:42.018046
	[+] Simplifying gadgets
	[+] Updating gadget tables                                            
	[+] Performing additionnal analysis (chain gadgets by transitivity)   
	[+] Performing additionnal analysis (poping registers from stack)
	[+] Performing additionnal analysis (writing registers on stack)   

Easily look for gadgets ! 

	>>> find rax=rbx

		Built matching ROP Chain(s):

		-------------------
		0x0000000000416991 (mov rax, rbx; pop rbx; ret)
		0xffffffffffffffff (Padding)
		-------------------
		0x00000000004169ce (mov rax, rbx; pop rbx; ret)
		0xffffffffffffffff (Padding)
		-------------------
		0x0000000000419592 (mov rax, rbx; pop rbx; ret)
		0xffffffffffffffff (Padding)


	>>> find rsi=rax

		Built matching ROP Chain(s):

		-------------------
		0x0000000000431357 (push rax; mov eax, ebp; pop rbx; pop rbp; pop r12; ret)
		0xffffffffffffffff (Padding)
		0xffffffffffffffff (Padding)
		0x00000000004043fe (pop rax; ret)
		0x0000000000400372 (@ddress of: ret)
		0x000000000042e7b8 (mov rdx, rbx; call rax)
		0x00000000004043fe (pop rax; ret)
		0x0000000000400372 (@ddress of: ret)
		0x000000000042e1c4 (mov rsi, rdx; call rax)



	>>> find mem(rsp-8)=rax

		Built matching ROP Chain(s):

		-------------------
		0x0000000000431357 (push rax; mov eax, ebp; pop rbx; pop rbp; pop r12; ret)
		0xffffffffffffffff (Padding)
		0xffffffffffffffff (Padding)
 

	>>> find rbx=0x441424344454647

		Built matching ROP Chain(s):

		-------------------
		0x000000000040445b (pop rbx; ret)
		0x0441424344454647 (Custom Padding)
		-------------------
		0x00000000004043fe (pop rax; ret)
		0x0441424344454647 (Custom Padding)
		0x0000000000431357 (push rax; mov eax, ebp; pop rbx; pop rbp; pop r12; ret)
		0xffffffffffffffff (Padding)
		0xffffffffffffffff (Padding)

		
