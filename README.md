ROPGenerator
============

ROPGenerator is a tool that makes ROP exploits easy. It enables you to automatically find gadgets or build ROP chains.
The current version supports *x86* and *x64* binaries. 

Overview
--------
ROPGenerator uses the tool ROPgadget (https://github.com/JonathanSalwan/ROPgadget) to extract gadgets from binaries and the barf-project (https://github.com/programa-stic/barf-project) to disassembly them. After gadgets are extracted, it analyzes them in order to compute their semantic and stores them according to their usefullness. Once the analysis is done, you can request ROPGenerator to automatically find gadgets or ROP chains by supplying semantic queries. 

ROPGenerator is written in python. The tool has python2-only dependencies so it runs under python2 so far.  

**Please note** that the current ROPGenerator version is still a beta under active development, therefore it might not work perfectly on some systems. 

Why using ROPGenerator ? 
----------------------------
- **Nice Command Line Interface** : Enjoy a nice and smooth CLI with easy-to-use commands 
- **Semantic gadget search** : Find your gadgets quickly by only specifying the desired semantics
- **Gadget chaining engine** : No suitable single gadget ? ROPGenerator will build ROP chains for you 

Installation
============
Install ROPGenerator
--------------------
You can download the source and run 

	$ sudo python setup.py install
	$ sudo ROPGenerator

    
Install Dependencies
--------------------
**ROPGenerator** depends on **ROPgadget**, **prompt_toolkit**, **enum**, **python-magic**, and **barf**:

- **python-magic**, **enum**, **barf v0.4.0**, and **prompt_toolkit** packages will be added automaticaly during installation

- **ROPgadget** will also be installed automatically if you don't have it already. However, the currently available package on pypi is not up-to-date. Therefore, it will be installed as "**ROPgadget4ROPGenerator**", a recent fork of ROPgadget.


Getting started
===============
Launch **ROPGenerator** 

![Alt text](/screenshots/start.png?raw=true)

Get help

![Alt text](/screenshots/help.png?raw=true)
			
If you are using ROPGenerator for the first time, quickly configure the tool

![Alt text](/screenshots/config.png?raw=true)
 			
Load gadgets from a binary

![Alt text](/screenshots/load.png?raw=true)

Easily look for gadgets ! 

![Alt text](/screenshots/search1.png?raw=true)
![Alt text](/screenshots/search2.png?raw=true)
![Alt text](/screenshots/search3.png?raw=true)
![Alt text](/screenshots/search4.png?raw=true)
