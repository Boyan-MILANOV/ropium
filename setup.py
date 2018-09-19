from setuptools import setup
import os
import pwd
import grp

ROPGenerator_dir = os.path.expanduser('~')+"/.ROPGenerator/"

setup(  name='ropgenerator',
        version = "1.0",
        description = "ROPGenerator makes ROP exploits easy by finding and\
                        chaining gadgets for you",
        url="https://github.com/Boyan-MILANOV/ropgenerator",
        author="Boyan MILANOV",
        author_email="boyan.milanov@hotmail.fr",
        licence="GPLv3",
        classifiers=[
        'Development Status :: 4 - Beta',
        "Environment :: Console",
        "Operating System :: Linux",
        "Programming Language :: Python :: 2.7",
        "Topic :: Security",
        ],    
        packages=['ropgenerator', 'ropgenerator/semantic', 'ropgenerator/exploit'\
                    , 'ropgenerator.exploit.ZwoELF', 'ropgenerator.exploit.syscalls'],
        scripts=['ROPGenerator'],
        install_requires=['python-magic', 'ROPGadget4ROPGenerator', 'prompt_toolkit>=2.0',\
        'barf==0.5.0', 'enum', 'capstone==3.0.5rc2'],
        keywords='rop generator chain gadget semantic automated exploit ropchain',
        zip_safe = False,
        data_files=[(ROPGenerator_dir, [])]
    )


# Change permissions on the .ROPGenerator directory in case command was run as root 
try:
    os.chmod(ROPGenerator_dir, 0777)
except:
    print("[!] Error while setting up ROPGenerator's data directory")
