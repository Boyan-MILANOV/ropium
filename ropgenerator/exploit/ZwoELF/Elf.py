#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# github: https://github.com/sqall01
#
# Licensed under the GNU Public License, version 2.


class Section(object):

	def __init__(self):
		self.sectionName = ""
		self.elfN_shdr = ElfN_Shdr()


class Segment(object):

	def __init__(self):
		# for 32 bit systems only
		self.elfN_Phdr = Elf32_Phdr() # change here to load Elf64_Phdr
		self.sectionsWithin = list()
		self.segmentsWithin = list()


class DynamicSymbol(object):

	def __init__(self):
		self.ElfN_Sym = ElfN_Sym()
		self.symbolName = ""


class ElfN_Ehdr(object):

	class EI_OSABI(object):
		'''
		This  byte  identifies  the operating system and ABI to which the
		object is targeted.  Some fields in other ELF structures have flags
		and values that have platform-specific  meanings;  the
		interpretation  of  those fields is determined by the value of this
		byte.  E.g.:

		ELFOSABI_NONE 		Same as ELFOSABI_SYSV (0x00)
		ELFOSABI_SYSV 		UNIX System V ABI.
		ELFOSABI_HPUX 		HP-UX ABI.
		ELFOSABI_NETBSD 	NetBSD ABI.
		ELFOSABI_LINUX 		Linux ABI. (0x03)
		ELFOSABI_SOLARIS 	Solaris ABI.
		ELFOSABI_IRIX 		IRIX ABI.
		ELFOSABI_FREEBSD 	FreeBSD ABI.
		ELFOSABI_TRU64 		TRU64 UNIX ABI.
		ELFOSABI_ARM 		ARM architecture ABI.
		ELFOSABI_STANDALONE	Stand-alone (embedded) ABI.
		'''
		reverse_lookup = {0x0: "ELFOSABI_NONE", 0x3: "ELFOSABI_LINUX"}
		ELFOSABI_NONE = 0x0
		ELFOSABI_LINUX = 0x3


	class EI_VERSION(object):
		'''
		The version number of the ELF specification:
		EV_NONE 		Invalid version. (0x00)
		EV_CURRENT 		Current version. (0x01)
		'''
		reverse_lookup = {0x0: "EV_NONE", 0x1: "EV_CURRENT"}
		EV_NONE = 0x0
		EV_CURRENT = 0x1


	class EI_DATA(object):
		'''
		The sixth byte of e_ident specifies the data encoding of the processor-
		specific data in the file. Currently  these encodings are supported:

		ELFDATANONE 	Unknown data format. (0x00)
		ELFDATA2LSB 	Two's complement, little-endian. (0x01)
		ELFDATA2MSB 	Two's complement, big-endian. (0x02)
		'''
		reverse_lookup = {0x0: "ELFDATANONE", 0x1: "ELFDATA2LSB",
			0x2: "ELFDATA2MSB"}
		ELFDATANONE = 0x0
		ELFDATA2LSB = 0x1
		ELFDATA2MSB = 0x2


	class EI_CLASS(object):
		'''
		EI_CLASS The fifth byte of e_ident identifies the architecture for
		this binary:

		ELFCLASSNONE 	This class is invalid. (0x00)
		ELFCLASS32 		This  defines  the  32-bit architecture.  It supports
			machines with files and virtual address spaces up
			to 4 Gigabytes. (0x01)
		ELFCLASS64 		This defines the 64-bit architecture. (0x02)
		'''
		ELFCLASSNONE = 0x0
		ELFCLASS32 = 0x1
		ELFCLASS64 = 0x2


	class E_machine(object):
		'''
		uint16_t      e_machine;

		This member specifies the required architecture for an individual file.
		E.g.:

		EM_NONE			An unknown machine. (0x0)
		EM_M32			AT&T WE 32100. (0x1)
		EM_SPARC		Sun Microsystems SPARC. (0x2)
		EM_386			Intel 80386. (0x3)
		EM_68K			Motorola 68000. (0x4)
		EM_88K			Motorola 88000. (0x5)
		EM_860			Intel 80860. (0x7)
		EM_MIPS			MIPS RS3000 (big-endian only). (0x8)
		EM_PARISC		HP/PA. (0xF)
		EM_SPARC32PLUS 	SPARC with enhanced instruction set. (0x12)
		EM_PPC 			PowerPC. (0x14)
		EM_PPC64		PowerPC 64-bit. (0x15)
		EM_S390 		BM S/390 (0x16)
		EM_ARM			Advanced RISC Machines (0x28)
		EM_SH 			Renesas SuperH (0x2A)
		EM_SPARCV9 		SPARC v9 64-bit. (0x2B)
		EM_IA_64 		Intel Itanium (0x32)
		EM_X86_64 		AMD x86-64 (0x3E)
		EM_VAX 			DEC Vax. (0x4B)
		'''
		reverse_lookup = {0x0: "EM_NONE", 0x1: "EM_M32", 0x2: "EM_SPARC",
			0x3: "EM_386", 0x4: "EM_68K", 0x5: "EM_88K", 0x7: "EM_860",
			0x8: "EM_MIPS", 0xF: "EM_PARISC", 0x12: "EM_SPARC32PLUS",
			0x14: "EM_PPC", 0x15: "EM_PPC64", 0x16: "EM_S390",
			0x28: "EM_ARM", 0x2A: "EM_SH", 0x2B: "EM_SPARCV9",
			0x32: "EM_IA_64", 0x3E: "EM_X86_64", 0x4B: "EM_VAX"}
		EM_NONE = 0x0
		EM_M32 = 0x1
		EM_SPARC = 0x2
		EM_386 = 0x3
		EM_68K = 0x3
		EM_88K = 0x4
		EM_860 = 0x7
		EM_MIPS = 0x8
		EM_PARISC = 0xF
		EM_SPARC32PLUS = 0x12
		EM_PPC = 0x14
		EM_PPC64 = 0x15
		EM_S390 = 0x16
		EM_ARM = 0x28
		EM_SH = 0x2A
		EM_SPARCV9 = 0x2B
		EM_IA_64 = 0x32
		EM_X86_64 = 0x3E
		EM_VAX = 0x4B


	class E_type(object):
		'''
		uint16_t      e_type;

		This member of the structure identifies the object file type:

		ET_NONE		An unknown type. (0x0)
		ET_REL		A relocatable file. (0x1)
		ET_EXEC		An executable file. (0x2)
		ET_DYN		A shared object. (0x3)
		ET_CORE		A core file. (0x4)
		'''
		reverse_lookup = {0x0: "T_NONE", 0x1: "ET_REL", 0x2: "ET_EXEC",
			0x3: "ET_DYN", 0x4: "ET_CORE"}
		ET_NONE = 0x0
		ET_REL = 0x1
		ET_EXEC = 0x2
		ET_DYN = 0x3
		ET_CORE = 0x4


	'''
	#define EI_NIDENT 16

	typedef struct {
		unsigned char e_ident[EI_NIDENT];
		uint16_t	e_type;
		uint16_t	e_machine;
		uint32_t	e_version;
		ElfN_Addr	e_entry;
		ElfN_Off	e_phoff;
		ElfN_Off	e_shoff;
		uint32_t	e_flags;
		uint16_t	e_ehsize;
		uint16_t	e_phentsize;
		uint16_t	e_phnum;
		uint16_t	e_shentsize;
		uint16_t	e_shnum;
		uint16_t	e_shstrndx;
	} ElfN_Ehdr;
	'''
	def __init__(self):
		self.e_ident = bytearray(16)
		self.e_type = None
		self.e_machine = None
		self.e_version = None
		self.e_entry = None
		self.e_phoff = None
		self.e_shoff = None
		self.e_flags = None
		self.e_ehsize = None
		self.e_phentsize = None
		self.e_phnum = None
		self.e_shentsize = None
		self.e_shnum = None
		self.e_shstrndx = None


class Shstrndx(object):
	'''
	SHN_UNDEF (0)	This  value  marks  an  undefined,  missing, irrelevant,
		or otherwise meaningless section reference.  For
		example, a symbol "defined" relative to section number SHN_UNDEF is an
		undefined symbol.

	SHN_LORESERVE (0xff00) This value specifies the lower bound of the range
		of reserved indices.

	SHN_LOPROC (0xff00)    Values greater than or equal to SHN_HIPROC are
		reserved for processor-specific semantics.

	SHN_HIPROC (0xff1f)    Values less than or equal to SHN_LOPROC are
		reserved for processor-specific semantics.

	SHN_ABS (0xfff1)       This value specifies absolute values for the
		corresponding reference.  For example, symbols defined relative
		to section number SHN_ABS have absolute values and are not
		affected by relocation.

	SHN_COMMON (0xfff2)    Symbols  defined  relative  to  this  section
		are common symbols, such as Fortran COMMON or unallocated C
		external variables.

	SHN_HIRESERVE (0xffff) This value specifies the upper bound of the range
		of reserved indices between SHN_LORESERVE and SHN_HIRESERVE,
		inclusive; the values do not reference the section header table.
		That is, the section header table does not contain entries for the
		reserved indices.
	'''
	SHN_UNDEF = 0x0
	SHN_LORESERVE = 0xff00
	SHN_LOPROC = 0xff00
	SHN_HIPROC = 0xff1f
	SHN_ABS = 0xfff1
	SHN_COMMON = 0xfff2
	SHN_HIRESERVE = 0xffff


class ElfN_Shdr(object):
	'''
	typedef struct {
		uint32_t	sh_name;
		uint32_t	sh_type;
		uintN_t		sh_flags;     (N = 32/64)
		ElfN_Addr	sh_addr;      (N = 32/64)
		ElfN_Off	sh_offset;    (N = 32/64)
		uintN_t		sh_size;      (N = 32/64)
		uint32_t	sh_link;
		uint32_t	sh_info;
		uintN_t		sh_addralign; (N = 32/64)
		uintN_t		sh_entsize;   (N = 32/64)
	} ElfN_Shdr;
	'''
	def __init__(self):
		self.sh_name = None
		self.sh_type = None
		self.sh_flags = None
		self.sh_offset = None
		self.sh_size = None
		self.sh_link = None
		self.sh_info = None
		self.sh_addralign = None
		self.sh_entsize = None


# section headers sh_flags values
class SH_flags(object):
	'''
	SHF_WRITE (0x1)      This section contains data that should be writable
		during process execution.

	SHF_ALLOC (0x2)      This  section occupies memory during process
		execution.  Some control sections do not reside in the memory
		image of an object file.  This attribute is off for those sections.

	SHF_EXECINSTR (0x4)  This section contains executable machine instructions.

	SHF_MASKPROC (0xf0000000)   All bits included in this mask are reserved
		for processor-specific semantics.
	'''
	SHF_WRITE = 0x1
	SHF_ALLOC = 0x2
	SHF_EXECINSTR = 0x4
	SHF_MASKPROC = 0xf0000000


# section headers sh_type values
class SH_type(object):
	'''
	SHT_NULL (0)      This  value  marks the section header as inactive.
		It does not have an associated section.  Other members
		of the section header have undefined values.

	SHT_PROGBITS (1)  This section holds information defined by the program,
		whose format and meaning are determined  solely  by
		the program.

	SHT_SYMTAB (2)   This section holds a symbol table.  Typically,
		SHT_SYMTAB provides symbols for link editing, though it may
		also be used for dynamic linking.  As a complete symbol table,
		it may contain many symbols unnecessary for
		dynamic linking.  An object file can also contain a SHT_DYNSYM section.

	SHT_STRTAB (3)     This section holds a string table.
		An object file may have multiple string table sections.

	SHT_RELA (4)     This  section holds relocation entries with explicit
		addends, such as type Elf32_Rela for the 32-bit class
		of object files.  An object may have multiple relocation sections.

	SHT_HASH (5)      This section holds a symbol hash table.  An object
		participating in dynamic linking must contain a  symbol
		hash table.  An object file may have only one hash table.

	SHT_DYNAMIC (6)   This section holds information for dynamic linking.
		An object file may have only one dynamic section.

	SHT_NOTE (7)      This section holds information that marks the file
		in some way.

	SHT_NOBITS (8)    A  section of this type occupies no space in the file
		but otherwise resembles SHT_PROGBITS.  Although this
		section contains no bytes, the sh_offset member contains
		the conceptual file offset.

	SHT_REL (9)       This section holds relocation offsets without explicit
		addends, such as  type  Elf32_Rel  for  the  32-bit
		class of object files.  An object file may have multiple
		relocation sections.

	SHT_SHLIB (10)     This section is reserved but has unspecified semantics.

	SHT_DYNSYM (11)    This section holds a minimal set of dynamic linking
		symbols.  An object file can also contain a SHT_SYMTAB section.

	SHT_LOPROC (0x70000000)    This value up to and including SHT_HIPROC is
		reserved for processor-specific semantics.

	SHT_HIPROC (0x7fffffff)    This value down to and including SHT_LOPROC is
		reserved for processor-specific semantics.

	SHT_LOUSER (0x80000000)    This value specifies the lower bound of the
		range of indices reserved for application programs.

	SHT_HIUSER (0xffffffff)    This value specifies the upper bound of the
		range of indices reserved for application  programs.   Section
		types  between  SHT_LOUSER and SHT_HIUSER may be used by the
		application, without conflicting with current
	'''
	reverse_lookup = {0x0: "SHT_NULL", 0x1: "SHT_PROGBITS",
		0x2: "SHT_SYMTAB", 0x3: "SHT_STRTAB", 0x4: "SHT_RELA",
		0x5: "SHT_HASH", 0x6: "SHT_DYNAMIC", 0x7: "SHT_NOTE",
		0x8: "SHT_NOBITS", 0x9: "SHT_REL", 0xA: "SHT_SHLIB",
		0xB: "SHT_DYNSYM", 0xe: "SHT_INIT_ARRAY",
		0xf: "SHT_FINI_ARRAY",
		0x6ffffff5: "SHT_GNU_ATTRIBUTES", 0x6ffffff6: "SHT_GNU_HASH",
		0x6ffffff7: "SHT_GNU_LIBLIST", 0x6ffffff8: "SHT_CHECKSUM",
		0x6ffffffe: "SHT_VERNEED", 0x6fffffff: "SHT_VERSYM",
		0x70000000: "SHT_LOPROC",
		0x7fffffff: "SHT_HIPROC", 0x80000000: "SHT_LOUSER",
		0xffffffff: "SHT_HIUSER"}
	SHT_NULL = 0x0
	SHT_PROGBITS = 0x1
	SHT_SYMTAB = 0x2
	SHT_STRTAB = 0x3
	SHT_RELA = 0x4
	SHT_HASH = 0x5
	SHT_DYNAMIC = 0x6
	SHT_NOTE = 0x7
	SHT_NOBITS = 0x8
	SHT_REL = 0x9
	SHT_SHLIB = 0xA
	SHT_DYNSYM = 0xB
	SHT_INIT_ARRAY = 0xe
	SHT_FINI_ARRAY = 0xf
	SHT_GNU_ATTRIBUTES = 0x6ffffff5
	SHT_GNU_HASH = 0x6ffffff6
	SHT_GNU_LIBLIST = 0x6ffffff7
	SHT_CHECKSUM = 0x6ffffff8
	SHT_VERNEED = 0x6ffffffe
	SHT_VERSYM = 0x6fffffff
	SHT_LOPROC = 0x70000000
	SHT_HIPROC = 0x7fffffff
	SHT_LOUSER = 0x80000000
	SHT_HIUSER = 0xffffffff


class Elf32_Phdr(object):
	'''
	typedef struct {
		uint32_t   p_type;
		Elf32_Off  p_offset;
		Elf32_Addr p_vaddr;
		Elf32_Addr p_paddr;
		uint32_t   p_filesz;
		uint32_t   p_memsz;
		uint32_t   p_flags;
		uint32_t   p_align;
	} Elf32_Phdr;
	'''
	def __init__(self):
		self.p_type = None
		self.p_offset = None
		self.p_vaddr = None
		self.p_paddr = None
		self.p_filesz = None
		self.p_memsz = None
		self.p_flags = None
		self.p_align = None


# program headers p_type values
class P_type(object):
	'''
	PT_NULL (0)     The array element is unused and the other members' values
		are undefined.  This lets the program header have
		ignored entries.

	PT_LOAD (1)     The array element specifies a loadable segment,
		described by p_filesz and p_memsz.  The bytes from the file
		are mapped to the beginning of the memory segment.
		If the segment's memory size p_memsz is larger than the
		file  size p_filesz, the "extra" bytes are defined to hold the
		value 0 and to follow the segment's initialized area.
		The file size may not be larger than the memory size.
		Loadable segment entries in the  program
		header table appear in ascending order, sorted on the p_vaddr member.

	PT_DYNAMIC (2)  The array element specifies dynamic linking information.

	PT_INTERP (3)   The  array  element  specifies  the  location and size
		of a null-terminated pathname to invoke as an interpreter.
		This segment type is meaningful only  for  executable  files
		(though  it  may  occur  for  shared
		objects).   However it may not occur more than once in a file.
		If it is present, it must precede any loadable segment entry.

	PT_NOTE (4)     The array element specifies the location and size
		for auxiliary information.

	PT_SHLIB (5)    This segment type is reserved but has unspecified
		semantics.  Programs that contain  an  array  element  of
		this type do not conform to the ABI.

	PT_PHDR (6)     The  array element, if present, specifies the location
		and size of the program header table itself, both in
		the file and in the memory image of the program.  This segment
		type may not occur more than once in a file.
		Moreover,  it may only occur if the program header table is
		part of the memory image of the program.  If it
		is present, it must precede any loadable segment entry.

	PT_LOPROC (0x70000000)   Values greater than or equal to PT_HIPROC
		are reserved for processor-specific semantics.

	PT_HIPROC (0x7fffffff)  Values less than or equal to PT_LOPROC
		are reserved for processor-specific semantics.

	PT_GNU_STACK GNU extension which is used by the Linux kernel to
		control the state of the stack via the flags set in  the
		p_flags member.

	PT_GNU_RELRO (0x6474e552)  Read only after relocation
	'''
	reverse_lookup = {0x0: "PT_NULL", 0x1: "PT_LOAD", 0x2: "PT_DYNAMIC",
		0x3: "PT_INTERP", 0x4: "PT_NOTE", 0x5: "PT_SHLIB",
		0x6: "PT_PHDR", 0x70000000: "PT_LOPROC",
		0x7fffffff: "PT_HIPROC", 0x6474E550: "PT_GNU_EH_FRAME",
		0x6474e551: "PT_GNU_STACK", 0x6474e552: "PT_GNU_RELRO"}
	PT_NULL = 0x0
	PT_LOAD = 0x1
	PT_DYNAMIC = 0x2
	PT_INTERP = 0x3
	PT_NOTE = 0x4
	PT_SHLIB = 0x5
	PT_PHDR = 0x6
	PT_LOPROC = 0x70000000
	PT_HIPROC = 0x7fffffff
	PT_GNU_EH_FRAME = 0x6474E550
	PT_GNU_STACK = 0x6474e551
	PT_GNU_RELRO = 0x6474e552


class P_flags(object):
	PF_X = 0x1
	PF_W = 0x2
	PF_R = 0x4


class D_tag(object):
	'''
	DT_NULL     Marks end of dynamic section

	DT_NEEDED   String table offset to name of a needed library

	DT_PLTRELSZ Size in bytes of PLT relocs

	DT_PLTGOT   Address of PLT and/or GOT

	DT_HASH     Address of symbol hash table

	DT_STRTAB   Address of string table

	DT_SYMTAB   Address of symbol table

	DT_RELA     Address of Rela relocs table

	DT_RELASZ   Size in bytes of Rela table

	DT_RELAENT  Size in bytes of a Rela table entry

	DT_STRSZ    Size in bytes of string table

	DT_SYMENT   Size in bytes of a symbol table entry

	DT_INIT     Address of the initialization function

	DT_FINI     Address of the termination function

	DT_SONAME   String table offset to name of shared object

	DT_RPATH    String table offset to library search path (deprecated)

	DT_SYMBOLIC Alert linker to search this shared object before the
		executable for symbols

	DT_REL      Address of Rel relocs table

	DT_RELSZ    Size in bytes of Rel table

	DT_RELENT   Size in bytes of a Rel table entry

	DT_PLTREL   Type of reloc the PLT refers (Rela or Rel)

	DT_DEBUG    Undefined use for debugging

	DT_TEXTREL  Absence of this indicates no relocs should apply to a
		nonwritable segment

	DT_JMPREL   Address of reloc entries solely for the PLT

	DT_BIND_NOW Instruct dynamic linker to process all relocs before
		transferring control to the executable

	DT_RUNPATH  String table offset to library search path

	DT_LOPROC   Start of processor-specific semantics

	DT_HIPROC   End of processor-specific semantics
	'''
	reverse_lookup = {0x0: "DT_NULL", 0x1: "DT_NEEDED", 0x2: "DT_PLTRELSZ",
		0x3: "DT_PLTGOT", 0x4: "DT_HASH", 0x5: "DT_STRTAB", 0x6: "DT_SYMTAB",
		0x7: "DT_RELA", 0x8: "DT_RELASZ", 0x9: "DT_RELAENT", 0xa: "DT_STRSZ",
		0xb: "DT_SYMENT", 0xc: "DT_INIT", 0xd: "DT_FINI", 0xe: "DT_SONAME",
		0xf: "DT_RPATH", 0x10: "DT_SYMBOLIC", 0x11: "DT_REL", 0x12: "DT_RELSZ",
		0x13: "DT_RELENT", 0x14: "DT_PLTREL", 0x15: "DT_DEBUG",
		0x16: "DT_TEXTREL", 0x17: "DT_JMPREL", 0x19: "DT_INIT_ARRAY",
		0x1a: "DT_FINI_ARRAY", 0x1b: "DT_INIT_ARRAYSZ",
		0x1c: "DT_FINI_ARRAYSZ", 0x6ffffef5: "DT_GNU_HASH",
		0x6ffffff0: "DT_VERSYM", 0x6ffffffe: "DT_VERNEED",
		0x6fffffff: "DT_VERNEEDNUM", 0x70000000: "DT_LOPROC",
		0x7fffffff: "DT_HIPROC"}
	DT_NULL = 0x0
	DT_NEEDED = 0x1
	DT_PLTRELSZ = 0x2
	DT_PLTGOT = 0x3
	DT_HASH = 0x4
	DT_STRTAB = 0x5
	DT_SYMTAB = 0x6
	DT_RELA = 0x7
	DT_RELASZ = 0x8
	DT_RELAENT = 0x9
	DT_STRSZ = 0xa
	DT_SYMENT = 0xb
	DT_INIT = 0xc
	DT_FINI = 0xd
	DT_SONAME = 0xe
	DT_RPATH = 0xf
	DT_SYMBOLIC = 0x10
	DT_REL = 0x11
	DT_RELSZ = 0x12
	DT_RELENT = 0x13
	DT_PLTREL = 0x14
	DT_DEBUG = 0x15
	DT_TEXTREL = 0x16
	DT_JMPREL = 0x17
	DT_INIT_ARRAY = 0x19
	DT_FINI_ARRAY = 0x1a
	DT_INIT_ARRAYSZ = 0x1b
	DT_FINI_ARRAYSZ = 0x1c
	#DT_BIND_NOW
	#DT_RUNPATH
	DT_GNU_HASH = 0x6ffffef5
	DT_VERSYM = 0x6ffffff0
	DT_VERNEED = 0x6ffffffe
	DT_VERNEEDNUM = 0x6fffffff
	DT_LOPROC = 0x70000000
	DT_HIPROC = 0x7fffffff


class ElfN_Dyn(object):
	'''
	typedef struct {
		Elf32_Sword    d_tag;
		union {
			Elf32_Word d_val;
			Elf32_Addr d_ptr;
		} d_un;
	} Elf32_Dyn;

	typedef struct {
		Elf64_Sxword    d_tag;
		union {
			Elf64_Xword d_val;
			Elf64_Addr  d_ptr;
		} d_un;
	} Elf64_Dyn;
	'''
	def __init__(self):
		self.d_tag = None
		self.d_un = None


class ElfN_Rel(object):
	'''
	typedef struct elf32_rel {
		Elf32_Addr    r_offset;
		Elf32_Word    r_info;
	} Elf32_Rel;

	typedef struct elf64_rel {
		Elf64_Addr r_offset;  /* Location at which to apply the action */
		Elf64_Xword r_info;   /* index and type of relocation */
	} Elf64_Rel;

	Macros for 32 bit systems
	#define ELF32_R_SYM(i)		((i)>>8)
	#define ELF32_R_TYPE(i)		((unsigned char)(i))
	#define ELF32_R_INFO(s,t)	(((s)<<8)+(unsigned char)(t))

	Macros for 64 bit systems
	#define ELF64_R_SYM(i)		((i)>>32)
	#define ELF64_R_TYPE(i)		((i)&0xffffffff)
	#define ELF64_R_INFO(s,t)	(((s)<<32)+(t))
	'''
	def __init__(self):
		# in executable and share object files => r_offset holds a virtual address
		self.r_offset = None

		# for 32 bit systems:
		# r_info = (r_sym << 8) + (r_type & 0xFF)
		self.r_info = None

		# for 32 bit systems calculated: "(unsigned char)(r_info)" or just "r_info & 0xFF"
		self.r_type = None

		# for 32 bit systems calculated: "r_info >> 8"
		self.r_sym = None

		# for 32 bit systems
		self.symbol = DynamicSymbol()


class ElfN_Rela(object):
	'''
	typedef struct
	{
		Elf32_Addr	r_offset;		/* Address */
		Elf32_Word	r_info;			/* Relocation type and symbol index */
		Elf32_Sword	r_addend;		/* Addend */
	} Elf32_Rela;

	typedef struct
	{
		Elf64_Addr		r_offset;		/* Address */
		Elf64_Xword		r_info;			/* Relocation type and symbol index */
		Elf64_Sxword	r_addend;		/* Addend */
	} Elf64_Rela;

	Macros for 32/64 bit systems: see description for ElfN_Rel
	'''
	def __init__(self):
		# in executable and share object files => r_offset holds a virtual address
		self.r_offset = None

		self.r_info = None
		self.r_type = None
		self.r_sym = None

		self.r_addend = None

		self.symbol = DynamicSymbol()


class ElfN_Sym(object):
	'''
	typedef struct elf32_sym {
		Elf32_Word		st_name;
		Elf32_Addr		st_value;
		Elf32_Word		st_size;
		unsigned char	st_info;
		unsigned char	st_other;
		Elf32_Half		st_shndx;
	} Elf32_Sym;

	typedef struct elf64_sym {
		Elf64_Word 		st_name;	/* Symbol name, index in string tbl */
		unsigned char 	st_info;	/* Type and binding attributes */
		unsigned char 	st_other;	/* No defined meaning, 0 */
		Elf64_Half 		st_shndx;	/* Associated section index */
		Elf64_Addr 		st_value;	/* Value of the symbol */
		Elf64_Xword 	st_size;	/* Associated symbol size */
	} Elf64_Sym;
	'''
	def __init__(self):
		st_name = None
		st_value = None
		st_size = None
		st_info = None
		st_other = None
		st_shndx = None


class R_type(object):
	'''
	R_386_GOT32 	This relocation type computes the distance from the
		base of the global offset
		table to the symbol's global offset table entry.
		It additionally instructs the link
		editor to build a global offset table.

	R_386_PLT32 	This relocation type computes the address of the
		symbol's procedure linkage
		table entry and additionally instructs the link editor to
		build a procedure linkage table.

	R_386_COPY 		The link editor creates this relocation type for
		dynamic linking. Its offset
		member refers to a location in a writable segment.
		The symbol table index specifies a symbol that should exist
		both in the current object file and in a shared
		object. During execution, the dynamic linker copies data
		associated with the shared object's symbol to the location
		specified by the offset.

	R_386_GLOB_DAT 	This relocation type is used to set a global offset
		table entry to the address of the specified symbol. The
		special relocation type allows one to determine the
		correspondence between symbols and global offset table entries.

	R_3862_JMP_SLOT The link editor creates this relocation type for
		dynamic linking. Its offset member gives the location of a
		procedure linkage table entry. The dynamic linker modifies
		the procedure linkage table entry to transfer control to the
		designated symbol's address.

	R_386_RELATIVE 	The link editor creates this relocation type for
		dynamic linking. Its offset member gives a location within a
		shared object that contains a value representing a relative address.
		The dynamic linker computes the corresponding virtual
		address by adding the virtual address at which the shared object
		was loaded to the relative address. Relocation entries for this
		type must specify 0 for the symbol table index.

	R_386_GOTOFF 	This relocation type computes the difference between a
		symbol's value and the address of the global offset table. It
		additionally instructs the link editor to build the global
		offset table.

	R_386_GOTPC 	This relocation type resembles R_386_PC32, except it uses
		the address of the global offset table in its calculation.
		The symbol referenced in this relocation
		normally is _GLOBAL_OFFSET_TABLE_, which additionally instructs
		the link editor to build the global offset table.
	'''
	reverse_lookup = {0: "R_386_NONE", 1: "R_386_32", 2: "R_386_PC32",
		3: "R_386_GOT32", 4: "R_386_PLT32", 5: "R_386_COPY",
		6: "R_386_GLOB_DAT", 7: "R_386_JMP_SLOT", 8: "R_386_RELATIVE",
		9: "R_386_GOTOFF", 10: "R_386_GOTPC"}
	R_386_NONE = 0
	R_386_32 = 1
	R_386_PC32 = 2
	R_386_GOT32 = 3
	R_386_PLT32 = 4
	R_386_COPY = 5
	R_386_GLOB_DAT = 6
	R_386_JMP_SLOT = 7
	R_386_RELATIVE = 8
	R_386_GOTOFF = 9
	R_386_GOTPC = 10
