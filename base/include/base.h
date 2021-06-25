/*************************************************************************/
/*	> File Name: base.h */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 12:10:37 PM CST */
/************************************************************************/
#ifndef BASE_H_
#define BASE_H_

#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/user.h>
#include <stdarg.h>

//remove warning
extern char *strdup (__const char *__s)
	__THROW __attribute_malloc__ __nonnull ((1));
extern size_t strnlen (__const char *__string, size_t __maxlen)
     __THROW __attribute_pure__ __nonnull ((1));

#define TRUE 1
#define FALSE 0

//"-V" for "Injector 1.0"
#define INJ_NAME "Injector"
#define INJ_MAJORVER 1
#define INJ_MINORVER 0
#define EXENAME_LEN 32

#if __WORDSIZE == 64
	typedef Elf64_Ehdr Elf_Ehdr;
	typedef Elf64_Shdr Elf_Shdr;
	typedef Elf64_Phdr Elf_Phdr;
	typedef Elf64_Sym Elf_Sym;
	typedef Elf64_Dyn Elf_Dyn;
#elif __WORDSIZE == 32
	typedef Elf32_Ehdr Elf_Ehdr;
	typedef Elf32_Shdr Elf_Shdr;
	typedef Elf32_Phdr Elf_Phdr;
	typedef Elf32_Sym Elf_Sym;
	typedef Elf32_Dyn Elf_Dyn;
#else
	#error ">>>> invalid word size, choices: 64 | 32 <<<<"
#endif

typedef enum{
	PERMISSION_INVALID = 0,
	PERMISSION_EXEC = 1,
	PERMISSION_WR = 2,
	PERMISSION_RD = 4,
	PERMISSION_SHARED = 8,
	PERMISSION_PRIVATE = 16,
	PERMISSION_ALLOC= 32,
}Permission;
typedef enum{
	MAPTYPE_INVALID = 0,
	MAPTYPE_SO,
	MAPTYPE_EXE,
	MAPTYPE_DATA,
	MAPTYPE_STACK,
	MAPTYPE_HEAP,
	MAPTYPE_VDSO,
	MAPTYPE_SYSCALL,
	MAPTYPE_ANONY,
}MapType;
typedef enum{
	SYMTYPE_INVALID = 0,
	SYMTYPE_FUNC,
	SYMTYPE_OBJ,
	SYMTYPE_SEC,
	SYMTYPE_FILE,
}SymType;
typedef enum{
	FILETYPE_INVALID = 0,
	FILETYPE_REL,
	FILETYPE_EXEC,
	FILETYPE_SO,
	FILETYPE_CORE,
}FileType;
typedef enum{
	ARCHITECTURE_INVALID = 0,
	ARCHITECTURE_X86_64,
	ARCHITECTURE_X86_32,
}Architecture;
typedef enum{
	CPUBITS_INVALID = 0,
	CPUBITS_64,
	CPUBITS_32,
}CpuBits;
typedef enum{
	ENDIAN_INVALID = 0,
	ENDIAN_BIG,
	ENDIAN_LITTLE,
}Endian;
typedef struct{
	int len;
	char *addr;
}String;

typedef struct{
	//"-v[vvv]"
	int iVerbose;
	//"-P PID"
	pid_t pid;
	//"-O [FILE]"
	struct{
		char isset; //for future
		char *filename;
	}stExportFile;
	//"-f ADDR/FUNC-NAME"
	struct{
		char isalloc;	//only used for func when we need to allocate memory for saving string, 0:allocated 1:non-allocated
		union{
			uintptr_t addr;
			char *func;
		}u;
	}stFrame;
	//"-s \"FUNC-NAME1 FUNC-NAME2\""
	struct{
		char *ori;
		char *now;
	}stStub;
	//"-m ADDR LEN"
	struct{
		uintptr_t addr;
		size_t len;
	}stMem;
	//"-M SYMBOL-NMAE"
	char *pcSymbol;
	//"-p	ADDR/FUNC-NAME"
	struct{
		char isalloc;
		union{
			uintptr_t addr;
			char *func;
		}u;
	}stSetPc;
	//"-i	SOLIB"
	char *pcSoName;
	//"-t ADDR/FUNC-NAME"
	struct{
		char isalloc;
		union{
			uintptr_t addr;
			char *func;
		}u;
	}stTestFunc;
}Args;

typedef struct{
	unsigned int ptype;
	Permission perm;	//enum Permission
	size_t offset;
	uintptr_t vaddr;
	String name;
}ProgHdr;
typedef struct{
	int phdrnum;
	ProgHdr *prog;	//needed program header for link_map
}ExeInfo;

typedef struct LibNodes_{
	MapType type;
	Permission perm;
	ino_t inode;
	struct LibNodes_ *next, *prev;
	uintptr_t dynaddr;//only used for EXE file
	uintptr_t bgnaddr;//only used for SO file
	uintptr_t endaddr;//last valid address
	char *libname;
}LibNodes;
typedef struct{
	unsigned int num;
	LibNodes *nodes;
	struct link_map last;
}LibInfo;

typedef struct{
	char *name;
	uintptr_t addr;
	size_t sz;
	SymType type;
}SymNode;
typedef struct{
	unsigned int num;	//number of all symbols in syms
	void *syms;	//array of many SymNode
	unsigned int *sortname;
	unsigned int *sortaddr;
}Symbol;

#define SHELL_NASM "nasm"
#define SHELL_YASM "yasm"
#define SHELL_RM "rm"
typedef enum{
	ASMCMD_INVALID = 0,
	ASMCMD_SFTINTR,
	ASMCMD_JUMP,
	ASMCMD_BUT,
}AsmCmdType;

typedef struct{
#define ASMCMD_NUM 30
	int num;
	String sftintr;	//soft interrupt
	String jump;	//jump instruction
	String saved;	//save asm code of target process
	String reserved[ASMCMD_NUM];	//reserved for future asm commands
}AsmCmd;
typedef struct{
	int num;
	uintptr_t *params;
}Params;

typedef struct{
#define INJ_LIB_LD "ld"
#define INJ_LIB_C "libc"
#define INJ_LIB_DL "libdl"
#define INJ_LIB_PTHREAD "libpthread"	//for future features

#define INJ_C_LD_MALLOC "malloc"
//for future features START
#define INJ_C_LD_REALLOC "realloc"
#define INJ_C_LD_CALLOC "calloc"
#define INJ_C_LD_FREE "free"
//for future features END
#define INJ_C_LD_PRINTF "printf"
#define INJ_C_LD_FOPEN "fopen"
#define INJ_C_LD_FPRINTF "fprintf"
#define INJ_C_LD_FCLOSE "fclose"
//for future features START
#define INJ_C_LD_OPEN "open"
#define INJ_C_LD_READ "read"
#define INJ_C_LD_WRITE "write"
#define INJ_C_LD_CLOSE "close"
#define INJ_C_DLOPEN "__libc_dlopen_mode"
#define INJ_C_DLSYM "__libc_dlsym"
#define INJ_C_DLCLOSE "__libc_dlclose"
//for future features END
#define INJ_DL_OPEN "dlopen"
#define INJ_DL_SYM "dlsym"
#define INJ_DL_CLOSE "dlclose"

#define INJ_C_SYSTEM "system"
#define INJ_C_STRLEN "strlen"

#define  INJ_MAX_PARAMS 6
	uintptr_t isinit;
	uintptr_t alloc;
	uintptr_t free;
	uintptr_t strlen;
	uintptr_t printf;
	uintptr_t fopen;
	uintptr_t fprintf;
	uintptr_t fclose;
	uintptr_t system;
	uintptr_t dlopen;
	uintptr_t dlsym;
	uintptr_t dlclose;
}SysFunc;

typedef struct{
#define TARGET_STRS_NUM 50
#define TARGET_MEMBLOCK_NUM 30
#define TARGET_SIZEPERBLK 256
	int strnum;
	int blknum;
	int szperblk;
	char *strs[TARGET_STRS_NUM];	//hold address of strings stored in target process
	int sused[TARGET_STRS_NUM];	//hold used space position of each strs block
	uintptr_t memblk[TARGET_MEMBLOCK_NUM];	//hold address of memory blocks allocated by malloc in target process
	uintptr_t mused[TARGET_MEMBLOCK_NUM];	//hold used space position of each mem block
}AuxStrs;

typedef struct{
	Args stArgs;	//hold args
	ExeInfo stExeInfo;	//hold exe info
	LibInfo stLib;	//dependent libs of target process
	Symbol stSymTab;	//symbols table of target process
	AsmCmd stAsmCmd;	//hold asm commands
	SysFunc stSysFunc;	//hold system functions in target mapped memory zone, like malloc,print,dl*,...
	AuxStrs stAuxStrs;	//hold momory or strings address we need to allocate in target memory for our cross-processes calling
}InjWrapper;

//basic objects to hold ELF information, which serves for 'Symbol' and 'LibInfo' in InjWrapper
typedef struct{
	unsigned int nmind;
	unsigned int stype;
	Permission perm;	//enum Permission
	size_t offset;
	size_t tbzonesz;
	size_t tbitemsz;
}SecHdr;
typedef struct{
	CpuBits bits;	//enum CpuBits
	Endian endian;	//enum Endian
	unsigned short osabi;
	FileType ftype;	//enum FileType
	Architecture arch;	//enum Architecture
	uintptr_t entry;
	uintptr_t phoff;
	uintptr_t shoff;
	unsigned int ehsz;
	unsigned int phunitsz;
	unsigned int phnum;
	unsigned int shunitsz;
	unsigned int shnum;
	unsigned int shstrind;
}ElfHdr;

typedef struct{	//hold ELF information of target process and dependent shared libraries
	ElfHdr elf;
	unsigned int shnum;
	SecHdr *sec;
	unsigned int phnum;
	ProgHdr *prog;
}ElfInfo;

typedef enum{	//suit with ResStr
	RESCODE_SUCCESS = 0,
	RESCODE_FAIL,	//1
	RESCODE_FAIL_ALLOC,	//2
	RESCODE_FAIL_OPEN,	//3
	RESCODE_FAIL_READ,	//4
	RESCODE_FAIL_SEEK,	//5
	RESCODE_FAIL_PTRACE_ATTACH,	//6
	RESCODE_FAIL_PTRACE_DETACH,	//7
	RESCODE_FAIL_PTRACE_POKE,	//8
	RESCODE_FAIL_PTRACE_PEEK,	//9
	RESCODE_FAIL_PTRACE_SETREG,	//10
	RESCODE_FAIL_PTRACE_GETREG,	//11
	RESCODE_FAIL_PTRACE_CONT,	//12
	RESCODE_FAIL_WAIT,	//13
	RESCODE_FAIL_NODIGIT,	//14
	RESCODE_FAIL_INVALID_ARGS,	//15
	RESCODE_FAIL_STRTOK,	//16
	RESCODE_FAIL_MKDIR,	//17
	RESCODE_FAIL_RMOVE,	//18
}ResCode;

#if __GNUC__ >= 4
	#if INJECTOR_EXPORT
		//#warning "----dynamic library----"
		#pragma message "----dynamic library----"
		#define API_PUBLIC __attribute__((visibility("default")))
		#define API_PRIVATE __attribute__((visibility("hidden")))
		#define VAR_PRIVATE API_PRIVATE
		#define VAR_PUBLIC API_PUBLIC
	#else
		//#warning "----static library----"
		#pragma message "----static library----"
		#define API_PUBLIC
		#define API_PRIVATE
		#define VAR_PRIVATE API_PRIVATE
		#define VAR_PUBLIC API_PUBLIC
	#endif
#else
	#error ">>> require gcc version >= 4.0 <<<"
#endif

#define LOGLEVEL_ERROR  0
#define LOGLEVEL_WARN  1
#define LOGLEVEL_INFO  2
#define LOGLEVEL_TRACE  3
#define LOGLEVEL_DEBUG  4
#define LOGLEVEL_MORE  5
#define ERROR "error| "
#define WARN "warning| "
#define INFO "info| "
#define TRACE "trace| "
#define DEBUG "debug| "
#define MORE "more| "

#ifdef __cplusplus
extern "C"{
#endif
VAR_PRIVATE extern va_list ap;
VAR_PUBLIC extern char *ResStr[];
VAR_PRIVATE extern const char sp[2];
VAR_PRIVATE extern const char dash[2];
VAR_PRIVATE extern const char newline[2];
VAR_PRIVATE extern const char colon[2];
VAR_PRIVATE extern const uintptr_t null;
#ifdef __cplusplus
}
#endif

#define ELOG(Code, ...) fprintf(stdout, ResStr[Code], __func__, ##__VA_ARGS__)
#define LOG(format, ...) fprintf(stdout, format, ##__VA_ARGS__)

#define CHECK(cond, err, ...){\
	if(cond) { ELOG(err, __LINE__, strerror(errno)); __VA_ARGS__; }\
}
#define FILTERC(cond, enable, err, ...){\
	if(cond) { if(enable) ELOG(err, __LINE__, strerror(errno)); __VA_ARGS__; }\
}
#define CHECKFAIL(cond, ...){\
	if(cond) { ELOG(RESCODE_FAIL, __LINE__); __VA_ARGS__; }\
}
#define FILTERCF(cond, enable, ...){\
	if(cond) { if(enable) ELOG(RESCODE_FAIL, __LINE__); __VA_ARGS__; }\
}
#define ENLOG(level, statement){\
	if(verbose >= level) {statement;} \
}

#endif
