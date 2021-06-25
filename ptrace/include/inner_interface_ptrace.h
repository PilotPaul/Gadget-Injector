/*************************************************************************/
/*	> File Name: inner_interface_ptrace.h */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 12:08:39 PM CST */
/************************************************************************/
#ifndef INNER_INTERFACE_PTRACE_H_
#define INNER_INTERFACE_PTRACE_H_

#include "base.h"

#if __WORDSIZE == 64 //usage of struct user's regs member
	#define INJREG_PC(R) (R).regs.rip
	#define INJREG_SP(R) (R).regs.rsp
	#define INJREG_BP(R) (R).regs.rbp
	#define INJREG_AX(R) (R).regs.rax	//return value
	#define INJREG_A1(R) (R).regs.rdi	//the 1st argument
	#define INJREG_A2(R) (R).regs.rsi	//the 2nd
	#define INJREG_A3(R) (R).regs.rdx	//3rd
	#define INJREG_A4(R) (R).regs.rcx	//4th
	#define INJREG_A5(R) (R).regs.r8	//5th
	#define INJREG_A6(R) (R).regs.r9	//6th
	#define RED_ZONE 128
#elif __WORDSIZE == 32
	#define INJREG_PC(R) (R).regs.eip
	#define INJREG_SP(R) (R).regs.esp
	#define INJREG_BP(R) (R).regs.ebp
	#define INJREG_AX(R) (R).regs.eax
	#define RED_ZONE 0
	//use POKEDATA to transfer argument to stack
#else
	#error "=== invalid word size ==="
#endif 

#define MAX_DEPTH 20
#define MAX_ARGUMENTLEN 128

#ifdef __cplusplus
extern "C"{
#endif
API_PRIVATE ResCode InjPrepareFuncAndPara(Params *paramlist, va_list vabgn, SysFunc *callset, uintptr_t func, pid_t pid, int verbose, ...);	//match args with funcitons
API_PRIVATE ResCode InjLiCall(uintptr_t *ret, int verbose, pid_t pid, uintptr_t func, ...);	//call in target process, "..." means variable argument lists with zero or more arguments,
API_PRIVATE ResCode InjSftBreak(pid_t pid, uintptr_t tgtaddr, String *intr, String *saved, struct user *ori, struct user *cur, int verbose);	//save process asm code,insert soft interrupt req,
API_PRIVATE ResCode InjSftRevert(pid_t pid, uintptr_t tgtaddr, String *origintr, struct user *origiregs, int verbose);	//revert breakpiont,
API_PRIVATE ResCode InjPokeAndPrintBt(pid_t pid, Symbol *symtab, struct user *regs, int verbose);	//print out the calling backtrace,
API_PRIVATE ResCode InjHardBreak();//to do
API_PRIVATE ResCode InjHardRevert();//to do
//following interfaces strongly require PATRACE_ATTACH,SETREGS,GETREGS to invoke system functions in target process
API_PRIVATE ResCode InjLiAttach(pid_t pid, int verbose);	//PTRACE_ATTACH,
API_PRIVATE ResCode InjLiContinue(pid_t pid);	//PTRACE_CONT,
API_PRIVATE ResCode InjLiWait(pid_t pid, int verbose);	//waitpid,
API_PRIVATE ResCode InjLiDetach(pid_t pid, int verbose);	//PTRACE_DETACH,
API_PRIVATE ResCode InjLiWriteDataOrTxt(pid_t pid, int isdata, uintptr_t taddr, uintptr_t wdata, size_t len, int verbose);	//PTRACE_POKEDATA and PTRACE_POKETEXT,
API_PRIVATE ResCode InjLiReadDataOrText(pid_t pid, int isdata, uintptr_t taddr, uintptr_t rdata, size_t len, int verbose);	//PTRACE_PEEKDATA or PEEKTEXT, former isn't equal to PEEKTXT when get from .txt,
API_PRIVATE ResCode InjLiSetRegs(pid_t pid, struct user *regs, int verbose);	//PTRACE_SETREGS,
API_PRIVATE ResCode InjLiGetRegs(pid_t pid, struct user *orig, int verbose);	//PTRACE_GETREGS,
#ifdef __cplusplus
}
#endif

#endif
